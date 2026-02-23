package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type resetRepoStub struct {
	fakeRepo

	getByTenantOut domain.AuthIdentity
	getByTenantErr error

	findByEmailOut []domain.AuthIdentity
	findByEmailErr error

	createResetErr   error
	createResetCalls int
	createdTenantIDs []uuid.UUID

	getResetOut domain.PasswordResetToken
	getResetErr error

	updatePasswordRows int64
	updatePasswordErr  error

	consumeRows int64
	consumeErr  error

	revokeSessionsErr error

	authByUserOut []domain.AuthIdentity
	authByUserErr error
}

func (r *resetRepoStub) GetAuthIdentityByEmailTenant(ctx context.Context, tenantID uuid.UUID, email string) (domain.AuthIdentity, error) {
	if r.getByTenantErr != nil {
		return domain.AuthIdentity{}, r.getByTenantErr
	}
	return r.getByTenantOut, nil
}

func (r *resetRepoStub) FindAuthIdentitiesByEmail(ctx context.Context, email string) ([]domain.AuthIdentity, error) {
	if r.findByEmailErr != nil {
		return nil, r.findByEmailErr
	}
	return r.findByEmailOut, nil
}

func (r *resetRepoStub) CreatePasswordResetToken(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, email, tokenHash string, expiresAt time.Time) error {
	r.createResetCalls++
	r.createdTenantIDs = append(r.createdTenantIDs, tenantID)
	return r.createResetErr
}

func (r *resetRepoStub) GetPasswordResetTokenByHash(context.Context, string) (domain.PasswordResetToken, error) {
	if r.getResetErr != nil {
		return domain.PasswordResetToken{}, r.getResetErr
	}
	return r.getResetOut, nil
}

func (r *resetRepoStub) UpdateAuthIdentityPassword(context.Context, uuid.UUID, string, string) (int64, error) {
	return r.updatePasswordRows, r.updatePasswordErr
}

func (r *resetRepoStub) ConsumePasswordResetToken(context.Context, string) (int64, error) {
	return r.consumeRows, r.consumeErr
}

func (r *resetRepoStub) RevokeUserSessions(context.Context, uuid.UUID, uuid.UUID) (int64, error) {
	return 0, r.revokeSessionsErr
}

func (r *resetRepoStub) GetAuthIdentitiesByUser(context.Context, uuid.UUID) ([]domain.AuthIdentity, error) {
	if r.authByUserErr != nil {
		return nil, r.authByUserErr
	}
	return r.authByUserOut, nil
}

type passwordPolicyStrictStub struct{}

func (passwordPolicyStrictStub) GetString(context.Context, string, *uuid.UUID, string) (string, error) {
	return "false", nil
}
func (passwordPolicyStrictStub) GetDuration(context.Context, string, *uuid.UUID, time.Duration) (time.Duration, error) {
	return time.Minute, nil
}
func (passwordPolicyStrictStub) GetInt(_ context.Context, key string, _ *uuid.UUID, def int) (int, error) {
	if key == "password.min_length" {
		return 12, nil
	}
	return def, nil
}

func TestService_RequestPasswordReset_Branches(t *testing.T) {
	pubEvents := make([]evdomain.Event, 0, 4)
	repo := &resetRepoStub{}
	s := &Service{
		repo:     repo,
		cfg:      config.Config{PublicBaseURL: "https://app.example", MagicLinkTTL: time.Minute},
		settings: settingsStub{value: "https://tenant.example"},
		pub: publisherFunc(func(ctx context.Context, e evdomain.Event) error {
			pubEvents = append(pubEvents, e)
			return nil
		}),
	}

	if err := s.RequestPasswordReset(context.Background(), domain.PasswordResetRequestInput{Email: "   "}); err == nil {
		t.Fatal("expected email required error")
	}

	tenantID := uuid.New()
	repo.getByTenantErr = errors.New("not found")
	if err := s.RequestPasswordReset(context.Background(), domain.PasswordResetRequestInput{TenantID: &tenantID, Email: "u@example.com"}); err != nil {
		t.Fatalf("expected silent success for unknown identity, got %v", err)
	}

	repo.getByTenantErr = nil
	repo.getByTenantOut = domain.AuthIdentity{UserID: uuid.New(), TenantID: tenantID, Email: "u@example.com"}
	repo.createResetErr = errors.New("insert failed")
	if err := s.RequestPasswordReset(context.Background(), domain.PasswordResetRequestInput{TenantID: &tenantID, Email: "u@example.com"}); err == nil {
		t.Fatal("expected create reset error in single-tenant flow")
	}

	repo.createResetErr = nil
	if err := s.RequestPasswordReset(context.Background(), domain.PasswordResetRequestInput{TenantID: &tenantID, Email: "u@example.com"}); err != nil {
		t.Fatalf("expected successful tenant-specific reset request, got %v", err)
	}
	if repo.createResetCalls == 0 {
		t.Fatal("expected CreatePasswordResetToken to be called")
	}

	repo.findByEmailErr = errors.New("db down")
	if err := s.RequestPasswordReset(context.Background(), domain.PasswordResetRequestInput{Email: "u@example.com"}); err != nil {
		t.Fatalf("expected silent success for lookup failure, got %v", err)
	}

	repo.findByEmailErr = nil
	repo.findByEmailOut = nil
	if err := s.RequestPasswordReset(context.Background(), domain.PasswordResetRequestInput{Email: "u@example.com"}); err != nil {
		t.Fatalf("expected silent success for missing user, got %v", err)
	}

	repo.findByEmailOut = []domain.AuthIdentity{{UserID: uuid.New(), TenantID: uuid.New(), Email: "u@example.com"}, {UserID: uuid.New(), TenantID: uuid.New(), Email: "u@example.com"}}
	beforeCalls := repo.createResetCalls
	if err := s.RequestPasswordReset(context.Background(), domain.PasswordResetRequestInput{Email: "u@example.com"}); err != nil {
		t.Fatalf("expected success for multi-tenant reset flow, got %v", err)
	}
	if repo.createResetCalls-beforeCalls != 2 {
		t.Fatalf("expected 2 reset-token creates in multi-tenant flow, got delta=%d", repo.createResetCalls-beforeCalls)
	}
	if len(pubEvents) == 0 {
		t.Fatal("expected password reset audit event(s)")
	}
}

func TestService_Revoke_UnsupportedType(t *testing.T) {
	s := &Service{}
	if err := s.Revoke(context.Background(), "token", "access"); err == nil || err.Error() != "unsupported token type" {
		t.Fatalf("expected unsupported token type error, got %v", err)
	}
}

func TestService_ConfirmPasswordReset_Branches(t *testing.T) {
	repo := &resetRepoStub{}
	now := time.Now()
	tenantID := uuid.New()
	userID := uuid.New()
	s := &Service{
		repo:     repo,
		settings: settingsStub{value: "false"},
		cfg:      config.Config{},
		pub: publisherFunc(func(context.Context, evdomain.Event) error {
			return nil
		}),
	}

	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{}); err == nil || err.Error() != "token required" {
		t.Fatalf("expected token required, got %v", err)
	}

	repo.getResetErr = errors.New("not found")
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", NewPassword: "Password!123"}); err == nil || err.Error() != "invalid or expired token" {
		t.Fatalf("expected invalid or expired token, got %v", err)
	}
	repo.getResetErr = nil

	consumed := now.Add(-time.Minute)
	repo.getResetOut = domain.PasswordResetToken{TenantID: tenantID, UserID: userID, Email: "u@example.com", ExpiresAt: now.Add(time.Hour), ConsumedAt: &consumed}
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", NewPassword: "Password!123"}); err == nil || err.Error() != "token expired or already used" {
		t.Fatalf("expected consumed-token error, got %v", err)
	}

	repo.getResetOut = domain.PasswordResetToken{TenantID: tenantID, UserID: userID, Email: "u@example.com", ExpiresAt: now.Add(-time.Minute)}
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", NewPassword: "Password!123"}); err == nil || err.Error() != "token expired or already used" {
		t.Fatalf("expected expired-token error, got %v", err)
	}

	repo.getResetOut = domain.PasswordResetToken{TenantID: tenantID, UserID: userID, Email: "u@example.com", ExpiresAt: now.Add(time.Hour)}
	otherTenant := uuid.New()
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", TenantID: &otherTenant, NewPassword: "Password!123"}); err == nil || err.Error() != "invalid token" {
		t.Fatalf("expected tenant mismatch error, got %v", err)
	}

	repo.updatePasswordErr = errors.New("update failed")
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", NewPassword: "Password!123"}); err == nil {
		t.Fatal("expected password update error")
	}
	repo.updatePasswordErr = nil

	repo.updatePasswordRows = 0
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", NewPassword: "Password!123"}); err == nil || err.Error() != "user not found" {
		t.Fatalf("expected user not found, got %v", err)
	}

	repo.updatePasswordRows = 1
	repo.consumeErr = errors.New("consume failed")
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", NewPassword: "Password!123"}); err == nil {
		t.Fatal("expected consume error")
	}

	repo.consumeErr = nil
	repo.consumeRows = 0 // race condition branch (non-fatal)
	repo.revokeSessionsErr = errors.New("revoke failed")
	if err := s.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{Token: "tok", NewPassword: "Password!123"}); err != nil {
		t.Fatalf("expected success despite consume=0/revoke error, got %v", err)
	}
}

func TestService_ChangePassword_Branches(t *testing.T) {
	repo := &resetRepoStub{}
	tenantID := uuid.New()
	userID := uuid.New()

	sStrict := &Service{repo: repo, settings: passwordPolicyStrictStub{}}
	if err := sStrict.ChangePassword(context.Background(), domain.PasswordChangeInput{UserID: userID, TenantID: tenantID, CurrentPassword: "old", NewPassword: "short"}); err == nil || !strings.Contains(err.Error(), "password policy violation") {
		t.Fatalf("expected password policy violation, got %v", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("old-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash old password: %v", err)
	}

	s := &Service{
		repo:     repo,
		settings: settingsStub{value: "false"},
		pub: publisherFunc(func(context.Context, evdomain.Event) error {
			return nil
		}),
	}
	repo.authByUserErr = errors.New("identities failed")
	if err := s.ChangePassword(context.Background(), domain.PasswordChangeInput{UserID: userID, TenantID: tenantID, CurrentPassword: "old-pass", NewPassword: "Password!123"}); err == nil {
		t.Fatal("expected identities lookup error")
	}
	repo.authByUserErr = nil

	repo.authByUserOut = []domain.AuthIdentity{{UserID: userID, TenantID: uuid.New(), Email: "u@example.com", PasswordHash: string(hash)}}
	if err := s.ChangePassword(context.Background(), domain.PasswordChangeInput{UserID: userID, TenantID: tenantID, CurrentPassword: "old-pass", NewPassword: "Password!123"}); err == nil || err.Error() != "user not found in tenant" {
		t.Fatalf("expected user not found in tenant, got %v", err)
	}

	repo.authByUserOut = []domain.AuthIdentity{{UserID: userID, TenantID: tenantID, Email: "u@example.com", PasswordHash: string(hash)}}
	if err := s.ChangePassword(context.Background(), domain.PasswordChangeInput{UserID: userID, TenantID: tenantID, CurrentPassword: "wrong", NewPassword: "Password!123"}); err == nil || err.Error() != "current password is incorrect" {
		t.Fatalf("expected current password mismatch error, got %v", err)
	}

	repo.updatePasswordErr = errors.New("update failed")
	if err := s.ChangePassword(context.Background(), domain.PasswordChangeInput{UserID: userID, TenantID: tenantID, CurrentPassword: "old-pass", NewPassword: "Password!123"}); err == nil {
		t.Fatal("expected update password error")
	}
	repo.updatePasswordErr = nil

	repo.updatePasswordRows = 0
	if err := s.ChangePassword(context.Background(), domain.PasswordChangeInput{UserID: userID, TenantID: tenantID, CurrentPassword: "old-pass", NewPassword: "Password!123"}); err == nil || err.Error() != "user not found" {
		t.Fatalf("expected user not found after update, got %v", err)
	}

	repo.updatePasswordRows = 1
	repo.revokeSessionsErr = errors.New("revoke failed") // non-fatal branch
	if err := s.ChangePassword(context.Background(), domain.PasswordChangeInput{UserID: userID, TenantID: tenantID, CurrentPassword: "old-pass", NewPassword: "Password!123"}); err != nil {
		t.Fatalf("expected success despite revoke warning, got %v", err)
	}
}
