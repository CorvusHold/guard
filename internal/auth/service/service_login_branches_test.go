package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type loginRepoStub struct {
	fakeRepo

	authIdentityOut domain.AuthIdentity
	authIdentityErr error
	lookupEmail     string

	userOut domain.User
	userErr error

	lockedUntil *time.Time

	incrementCountOut int32
	incrementErr      error
	incrementCalled   bool

	lockCalled bool
	lockUntil  time.Time
	lockErr    error

	mfaSecret domain.MFASecret
	mfaErr    error

	resetCalled       bool
	updateLoginCalled bool
}

func (r *loginRepoStub) GetAuthIdentityByEmailTenant(ctx context.Context, tenantID uuid.UUID, email string) (domain.AuthIdentity, error) {
	r.lookupEmail = email
	if r.authIdentityErr != nil {
		return domain.AuthIdentity{}, r.authIdentityErr
	}
	return r.authIdentityOut, nil
}

func (r *loginRepoStub) GetUserByID(context.Context, uuid.UUID) (domain.User, error) {
	if r.userErr != nil {
		return domain.User{}, r.userErr
	}
	return r.userOut, nil
}

func (r *loginRepoStub) GetLockoutStatus(context.Context, uuid.UUID, string) (int32, *time.Time, error) {
	return 0, r.lockedUntil, nil
}

func (r *loginRepoStub) IncrementFailedAttempts(context.Context, uuid.UUID, string) (int32, error) {
	r.incrementCalled = true
	if r.incrementErr != nil {
		return 0, r.incrementErr
	}
	return r.incrementCountOut, nil
}

func (r *loginRepoStub) LockAccount(context.Context, uuid.UUID, string, time.Time) error {
	r.lockCalled = true
	return r.lockErr
}

func (r *loginRepoStub) GetMFASecret(context.Context, uuid.UUID) (domain.MFASecret, error) {
	if r.mfaErr != nil {
		return domain.MFASecret{}, r.mfaErr
	}
	return r.mfaSecret, nil
}

func (r *loginRepoStub) ResetFailedAttempts(context.Context, uuid.UUID, string) error {
	r.resetCalled = true
	return nil
}

func (r *loginRepoStub) UpdateUserLoginAt(context.Context, uuid.UUID) error {
	r.updateLoginCalled = true
	return nil
}

func (r *loginRepoStub) GetAuthIdentitiesByUser(context.Context, uuid.UUID) ([]domain.AuthIdentity, error) {
	return []domain.AuthIdentity{{TenantID: r.authIdentityOut.TenantID, Email: r.authIdentityOut.Email}}, nil
}

func (r *loginRepoStub) ListUserRoleNames(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
	return []string{"member"}, nil
}

func (r *loginRepoStub) InsertRefreshTokenWithFamily(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, *uuid.UUID, string, string, time.Time, string, *uuid.UUID, *domain.RefreshTokenMetadata, uuid.UUID) error {
	return nil
}

type loginSettingsStub struct{}

func (loginSettingsStub) GetString(context.Context, string, *uuid.UUID, string) (string, error) {
	return "", nil
}
func (loginSettingsStub) GetDuration(context.Context, string, *uuid.UUID, time.Duration) (time.Duration, error) {
	return time.Minute, nil
}
func (loginSettingsStub) GetInt(_ context.Context, key string, _ *uuid.UUID, def int) (int, error) {
	if key == sdomain.KeyLockoutThreshold {
		return 2, nil
	}
	return def, nil
}

func TestService_Login_EarlyAndFailureBranches(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	hash, err := bcrypt.GenerateFromPassword([]byte("right-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &loginRepoStub{
		authIdentityOut:   domain.AuthIdentity{UserID: userID, TenantID: tenantID, Email: "user@example.com", PasswordHash: string(hash)},
		userOut:           domain.User{ID: userID, IsActive: true},
		incrementCountOut: 2,
	}
	s := &Service{repo: repo, settings: loginSettingsStub{}, cfg: config.Config{}}

	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID}); err == nil || !strings.Contains(err.Error(), "email and password are required") {
		t.Fatalf("expected missing credentials error, got %v", err)
	}

	repo.authIdentityErr = errors.New("identity lookup failed")
	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "u@example.com", Password: "x"}); err == nil {
		t.Fatal("expected auth identity lookup error")
	}
	repo.authIdentityErr = nil

	repo.userErr = errors.New("user lookup failed")
	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "u@example.com", Password: "x"}); err == nil {
		t.Fatal("expected user lookup error")
	}
	repo.userErr = nil

	repo.userOut = domain.User{ID: userID, IsActive: false}
	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "u@example.com", Password: "x"}); err == nil || err.Error() != "user is blocked" {
		t.Fatalf("expected blocked user error, got %v", err)
	}
	repo.userOut = domain.User{ID: userID, IsActive: true}

	locked := time.Now().Add(2 * time.Minute)
	repo.lockedUntil = &locked
	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "u@example.com", Password: "x"}); err == nil || !strings.Contains(err.Error(), "temporarily locked") {
		t.Fatalf("expected account lockout error, got %v", err)
	}
	repo.lockedUntil = nil

	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "  USER@Example.com ", Password: "wrong-pass"}); err == nil || err.Error() != "invalid credentials" {
		t.Fatalf("expected invalid credentials error, got %v", err)
	}
	if repo.lookupEmail != "user@example.com" {
		t.Fatalf("expected normalized lowercase email lookup, got %q", repo.lookupEmail)
	}
	if !repo.incrementCalled {
		t.Fatal("expected failed-attempt increment on bad password")
	}
	if !repo.lockCalled {
		t.Fatal("expected lock account when threshold reached")
	}
}

func TestService_Login_MFAAndSuccessBranches(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	hash, err := bcrypt.GenerateFromPassword([]byte("right-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	repo := &loginRepoStub{
		authIdentityOut: domain.AuthIdentity{UserID: userID, TenantID: tenantID, Email: "user@example.com", PasswordHash: string(hash)},
		userOut:         domain.User{ID: userID, IsActive: true, FirstName: "U", LastName: "Ser"},
	}
	s := &Service{repo: repo, settings: loginSettingsStub{}, cfg: config.Config{}, pub: publisherFunc(func(context.Context, evdomain.Event) error { return nil })}

	// MFA enabled + no key manager => key manager required branch
	repo.mfaSecret = domain.MFASecret{Enabled: true, Secret: "ABC"}
	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "u@example.com", Password: "right-pass"}); err == nil || err.Error() != "asymmetric key manager required" {
		t.Fatalf("expected key manager required for MFA challenge, got %v", err)
	}

	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	s.SetKeyManager(km)

	// MFA enabled + key manager => ErrMFARequired challenge
	if _, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "u@example.com", Password: "right-pass"}); err == nil || !strings.Contains(fmt.Sprintf("%T", err), "ErrMFARequired") {
		t.Fatalf("expected ErrMFARequired, got %v", err)
	}

	// MFA disabled => successful login token issuance
	repo.mfaSecret = domain.MFASecret{Enabled: false}
	toks, err := s.Login(context.Background(), domain.LoginInput{TenantID: tenantID, Email: "u@example.com", Password: "right-pass", UserAgent: "ua", IP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("expected successful login, got %v", err)
	}
	if toks.AccessToken == "" || toks.RefreshToken == "" {
		t.Fatalf("expected tokens, got %+v", toks)
	}
	if !repo.resetCalled || !repo.updateLoginCalled {
		t.Fatalf("expected reset/update side-effects, got reset=%v updateLogin=%v", repo.resetCalled, repo.updateLoginCalled)
	}
}
