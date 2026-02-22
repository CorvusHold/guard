package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type authFlowRepoStub struct {
	fakeRepo

	createUserErr error
	createAuthErr error
	addTenantErr  error

	createdEmail string
	createdUser  uuid.UUID

	mfaSecretOut domain.MFASecret
	mfaSecretErr error

	consumeBackupOut bool
	consumeBackupErr error

	loginAtErr error
}

func (r *authFlowRepoStub) CreateUser(ctx context.Context, id uuid.UUID, firstName, lastName string, roles []string) error {
	r.createdUser = id
	return r.createUserErr
}

func (r *authFlowRepoStub) CreateAuthIdentity(ctx context.Context, id uuid.UUID, userID uuid.UUID, tenantID uuid.UUID, email, passwordHash string) error {
	r.createdEmail = email
	return r.createAuthErr
}

func (r *authFlowRepoStub) AddUserToTenant(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) error {
	return r.addTenantErr
}

func (r *authFlowRepoStub) GetMFASecret(ctx context.Context, userID uuid.UUID) (domain.MFASecret, error) {
	if r.mfaSecretErr != nil {
		return domain.MFASecret{}, r.mfaSecretErr
	}
	return r.mfaSecretOut, nil
}

func (r *authFlowRepoStub) ConsumeMFABackupCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	if r.consumeBackupErr != nil {
		return false, r.consumeBackupErr
	}
	return r.consumeBackupOut, nil
}

func (r *authFlowRepoStub) UpdateUserLoginAt(ctx context.Context, userID uuid.UUID) error {
	return r.loginAtErr
}

func makeChallengeToken(t *testing.T, km *keys.Manager, userID, tenantID uuid.UUID, sub, ten string) string {
	t.Helper()
	if sub == "" {
		sub = userID.String()
	}
	if ten == "" {
		ten = tenantID.String()
	}
	claims := jwt.MapClaims{
		"sub": sub,
		"ten": ten,
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(km.SigningMethod(), claims)
	tok.Header["kid"] = km.KeyID()
	signed, err := tok.SignedString(km.SigningKey(""))
	if err != nil {
		t.Fatalf("sign challenge token: %v", err)
	}
	return signed
}

func TestService_Signup_Branches(t *testing.T) {
	repo := &authFlowRepoStub{}
	s := &Service{
		repo:     repo,
		settings: fakeSettings{},
		cfg: config.Config{
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
			PublicBaseURL:   "http://app.example",
		},
		pub: publisherFunc(func(context.Context, evdomain.Event) error { return nil }),
	}

	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	s.SetKeyManager(km)
	tenantID := uuid.New()

	if _, err := s.Signup(context.Background(), domain.SignupInput{TenantID: tenantID, Email: "", Password: ""}); err == nil {
		t.Fatal("expected required email/password error")
	}
	if _, err := s.Signup(context.Background(), domain.SignupInput{TenantID: tenantID, Email: "u@example.com", Password: "short"}); err == nil {
		t.Fatal("expected password policy error")
	}

	repo.createUserErr = errors.New("create user failed")
	if _, err := s.Signup(context.Background(), domain.SignupInput{TenantID: tenantID, Email: "u@example.com", Password: "Password!123"}); err == nil {
		t.Fatal("expected create user error")
	}
	repo.createUserErr = nil

	repo.createAuthErr = errors.New("create auth failed")
	if _, err := s.Signup(context.Background(), domain.SignupInput{TenantID: tenantID, Email: "u@example.com", Password: "Password!123"}); err == nil {
		t.Fatal("expected create auth identity error")
	}
	repo.createAuthErr = nil

	repo.addTenantErr = errors.New("add tenant failed")
	if _, err := s.Signup(context.Background(), domain.SignupInput{TenantID: tenantID, Email: "u@example.com", Password: "Password!123"}); err == nil {
		t.Fatal("expected add user to tenant error")
	}
	repo.addTenantErr = nil

	toks, err := s.Signup(context.Background(), domain.SignupInput{TenantID: tenantID, Email: " USER@Example.com ", Password: "Password!123"})
	if err != nil {
		t.Fatalf("Signup unexpected err=%v", err)
	}
	if toks.AccessToken == "" || toks.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens, got %+v", toks)
	}
	if repo.createdEmail != "user@example.com" {
		t.Fatalf("expected normalized email, got %q", repo.createdEmail)
	}
}

func TestService_VerifyMFA_Branches(t *testing.T) {
	repo := &authFlowRepoStub{}
	s := &Service{
		repo:     repo,
		settings: fakeSettings{},
		cfg: config.Config{
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
			PublicBaseURL:   "http://app.example",
		},
		pub: publisherFunc(func(context.Context, evdomain.Event) error { return nil }),
	}

	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	s.SetKeyManager(km)
	uid := uuid.New()
	tid := uuid.New()

	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{}); err == nil {
		t.Fatal("expected required field error")
	}
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: "not-jwt", Method: "totp", Code: "123456"}); err == nil || err.Error() != "invalid challenge token" {
		t.Fatalf("expected invalid challenge token, got %v", err)
	}

	badSub := makeChallengeToken(t, km, uid, tid, "bad-subject", "")
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: badSub, Method: "totp", Code: "123456"}); err == nil || err.Error() != "invalid subject in challenge" {
		t.Fatalf("expected invalid subject error, got %v", err)
	}

	badTen := makeChallengeToken(t, km, uid, tid, "", "bad-tenant")
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: badTen, Method: "totp", Code: "123456"}); err == nil || err.Error() != "invalid tenant in challenge" {
		t.Fatalf("expected invalid tenant error, got %v", err)
	}

	goodToken := makeChallengeToken(t, km, uid, tid, "", "")
	sNoKM := &Service{repo: repo, settings: fakeSettings{}, pub: publisherFunc(func(context.Context, evdomain.Event) error { return nil })}
	if _, err := sNoKM.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: goodToken, Method: "totp", Code: "123456"}); err == nil || err.Error() != "asymmetric key manager required" {
		t.Fatalf("expected key manager required error without key manager, got %v", err)
	}

	repo.mfaSecretOut = domain.MFASecret{UserID: uid, Secret: "JBSWY3DPEHPK3PXP", Enabled: false}
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: goodToken, Method: "totp", Code: "123456"}); err == nil || err.Error() != "mfa not enabled" {
		t.Fatalf("expected mfa not enabled, got %v", err)
	}

	repo.mfaSecretOut = domain.MFASecret{UserID: uid, Secret: "JBSWY3DPEHPK3PXP", Enabled: true}
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: goodToken, Method: "totp", Code: "000000"}); err == nil || err.Error() != "invalid totp code" {
		t.Fatalf("expected invalid totp code, got %v", err)
	}

	repo.consumeBackupErr = errors.New("consume backup failed")
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: goodToken, Method: "backup_code", Code: "abc"}); err == nil {
		t.Fatal("expected backup consume error")
	}
	repo.consumeBackupErr = nil
	repo.consumeBackupOut = false
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: goodToken, Method: "backup_code", Code: "abc"}); err == nil || err.Error() != "invalid backup code" {
		t.Fatalf("expected invalid backup code, got %v", err)
	}
	if _, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: goodToken, Method: "sms", Code: "123"}); err == nil || err.Error() != "unsupported method" {
		t.Fatalf("expected unsupported method, got %v", err)
	}

	code, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	toks, err := s.VerifyMFA(context.Background(), domain.MFAVerifyInput{ChallengeToken: goodToken, Method: "totp", Code: code})
	if err != nil {
		t.Fatalf("VerifyMFA unexpected err=%v", err)
	}
	if toks.AccessToken == "" || toks.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens, got %+v", toks)
	}
}
