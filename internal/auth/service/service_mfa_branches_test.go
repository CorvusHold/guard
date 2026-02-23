package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/config"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type mfaRepoStub struct {
	fakeRepo

	getAuthIDsOut []domain.AuthIdentity
	getAuthIDsErr error

	upsertErr         error
	upsertUserID      uuid.UUID
	upsertSecret      string
	upsertEnabled     bool
	upsertCalledCount int

	getMFAOut domain.MFASecret
	getMFAErr error

	insertBackupErr       error
	insertBackupCalledCnt int

	consumeBackupOut  bool
	consumeBackupErr  error
	consumeBackupHash string

	countBackupOut int64
	countBackupErr error
}

func (r *mfaRepoStub) GetAuthIdentitiesByUser(context.Context, uuid.UUID) ([]domain.AuthIdentity, error) {
	return r.getAuthIDsOut, r.getAuthIDsErr
}

func (r *mfaRepoStub) UpsertMFASecret(ctx context.Context, userID uuid.UUID, secret string, enabled bool) error {
	r.upsertUserID = userID
	r.upsertSecret = secret
	r.upsertEnabled = enabled
	r.upsertCalledCount++
	return r.upsertErr
}

func (r *mfaRepoStub) GetMFASecret(context.Context, uuid.UUID) (domain.MFASecret, error) {
	if r.getMFAErr != nil {
		return domain.MFASecret{}, r.getMFAErr
	}
	return r.getMFAOut, nil
}

func (r *mfaRepoStub) InsertMFABackupCode(context.Context, uuid.UUID, uuid.UUID, string) error {
	r.insertBackupCalledCnt++
	return r.insertBackupErr
}

func (r *mfaRepoStub) ConsumeMFABackupCode(ctx context.Context, userID uuid.UUID, codeHash string) (bool, error) {
	r.consumeBackupHash = codeHash
	return r.consumeBackupOut, r.consumeBackupErr
}

func (r *mfaRepoStub) CountRemainingMFABackupCodes(context.Context, uuid.UUID) (int64, error) {
	return r.countBackupOut, r.countBackupErr
}

func TestService_MFAEnrollmentAndBackupCodeBranches(t *testing.T) {
	repo := &mfaRepoStub{}
	tenantID := uuid.New()
	userID := uuid.New()
	s := &Service{repo: repo, cfg: config.Config{}, settings: settingsStub{value: "issuer-1"}}

	repo.getAuthIDsOut = []domain.AuthIdentity{{TenantID: tenantID, Email: "user@example.com"}}
	secret, otpauth, err := s.StartTOTPEnrollment(context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("StartTOTPEnrollment unexpected err=%v", err)
	}
	if secret == "" || !strings.Contains(otpauth, "issuer-1") {
		t.Fatalf("expected secret and otpauth with issuer, got secret=%q url=%q", secret, otpauth)
	}
	if repo.upsertUserID != userID || repo.upsertSecret == "" || repo.upsertEnabled {
		t.Fatalf("expected disabled secret upsert, got user=%s secret=%q enabled=%v", repo.upsertUserID, repo.upsertSecret, repo.upsertEnabled)
	}

	repo.upsertErr = errors.New("write failed")
	if _, _, err := s.StartTOTPEnrollment(context.Background(), userID, tenantID); err == nil {
		t.Fatal("expected upsert error from StartTOTPEnrollment")
	}
	repo.upsertErr = nil

	repo.getMFAErr = errors.New("not found")
	if err := s.ActivateTOTP(context.Background(), userID, "123456"); err == nil {
		t.Fatal("expected GetMFASecret error")
	}
	repo.getMFAErr = nil

	repo.getMFAOut = domain.MFASecret{UserID: userID, Secret: secret, Enabled: false}
	if err := s.ActivateTOTP(context.Background(), userID, "000000"); err == nil || err.Error() != "invalid TOTP code" {
		t.Fatalf("expected invalid TOTP code error, got %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if err := s.ActivateTOTP(context.Background(), userID, code); err != nil {
		t.Fatalf("ActivateTOTP unexpected err=%v", err)
	}
	if !repo.upsertEnabled {
		t.Fatal("expected ActivateTOTP to enable MFA")
	}

	if err := s.DisableTOTP(context.Background(), userID); err != nil {
		t.Fatalf("DisableTOTP unexpected err=%v", err)
	}
	if repo.upsertEnabled {
		t.Fatal("expected DisableTOTP to persist enabled=false")
	}

	if _, err := s.GenerateBackupCodes(context.Background(), userID, 0); err == nil {
		t.Fatal("expected count validation error")
	}
	repo.insertBackupErr = errors.New("insert failed")
	if _, err := s.GenerateBackupCodes(context.Background(), userID, 1); err == nil {
		t.Fatal("expected insert backup code error")
	}
	repo.insertBackupErr = nil
	repo.insertBackupCalledCnt = 0

	codes, err := s.GenerateBackupCodes(context.Background(), userID, 2)
	if err != nil || len(codes) != 2 || repo.insertBackupCalledCnt != 2 {
		t.Fatalf("GenerateBackupCodes unexpected result codes=%v err=%v inserts=%d", codes, err, repo.insertBackupCalledCnt)
	}
	if codes[0] == codes[1] {
		t.Fatalf("expected distinct backup codes, got %v", codes)
	}

	if _, err := s.ConsumeBackupCode(context.Background(), userID, ""); err == nil {
		t.Fatal("expected code required error")
	}
	repo.consumeBackupOut = true
	ok, err := s.ConsumeBackupCode(context.Background(), userID, "abc")
	if err != nil || !ok || repo.consumeBackupHash == "abc" || repo.consumeBackupHash == "" {
		t.Fatalf("ConsumeBackupCode unexpected ok=%v err=%v hash=%q", ok, err, repo.consumeBackupHash)
	}

	repo.countBackupOut = 3
	count, err := s.CountRemainingBackupCodes(context.Background(), userID)
	if err != nil || count != 3 {
		t.Fatalf("CountRemainingBackupCodes unexpected count=%d err=%v", count, err)
	}
}

func TestService_BackupCodeHelpers(t *testing.T) {
	h1 := hashCode("abc")
	h2 := hashCode("abc")
	if h1 == "" || h1 != h2 {
		t.Fatalf("expected deterministic non-empty hash, got h1=%q h2=%q", h1, h2)
	}

	code, err := generateBackupCode(10)
	if err != nil {
		t.Fatalf("generateBackupCode unexpected err=%v", err)
	}
	if code == "" {
		t.Fatal("expected generated backup code")
	}
}
