package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/keys"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type settingsStub struct {
	value string
}

func (s settingsStub) GetString(context.Context, string, *uuid.UUID, string) (string, error) {
	return s.value, nil
}
func (s settingsStub) GetDuration(context.Context, string, *uuid.UUID, time.Duration) (time.Duration, error) {
	return 0, nil
}
func (s settingsStub) GetInt(context.Context, string, *uuid.UUID, int) (int, error) { return 0, nil }

type emailSenderStub struct{}

func (emailSenderStub) Send(context.Context, uuid.UUID, string, string, string) error { return nil }

func writeTestECPrivateKey(t *testing.T) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	keyPath := filepath.Join(t.TempDir(), "jwt-es256-private.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return keyPath
}

func TestService_NewAndSettersAndIsEmailEnabled(t *testing.T) {
	repo := &fakeRepo{}
	cfg := config.Config{JWTSigningAlgorithm: "ES256", JWTPrivateKeyPath: writeTestECPrivateKey(t)}
	s := New(repo, cfg, settingsStub{value: "true"})
	if s == nil {
		t.Fatal("expected New to return service")
	}
	if s.repo != repo {
		t.Fatal("expected repo to be assigned")
	}

	pub := publisherFunc(func(context.Context, evdomain.Event) error { return nil })
	s.SetPublisher(pub)
	if s.pub == nil {
		t.Fatal("expected publisher to be set")
	}

	logger := zerolog.Nop()
	s.SetLogger(logger)
	if s.log.GetLevel() != logger.GetLevel() {
		t.Fatal("expected logger to be assigned")
	}

	sender := emailSenderStub{}
	s.SetEmailSender(sender)
	if s.emailSender == nil {
		t.Fatal("expected email sender to be set")
	}

	km, err := keys.NewManager("HS256", "", "unit-test-signing-key")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	s.SetKeyManager(km)
	if s.KeyManager() != km {
		t.Fatal("expected key manager round-trip")
	}

	tid := uuid.New()
	if !s.isEmailEnabled(context.Background(), &tid) {
		t.Fatal("expected email enabled when setting is true")
	}

	s.settings = settingsStub{value: " FALSE "}
	if s.isEmailEnabled(context.Background(), &tid) {
		t.Fatal("expected email disabled when setting is false")
	}
}

func TestValidatePassword_AllConstraintBranches(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:        8,
		MaxLength:        12,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}

	violations := ValidatePassword("abc", policy)
	if len(violations) != 4 {
		t.Fatalf("expected exactly 4 violations, got %d: %v", len(violations), violations)
	}

	violations = ValidatePassword("Aa1!Aa1!Aa1!Aa1!", policy)
	if len(violations) != 1 {
		t.Fatalf("expected max length violation, got %v", violations)
	}

	violations = ValidatePassword("Abcdef1!", policy)
	if len(violations) != 0 {
		t.Fatalf("expected no violations for valid password, got %v", violations)
	}

	noMaxPolicy := PasswordPolicy{MinLength: 1, MaxLength: 0}
	if got := ValidatePassword("x", noMaxPolicy); len(got) != 0 {
		t.Fatalf("expected no violations when max length disabled, got %v", got)
	}

}
