package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"reflect"
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

	published := false
	pub := publisherFunc(func(context.Context, evdomain.Event) error {
		published = true
		return nil
	})
	s.SetPublisher(pub)
	if s.pub == nil {
		t.Fatal("expected publisher to be set")
	}
	if err := s.pub.Publish(context.Background(), evdomain.Event{}); err != nil {
		t.Fatalf("expected publisher to be callable, got err=%v", err)
	}
	if !published {
		t.Fatal("expected SetPublisher to replace publisher with sentinel")
	}

	logger := zerolog.New(io.Discard).Level(zerolog.InfoLevel)
	s.SetLogger(logger)
	if s.log.GetLevel() != logger.GetLevel() {
		t.Fatalf("expected logger level %s, got %s", logger.GetLevel(), s.log.GetLevel())
	}

	sender := emailSenderStub{}
	s.SetEmailSender(sender)
	if s.emailSender == nil {
		t.Fatal("expected email sender to be set")
	}

	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	s.SetKeyManager(km)
	if s.KeyManager() != km || !s.KeyManager().IsAsymmetric() {
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

	tests := []struct {
		name     string
		password string
		policy   PasswordPolicy
		want     []string
	}{
		{
			name:     "short password reports expected violations",
			password: "abc",
			policy:   policy,
			want: []string{
				"password must be at least 8 characters",
				"password must contain at least one uppercase letter",
				"password must contain at least one digit",
				"password must contain at least one special character",
			},
		},
		{
			name:     "max length violation",
			password: "Aa1!Aa1!Aa1!Aa1!",
			policy:   policy,
			want:     []string{"password must be at most 12 characters"},
		},
		{
			name:     "valid password",
			password: "Abcdef1!",
			policy:   policy,
			want:     nil,
		},
		{
			name:     "max length disabled",
			password: "x",
			policy:   PasswordPolicy{MinLength: 1, MaxLength: 0},
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidatePassword(tc.password, tc.policy)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("unexpected violations for %q: got=%v want=%v", tc.password, got, tc.want)
			}
		})
	}
}
