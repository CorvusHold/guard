package service

import (
	"context"
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

func TestService_NewAndSettersAndIsEmailEnabled(t *testing.T) {
	repo := &fakeRepo{}
	s := New(repo, config.Config{}, settingsStub{value: "true"})
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
