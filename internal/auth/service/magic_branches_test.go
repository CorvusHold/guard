package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

type magicRepoStub struct {
	fakeRepo

	authIdentityOut domain.AuthIdentity
	authIdentityErr error

	createMagicErr    error
	createMagicCalled bool

	magicByHashOut domain.MagicLink
	magicByHashErr error

	consumeMagicErr error

	createUserErr         error
	createAuthIdentityErr error
	addUserToTenantErr    error

	insertRefreshErr error
}

func (r *magicRepoStub) GetAuthIdentityByEmailTenant(context.Context, uuid.UUID, string) (domain.AuthIdentity, error) {
	if r.authIdentityErr != nil {
		return domain.AuthIdentity{}, r.authIdentityErr
	}
	return r.authIdentityOut, nil
}

func (r *magicRepoStub) CreateMagicLink(context.Context, uuid.UUID, *uuid.UUID, uuid.UUID, string, string, string, time.Time) error {
	r.createMagicCalled = true
	return r.createMagicErr
}

func (r *magicRepoStub) GetMagicLinkByHash(context.Context, string) (domain.MagicLink, error) {
	if r.magicByHashErr != nil {
		return domain.MagicLink{}, r.magicByHashErr
	}
	return r.magicByHashOut, nil
}

func (r *magicRepoStub) ConsumeMagicLink(context.Context, string) error { return r.consumeMagicErr }
func (r *magicRepoStub) CreateUser(context.Context, uuid.UUID, string, string, []string) error {
	return r.createUserErr
}
func (r *magicRepoStub) CreateAuthIdentity(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, string) error {
	return r.createAuthIdentityErr
}
func (r *magicRepoStub) AddUserToTenant(context.Context, uuid.UUID, uuid.UUID) error {
	return r.addUserToTenantErr
}
func (r *magicRepoStub) InsertRefreshToken(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, string, *uuid.UUID, string, string, time.Time, string, *uuid.UUID, *domain.RefreshTokenMetadata) error {
	return r.insertRefreshErr
}

type magicSettingsStub struct{}

func (magicSettingsStub) GetString(context.Context, string, *uuid.UUID, string) (string, error) {
	return "https://app.example", nil
}
func (magicSettingsStub) GetDuration(context.Context, string, *uuid.UUID, time.Duration) (time.Duration, error) {
	return time.Minute, nil
}
func (magicSettingsStub) GetInt(context.Context, string, *uuid.UUID, int) (int, error) { return 0, nil }

type magicEmailStub struct {
	to string
}

func (m *magicEmailStub) Send(ctx context.Context, tenantID uuid.UUID, to, subject, body string) error {
	m.to = to
	return nil
}

func TestMagic_NewAndSetters(t *testing.T) {
	repo := &magicRepoStub{}
	email := &magicEmailStub{}
	m := NewMagic(repo, config.Config{}, magicSettingsStub{}, email)
	if m == nil || m.repo != repo || m.email != email {
		t.Fatalf("expected NewMagic wiring, got %#v", m)
	}

	pub := publisherFunc(func(context.Context, evdomain.Event) error { return nil })
	m.SetPublisher(pub)
	if m.pub == nil {
		t.Fatal("expected SetPublisher to assign publisher")
	}

	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	m.SetKeyManager(km)
	if m.keyMgr != km {
		t.Fatal("expected SetKeyManager to replace key manager")
	}
}

func TestMagic_SendAndCreateForTest_Branches(t *testing.T) {
	repo := &magicRepoStub{}
	email := &magicEmailStub{}
	m := &Magic{repo: repo, settings: magicSettingsStub{}, email: email}

	if err := m.Send(context.Background(), domain.MagicSendInput{}); err == nil || err.Error() != "email is required" {
		t.Fatalf("expected email required from Send, got %v", err)
	}
	if _, err := m.CreateForTest(context.Background(), domain.MagicSendInput{}); err == nil || err.Error() != "email is required" {
		t.Fatalf("expected email required from CreateForTest, got %v", err)
	}

	repo.createMagicErr = errors.New("insert failed")
	if err := m.Send(context.Background(), domain.MagicSendInput{TenantID: uuid.New(), Email: "u@example.com"}); err == nil {
		t.Fatal("expected create magic link error from Send")
	}
	if _, err := m.CreateForTest(context.Background(), domain.MagicSendInput{TenantID: uuid.New(), Email: "u@example.com"}); err == nil {
		t.Fatal("expected create magic link error from CreateForTest")
	}

	repo.createMagicErr = nil
	if err := m.Send(context.Background(), domain.MagicSendInput{TenantID: uuid.New(), Email: "u@example.com"}); err != nil {
		t.Fatalf("Send unexpected err=%v", err)
	}
	if !repo.createMagicCalled || email.to != "u@example.com" {
		t.Fatalf("expected Send path to persist link and send email, called=%v to=%q", repo.createMagicCalled, email.to)
	}

	tok, err := m.CreateForTest(context.Background(), domain.MagicSendInput{TenantID: uuid.New(), Email: "u@example.com"})
	if err != nil || tok == "" {
		t.Fatalf("CreateForTest unexpected token=%q err=%v", tok, err)
	}
}

func TestMagic_Verify_Branches(t *testing.T) {
	repo := &magicRepoStub{}
	m := &Magic{
		repo:     repo,
		settings: magicSettingsStub{},
		pub: publisherFunc(func(context.Context, evdomain.Event) error {
			return nil
		}),
	}

	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{}); err == nil || err.Error() != "token required" {
		t.Fatalf("expected token required, got %v", err)
	}

	repo.magicByHashErr = errors.New("not found")
	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"}); err == nil {
		t.Fatal("expected magic lookup error")
	}
	repo.magicByHashErr = nil

	consumed := time.Now().Add(-time.Minute)
	repo.magicByHashOut = domain.MagicLink{TenantID: uuid.New(), Email: "u@example.com", ExpiresAt: time.Now().Add(time.Hour), ConsumedAt: &consumed}
	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"}); err == nil || err.Error() != "token expired or already used" {
		t.Fatalf("expected consumed/expired error, got %v", err)
	}

	repo.magicByHashOut = domain.MagicLink{TenantID: uuid.New(), Email: "u@example.com", ExpiresAt: time.Now().Add(time.Hour)}
	repo.consumeMagicErr = errors.New("consume failed")
	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"}); err == nil {
		t.Fatal("expected consume error")
	}
	repo.consumeMagicErr = nil

	repo.authIdentityErr = errors.New("not found")
	repo.createUserErr = errors.New("create user failed")
	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"}); err == nil {
		t.Fatal("expected create user error")
	}
	repo.createUserErr = nil
	repo.createAuthIdentityErr = errors.New("create identity failed")
	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"}); err == nil {
		t.Fatal("expected create auth identity error")
	}
	repo.createAuthIdentityErr = nil
	repo.addUserToTenantErr = errors.New("add tenant failed")
	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"}); err == nil {
		t.Fatal("expected add user to tenant error")
	}
	repo.addUserToTenantErr = nil

	// Reach token issuance branch with key manager missing
	repo.authIdentityErr = nil
	repo.authIdentityOut = domain.AuthIdentity{UserID: uuid.New(), TenantID: uuid.New(), Email: "u@example.com"}
	_, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"})
	if err == nil || !strings.Contains(err.Error(), "asymmetric key manager required") {
		t.Fatalf("expected asymmetric key manager required, got %v", err)
	}

	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	m.keyMgr = km
	repo.insertRefreshErr = errors.New("insert refresh failed")
	if _, err := m.Verify(context.Background(), domain.MagicVerifyInput{Token: "tok"}); err == nil {
		t.Fatal("expected refresh insert error")
	}
}
