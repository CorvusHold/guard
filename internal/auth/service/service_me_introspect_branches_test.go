package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/auth/keys"
	"github.com/corvusHold/guard/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type meIntroRepoStub struct {
	fakeRepo

	userOut domain.User
	userErr error

	idsOut []domain.AuthIdentity
	idsErr error

	mfaOut domain.MFASecret
	mfaErr error

	rolesOut []string
	rolesErr error
}

func TestService_ParseAccessToken_Branches(t *testing.T) {
	s := &Service{}
	if _, err := s.ParseAccessToken(context.Background(), "x"); err == nil || err.Error() != "asymmetric key manager required" {
		t.Fatalf("expected key manager required error, got %v", err)
	}

	km, err := keys.NewManager("ES256", "", "")
	if err != nil {
		t.Fatalf("new key manager: %v", err)
	}
	s.keyMgr = km

	if _, err := s.ParseAccessToken(context.Background(), "not-a-jwt"); err == nil || err.Error() != "invalid token" {
		t.Fatalf("expected invalid token error, got %v", err)
	}

	uid := uuid.New()
	tid := uuid.New()
	claims := jwt.MapClaims{"sub": uid.String(), "ten": tid.String(), "email": "u@example.com", "roles": []string{"admin", "member"}, "exp": time.Now().Add(time.Hour).Unix()}
	tok := jwt.NewWithClaims(km.SigningMethod(), claims)
	tok.Header["kid"] = km.KeyID()
	signed, err := tok.SignedString(km.SigningKey("unused"))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	parsed, err := s.ParseAccessToken(context.Background(), signed)
	if err != nil {
		t.Fatalf("ParseAccessToken unexpected err=%v", err)
	}
	if parsed.UserID != uid || parsed.TenantID != tid || parsed.Email != "u@example.com" || len(parsed.Roles) != 2 {
		t.Fatalf("unexpected parsed claims: %+v", parsed)
	}
}

func (r *meIntroRepoStub) GetUserByID(context.Context, uuid.UUID) (domain.User, error) {
	if r.userErr != nil {
		return domain.User{}, r.userErr
	}
	return r.userOut, nil
}

func (r *meIntroRepoStub) GetAuthIdentitiesByUser(context.Context, uuid.UUID) ([]domain.AuthIdentity, error) {
	if r.idsErr != nil {
		return nil, r.idsErr
	}
	return r.idsOut, nil
}

func (r *meIntroRepoStub) GetMFASecret(context.Context, uuid.UUID) (domain.MFASecret, error) {
	if r.mfaErr != nil {
		return domain.MFASecret{}, r.mfaErr
	}
	return r.mfaOut, nil
}

func (r *meIntroRepoStub) ListUserRoleNames(context.Context, uuid.UUID, uuid.UUID) ([]string, error) {
	if r.rolesErr != nil {
		return nil, r.rolesErr
	}
	return r.rolesOut, nil
}

func TestService_Me_Branches(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	repo := &meIntroRepoStub{}
	s := &Service{repo: repo}

	repo.userErr = errors.New("user lookup failed")
	if _, err := s.Me(context.Background(), userID, tenantID); err == nil {
		t.Fatal("expected user lookup error")
	}
	repo.userErr = nil

	repo.userOut = domain.User{ID: userID, IsActive: true}
	repo.idsErr = errors.New("identities failed")
	if _, err := s.Me(context.Background(), userID, tenantID); err == nil {
		t.Fatal("expected identities lookup error")
	}
	repo.idsErr = nil

	repo.idsOut = []domain.AuthIdentity{{UserID: userID, TenantID: tenantID, Email: "u@example.com"}}
	repo.rolesErr = errors.New("roles failed")
	if _, err := s.Me(context.Background(), userID, tenantID); err == nil {
		t.Fatal("expected role names error")
	}
	repo.rolesErr = nil

	repo.userOut = domain.User{ID: userID, IsActive: true, Roles: []string{"legacy_admin"}, FirstName: "U", LastName: "Ser", EmailVerified: true}
	repo.mfaOut = domain.MFASecret{Enabled: true}
	repo.rolesOut = []string{}
	profile, err := s.Me(context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("Me unexpected err=%v", err)
	}
	if profile.Email != "u@example.com" || !profile.MFAEnabled || len(profile.Roles) != 1 || profile.Roles[0] != "legacy_admin" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
}

func TestService_Introspect_EarlyBranches(t *testing.T) {
	repo := &meIntroRepoStub{userOut: domain.User{ID: uuid.New(), IsActive: true}}
	s := &Service{repo: repo, settings: settingsStub{value: "x"}, cfg: config.Config{PublicBaseURL: "https://app.example"}}

	out, err := s.Introspect(context.Background(), "")
	if err == nil || out.Active {
		t.Fatalf("expected token required inactive response, out=%+v err=%v", out, err)
	}

	out, err = s.Introspect(context.Background(), "not-a-jwt")
	if err == nil || out.Active {
		t.Fatalf("expected invalid token format, out=%+v err=%v", out, err)
	}

	claimsNoTen := jwt.MapClaims{"sub": uuid.NewString(), "exp": time.Now().Add(time.Hour).Unix()}
	tokNoTen := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsNoTen)
	rawNoTen, _ := tokNoTen.SignedString([]byte("k"))
	out, err = s.Introspect(context.Background(), rawNoTen)
	if err == nil || err.Error() != "invalid ten" || out.Active {
		t.Fatalf("expected invalid ten error, out=%+v err=%v", out, err)
	}

	tenantID := uuid.New()
	claimsTen := jwt.MapClaims{"sub": uuid.NewString(), "ten": tenantID.String(), "exp": time.Now().Add(time.Hour).Unix()}
	tokTen := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsTen)
	rawTen, _ := tokTen.SignedString([]byte("k"))
	out, err = s.Introspect(context.Background(), rawTen)
	if err == nil || err.Error() != "asymmetric key manager required" || out.Active {
		t.Fatalf("expected asymmetric key manager required, out=%+v err=%v", out, err)
	}
}
