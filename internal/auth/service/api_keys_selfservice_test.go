package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

type apiKeyRepoStub struct {
	fakeRepo
	createErr          error
	createCalled       bool
	createdKeyPrefix   string
	createdName        string
	createdScopes      []string
	getByHashErr       error
	getByHashResult    domain.APIKey
	updatedLastUsedFor uuid.UUID
	revokeErr          error
	revokedKeyID       uuid.UUID
	revokedTenantID    uuid.UUID
	revokeChainErr     error
	revokeChainID      uuid.UUID
	mfaEnrolled        bool
	mfaErr             error
	listKeysOut        []domain.APIKey
	listKeysErr        error
}

func (r *apiKeyRepoStub) CreateAPIKey(ctx context.Context, id uuid.UUID, tenantID uuid.UUID, name, keyHash, keyPrefix string, scopes []string, createdBy uuid.UUID, expiresAt *time.Time) (domain.APIKey, error) {
	r.createCalled = true
	r.createdKeyPrefix = keyPrefix
	r.createdName = name
	r.createdScopes = append([]string{}, scopes...)
	if r.createErr != nil {
		return domain.APIKey{}, r.createErr
	}
	return domain.APIKey{ID: id, TenantID: tenantID, Name: name, KeyPrefix: keyPrefix, Scopes: scopes}, nil
}

func (r *apiKeyRepoStub) GetAPIKeyByHash(ctx context.Context, keyHash string) (domain.APIKey, error) {
	if r.getByHashErr != nil {
		return domain.APIKey{}, r.getByHashErr
	}
	return r.getByHashResult, nil
}

func (r *apiKeyRepoStub) UpdateAPIKeyLastUsed(ctx context.Context, keyID uuid.UUID) error {
	r.updatedLastUsedFor = keyID
	return nil
}

func (r *apiKeyRepoStub) RevokeAPIKey(ctx context.Context, keyID, tenantID uuid.UUID) error {
	r.revokedKeyID = keyID
	r.revokedTenantID = tenantID
	return r.revokeErr
}

func (r *apiKeyRepoStub) RevokeTokenChain(ctx context.Context, tokenID uuid.UUID) error {
	r.revokeChainID = tokenID
	return r.revokeChainErr
}

func (r *apiKeyRepoStub) IsMFAEnrolled(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	return r.mfaEnrolled, r.mfaErr
}

func (r *apiKeyRepoStub) ListAPIKeysByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.APIKey, error) {
	if r.listKeysErr != nil {
		return nil, r.listKeysErr
	}
	return r.listKeysOut, nil
}

func TestService_CreateAPIKey_ValidationAndSuccess(t *testing.T) {
	tenantID := uuid.New()
	creator := uuid.New()
	repo := &apiKeyRepoStub{}
	events := make([]evdomain.Event, 0, 1)
	s := &Service{repo: repo, pub: publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	})}

	if _, _, err := s.CreateAPIKey(context.Background(), tenantID, "", nil, creator, nil); err == nil {
		t.Fatal("expected name validation error")
	}

	key, raw, err := s.CreateAPIKey(context.Background(), tenantID, "ci key", nil, creator, nil)
	if err != nil {
		t.Fatalf("CreateAPIKey error: %v", err)
	}
	if !repo.createCalled {
		t.Fatal("expected repository CreateAPIKey to be called")
	}
	if repo.createdName != "ci key" {
		t.Fatalf("expected key name ci key, got %q", repo.createdName)
	}
	if !strings.HasPrefix(raw, "gk_") || len(raw) != 67 {
		t.Fatalf("unexpected raw key format: %q", raw)
	}
	if !strings.HasPrefix(repo.createdKeyPrefix, "gk_") || len(repo.createdKeyPrefix) != 12 {
		t.Fatalf("unexpected stored key prefix: %q", repo.createdKeyPrefix)
	}
	if len(repo.createdScopes) != 0 {
		t.Fatalf("expected nil scopes normalized to empty slice, got %#v", repo.createdScopes)
	}
	if key.Name != "ci key" || key.TenantID != tenantID {
		t.Fatalf("unexpected returned key: %+v", key)
	}
	if len(events) != 1 || events[0].Type != "auth.api_key.created" {
		t.Fatalf("expected one creation event, got %#v", events)
	}
}

func TestService_CreateAPIKey_RepoError(t *testing.T) {
	repo := &apiKeyRepoStub{createErr: errors.New("insert failed")}
	s := &Service{repo: repo, pub: publisherFunc(func(context.Context, evdomain.Event) error { return nil })}
	if _, _, err := s.CreateAPIKey(context.Background(), uuid.New(), "name", []string{"read"}, uuid.New(), nil); err == nil {
		t.Fatal("expected create error")
	}
}

func TestService_ValidateAPIKey_Paths(t *testing.T) {
	now := time.Now()
	exp := now.Add(-time.Minute)
	liveID := uuid.New()
	repo := &apiKeyRepoStub{}
	s := &Service{repo: repo}

	if _, err := s.ValidateAPIKey(context.Background(), ""); err == nil {
		t.Fatal("expected required key error")
	}

	repo.getByHashErr = errors.New("not found")
	if _, err := s.ValidateAPIKey(context.Background(), "gk_x"); err == nil || err.Error() != "invalid api key" {
		t.Fatalf("expected invalid api key, got %v", err)
	}

	repo.getByHashErr = nil
	repo.getByHashResult = domain.APIKey{ID: uuid.New(), ExpiresAt: &exp}
	if _, err := s.ValidateAPIKey(context.Background(), "gk_x"); err == nil || err.Error() != "api key expired" {
		t.Fatalf("expected api key expired, got %v", err)
	}

	repo.getByHashResult = domain.APIKey{ID: liveID, Name: "live"}
	k, err := s.ValidateAPIKey(context.Background(), "gk_live")
	if err != nil {
		t.Fatalf("expected successful validation, got %v", err)
	}
	if k.ID != liveID || repo.updatedLastUsedFor != liveID {
		t.Fatalf("expected last-used update for key %s, got key=%s updated=%s", liveID, k.ID, repo.updatedLastUsedFor)
	}
}

func TestService_RevokeAPIKey_Paths(t *testing.T) {
	keyID := uuid.New()
	tenantID := uuid.New()
	repo := &apiKeyRepoStub{revokeErr: errors.New("revoke failed")}
	s := &Service{repo: repo, pub: publisherFunc(func(context.Context, evdomain.Event) error { return nil })}

	if err := s.RevokeAPIKey(context.Background(), keyID, tenantID); err == nil {
		t.Fatal("expected revoke error")
	}

	events := make([]evdomain.Event, 0, 1)
	repo.revokeErr = nil
	s.pub = publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	})
	if err := s.RevokeAPIKey(context.Background(), keyID, tenantID); err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}
	if repo.revokedKeyID != keyID || repo.revokedTenantID != tenantID {
		t.Fatalf("unexpected revoke args: key=%s tenant=%s", repo.revokedKeyID, repo.revokedTenantID)
	}
	if len(events) != 1 || events[0].Type != "auth.api_key.revoked" {
		t.Fatalf("expected one revoke event, got %#v", events)
	}
}

func TestService_SelfService_Passthroughs(t *testing.T) {
	tokenID := uuid.New()
	userID := uuid.New()
	tenantID := uuid.New()
	repo := &apiKeyRepoStub{revokeChainErr: errors.New("chain failed")}
	s := &Service{repo: repo}

	if err := s.RevokeTokenChain(context.Background(), tokenID); err == nil {
		t.Fatal("expected revoke token chain error")
	}
	repo.revokeChainErr = nil
	if err := s.RevokeTokenChain(context.Background(), tokenID); err != nil {
		t.Fatalf("unexpected revoke token chain error: %v", err)
	}
	if repo.revokeChainID != tokenID {
		t.Fatalf("expected revoke chain id %s, got %s", tokenID, repo.revokeChainID)
	}

	repo.mfaErr = errors.New("mfa lookup failed")
	if _, err := s.IsMFAEnrolled(context.Background(), userID, tenantID); err == nil {
		t.Fatal("expected mfa lookup error")
	}
	repo.mfaErr = nil
	repo.mfaEnrolled = true
	ok, err := s.IsMFAEnrolled(context.Background(), userID, tenantID)
	if err != nil || !ok {
		t.Fatalf("expected enrolled=true, err=nil; got enrolled=%v err=%v", ok, err)
	}

	repo.listKeysErr = errors.New("list failed")
	if _, err := s.ListAPIKeys(context.Background(), tenantID); err == nil {
		t.Fatal("expected list api keys error")
	}
	repo.listKeysErr = nil
	repo.listKeysOut = []domain.APIKey{{ID: uuid.New(), TenantID: tenantID, Name: "ci"}}
	keys, err := s.ListAPIKeys(context.Background(), tenantID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("expected list api keys success, got keys=%v err=%v", keys, err)
	}
}
