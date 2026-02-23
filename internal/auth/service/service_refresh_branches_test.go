package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

type refreshRepoStub struct {
	fakeRepo

	refreshOut domain.RefreshToken
	refreshErr error

	revokeFamilyErr error
	revokedFamilyID uuid.UUID

	revokeChainErr error
	revokedChainID uuid.UUID

	lastUsedErr error

	userOut domain.User
	userErr error
}

func (r *refreshRepoStub) GetRefreshTokenByHash(context.Context, string) (domain.RefreshToken, error) {
	if r.refreshErr != nil {
		return domain.RefreshToken{}, r.refreshErr
	}
	return r.refreshOut, nil
}
func (r *refreshRepoStub) RevokeTokenFamily(ctx context.Context, familyID uuid.UUID) error {
	r.revokedFamilyID = familyID
	return r.revokeFamilyErr
}
func (r *refreshRepoStub) RevokeTokenChain(ctx context.Context, id uuid.UUID) error {
	r.revokedChainID = id
	return r.revokeChainErr
}
func (r *refreshRepoStub) UpdateRefreshTokenLastUsed(context.Context, string) error { return r.lastUsedErr }
func (r *refreshRepoStub) GetUserByID(context.Context, uuid.UUID) (domain.User, error) {
	if r.userErr != nil {
		return domain.User{}, r.userErr
	}
	return r.userOut, nil
}

type idleSettingsStub struct{ idle time.Duration }

func (s idleSettingsStub) GetString(context.Context, string, *uuid.UUID, string) (string, error) {
	return "", nil
}
func (s idleSettingsStub) GetInt(context.Context, string, *uuid.UUID, int) (int, error) { return 0, nil }
func (s idleSettingsStub) GetDuration(context.Context, string, *uuid.UUID, time.Duration) (time.Duration, error) {
	return s.idle, nil
}

func TestService_Refresh_EarlyAndFailureBranches(t *testing.T) {
	repo := &refreshRepoStub{}
	s := &Service{
		repo:     repo,
		settings: idleSettingsStub{idle: time.Hour},
		pub: publisherFunc(func(context.Context, evdomain.Event) error {
			return nil
		}),
	}

	if _, err := s.Refresh(context.Background(), domain.RefreshInput{}); err == nil || err.Error() != "refresh token required" {
		t.Fatalf("expected missing refresh token error, got %v", err)
	}

	repo.refreshErr = errors.New("lookup failed")
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil {
		t.Fatal("expected refresh lookup error")
	}
	repo.refreshErr = nil

	tid := uuid.New()
	uid := uuid.New()
	rid := uuid.New()
	repo.refreshOut = domain.RefreshToken{ID: rid, TenantID: tid, UserID: uid, Revoked: true, FamilyID: uuid.New()}
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil || err.Error() != "refresh token reuse detected" {
		t.Fatalf("expected token reuse detected, got %v", err)
	}
	if repo.revokedFamilyID == uuid.Nil {
		t.Fatal("expected family revoke on reused token")
	}

	repo.revokedFamilyID = uuid.Nil
	repo.refreshOut = domain.RefreshToken{ID: rid, TenantID: tid, UserID: uid, Revoked: true, FamilyID: uuid.Nil}
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil || err.Error() != "refresh token reuse detected" {
		t.Fatalf("expected token reuse detected, got %v", err)
	}
	if repo.revokedChainID != rid {
		t.Fatalf("expected chain revoke fallback for legacy token, got %s", repo.revokedChainID)
	}

	repo.refreshOut = domain.RefreshToken{ID: rid, TenantID: tid, UserID: uid, ExpiresAt: time.Now().Add(-time.Minute)}
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil || err.Error() != "refresh token expired" {
		t.Fatalf("expected refresh token expired, got %v", err)
	}

	s.settings = idleSettingsStub{idle: time.Minute}
	repo.refreshOut = domain.RefreshToken{ID: rid, TenantID: tid, UserID: uid, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now().Add(-2 * time.Hour)}
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil || err.Error() != "session expired due to inactivity" {
		t.Fatalf("expected idle-timeout error, got %v", err)
	}

	s.settings = idleSettingsStub{idle: 0}
	repo.refreshOut = domain.RefreshToken{ID: rid, TenantID: tid, UserID: uid, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	repo.revokeChainErr = errors.New("revoke failed")
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil {
		t.Fatal("expected revoke chain error")
	}
	repo.revokeChainErr = nil

	repo.userErr = errors.New("user lookup failed")
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil {
		t.Fatal("expected user lookup error")
	}
	repo.userErr = nil

	repo.userOut = domain.User{ID: uid, IsActive: false}
	if _, err := s.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "rt"}); err == nil || err.Error() != "user is blocked" {
		t.Fatalf("expected blocked user error, got %v", err)
	}
}
