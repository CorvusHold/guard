package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/auth/domain"
	"github.com/google/uuid"
)

type logoutRepoStub struct {
	fakeRepo
	refreshOut domain.RefreshToken
	refreshErr error
	revokeErr  error
	revokedID  uuid.UUID
	loginAtErr error
}

func (r *logoutRepoStub) GetRefreshTokenByHash(context.Context, string) (domain.RefreshToken, error) {
	if r.refreshErr != nil {
		return domain.RefreshToken{}, r.refreshErr
	}
	return r.refreshOut, nil
}

func (r *logoutRepoStub) RevokeTokenChain(ctx context.Context, id uuid.UUID) error {
	r.revokedID = id
	return r.revokeErr
}

func (r *logoutRepoStub) UpdateUserLoginAt(context.Context, uuid.UUID) error { return r.loginAtErr }

func TestService_Logout_Branches(t *testing.T) {
	repo := &logoutRepoStub{}
	s := &Service{repo: repo}

	if err := s.Logout(context.Background(), ""); err != nil {
		t.Fatalf("empty refresh token should no-op: %v", err)
	}

	repo.refreshErr = errors.New("not found")
	if err := s.Logout(context.Background(), "rt"); err == nil {
		t.Fatal("expected refresh lookup error")
	}
	repo.refreshErr = nil

	repo.refreshOut = domain.RefreshToken{ID: uuid.New(), Revoked: true}
	if err := s.Logout(context.Background(), "rt"); err != nil {
		t.Fatalf("already revoked should no-op, got %v", err)
	}

	repo.refreshOut = domain.RefreshToken{ID: uuid.New(), Revoked: false, ExpiresAt: time.Now().Add(time.Hour)}
	repo.revokeErr = errors.New("revoke failed")
	if err := s.Logout(context.Background(), "rt"); err == nil {
		t.Fatal("expected revoke chain error")
	}
	repo.revokeErr = nil
	if err := s.Logout(context.Background(), "rt"); err != nil {
		t.Fatalf("Logout unexpected error: %v", err)
	}
	if repo.revokedID == uuid.Nil {
		t.Fatal("expected token chain revoke call")
	}
}

func TestService_IssueTokensForSSO_UpdateLoginError(t *testing.T) {
	repo := &logoutRepoStub{loginAtErr: errors.New("update login failed")}
	s := &Service{repo: repo}
	_, err := s.IssueTokensForSSO(context.Background(), domain.SSOTokenInput{UserID: uuid.New(), TenantID: uuid.New()})
	if err == nil {
		t.Fatal("expected UpdateUserLoginAt error")
	}
}
