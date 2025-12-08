package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// fakeRepoWithRevoke extends fakeRepo with session revocation tracking
type fakeRepoWithRevoke struct {
	fakeRepo
	revokedUserID   uuid.UUID
	revokedTenantID uuid.UUID
	revokeCount     int64
	revokeCalled    bool
}

func (f *fakeRepoWithRevoke) RevokeUserSessions(ctx context.Context, userID, tenantID uuid.UUID) (int64, error) {
	f.revokeCalled = true
	f.revokedUserID = userID
	f.revokedTenantID = tenantID
	return f.revokeCount, nil
}

func TestService_RevokeUserSessions(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	repo := &fakeRepoWithRevoke{
		revokeCount: 5, // Simulate 5 sessions revoked
	}
	svc := &Service{repo: repo}

	count, err := svc.RevokeUserSessions(context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("RevokeUserSessions error: %v", err)
	}

	if !repo.revokeCalled {
		t.Error("repository RevokeUserSessions was not called")
	}

	if repo.revokedUserID != userID {
		t.Errorf("expected userID %s, got %s", userID, repo.revokedUserID)
	}

	if repo.revokedTenantID != tenantID {
		t.Errorf("expected tenantID %s, got %s", tenantID, repo.revokedTenantID)
	}

	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestService_RevokeUserSessions_ZeroSessions(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()

	repo := &fakeRepoWithRevoke{
		revokeCount: 0, // No sessions to revoke
	}
	svc := &Service{repo: repo}

	count, err := svc.RevokeUserSessions(context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("RevokeUserSessions error: %v", err)
	}

	if count != 0 {
		t.Errorf("expected count 0, got %d", count)
	}
}
