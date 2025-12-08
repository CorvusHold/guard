package service

import (
	"context"
	"errors"
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

// fakeRepoWithRevokeError extends fakeRepo with error simulation
type fakeRepoWithRevokeError struct {
	fakeRepo
	err error
}

func (f *fakeRepoWithRevokeError) RevokeUserSessions(ctx context.Context, userID, tenantID uuid.UUID) (int64, error) {
	return 0, f.err
}

func TestService_RevokeUserSessions_Error(t *testing.T) {
	userID := uuid.New()
	tenantID := uuid.New()
	expectedErr := errors.New("db connection error")

	repo := &fakeRepoWithRevokeError{
		err: expectedErr,
	}
	svc := &Service{repo: repo}

	_, err := svc.RevokeUserSessions(context.Background(), userID, tenantID)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if err.Error() != expectedErr.Error() {
		t.Errorf("expected error %q, got %q", expectedErr.Error(), err.Error())
	}
}
