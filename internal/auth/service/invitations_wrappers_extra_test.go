package service

import (
	"context"
	"errors"
	"testing"

	"github.com/corvusHold/guard/internal/auth/domain"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/google/uuid"
)

type invitationWrapperRepoStub struct {
	fakeRepo

	invByHashOut domain.Invitation
	invByHashErr error

	listInvOut []domain.Invitation
	listInvErr error

	listPendingOut []domain.Invitation
	listPendingErr error

	revokeErr error
	deleteErr error

	revokedID     uuid.UUID
	revokedTenant uuid.UUID
	deletedID     uuid.UUID
	deletedTenant uuid.UUID
}

func (r *invitationWrapperRepoStub) GetInvitationByHash(ctx context.Context, tokenHash string) (domain.Invitation, error) {
	if r.invByHashErr != nil {
		return domain.Invitation{}, r.invByHashErr
	}
	return r.invByHashOut, nil
}

func (r *invitationWrapperRepoStub) ListInvitationsByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.Invitation, error) {
	if r.listInvErr != nil {
		return nil, r.listInvErr
	}
	return r.listInvOut, nil
}

func (r *invitationWrapperRepoStub) ListPendingInvitationsByTenant(ctx context.Context, tenantID uuid.UUID) ([]domain.Invitation, error) {
	if r.listPendingErr != nil {
		return nil, r.listPendingErr
	}
	return r.listPendingOut, nil
}

func (r *invitationWrapperRepoStub) RevokeInvitation(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	r.revokedID = id
	r.revokedTenant = tenantID
	return r.revokeErr
}

func (r *invitationWrapperRepoStub) DeleteInvitation(ctx context.Context, id uuid.UUID, tenantID uuid.UUID) error {
	r.deletedID = id
	r.deletedTenant = tenantID
	return r.deleteErr
}

func TestService_InvitationWrappers_Branches(t *testing.T) {
	repo := &invitationWrapperRepoStub{}
	s := &Service{repo: repo, pub: publisherFunc(func(context.Context, evdomain.Event) error { return nil })}
	tenantID := uuid.New()
	invID := uuid.New()

	repo.invByHashErr = errors.New("not found")
	if _, err := s.GetInvitationByToken(context.Background(), "tok"); err == nil {
		t.Fatal("expected GetInvitationByToken error")
	}
	repo.invByHashErr = nil
	repo.invByHashOut = domain.Invitation{ID: invID, TenantID: &tenantID, Email: "u@example.com"}
	inv, err := s.GetInvitationByToken(context.Background(), "tok")
	if err != nil || inv.ID != invID {
		t.Fatalf("GetInvitationByToken unexpected inv=%+v err=%v", inv, err)
	}

	repo.listInvErr = errors.New("list failed")
	if _, err := s.ListInvitations(context.Background(), tenantID); err == nil {
		t.Fatal("expected ListInvitations error")
	}
	repo.listInvErr = nil
	repo.listInvOut = []domain.Invitation{{ID: invID, TenantID: &tenantID}}
	items, err := s.ListInvitations(context.Background(), tenantID)
	if err != nil || len(items) != 1 {
		t.Fatalf("ListInvitations unexpected items=%v err=%v", items, err)
	}

	repo.listPendingErr = errors.New("pending failed")
	if _, err := s.ListPendingInvitations(context.Background(), tenantID); err == nil {
		t.Fatal("expected ListPendingInvitations error")
	}
	repo.listPendingErr = nil
	repo.listPendingOut = []domain.Invitation{{ID: invID, TenantID: &tenantID, Status: "pending"}}
	pending, err := s.ListPendingInvitations(context.Background(), tenantID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("ListPendingInvitations unexpected items=%v err=%v", pending, err)
	}

	repo.revokeErr = errors.New("revoke failed")
	if err := s.RevokeInvitation(context.Background(), invID, tenantID); err == nil {
		t.Fatal("expected RevokeInvitation error")
	}
	repo.revokeErr = nil
	if err := s.RevokeInvitation(context.Background(), invID, tenantID); err != nil {
		t.Fatalf("RevokeInvitation unexpected err=%v", err)
	}
	if repo.revokedID != invID || repo.revokedTenant != tenantID {
		t.Fatalf("expected revoke args, got id=%s tenant=%s", repo.revokedID, repo.revokedTenant)
	}

	repo.deleteErr = errors.New("delete failed")
	if err := s.DeleteInvitation(context.Background(), invID, tenantID); err == nil {
		t.Fatal("expected DeleteInvitation error")
	}
	repo.deleteErr = nil
	if err := s.DeleteInvitation(context.Background(), invID, tenantID); err != nil {
		t.Fatalf("DeleteInvitation unexpected err=%v", err)
	}
	if repo.deletedID != invID || repo.deletedTenant != tenantID {
		t.Fatalf("expected delete args, got id=%s tenant=%s", repo.deletedID, repo.deletedTenant)
	}
}
