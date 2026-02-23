package service

import (
	"context"
	"errors"
	"testing"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/corvusHold/guard/internal/tenants/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type repoStub struct {
	mockRepo
	getByNameTenant db.Tenant
	getByNameErr    error
	getByIDTenant   db.Tenant
	getByIDErr      error
	createErr       error
	updateParentErr error
	ancestors       []db.Tenant
	ancestorsErr    error
	listItems       []db.Tenant
	listTotal       int64
	listErr         error
	childItems      []db.Tenant
	childTotal      int64
	childErr        error
	lastListActive  int
}

func (r *repoStub) Create(ctx context.Context, id uuid.UUID, name string, parentTenantID *uuid.UUID) error {
	return r.createErr
}
func (r *repoStub) GetByID(ctx context.Context, id uuid.UUID) (db.Tenant, error) {
	if r.getByIDErr != nil {
		return db.Tenant{}, r.getByIDErr
	}
	if r.getByIDTenant.ID.Valid {
		return r.getByIDTenant, nil
	}
	return db.Tenant{ID: pgtype.UUID{Bytes: id, Valid: true}, Name: "tenant"}, nil
}
func (r *repoStub) GetByName(ctx context.Context, name string) (db.Tenant, error) {
	if r.getByNameErr != nil {
		return db.Tenant{}, r.getByNameErr
	}
	if r.getByNameTenant.ID.Valid || r.getByNameTenant.Name != "" {
		return r.getByNameTenant, nil
	}
	return db.Tenant{}, pgx.ErrNoRows
}
func (r *repoStub) List(ctx context.Context, query string, active int, limit, offset int32) ([]db.Tenant, int64, error) {
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	r.lastListActive = active
	return r.listItems, r.listTotal, nil
}
func (r *repoStub) ListChildTenants(ctx context.Context, parentID uuid.UUID, limit, offset int32) ([]db.Tenant, int64, error) {
	if r.childErr != nil {
		return nil, 0, r.childErr
	}
	return r.childItems, r.childTotal, nil
}
func (r *repoStub) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) {
	if r.ancestorsErr != nil {
		return nil, r.ancestorsErr
	}
	return r.ancestors, nil
}
func (r *repoStub) UpdateParent(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error {
	return r.updateParentErr
}

func TestServiceCreateAndUpdateParentBranches(t *testing.T) {
	s := New(&repoStub{})
	if _, err := s.Create(context.Background(), "", nil); err == nil {
		t.Fatal("expected tenant name required error")
	}

	r := &repoStub{getByNameTenant: db.Tenant{Name: "exists"}}
	s = New(r)
	if _, err := s.Create(context.Background(), "exists", nil); err == nil {
		t.Fatal("expected duplicate name error")
	}

	r = &repoStub{getByNameErr: errors.New("db down")}
	s = New(r)
	if _, err := s.Create(context.Background(), "acme", nil); err == nil {
		t.Fatal("expected passthrough lookup error")
	}

	parentID := uuid.New()
	r = &repoStub{getByIDErr: errors.New("no parent")}
	s = New(r)
	if _, err := s.Create(context.Background(), "acme", &parentID); err == nil || err.Error() != "parent tenant not found" {
		t.Fatalf("expected parent not found, got %v", err)
	}

	selfID := uuid.New()
	r = &repoStub{}
	s = New(r)
	if err := s.UpdateParent(context.Background(), selfID, &selfID); err == nil || err.Error() != "cannot set tenant as its own parent" {
		t.Fatalf("expected self-parent error, got %v", err)
	}

	desc := uuid.New()
	r = &repoStub{ancestors: []db.Tenant{{ID: pgtype.UUID{Bytes: selfID, Valid: true}}}}
	s = New(r)
	if err := s.UpdateParent(context.Background(), selfID, &desc); err == nil || err.Error() != "cannot set parent to a descendant tenant" {
		t.Fatalf("expected descendant error, got %v", err)
	}
}

func TestServiceListAndAncestorsBranches(t *testing.T) {
	r := &repoStub{
		listItems:  []db.Tenant{{Name: "a"}},
		listTotal:  1,
		childItems: []db.Tenant{{Name: "c"}},
		childTotal: 3,
	}
	s := New(r)
	res, err := s.List(context.Background(), domain.ListOptions{Active: 7, PageSize: 0, Page: 0})
	if err != nil {
		t.Fatalf("List error: %v", err)
	}
	if res.Page != 1 || res.PageSize != 20 || r.lastListActive != -1 {
		t.Fatalf("expected normalized options, got page=%d pageSize=%d active=%d", res.Page, res.PageSize, r.lastListActive)
	}

	child, err := s.ListChildTenants(context.Background(), uuid.New(), domain.ListOptions{Page: 0, PageSize: 999})
	if err != nil {
		t.Fatalf("ListChildTenants error: %v", err)
	}
	if child.Page != 1 || child.PageSize != 20 || child.TotalPages != 1 {
		t.Fatalf("unexpected child pagination: %+v", child)
	}

	ancestorID := uuid.New()
	r.ancestors = []db.Tenant{{ID: pgtype.UUID{Bytes: ancestorID, Valid: true}}}
	ok, err := s.IsAncestorOf(context.Background(), ancestorID, uuid.New())
	if err != nil || !ok {
		t.Fatalf("expected ancestor true, got ok=%v err=%v", ok, err)
	}

	r.ancestorsErr = errors.New("boom")
	if _, err := s.IsAncestorOf(context.Background(), ancestorID, uuid.New()); err == nil {
		t.Fatal("expected ancestor lookup error")
	}
}

func TestServicePassthroughAndRepoErrorBranches(t *testing.T) {
	id := uuid.New()

	r := &repoStub{createErr: errors.New("create failed")}
	s := New(r)
	if _, err := s.Create(context.Background(), "acme", nil); err == nil {
		t.Fatal("expected create passthrough error")
	}

	r = &repoStub{
		getByNameErr: errors.New("lookup failed"),
		getByIDErr:   errors.New("lookup failed"),
	}
	s = New(r)
	if _, err := s.GetByID(context.Background(), id); err == nil {
		t.Fatal("expected GetByID passthrough error")
	}
	if _, err := s.GetByName(context.Background(), "acme"); err == nil {
		t.Fatal("expected GetByName passthrough error")
	}

	r = &repoStub{updateParentErr: errors.New("update failed")}
	s = New(r)
	if err := s.UpdateParent(context.Background(), id, nil); err == nil {
		t.Fatal("expected UpdateParent passthrough error for nil parent")
	}

	r = &repoStub{getByIDErr: errors.New("missing")}
	s = New(r)
	parent := uuid.New()
	if err := s.UpdateParent(context.Background(), id, &parent); err == nil || err.Error() != "parent tenant not found" {
		t.Fatalf("expected parent not found error, got %v", err)
	}

	r = &repoStub{listItems: nil, listTotal: 0, childItems: nil, childTotal: 0}
	s = New(r)
	res, err := s.List(context.Background(), domain.ListOptions{Page: 1, PageSize: 10, Active: 1})
	if err != nil {
		t.Fatalf("expected list success: %v", err)
	}
	if res.TotalPages != 0 {
		t.Fatalf("expected zero total pages for empty result, got %d", res.TotalPages)
	}

	child, err := s.ListChildTenants(context.Background(), uuid.New(), domain.ListOptions{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("expected child list success: %v", err)
	}
	if child.TotalPages != 0 {
		t.Fatalf("expected zero total pages for empty child result, got %d", child.TotalPages)
	}
}

func TestServiceListAndChildListRepoErrors(t *testing.T) {
	r := &repoStub{listErr: errors.New("list failed")}
	if _, err := New(r).List(context.Background(), domain.ListOptions{}); err == nil {
		t.Fatal("expected list repo error")
	}

	r = &repoStub{childErr: errors.New("child failed")}
	if _, err := New(r).ListChildTenants(context.Background(), uuid.New(), domain.ListOptions{}); err == nil {
		t.Fatal("expected child list repo error")
	}
}
