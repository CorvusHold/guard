package controller

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/corvusHold/guard/internal/tenants/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
)

type tenantsSvcStub struct {
	createFn       func(ctx context.Context, name string, parentTenantID *uuid.UUID) (db.Tenant, error)
	getByIDFn      func(ctx context.Context, id uuid.UUID) (db.Tenant, error)
	getByNameFn    func(ctx context.Context, name string) (db.Tenant, error)
	deactivateFn   func(ctx context.Context, id uuid.UUID) error
	listFn         func(ctx context.Context, opts domain.ListOptions) (domain.ListResult, error)
	listChildFn    func(ctx context.Context, parentID uuid.UUID, opts domain.ListOptions) (domain.ListResult, error)
	ancestorsFn    func(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error)
	updateParentFn func(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error
}

func (s *tenantsSvcStub) Create(ctx context.Context, name string, parentTenantID *uuid.UUID) (db.Tenant, error) {
	return s.createFn(ctx, name, parentTenantID)
}
func (s *tenantsSvcStub) GetByID(ctx context.Context, id uuid.UUID) (db.Tenant, error) {
	return s.getByIDFn(ctx, id)
}
func (s *tenantsSvcStub) GetByName(ctx context.Context, name string) (db.Tenant, error) {
	return s.getByNameFn(ctx, name)
}
func (s *tenantsSvcStub) Deactivate(ctx context.Context, id uuid.UUID) error {
	return s.deactivateFn(ctx, id)
}
func (s *tenantsSvcStub) List(ctx context.Context, opts domain.ListOptions) (domain.ListResult, error) {
	return s.listFn(ctx, opts)
}
func (s *tenantsSvcStub) ListChildTenants(ctx context.Context, parentID uuid.UUID, opts domain.ListOptions) (domain.ListResult, error) {
	return s.listChildFn(ctx, parentID, opts)
}
func (s *tenantsSvcStub) GetTenantAncestors(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) {
	return s.ancestorsFn(ctx, tenantID)
}
func (s *tenantsSvcStub) IsAncestorOf(ctx context.Context, ancestorID, descendantID uuid.UUID) (bool, error) {
	return false, nil
}
func (s *tenantsSvcStub) UpdateParent(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error {
	return s.updateParentFn(ctx, id, parentID)
}

func tenantRow(id uuid.UUID, name string) db.Tenant {
	return db.Tenant{
		ID:        pgtype.UUID{Bytes: id, Valid: true},
		Name:      name,
		IsActive:  true,
		CreatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
		UpdatedAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true},
	}
}

func TestTenantsController_Branches(t *testing.T) {
	tenantID := uuid.New()
	e := echo.New()
	e.Validator = testValidator{}
	stub := &tenantsSvcStub{
		createFn: func(ctx context.Context, name string, parentTenantID *uuid.UUID) (db.Tenant, error) {
			return tenantRow(uuid.New(), name), nil
		},
		getByIDFn:    func(ctx context.Context, id uuid.UUID) (db.Tenant, error) { return tenantRow(id, "acme"), nil },
		getByNameFn:  func(ctx context.Context, name string) (db.Tenant, error) { return tenantRow(uuid.New(), name), nil },
		deactivateFn: func(ctx context.Context, id uuid.UUID) error { return nil },
		listFn: func(ctx context.Context, opts domain.ListOptions) (domain.ListResult, error) {
			return domain.ListResult{}, nil
		},
		listChildFn: func(ctx context.Context, parentID uuid.UUID, opts domain.ListOptions) (domain.ListResult, error) {
			return domain.ListResult{}, nil
		},
		ancestorsFn:    func(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) { return []db.Tenant{}, nil },
		updateParentFn: func(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error { return nil },
	}
	h := New(stub)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	_ = h.createTenant(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid json, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"x","parent_tenant_id":"bad"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	_ = h.createTenant(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid parent id, got %d", rec.Code)
	}

	stub.createFn = func(ctx context.Context, name string, parentTenantID *uuid.UUID) (db.Tenant, error) {
		return db.Tenant{}, errors.New("create failed")
	}
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	_ = h.createTenant(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 create failure, got %d", rec.Code)
	}

	stub.createFn = func(ctx context.Context, name string, parentTenantID *uuid.UUID) (db.Tenant, error) {
		return tenantRow(tenantID, "x"), nil
	}
	h.WithOnTenantCreated(func(ctx context.Context, tenantID uuid.UUID) error { return errors.New("hook failed") })
	req = httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	_ = h.createTenant(c)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 despite hook error, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("bad")
	_ = h.getTenantByID(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid id, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(tenantID.String())
	_ = h.updateTenantParent(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid json, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString(`{"parent_tenant_id":"bad"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues(tenantID.String())
	_ = h.updateTenantParent(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid parent_tenant_id, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	c = e.NewContext(req, rec)
	c.SetParamNames("id")
	c.SetParamValues("bad")
	_ = h.listChildTenants(c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid id child list, got %d", rec.Code)
	}
}

type testValidator struct{}

func (testValidator) Validate(i interface{}) error { return nil }
