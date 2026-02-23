package controller

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	db "github.com/corvusHold/guard/internal/db/sqlc"
	"github.com/corvusHold/guard/internal/tenants/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
)

type failingValidator struct{}

func (failingValidator) Validate(i interface{}) error { return errors.New("invalid payload") }

func TestTenantsController_HelperFormatting(t *testing.T) {
	if got := toUUIDString(pgtype.UUID{}); got != "" {
		t.Fatalf("expected empty uuid string, got %q", got)
	}
	id := uuid.New()
	if got := toUUIDString(pgtype.UUID{Bytes: id, Valid: true}); got != id.String() {
		t.Fatalf("expected uuid %q got %q", id.String(), got)
	}
	if got := toTimeString(pgtype.Timestamptz{}); got != "" {
		t.Fatalf("expected empty time string, got %q", got)
	}
}

func TestTenantsController_MainHandlers(t *testing.T) {
	e := echo.New()
	e.Validator = testValidator{}
	tenantID := uuid.New()

	stub := &tenantsSvcStub{
		createFn: func(ctx context.Context, name string, parentTenantID *uuid.UUID) (db.Tenant, error) {
			return tenantRow(tenantID, name), nil
		},
		getByIDFn: func(ctx context.Context, id uuid.UUID) (db.Tenant, error) {
			return tenantRow(id, "acme"), nil
		},
		getByNameFn: func(ctx context.Context, name string) (db.Tenant, error) {
			return tenantRow(tenantID, name), nil
		},
		deactivateFn: func(ctx context.Context, id uuid.UUID) error { return nil },
		listFn: func(ctx context.Context, opts domain.ListOptions) (domain.ListResult, error) {
			return domain.ListResult{Items: []db.Tenant{tenantRow(tenantID, "acme")}, Total: 1, Page: 1, PageSize: 20, TotalPages: 1}, nil
		},
		listChildFn: func(ctx context.Context, parentID uuid.UUID, opts domain.ListOptions) (domain.ListResult, error) {
			return domain.ListResult{Items: []db.Tenant{tenantRow(uuid.New(), "child")}, Total: 1, Page: 1, PageSize: 20, TotalPages: 1}, nil
		},
		ancestorsFn: func(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) {
			return []db.Tenant{tenantRow(uuid.New(), "parent")}, nil
		},
		updateParentFn: func(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error { return nil },
	}
	h := New(stub)

	t.Run("create validation error", func(t *testing.T) {
		e.Validator = failingValidator{}
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"name":""}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.createTenant(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 validate error, got %d", rec.Code)
		}
		e.Validator = testValidator{}
	})

	t.Run("get by id not found", func(t *testing.T) {
		stub.getByIDFn = func(ctx context.Context, id uuid.UUID) (db.Tenant, error) { return db.Tenant{}, errors.New("missing") }
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.getTenantByID(c)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", rec.Code)
		}
		stub.getByIDFn = func(ctx context.Context, id uuid.UUID) (db.Tenant, error) { return tenantRow(id, "acme"), nil }
	})

	t.Run("get by name branches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("name")
		c.SetParamValues("")
		_ = h.getTenantByName(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 missing name, got %d", rec.Code)
		}

		stub.getByNameFn = func(ctx context.Context, name string) (db.Tenant, error) { return db.Tenant{}, errors.New("missing") }
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("name")
		c.SetParamValues("acme")
		_ = h.getTenantByName(c)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 missing name, got %d", rec.Code)
		}

		stub.getByNameFn = func(ctx context.Context, name string) (db.Tenant, error) { return tenantRow(tenantID, name), nil }
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("name")
		c.SetParamValues("acme")
		_ = h.getTenantByName(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 get by name, got %d", rec.Code)
		}
	})

	t.Run("deactivate branches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("bad")
		_ = h.deactivateTenant(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid id, got %d", rec.Code)
		}

		stub.deactivateFn = func(ctx context.Context, id uuid.UUID) error { return errors.New("nope") }
		req = httptest.NewRequest(http.MethodPatch, "/", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.deactivateTenant(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 deactivate err, got %d", rec.Code)
		}

		stub.deactivateFn = func(ctx context.Context, id uuid.UUID) error { return nil }
		req = httptest.NewRequest(http.MethodPatch, "/", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.deactivateTenant(c)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 deactivate ok, got %d", rec.Code)
		}
	})

	t.Run("ancestors branches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("bad")
		_ = h.getTenantAncestors(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid id, got %d", rec.Code)
		}

		stub.ancestorsFn = func(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) { return nil, errors.New("nope") }
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.getTenantAncestors(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 ancestor err, got %d", rec.Code)
		}

		stub.ancestorsFn = func(ctx context.Context, tenantID uuid.UUID) ([]db.Tenant, error) {
			return []db.Tenant{tenantRow(uuid.New(), "parent")}, nil
		}
		req = httptest.NewRequest(http.MethodGet, "/", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.getTenantAncestors(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 ancestors, got %d", rec.Code)
		}
	})

	t.Run("update parent service error and success", func(t *testing.T) {
		parent := uuid.New()
		stub.updateParentFn = func(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error { return errors.New("bad parent") }
		req := httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString(`{"parent_tenant_id":"`+parent.String()+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.updateTenantParent(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 update error, got %d", rec.Code)
		}

		stub.updateParentFn = func(ctx context.Context, id uuid.UUID, parentID *uuid.UUID) error { return nil }
		req = httptest.NewRequest(http.MethodPatch, "/", bytes.NewBufferString(`{"parent_tenant_id":"`+parent.String()+`"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.updateTenantParent(c)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 update parent, got %d", rec.Code)
		}
	})

	t.Run("list tenants and children branches", func(t *testing.T) {
		stub.listFn = func(ctx context.Context, opts domain.ListOptions) (domain.ListResult, error) { return domain.ListResult{}, errors.New("boom") }
		req := httptest.NewRequest(http.MethodGet, "/?active=1&page=1&page_size=20", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		_ = h.listTenants(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 list err, got %d", rec.Code)
		}

		stub.listFn = func(ctx context.Context, opts domain.ListOptions) (domain.ListResult, error) {
			return domain.ListResult{Items: []db.Tenant{tenantRow(tenantID, "acme")}, Total: 1, Page: 1, PageSize: 20, TotalPages: 1}, nil
		}
		req = httptest.NewRequest(http.MethodGet, "/?active=bogus&page=bogus&page_size=bogus", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		_ = h.listTenants(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 list success, got %d", rec.Code)
		}

		stub.listChildFn = func(ctx context.Context, parentID uuid.UUID, opts domain.ListOptions) (domain.ListResult, error) {
			return domain.ListResult{}, errors.New("boom")
		}
		req = httptest.NewRequest(http.MethodGet, "/?page=1&page_size=20", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.listChildTenants(c)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 list child err, got %d", rec.Code)
		}

		stub.listChildFn = func(ctx context.Context, parentID uuid.UUID, opts domain.ListOptions) (domain.ListResult, error) {
			return domain.ListResult{Items: []db.Tenant{tenantRow(uuid.New(), "child")}, Total: 1, Page: 1, PageSize: 20, TotalPages: 1}, nil
		}
		req = httptest.NewRequest(http.MethodGet, "/?page=bogus&page_size=bogus", nil)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(tenantID.String())
		_ = h.listChildTenants(c)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 list child success, got %d", rec.Code)
		}
	})
}
