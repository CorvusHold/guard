package controller

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

func TestRBACHandlers_NonDBValidationBranches_Extra(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	h := &Controller{}

	t.Run("rbacCreateRole invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.rbacCreateRole(c); err != nil {
			t.Fatalf("rbacCreateRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rbacCreateRole invalid tenant", func(t *testing.T) {
		body := `{"tenant_id":"bad","name":"admin"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.rbacCreateRole(c); err != nil {
			t.Fatalf("rbacCreateRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rbacUpdateRole invalid role id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/rbac/roles/bad", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("bad")
		if err := h.rbacUpdateRole(c); err != nil {
			t.Fatalf("rbacUpdateRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rbacUpdateRole invalid json", func(t *testing.T) {
		rid := uuid.NewString()
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/rbac/roles/"+rid, bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(rid)
		if err := h.rbacUpdateRole(c); err != nil {
			t.Fatalf("rbacUpdateRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rbacUpdateRole invalid tenant", func(t *testing.T) {
		rid := uuid.NewString()
		body := `{"tenant_id":"bad","name":"admin"}`
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/rbac/roles/"+rid, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(rid)
		if err := h.rbacUpdateRole(c); err != nil {
			t.Fatalf("rbacUpdateRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rbacDeleteRole validation branches", func(t *testing.T) {
		// invalid role id
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/bad", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("bad")
		if err := h.rbacDeleteRole(c); err != nil {
			t.Fatalf("rbacDeleteRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid role id, got %d body=%s", rec.Code, rec.Body.String())
		}

		// missing tenant_id
		rid := uuid.NewString()
		req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+rid, nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		c2.SetParamNames("id")
		c2.SetParamValues(rid)
		if err := h.rbacDeleteRole(c2); err != nil {
			t.Fatalf("rbacDeleteRole returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing tenant_id, got %d body=%s", rec2.Code, rec2.Body.String())
		}

		// invalid tenant_id
		req3 := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+rid+"?tenant_id=bad", nil)
		rec3 := httptest.NewRecorder()
		c3 := e.NewContext(req3, rec3)
		c3.SetParamNames("id")
		c3.SetParamValues(rid)
		if err := h.rbacDeleteRole(c3); err != nil {
			t.Fatalf("rbacDeleteRole returned error: %v", err)
		}
		if rec3.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid tenant_id, got %d body=%s", rec3.Code, rec3.Body.String())
		}
	})

	t.Run("rbacListUserRoles validation branches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/bad/roles", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("bad")
		if err := h.rbacListUserRoles(c); err != nil {
			t.Fatalf("rbacListUserRoles returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid user id, got %d body=%s", rec.Code, rec.Body.String())
		}

		uid := uuid.NewString()
		req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+uid+"/roles", nil)
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		c2.SetParamNames("id")
		c2.SetParamValues(uid)
		if err := h.rbacListUserRoles(c2); err != nil {
			t.Fatalf("rbacListUserRoles returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for missing tenant_id, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})

	t.Run("rbacAddUserRole validation branches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/users/bad/roles", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("bad")
		if err := h.rbacAddUserRole(c); err != nil {
			t.Fatalf("rbacAddUserRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid user id, got %d body=%s", rec.Code, rec.Body.String())
		}

		uid := uuid.NewString()
		req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/users/"+uid+"/roles", bytes.NewBufferString("{"))
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		c2.SetParamNames("id")
		c2.SetParamValues(uid)
		if err := h.rbacAddUserRole(c2); err != nil {
			t.Fatalf("rbacAddUserRole returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})

	t.Run("rbacRemoveUserRole validation branches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/users/bad/roles", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("bad")
		if err := h.rbacRemoveUserRole(c); err != nil {
			t.Fatalf("rbacRemoveUserRole returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid user id, got %d body=%s", rec.Code, rec.Body.String())
		}

		uid := uuid.NewString()
		req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/users/"+uid+"/roles", bytes.NewBufferString("{"))
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		c2 := e.NewContext(req2, rec2)
		c2.SetParamNames("id")
		c2.SetParamValues(uid)
		if err := h.rbacRemoveUserRole(c2); err != nil {
			t.Fatalf("rbacRemoveUserRole returned error: %v", err)
		}
		if rec2.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid json, got %d body=%s", rec2.Code, rec2.Body.String())
		}
	})
}
