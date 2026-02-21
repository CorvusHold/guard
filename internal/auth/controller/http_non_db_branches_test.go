package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corvusHold/guard/internal/config"
	"github.com/labstack/echo/v4"
)

func TestInvitationAdminHandlers_MissingBearerToken(t *testing.T) {
	h := &Controller{}
	e := echo.New()

	tests := []struct {
		name    string
		path    string
		handler func(echo.Context) error
	}{
		{name: "inviteUser", path: "/api/v1/auth/admin/invitations", handler: h.inviteUser},
		{name: "listInvitations", path: "/api/v1/auth/admin/invitations", handler: h.listInvitations},
		{name: "revokeInvitation", path: "/api/v1/auth/admin/invitations/123/revoke", handler: h.revokeInvitation},
		{name: "deleteInvitation", path: "/api/v1/auth/admin/invitations/123", handler: h.deleteInvitation},
		{name: "adminCreateUser", path: "/api/v1/auth/admin/users", handler: h.adminCreateUser},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			if tc.name == "revokeInvitation" || tc.name == "deleteInvitation" {
				c.SetParamNames("id")
				c.SetParamValues("123")
			}

			if err := tc.handler(c); err != nil {
				t.Fatalf("handler returned error: %v", err)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte("missing bearer token")) {
				t.Fatalf("expected missing bearer token body, got %s", rec.Body.String())
			}
		})
	}
}

func TestInvitationPublicHandlers_NonDBValidationBranches(t *testing.T) {
	e := echo.New()
	h := &Controller{cfg: config.Config{DefaultAuthMode: "bearer"}}

	t.Run("acceptInvitation invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/invitations/accept", bytes.NewBufferString("{"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.acceptInvitation(c); err != nil {
			t.Fatalf("acceptInvitation returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("getInvitation missing token query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/invitations", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		if err := h.getInvitation(c); err != nil {
			t.Fatalf("getInvitation returned error: %v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte("token is required")) {
			t.Fatalf("expected token is required error body, got %s", rec.Body.String())
		}
	})
}

func TestRBACListRoles_ValidationBeforeAuth(t *testing.T) {
	e := echo.New()
	h := &Controller{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/roles", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := h.rbacListRoles(c); err != nil {
		t.Fatalf("rbacListRoles returned error: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/roles?tenant_id=bad", nil)
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)
	if err := h.rbacListRoles(c2); err != nil {
		t.Fatalf("rbacListRoles invalid tenant returned error: %v", err)
	}
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec2.Code, rec2.Body.String())
	}

	var body map[string]string
	if err := json.Unmarshal(rec2.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "invalid tenant_id" {
		t.Fatalf("unexpected error body: %+v", body)
	}
}
