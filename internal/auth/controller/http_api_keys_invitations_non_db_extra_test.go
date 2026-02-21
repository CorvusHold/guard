package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/config"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type controllerSvcStub struct {
	adomain.Service

	introspectOut adomain.Introspection
	introspectErr error

	createKeyOut adomain.APIKey
	createKeyRaw string
	createKeyErr error

	listKeysOut []adomain.APIKey
	listKeysErr error

	revokeKeyErr    error
	revokeKeyID     uuid.UUID
	revokeKeyTenant uuid.UUID

	inviteOut adomain.Invitation
	inviteRaw string
	inviteErr error

	listInvOut     []adomain.Invitation
	listInvErr     error
	listPendingOut []adomain.Invitation
	listPendingErr error

	revokeInvErr    error
	revokeInvID     uuid.UUID
	revokeInvTenant uuid.UUID

	deleteInvErr    error
	deleteInvID     uuid.UUID
	deleteInvTenant uuid.UUID

	acceptOut adomain.AccessTokens
	acceptErr error

	getInvOut adomain.Invitation
	getInvErr error

	adminCreateOut adomain.User
	adminCreateErr error
}

func (s *controllerSvcStub) Introspect(context.Context, string) (adomain.Introspection, error) {
	if s.introspectErr != nil {
		return adomain.Introspection{}, s.introspectErr
	}
	return s.introspectOut, nil
}

func (s *controllerSvcStub) CreateAPIKey(context.Context, uuid.UUID, string, []string, uuid.UUID, *time.Time) (adomain.APIKey, string, error) {
	if s.createKeyErr != nil {
		return adomain.APIKey{}, "", s.createKeyErr
	}
	return s.createKeyOut, s.createKeyRaw, nil
}

func (s *controllerSvcStub) ListAPIKeys(context.Context, uuid.UUID) ([]adomain.APIKey, error) {
	if s.listKeysErr != nil {
		return nil, s.listKeysErr
	}
	return s.listKeysOut, nil
}

func (s *controllerSvcStub) RevokeAPIKey(ctx context.Context, keyID, tenantID uuid.UUID) error {
	s.revokeKeyID = keyID
	s.revokeKeyTenant = tenantID
	return s.revokeKeyErr
}

func (s *controllerSvcStub) InviteUser(context.Context, adomain.InviteUserInput) (adomain.Invitation, string, error) {
	if s.inviteErr != nil {
		return adomain.Invitation{}, "", s.inviteErr
	}
	return s.inviteOut, s.inviteRaw, nil
}

func (s *controllerSvcStub) ListInvitations(context.Context, uuid.UUID) ([]adomain.Invitation, error) {
	if s.listInvErr != nil {
		return nil, s.listInvErr
	}
	return s.listInvOut, nil
}

func (s *controllerSvcStub) ListPendingInvitations(context.Context, uuid.UUID) ([]adomain.Invitation, error) {
	if s.listPendingErr != nil {
		return nil, s.listPendingErr
	}
	return s.listPendingOut, nil
}

func (s *controllerSvcStub) RevokeInvitation(ctx context.Context, invitationID, tenantID uuid.UUID) error {
	s.revokeInvID = invitationID
	s.revokeInvTenant = tenantID
	return s.revokeInvErr
}

func (s *controllerSvcStub) DeleteInvitation(ctx context.Context, invitationID, tenantID uuid.UUID) error {
	s.deleteInvID = invitationID
	s.deleteInvTenant = tenantID
	return s.deleteInvErr
}

func (s *controllerSvcStub) AcceptInvitation(context.Context, adomain.AcceptInvitationInput) (adomain.AccessTokens, error) {
	if s.acceptErr != nil {
		return adomain.AccessTokens{}, s.acceptErr
	}
	return s.acceptOut, nil
}

func (s *controllerSvcStub) GetInvitationByToken(context.Context, string) (adomain.Invitation, error) {
	if s.getInvErr != nil {
		return adomain.Invitation{}, s.getInvErr
	}
	return s.getInvOut, nil
}

func (s *controllerSvcStub) AdminCreateUser(context.Context, adomain.AdminCreateUserInput) (adomain.User, error) {
	if s.adminCreateErr != nil {
		return adomain.User{}, s.adminCreateErr
	}
	return s.adminCreateOut, nil
}

func TestAPIKeysHandlers_NonDBBranches_Extra(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	tenantID := uuid.New()
	userID := uuid.New()
	svc := &controllerSvcStub{introspectOut: adomain.Introspection{Active: true, TenantID: tenantID, UserID: userID, Roles: []string{"admin"}}}
	h := &Controller{svc: svc}

	t.Run("createAPIKey invalid expires_at", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/api-keys", bytes.NewBufferString(`{"name":"ci","expires_at":"bad-date"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.createAPIKey(c); err != nil {
			t.Fatalf("createAPIKey returned err=%v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("createAPIKey service error", func(t *testing.T) {
		svc.createKeyErr = errors.New("create failed")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/api-keys", bytes.NewBufferString(`{"name":"ci"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.createAPIKey(c); err != nil {
			t.Fatalf("createAPIKey returned err=%v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
		svc.createKeyErr = nil
	})

	t.Run("createAPIKey success", func(t *testing.T) {
		svc.createKeyOut = adomain.APIKey{ID: uuid.New(), TenantID: tenantID, Name: "ci", KeyPrefix: "gk_abc", Scopes: []string{"read"}, CreatedAt: time.Now()}
		svc.createKeyRaw = "gk_raw"
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/api-keys", bytes.NewBufferString(`{"name":"ci","scopes":["read"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.createAPIKey(c); err != nil {
			t.Fatalf("createAPIKey returned err=%v", err)
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("listAPIKeys forbidden for non-admin", func(t *testing.T) {
		svc.introspectOut.Roles = []string{"member"}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/api-keys", nil)
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.listAPIKeys(c); err != nil {
			t.Fatalf("listAPIKeys returned err=%v", err)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
		}
		svc.introspectOut.Roles = []string{"admin"}
	})

	t.Run("listAPIKeys success", func(t *testing.T) {
		svc.listKeysOut = []adomain.APIKey{{ID: uuid.New(), TenantID: tenantID, Name: "k1", KeyPrefix: "gk_1"}}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/api-keys", nil)
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.listAPIKeys(c); err != nil {
			t.Fatalf("listAPIKeys returned err=%v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}
		var out map[string][]map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode list response: %v", err)
		}
		if len(out["api_keys"]) != 1 {
			t.Fatalf("expected one key in response, got %#v", out)
		}
	})

	t.Run("revokeAPIKey invalid id then service error then success", func(t *testing.T) {
		reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/api-keys/bad/revoke", nil)
		reqBad.Header.Set("Authorization", "Bearer token")
		recBad := httptest.NewRecorder()
		cBad := e.NewContext(reqBad, recBad)
		cBad.SetParamNames("id")
		cBad.SetParamValues("bad")
		if err := h.revokeAPIKey(cBad); err != nil {
			t.Fatalf("revokeAPIKey returned err=%v", err)
		}
		if recBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid id, got %d body=%s", recBad.Code, recBad.Body.String())
		}

		keyID := uuid.New()
		svc.revokeKeyErr = errors.New("revoke failed")
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/api-keys/"+keyID.String()+"/revoke", nil)
		reqErr.Header.Set("Authorization", "Bearer token")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		cErr.SetParamNames("id")
		cErr.SetParamValues(keyID.String())
		if err := h.revokeAPIKey(cErr); err != nil {
			t.Fatalf("revokeAPIKey returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 service error, got %d body=%s", recErr.Code, recErr.Body.String())
		}

		svc.revokeKeyErr = nil
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/api-keys/"+keyID.String()+"/revoke", nil)
		reqOK.Header.Set("Authorization", "Bearer token")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		cOK.SetParamNames("id")
		cOK.SetParamValues(keyID.String())
		if err := h.revokeAPIKey(cOK); err != nil {
			t.Fatalf("revokeAPIKey returned err=%v", err)
		}
		if recOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d body=%s", recOK.Code, recOK.Body.String())
		}
	})
}

func TestInvitationHandlers_NonDBBranches_Extra(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	tenantID := uuid.New()
	userID := uuid.New()
	svc := &controllerSvcStub{introspectOut: adomain.Introspection{Active: true, TenantID: tenantID, UserID: userID, Roles: []string{"admin"}}}
	h := &Controller{svc: svc, cfg: config.Config{DefaultAuthMode: "bearer"}}

	t.Run("inviteUser cross-tenant forbidden", func(t *testing.T) {
		otherTenant := uuid.New()
		body := `{"tenant_id":"` + otherTenant.String() + `","email":"u@example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/invitations", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.inviteUser(c); err != nil {
			t.Fatalf("inviteUser returned err=%v", err)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("inviteUser service error then success", func(t *testing.T) {
		svc.inviteErr = errors.New("invite failed")
		body := `{"tenant_id":"` + tenantID.String() + `","email":"u@example.com","role":"member"}`
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/invitations", bytes.NewBufferString(body))
		reqErr.Header.Set("Content-Type", "application/json")
		reqErr.Header.Set("Authorization", "Bearer token")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.inviteUser(cErr); err != nil {
			t.Fatalf("inviteUser returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", recErr.Code, recErr.Body.String())
		}

		svc.inviteErr = nil
		svc.inviteRaw = "raw-token"
		svc.inviteOut = adomain.Invitation{ID: uuid.New(), Email: "u@example.com", Role: "member", Status: "pending", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/invitations", bytes.NewBufferString(body))
		reqOK.Header.Set("Content-Type", "application/json")
		reqOK.Header.Set("Authorization", "Bearer token")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.inviteUser(cOK); err != nil {
			t.Fatalf("inviteUser returned err=%v", err)
		}
		if recOK.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d body=%s", recOK.Code, recOK.Body.String())
		}
	})

	t.Run("listInvitations invalid status filter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/invitations?status=weird", nil)
		req.Header.Set("Authorization", "Bearer token")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.listInvitations(c); err != nil {
			t.Fatalf("listInvitations returned err=%v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("listInvitations pending and accepted filter paths", func(t *testing.T) {
		svc.listPendingOut = []adomain.Invitation{{ID: uuid.New(), TenantID: &tenantID, Status: "pending"}}
		reqP := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/invitations?status=pending", nil)
		reqP.Header.Set("Authorization", "Bearer token")
		recP := httptest.NewRecorder()
		cP := e.NewContext(reqP, recP)
		if err := h.listInvitations(cP); err != nil {
			t.Fatalf("listInvitations returned err=%v", err)
		}
		if recP.Code != http.StatusOK {
			t.Fatalf("expected 200 pending, got %d body=%s", recP.Code, recP.Body.String())
		}

		svc.listInvOut = []adomain.Invitation{{ID: uuid.New(), TenantID: &tenantID, Status: "accepted"}, {ID: uuid.New(), TenantID: &tenantID, Status: "pending"}}
		reqA := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/invitations?status=accepted", nil)
		reqA.Header.Set("Authorization", "Bearer token")
		recA := httptest.NewRecorder()
		cA := e.NewContext(reqA, recA)
		if err := h.listInvitations(cA); err != nil {
			t.Fatalf("listInvitations returned err=%v", err)
		}
		if recA.Code != http.StatusOK {
			t.Fatalf("expected 200 accepted, got %d body=%s", recA.Code, recA.Body.String())
		}
	})

	t.Run("revoke/delete invitation invalid id and service errors", func(t *testing.T) {
		reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/invitations/bad/revoke", nil)
		reqBad.Header.Set("Authorization", "Bearer token")
		recBad := httptest.NewRecorder()
		cBad := e.NewContext(reqBad, recBad)
		cBad.SetParamNames("id")
		cBad.SetParamValues("bad")
		if err := h.revokeInvitation(cBad); err != nil {
			t.Fatalf("revokeInvitation returned err=%v", err)
		}
		if recBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid invitation id, got %d", recBad.Code)
		}

		invID := uuid.New()
		svc.revokeInvErr = errors.New("revoke invitation failed")
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/invitations/"+invID.String()+"/revoke", nil)
		reqErr.Header.Set("Authorization", "Bearer token")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		cErr.SetParamNames("id")
		cErr.SetParamValues(invID.String())
		if err := h.revokeInvitation(cErr); err != nil {
			t.Fatalf("revokeInvitation returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 revoke service error, got %d", recErr.Code)
		}
		svc.revokeInvErr = nil

		svc.deleteInvErr = errors.New("delete invitation failed")
		reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/invitations/"+invID.String(), nil)
		reqDel.Header.Set("Authorization", "Bearer token")
		recDel := httptest.NewRecorder()
		cDel := e.NewContext(reqDel, recDel)
		cDel.SetParamNames("id")
		cDel.SetParamValues(invID.String())
		if err := h.deleteInvitation(cDel); err != nil {
			t.Fatalf("deleteInvitation returned err=%v", err)
		}
		if recDel.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 delete service error, got %d", recDel.Code)
		}
	})

	t.Run("acceptInvitation and getInvitation service error/success", func(t *testing.T) {
		svc.acceptErr = errors.New("accept failed")
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/invitations/accept", bytes.NewBufferString(`{"token":"tok","password":"Password!123"}`))
		reqErr.Header.Set("Content-Type", "application/json")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.acceptInvitation(cErr); err != nil {
			t.Fatalf("acceptInvitation returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 accept service error, got %d body=%s", recErr.Code, recErr.Body.String())
		}

		svc.acceptErr = nil
		svc.acceptOut = adomain.AccessTokens{AccessToken: "at", RefreshToken: "rt"}
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/invitations/accept", bytes.NewBufferString(`{"token":"tok","password":"Password!123"}`))
		reqOK.Header.Set("Content-Type", "application/json")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.acceptInvitation(cOK); err != nil {
			t.Fatalf("acceptInvitation returned err=%v", err)
		}
		if recOK.Code != http.StatusCreated {
			t.Fatalf("expected 201 accept success, got %d body=%s", recOK.Code, recOK.Body.String())
		}

		svc.getInvErr = errors.New("not found")
		reqGetErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/invitations?token=tok", nil)
		recGetErr := httptest.NewRecorder()
		cGetErr := e.NewContext(reqGetErr, recGetErr)
		if err := h.getInvitation(cGetErr); err != nil {
			t.Fatalf("getInvitation returned err=%v", err)
		}
		if recGetErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 get service error, got %d body=%s", recGetErr.Code, recGetErr.Body.String())
		}

		svc.getInvErr = nil
		svc.getInvOut = adomain.Invitation{ID: uuid.New(), TenantID: &tenantID, Email: "u@example.com", Status: "pending", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
		reqGetOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/invitations?token=tok", nil)
		recGetOK := httptest.NewRecorder()
		cGetOK := e.NewContext(reqGetOK, recGetOK)
		if err := h.getInvitation(cGetOK); err != nil {
			t.Fatalf("getInvitation returned err=%v", err)
		}
		if recGetOK.Code != http.StatusOK {
			t.Fatalf("expected 200 get success, got %d body=%s", recGetOK.Code, recGetOK.Body.String())
		}
	})

	t.Run("adminCreateUser auth/validation/error/success branches", func(t *testing.T) {
		// missing bearer token
		reqMissing := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqMissing.Header.Set("Content-Type", "application/json")
		recMissing := httptest.NewRecorder()
		cMissing := e.NewContext(reqMissing, recMissing)
		if err := h.adminCreateUser(cMissing); err != nil {
			t.Fatalf("adminCreateUser returned err=%v", err)
		}
		if recMissing.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 missing bearer token, got %d", recMissing.Code)
		}

		// invalid token
		svc.introspectErr = errors.New("invalid token")
		reqBadTok := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqBadTok.Header.Set("Authorization", "Bearer token")
		reqBadTok.Header.Set("Content-Type", "application/json")
		recBadTok := httptest.NewRecorder()
		cBadTok := e.NewContext(reqBadTok, recBadTok)
		if err := h.adminCreateUser(cBadTok); err != nil {
			t.Fatalf("adminCreateUser returned err=%v", err)
		}
		if recBadTok.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 invalid token, got %d", recBadTok.Code)
		}
		svc.introspectErr = nil

		// forbidden for non-admin role
		svc.introspectOut.Roles = []string{"member"}
		reqForbidden := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqForbidden.Header.Set("Authorization", "Bearer token")
		reqForbidden.Header.Set("Content-Type", "application/json")
		recForbidden := httptest.NewRecorder()
		cForbidden := e.NewContext(reqForbidden, recForbidden)
		if err := h.adminCreateUser(cForbidden); err != nil {
			t.Fatalf("adminCreateUser returned err=%v", err)
		}
		if recForbidden.Code != http.StatusForbidden {
			t.Fatalf("expected 403 forbidden, got %d", recForbidden.Code)
		}
		svc.introspectOut.Roles = []string{"admin"}

		// invalid json
		reqInvalidJSON := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users", bytes.NewBufferString("{"))
		reqInvalidJSON.Header.Set("Authorization", "Bearer token")
		reqInvalidJSON.Header.Set("Content-Type", "application/json")
		recInvalidJSON := httptest.NewRecorder()
		cInvalidJSON := e.NewContext(reqInvalidJSON, recInvalidJSON)
		if err := h.adminCreateUser(cInvalidJSON); err != nil {
			t.Fatalf("adminCreateUser returned err=%v", err)
		}
		if recInvalidJSON.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recInvalidJSON.Code)
		}

		// cross-tenant forbidden
		otherTenant := uuid.New()
		reqCrossTenant := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users", bytes.NewBufferString(`{"tenant_id":"`+otherTenant.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqCrossTenant.Header.Set("Authorization", "Bearer token")
		reqCrossTenant.Header.Set("Content-Type", "application/json")
		recCrossTenant := httptest.NewRecorder()
		cCrossTenant := e.NewContext(reqCrossTenant, recCrossTenant)
		if err := h.adminCreateUser(cCrossTenant); err != nil {
			t.Fatalf("adminCreateUser returned err=%v", err)
		}
		if recCrossTenant.Code != http.StatusForbidden {
			t.Fatalf("expected 403 cross-tenant forbidden, got %d", recCrossTenant.Code)
		}

		// service error
		svc.adminCreateErr = errors.New("create failed")
		reqSvcErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqSvcErr.Header.Set("Authorization", "Bearer token")
		reqSvcErr.Header.Set("Content-Type", "application/json")
		recSvcErr := httptest.NewRecorder()
		cSvcErr := e.NewContext(reqSvcErr, recSvcErr)
		if err := h.adminCreateUser(cSvcErr); err != nil {
			t.Fatalf("adminCreateUser returned err=%v", err)
		}
		if recSvcErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 service error, got %d", recSvcErr.Code)
		}

		// success
		svc.adminCreateErr = nil
		svc.adminCreateOut = adomain.User{ID: uuid.New(), FirstName: "U", LastName: "Ser", Roles: []string{"member"}, EmailVerified: true, IsActive: true, CreatedAt: time.Now()}
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","roles":["member"],"email_verified":true}`))
		reqOK.Header.Set("Authorization", "Bearer token")
		reqOK.Header.Set("Content-Type", "application/json")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.adminCreateUser(cOK); err != nil {
			t.Fatalf("adminCreateUser returned err=%v", err)
		}
		if recOK.Code != http.StatusCreated {
			t.Fatalf("expected 201 success, got %d body=%s", recOK.Code, recOK.Body.String())
		}
	})
}
