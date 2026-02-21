package controller

import (
	"bytes"
	"context"
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

type controllerHTTPSvcStub struct {
	adomain.Service

	introspection adomain.Introspection
	introspectErr error

	updateProfileErr error
	verifyMFAOut     adomain.AccessTokens
	verifyMFAErr     error

	updateRolesErr error
	listUsersOut   []adomain.User
	listUsersErr   error

	updateNamesErr error
	setActiveErr   error
	unlockErr      error
	setVerifiedErr error

	listSessionsOut []adomain.RefreshToken
	listSessionsErr error
	revokeSessErr   error
}

func (s *controllerHTTPSvcStub) Introspect(context.Context, string) (adomain.Introspection, error) {
	if s.introspectErr != nil {
		return adomain.Introspection{}, s.introspectErr
	}
	return s.introspection, nil
}

func (s *controllerHTTPSvcStub) UpdateProfile(context.Context, uuid.UUID, string, string) error {
	return s.updateProfileErr
}

func (s *controllerHTTPSvcStub) VerifyMFA(context.Context, adomain.MFAVerifyInput) (adomain.AccessTokens, error) {
	if s.verifyMFAErr != nil {
		return adomain.AccessTokens{}, s.verifyMFAErr
	}
	return s.verifyMFAOut, nil
}

func (s *controllerHTTPSvcStub) UpdateUserRoles(context.Context, uuid.UUID, []string) error {
	return s.updateRolesErr
}

func (s *controllerHTTPSvcStub) ListTenantUsers(context.Context, uuid.UUID) ([]adomain.User, error) {
	if s.listUsersErr != nil {
		return nil, s.listUsersErr
	}
	return s.listUsersOut, nil
}

func (s *controllerHTTPSvcStub) UpdateUserNames(context.Context, uuid.UUID, string, string) error {
	return s.updateNamesErr
}
func (s *controllerHTTPSvcStub) SetUserActive(context.Context, uuid.UUID, bool) error {
	return s.setActiveErr
}
func (s *controllerHTTPSvcStub) UnlockAccount(context.Context, uuid.UUID) error { return s.unlockErr }
func (s *controllerHTTPSvcStub) SetUserEmailVerified(context.Context, uuid.UUID, bool) error {
	return s.setVerifiedErr
}

func (s *controllerHTTPSvcStub) ListUserSessions(context.Context, uuid.UUID, uuid.UUID) ([]adomain.RefreshToken, error) {
	if s.listSessionsErr != nil {
		return nil, s.listSessionsErr
	}
	return s.listSessionsOut, nil
}

func (s *controllerHTTPSvcStub) RevokeSession(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return s.revokeSessErr
}

func TestHTTP_AdminProfileSessionsMFA_ExtraBranches(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	tenantID := uuid.New()
	uid := uuid.New()
	svc := &controllerHTTPSvcStub{introspection: adomain.Introspection{Active: true, UserID: uid, TenantID: tenantID, Roles: []string{"admin"}}}
	h := &Controller{svc: svc, cfg: config.Config{DefaultAuthMode: "bearer"}}
	authHeader := "Bearer token"

	t.Run("updateProfile invalid json error success", func(t *testing.T) {
		reqBad := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewBufferString("{"))
		reqBad.Header.Set("Content-Type", "application/json")
		reqBad.Header.Set("Authorization", authHeader)
		recBad := httptest.NewRecorder()
		cBad := e.NewContext(reqBad, recBad)
		if err := h.updateProfile(cBad); err != nil {
			t.Fatalf("updateProfile returned err=%v", err)
		}
		if recBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", recBad.Code)
		}

		svc.updateProfileErr = errors.New("update failed")
		reqErr := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewBufferString(`{"first_name":"A"}`))
		reqErr.Header.Set("Content-Type", "application/json")
		reqErr.Header.Set("Authorization", authHeader)
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.updateProfile(cErr); err != nil {
			t.Fatalf("updateProfile returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 service error, got %d", recErr.Code)
		}

		svc.updateProfileErr = nil
		reqOK := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/profile", bytes.NewBufferString(`{"first_name":"A"}`))
		reqOK.Header.Set("Content-Type", "application/json")
		reqOK.Header.Set("Authorization", authHeader)
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.updateProfile(cOK); err != nil {
			t.Fatalf("updateProfile returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", recOK.Code)
		}
	})

	t.Run("verifyMFA invalid json error success", func(t *testing.T) {
		reqBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewBufferString("{"))
		reqBad.Header.Set("Content-Type", "application/json")
		recBad := httptest.NewRecorder()
		cBad := e.NewContext(reqBad, recBad)
		if err := h.verifyMFA(cBad); err != nil {
			t.Fatalf("verifyMFA returned err=%v", err)
		}
		if recBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recBad.Code)
		}

		svc.verifyMFAErr = errors.New("invalid challenge")
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewBufferString(`{"challenge_token":"c","method":"totp","code":"123456"}`))
		reqErr.Header.Set("Content-Type", "application/json")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.verifyMFA(cErr); err != nil {
			t.Fatalf("verifyMFA returned err=%v", err)
		}
		if recErr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 verify error, got %d", recErr.Code)
		}

		svc.verifyMFAErr = nil
		svc.verifyMFAOut = adomain.AccessTokens{AccessToken: "at", RefreshToken: "rt"}
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/verify", bytes.NewBufferString(`{"challenge_token":"c","method":"totp","code":"123456"}`))
		reqOK.Header.Set("Content-Type", "application/json")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.verifyMFA(cOK); err != nil {
			t.Fatalf("verifyMFA returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200 verify success, got %d body=%s", recOK.Code, recOK.Body.String())
		}
	})

	t.Run("adminUpdateRoles and adminListUsers branches", func(t *testing.T) {
		reqBadID := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/bad/roles", bytes.NewBufferString(`{"roles":["admin"]}`))
		reqBadID.Header.Set("Content-Type", "application/json")
		reqBadID.Header.Set("Authorization", authHeader)
		recBadID := httptest.NewRecorder()
		cBadID := e.NewContext(reqBadID, recBadID)
		cBadID.SetParamNames("id")
		cBadID.SetParamValues("bad")
		if err := h.adminUpdateRoles(cBadID); err != nil {
			t.Fatalf("adminUpdateRoles returned err=%v", err)
		}
		if recBadID.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid user id, got %d", recBadID.Code)
		}

		reqEmpty := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/"+uuid.New().String()+"/roles", bytes.NewBufferString(`{"roles":[]}`))
		reqEmpty.Header.Set("Content-Type", "application/json")
		reqEmpty.Header.Set("Authorization", authHeader)
		recEmpty := httptest.NewRecorder()
		cEmpty := e.NewContext(reqEmpty, recEmpty)
		cEmpty.SetParamNames("id")
		cEmpty.SetParamValues(uuid.New().String())
		if err := h.adminUpdateRoles(cEmpty); err != nil {
			t.Fatalf("adminUpdateRoles returned err=%v", err)
		}
		if recEmpty.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 empty roles, got %d", recEmpty.Code)
		}

		reqMissTen := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users", nil)
		reqMissTen.Header.Set("Authorization", authHeader)
		recMissTen := httptest.NewRecorder()
		cMissTen := e.NewContext(reqMissTen, recMissTen)
		if err := h.adminListUsers(cMissTen); err != nil {
			t.Fatalf("adminListUsers returned err=%v", err)
		}
		if recMissTen.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 tenant required, got %d", recMissTen.Code)
		}

		reqBadTen := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users?tenant_id=bad", nil)
		reqBadTen.Header.Set("Authorization", authHeader)
		recBadTen := httptest.NewRecorder()
		cBadTen := e.NewContext(reqBadTen, recBadTen)
		if err := h.adminListUsers(cBadTen); err != nil {
			t.Fatalf("adminListUsers returned err=%v", err)
		}
		if recBadTen.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid tenant, got %d", recBadTen.Code)
		}

		svc.listUsersErr = errors.New("list failed")
		reqListErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users?tenant_id="+tenantID.String(), nil)
		reqListErr.Header.Set("Authorization", authHeader)
		recListErr := httptest.NewRecorder()
		cListErr := e.NewContext(reqListErr, recListErr)
		if err := h.adminListUsers(cListErr); err != nil {
			t.Fatalf("adminListUsers returned err=%v", err)
		}
		if recListErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 list error, got %d", recListErr.Code)
		}

		svc.listUsersErr = nil
		svc.listUsersOut = []adomain.User{{ID: uuid.New(), Email: "u@example.com", Roles: []string{"member"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, {ID: uuid.New(), Email: "x@example.com", Roles: []string{"admin"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}}
		reqListOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users?tenant_id="+tenantID.String()+"&email=u@example.com", nil)
		reqListOK.Header.Set("Authorization", authHeader)
		recListOK := httptest.NewRecorder()
		cListOK := e.NewContext(reqListOK, recListOK)
		if err := h.adminListUsers(cListOK); err != nil {
			t.Fatalf("adminListUsers returned err=%v", err)
		}
		if recListOK.Code != http.StatusOK {
			t.Fatalf("expected 200 list success, got %d", recListOK.Code)
		}
	})

	t.Run("admin user mutation and sessions branches", func(t *testing.T) {
		badID := "bad"
		cases := []struct {
			name    string
			handler func(echo.Context) error
			path    string
		}{
			{name: "adminUpdateNames", handler: h.adminUpdateNames, path: "/api/v1/auth/admin/users/" + badID},
			{name: "adminBlockUser", handler: h.adminBlockUser, path: "/api/v1/auth/admin/users/" + badID + "/block"},
			{name: "adminUnblockUser", handler: h.adminUnblockUser, path: "/api/v1/auth/admin/users/" + badID + "/unblock"},
			{name: "adminUnlockAccount", handler: h.adminUnlockAccount, path: "/api/v1/auth/admin/users/" + badID + "/unlock"},
			{name: "adminVerifyEmail", handler: h.adminVerifyEmail, path: "/api/v1/auth/admin/users/" + badID + "/verify-email"},
			{name: "adminUnverifyEmail", handler: h.adminUnverifyEmail, path: "/api/v1/auth/admin/users/" + badID + "/unverify-email"},
		}
		for _, tc := range cases {
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(`{"first_name":"A","last_name":"B"}`))
			req.Header.Set("Authorization", authHeader)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("id")
			c.SetParamValues(badID)
			if err := tc.handler(c); err != nil {
				t.Fatalf("%s returned err=%v", tc.name, err)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s expected 400 invalid user id, got %d", tc.name, rec.Code)
			}
		}

		svc.listSessionsErr = errors.New("sessions failed")
		reqSessErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
		reqSessErr.Header.Set("Authorization", authHeader)
		recSessErr := httptest.NewRecorder()
		cSessErr := e.NewContext(reqSessErr, recSessErr)
		if err := h.sessionsList(cSessErr); err != nil {
			t.Fatalf("sessionsList returned err=%v", err)
		}
		if recSessErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 sessions err, got %d", recSessErr.Code)
		}

		svc.listSessionsErr = nil
		ssoID := uuid.New()
		svc.listSessionsOut = []adomain.RefreshToken{{ID: uuid.New(), UserID: uid, TenantID: tenantID, AuthMethod: "sso", SSOProviderID: &ssoID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}}
		reqSessOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
		reqSessOK.Header.Set("Authorization", authHeader)
		recSessOK := httptest.NewRecorder()
		cSessOK := e.NewContext(reqSessOK, recSessOK)
		if err := h.sessionsList(cSessOK); err != nil {
			t.Fatalf("sessionsList returned err=%v", err)
		}
		if recSessOK.Code != http.StatusOK {
			t.Fatalf("expected 200 sessions success, got %d", recSessOK.Code)
		}

		reqRevBad := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions/bad/revoke", nil)
		reqRevBad.Header.Set("Authorization", authHeader)
		recRevBad := httptest.NewRecorder()
		cRevBad := e.NewContext(reqRevBad, recRevBad)
		cRevBad.SetParamNames("id")
		cRevBad.SetParamValues("bad")
		if err := h.sessionRevoke(cRevBad); err != nil {
			t.Fatalf("sessionRevoke returned err=%v", err)
		}
		if recRevBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid session id, got %d", recRevBad.Code)
		}

		svc.revokeSessErr = errors.New("revoke failed")
		sid := uuid.New()
		reqRevErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions/"+sid.String()+"/revoke", nil)
		reqRevErr.Header.Set("Authorization", authHeader)
		recRevErr := httptest.NewRecorder()
		cRevErr := e.NewContext(reqRevErr, recRevErr)
		cRevErr.SetParamNames("id")
		cRevErr.SetParamValues(sid.String())
		if err := h.sessionRevoke(cRevErr); err != nil {
			t.Fatalf("sessionRevoke returned err=%v", err)
		}
		if recRevErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 revoke err, got %d", recRevErr.Code)
		}
	})

	t.Run("admin mutation success and service-error branches", func(t *testing.T) {
		targetID := uuid.New()

		// adminUpdateNames: service error then success
		svc.updateNamesErr = errors.New("update names failed")
		reqNamesErr := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/users/"+targetID.String(), bytes.NewBufferString(`{"first_name":"X","last_name":"Y"}`))
		reqNamesErr.Header.Set("Authorization", authHeader)
		reqNamesErr.Header.Set("Content-Type", "application/json")
		recNamesErr := httptest.NewRecorder()
		cNamesErr := e.NewContext(reqNamesErr, recNamesErr)
		cNamesErr.SetParamNames("id")
		cNamesErr.SetParamValues(targetID.String())
		if err := h.adminUpdateNames(cNamesErr); err != nil {
			t.Fatalf("adminUpdateNames returned err=%v", err)
		}
		if recNamesErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 update names error, got %d", recNamesErr.Code)
		}

		svc.updateNamesErr = nil
		reqNamesOK := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/users/"+targetID.String(), bytes.NewBufferString(`{"first_name":"X","last_name":"Y"}`))
		reqNamesOK.Header.Set("Authorization", authHeader)
		reqNamesOK.Header.Set("Content-Type", "application/json")
		recNamesOK := httptest.NewRecorder()
		cNamesOK := e.NewContext(reqNamesOK, recNamesOK)
		cNamesOK.SetParamNames("id")
		cNamesOK.SetParamValues(targetID.String())
		if err := h.adminUpdateNames(cNamesOK); err != nil {
			t.Fatalf("adminUpdateNames returned err=%v", err)
		}
		if recNamesOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 update names success, got %d", recNamesOK.Code)
		}

		// block/unblock/unlock/verify/unverify: service error then success
		type adminMutCase struct {
			name       string
			handler    func(echo.Context) error
			setErr     func(error)
			pathSuffix string
		}
		cases := []adminMutCase{
			{name: "adminBlockUser", handler: h.adminBlockUser, setErr: func(err error) { svc.setActiveErr = err }, pathSuffix: "/block"},
			{name: "adminUnblockUser", handler: h.adminUnblockUser, setErr: func(err error) { svc.setActiveErr = err }, pathSuffix: "/unblock"},
			{name: "adminUnlockAccount", handler: h.adminUnlockAccount, setErr: func(err error) { svc.unlockErr = err }, pathSuffix: "/unlock"},
			{name: "adminVerifyEmail", handler: h.adminVerifyEmail, setErr: func(err error) { svc.setVerifiedErr = err }, pathSuffix: "/verify-email"},
			{name: "adminUnverifyEmail", handler: h.adminUnverifyEmail, setErr: func(err error) { svc.setVerifiedErr = err }, pathSuffix: "/unverify-email"},
		}
		for _, tc := range cases {
			tc.setErr(errors.New("op failed"))
			reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/"+targetID.String()+tc.pathSuffix, nil)
			reqErr.Header.Set("Authorization", authHeader)
			recErr := httptest.NewRecorder()
			cErr := e.NewContext(reqErr, recErr)
			cErr.SetParamNames("id")
			cErr.SetParamValues(targetID.String())
			if err := tc.handler(cErr); err != nil {
				t.Fatalf("%s returned err=%v", tc.name, err)
			}
			if recErr.Code != http.StatusBadRequest {
				t.Fatalf("%s expected 400 service error, got %d", tc.name, recErr.Code)
			}

			tc.setErr(nil)
			reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/"+targetID.String()+tc.pathSuffix, nil)
			reqOK.Header.Set("Authorization", authHeader)
			recOK := httptest.NewRecorder()
			cOK := e.NewContext(reqOK, recOK)
			cOK.SetParamNames("id")
			cOK.SetParamValues(targetID.String())
			if err := tc.handler(cOK); err != nil {
				t.Fatalf("%s returned err=%v", tc.name, err)
			}
			if recOK.Code != http.StatusNoContent {
				t.Fatalf("%s expected 204 success, got %d", tc.name, recOK.Code)
			}
		}

		// adminUpdateRoles: service error then success
		svc.updateRolesErr = errors.New("update roles failed")
		reqRolesErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/"+targetID.String()+"/roles", bytes.NewBufferString(`{"roles":["admin"]}`))
		reqRolesErr.Header.Set("Authorization", authHeader)
		reqRolesErr.Header.Set("Content-Type", "application/json")
		recRolesErr := httptest.NewRecorder()
		cRolesErr := e.NewContext(reqRolesErr, recRolesErr)
		cRolesErr.SetParamNames("id")
		cRolesErr.SetParamValues(targetID.String())
		if err := h.adminUpdateRoles(cRolesErr); err != nil {
			t.Fatalf("adminUpdateRoles returned err=%v", err)
		}
		if recRolesErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 update roles error, got %d", recRolesErr.Code)
		}

		svc.updateRolesErr = nil
		reqRolesOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/"+targetID.String()+"/roles", bytes.NewBufferString(`{"roles":["admin"]}`))
		reqRolesOK.Header.Set("Authorization", authHeader)
		reqRolesOK.Header.Set("Content-Type", "application/json")
		recRolesOK := httptest.NewRecorder()
		cRolesOK := e.NewContext(reqRolesOK, recRolesOK)
		cRolesOK.SetParamNames("id")
		cRolesOK.SetParamValues(targetID.String())
		if err := h.adminUpdateRoles(cRolesOK); err != nil {
			t.Fatalf("adminUpdateRoles returned err=%v", err)
		}
		if recRolesOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 update roles success, got %d", recRolesOK.Code)
		}
	})
}
