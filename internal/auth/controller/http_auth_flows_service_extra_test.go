package controller

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	adomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/config"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type authFlowControllerSvcStub struct {
	adomain.Service

	signupOut adomain.AccessTokens
	signupErr error

	loginOut adomain.AccessTokens
	loginErr error

	refreshOut adomain.AccessTokens
	refreshErr error

	logoutErr error

	adminRoleOut adomain.Role
	adminRoleErr error

	parseClaimsOut adomain.AccessTokenClaims
	parseClaimsErr error

	addUserRoleErr     error
	updateUserRolesErr error

	meOut adomain.UserProfile
	meErr error

	introspectSeq []struct {
		out adomain.Introspection
		err error
	}
}

func (s *authFlowControllerSvcStub) Signup(context.Context, adomain.SignupInput) (adomain.AccessTokens, error) {
	if s.signupErr != nil {
		return adomain.AccessTokens{}, s.signupErr
	}
	return s.signupOut, nil
}

func (s *authFlowControllerSvcStub) Login(context.Context, adomain.LoginInput) (adomain.AccessTokens, error) {
	if s.loginErr != nil {
		return adomain.AccessTokens{}, s.loginErr
	}
	return s.loginOut, nil
}

func (s *authFlowControllerSvcStub) Refresh(context.Context, adomain.RefreshInput) (adomain.AccessTokens, error) {
	if s.refreshErr != nil {
		return adomain.AccessTokens{}, s.refreshErr
	}
	return s.refreshOut, nil
}

func (s *authFlowControllerSvcStub) Logout(context.Context, string) error { return s.logoutErr }

func (s *authFlowControllerSvcStub) GetOrCreateAdminRole(context.Context, uuid.UUID) (adomain.Role, error) {
	if s.adminRoleErr != nil {
		return adomain.Role{}, s.adminRoleErr
	}
	return s.adminRoleOut, nil
}

func (s *authFlowControllerSvcStub) ParseAccessToken(string) (adomain.AccessTokenClaims, error) {
	if s.parseClaimsErr != nil {
		return adomain.AccessTokenClaims{}, s.parseClaimsErr
	}
	return s.parseClaimsOut, nil
}

func (s *authFlowControllerSvcStub) AddUserRole(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error {
	return s.addUserRoleErr
}
func (s *authFlowControllerSvcStub) UpdateUserRoles(context.Context, uuid.UUID, []string) error {
	return s.updateUserRolesErr
}

func (s *authFlowControllerSvcStub) Me(context.Context, uuid.UUID, uuid.UUID) (adomain.UserProfile, error) {
	if s.meErr != nil {
		return adomain.UserProfile{}, s.meErr
	}
	return s.meOut, nil
}

func (s *authFlowControllerSvcStub) Introspect(context.Context, string) (adomain.Introspection, error) {
	if len(s.introspectSeq) == 0 {
		return adomain.Introspection{}, errors.New("no introspection response configured")
	}
	r := s.introspectSeq[0]
	s.introspectSeq = s.introspectSeq[1:]
	return r.out, r.err
}

func TestHTTP_AuthFlows_ServiceBranches_Extra(t *testing.T) {
	e := echo.New()
	e.Validator = noopValidator{}
	tenantID := uuid.New()
	uid := uuid.New()
	svc := &authFlowControllerSvcStub{}
	h := &Controller{svc: svc, cfg: config.Config{DefaultAuthMode: "bearer"}}

	t.Run("signup service and assign-admin branches", func(t *testing.T) {
		svc.signupErr = errors.New("signup failed")
		reqErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqErr.Header.Set("Content-Type", "application/json")
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.signup(cErr); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 signup error, got %d", recErr.Code)
		}

		svc.signupErr = nil
		svc.signupOut = adomain.AccessTokens{AccessToken: "at", RefreshToken: "rt"}
		svc.adminRoleErr = errors.New("role error")
		reqRoleErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","assign_admin":true}`))
		reqRoleErr.Header.Set("Content-Type", "application/json")
		recRoleErr := httptest.NewRecorder()
		cRoleErr := e.NewContext(reqRoleErr, recRoleErr)
		if err := h.signup(cRoleErr); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recRoleErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 role error, got %d", recRoleErr.Code)
		}

		svc.adminRoleErr = nil
		svc.adminRoleOut = adomain.Role{}
		reqNilRole := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","assign_admin":true}`))
		reqNilRole.Header.Set("Content-Type", "application/json")
		recNilRole := httptest.NewRecorder()
		cNilRole := e.NewContext(reqNilRole, recNilRole)
		if err := h.signup(cNilRole); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recNilRole.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 invalid admin role, got %d", recNilRole.Code)
		}

		svc.adminRoleOut = adomain.Role{ID: uuid.New(), TenantID: tenantID, Name: "admin"}
		svc.parseClaimsErr = errors.New("parse failed")
		reqParseErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","assign_admin":true}`))
		reqParseErr.Header.Set("Content-Type", "application/json")
		recParseErr := httptest.NewRecorder()
		cParseErr := e.NewContext(reqParseErr, recParseErr)
		if err := h.signup(cParseErr); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recParseErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 parse error, got %d", recParseErr.Code)
		}

		svc.parseClaimsErr = nil
		svc.parseClaimsOut = adomain.AccessTokenClaims{}
		reqNilUID := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","assign_admin":true}`))
		reqNilUID.Header.Set("Content-Type", "application/json")
		recNilUID := httptest.NewRecorder()
		cNilUID := e.NewContext(reqNilUID, recNilUID)
		if err := h.signup(cNilUID); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recNilUID.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 invalid user id, got %d", recNilUID.Code)
		}

		svc.parseClaimsOut = adomain.AccessTokenClaims{UserID: uid, TenantID: tenantID}
		svc.addUserRoleErr = errors.New("add role failed")
		reqAddRoleErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","assign_admin":true}`))
		reqAddRoleErr.Header.Set("Content-Type", "application/json")
		recAddRoleErr := httptest.NewRecorder()
		cAddRoleErr := e.NewContext(reqAddRoleErr, recAddRoleErr)
		if err := h.signup(cAddRoleErr); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recAddRoleErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 add role error, got %d", recAddRoleErr.Code)
		}

		svc.addUserRoleErr = nil
		svc.updateUserRolesErr = errors.New("sync roles failed")
		reqSyncErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","assign_admin":true}`))
		reqSyncErr.Header.Set("Content-Type", "application/json")
		recSyncErr := httptest.NewRecorder()
		cSyncErr := e.NewContext(reqSyncErr, recSyncErr)
		if err := h.signup(cSyncErr); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recSyncErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 sync roles error, got %d", recSyncErr.Code)
		}

		svc.updateUserRolesErr = nil
		reqOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123","assign_admin":true}`))
		reqOK.Header.Set("Content-Type", "application/json")
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.signup(cOK); err != nil {
			t.Fatalf("signup returned err=%v", err)
		}
		if recOK.Code != http.StatusCreated {
			t.Fatalf("expected 201 signup success, got %d", recOK.Code)
		}
	})

	t.Run("login refresh logout me branches", func(t *testing.T) {
		svc.loginErr = adomain.ErrMFARequired{ChallengeToken: "challenge", Methods: []string{"totp"}}
		reqMFA := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqMFA.Header.Set("Content-Type", "application/json")
		recMFA := httptest.NewRecorder()
		cMFA := e.NewContext(reqMFA, recMFA)
		if err := h.login(cMFA); err != nil {
			t.Fatalf("login returned err=%v", err)
		}
		if recMFA.Code != http.StatusAccepted {
			t.Fatalf("expected 202 mfa required, got %d", recMFA.Code)
		}

		svc.loginErr = errors.New("invalid credentials")
		reqLoginErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqLoginErr.Header.Set("Content-Type", "application/json")
		recLoginErr := httptest.NewRecorder()
		cLoginErr := e.NewContext(reqLoginErr, recLoginErr)
		if err := h.login(cLoginErr); err != nil {
			t.Fatalf("login returned err=%v", err)
		}
		if recLoginErr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 login error, got %d", recLoginErr.Code)
		}

		svc.loginErr = nil
		svc.loginOut = adomain.AccessTokens{AccessToken: "at", RefreshToken: "rt"}
		reqLoginOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewBufferString(`{"tenant_id":"`+tenantID.String()+`","email":"u@example.com","password":"Password!123"}`))
		reqLoginOK.Header.Set("Content-Type", "application/json")
		recLoginOK := httptest.NewRecorder()
		cLoginOK := e.NewContext(reqLoginOK, recLoginOK)
		if err := h.login(cLoginOK); err != nil {
			t.Fatalf("login returned err=%v", err)
		}
		if recLoginOK.Code != http.StatusOK {
			t.Fatalf("expected 200 login success, got %d", recLoginOK.Code)
		}

		svc.refreshErr = errors.New("invalid refresh")
		reqRefreshErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{"refresh_token":"r"}`))
		reqRefreshErr.Header.Set("Content-Type", "application/json")
		recRefreshErr := httptest.NewRecorder()
		cRefreshErr := e.NewContext(reqRefreshErr, recRefreshErr)
		if err := h.refresh(cRefreshErr); err != nil {
			t.Fatalf("refresh returned err=%v", err)
		}
		if recRefreshErr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 refresh error, got %d", recRefreshErr.Code)
		}

		svc.refreshErr = nil
		svc.refreshOut = adomain.AccessTokens{AccessToken: "at2", RefreshToken: "rt2"}
		reqRefreshOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{"refresh_token":"r"}`))
		reqRefreshOK.Header.Set("Content-Type", "application/json")
		recRefreshOK := httptest.NewRecorder()
		cRefreshOK := e.NewContext(reqRefreshOK, recRefreshOK)
		if err := h.refresh(cRefreshOK); err != nil {
			t.Fatalf("refresh returned err=%v", err)
		}
		if recRefreshOK.Code != http.StatusOK {
			t.Fatalf("expected 200 refresh success, got %d", recRefreshOK.Code)
		}

		svc.logoutErr = errors.New("logout failed")
		reqLogoutErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBufferString(`{"refresh_token":"r"}`))
		reqLogoutErr.Header.Set("Content-Type", "application/json")
		recLogoutErr := httptest.NewRecorder()
		cLogoutErr := e.NewContext(reqLogoutErr, recLogoutErr)
		if err := h.logout(cLogoutErr); err != nil {
			t.Fatalf("logout returned err=%v", err)
		}
		if recLogoutErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 logout error, got %d", recLogoutErr.Code)
		}

		svc.logoutErr = nil
		reqLogoutOK := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBufferString(`{"refresh_token":"r"}`))
		reqLogoutOK.Header.Set("Content-Type", "application/json")
		recLogoutOK := httptest.NewRecorder()
		cLogoutOK := e.NewContext(reqLogoutOK, recLogoutOK)
		if err := h.logout(cLogoutOK); err != nil {
			t.Fatalf("logout returned err=%v", err)
		}
		if recLogoutOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 logout success, got %d", recLogoutOK.Code)
		}

		svc.meErr = errors.New("profile failed")
		svc.introspectSeq = []struct {
			out adomain.Introspection
			err error
		}{{out: adomain.Introspection{Active: true, UserID: uid, TenantID: tenantID}, err: nil}}
		reqMeErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		reqMeErr.Header.Set("Authorization", "Bearer token")
		recMeErr := httptest.NewRecorder()
		cMeErr := e.NewContext(reqMeErr, recMeErr)
		if err := h.me(cMeErr); err != nil {
			t.Fatalf("me returned err=%v", err)
		}
		if recMeErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 me profile error, got %d", recMeErr.Code)
		}

		svc.meErr = nil
		svc.meOut = adomain.UserProfile{ID: uid, TenantID: tenantID, Email: "u@example.com"}
		svc.introspectSeq = []struct {
			out adomain.Introspection
			err error
		}{{out: adomain.Introspection{}, err: errors.New("invalid bearer")}, {out: adomain.Introspection{Active: true, UserID: uid, TenantID: tenantID}, err: nil}}
		reqMeCookieFallback := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		reqMeCookieFallback.Header.Set("Authorization", "Bearer token")
		reqMeCookieFallback.Header.Set("X-Auth-Mode", "cookie")
		reqMeCookieFallback.AddCookie(&http.Cookie{Name: "guard_access_token", Value: "cookie-token"})
		recMeCookieFallback := httptest.NewRecorder()
		cMeCookieFallback := e.NewContext(reqMeCookieFallback, recMeCookieFallback)
		if err := h.me(cMeCookieFallback); err != nil {
			t.Fatalf("me returned err=%v", err)
		}
		if recMeCookieFallback.Code != http.StatusOK {
			t.Fatalf("expected 200 me cookie fallback, got %d", recMeCookieFallback.Code)
		}

		// Cookie-mode refresh: fallback to cookie token and success response
		svc.refreshOut = adomain.AccessTokens{AccessToken: "cat", RefreshToken: "crt"}
		reqRefreshCookie := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{}`))
		reqRefreshCookie.Header.Set("Content-Type", "application/json")
		reqRefreshCookie.Header.Set("X-Auth-Mode", "cookie")
		reqRefreshCookie.AddCookie(&http.Cookie{Name: "guard_refresh_token", Value: "cookie-rt"})
		recRefreshCookie := httptest.NewRecorder()
		cRefreshCookie := e.NewContext(reqRefreshCookie, recRefreshCookie)
		if err := h.refresh(cRefreshCookie); err != nil {
			t.Fatalf("refresh returned err=%v", err)
		}
		if recRefreshCookie.Code != http.StatusOK {
			t.Fatalf("expected 200 cookie refresh success, got %d", recRefreshCookie.Code)
		}

		// Cookie-mode refresh missing both body and cookie -> bad request
		reqRefreshCookieMissing := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{}`))
		reqRefreshCookieMissing.Header.Set("Content-Type", "application/json")
		reqRefreshCookieMissing.Header.Set("X-Auth-Mode", "cookie")
		recRefreshCookieMissing := httptest.NewRecorder()
		cRefreshCookieMissing := e.NewContext(reqRefreshCookieMissing, recRefreshCookieMissing)
		if err := h.refresh(cRefreshCookieMissing); err != nil {
			t.Fatalf("refresh returned err=%v", err)
		}
		if recRefreshCookieMissing.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 cookie refresh missing token, got %d", recRefreshCookieMissing.Code)
		}

		// Cookie-mode logout with missing token should still clear and return 204
		reqLogoutCookie := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBufferString(`{}`))
		reqLogoutCookie.Header.Set("Content-Type", "application/json")
		reqLogoutCookie.Header.Set("X-Auth-Mode", "cookie")
		recLogoutCookie := httptest.NewRecorder()
		cLogoutCookie := e.NewContext(reqLogoutCookie, recLogoutCookie)
		if err := h.logout(cLogoutCookie); err != nil {
			t.Fatalf("logout returned err=%v", err)
		}
		if recLogoutCookie.Code != http.StatusNoContent {
			t.Fatalf("expected 204 cookie logout no token, got %d", recLogoutCookie.Code)
		}

		// me with bearer only invalid in bearer mode -> unauthorized
		svc.introspectSeq = []struct {
			out adomain.Introspection
			err error
		}{{out: adomain.Introspection{}, err: errors.New("invalid bearer")}}
		reqMeUnauthorized := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		reqMeUnauthorized.Header.Set("Authorization", "Bearer token")
		recMeUnauthorized := httptest.NewRecorder()
		cMeUnauthorized := e.NewContext(reqMeUnauthorized, recMeUnauthorized)
		if err := h.me(cMeUnauthorized); err != nil {
			t.Fatalf("me returned err=%v", err)
		}
		if recMeUnauthorized.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 me unauthorized, got %d", recMeUnauthorized.Code)
		}

		// me direct bearer success
		svc.introspectSeq = []struct {
			out adomain.Introspection
			err error
		}{{out: adomain.Introspection{Active: true, UserID: uid, TenantID: tenantID}, err: nil}}
		reqMeOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		reqMeOK.Header.Set("Authorization", "Bearer token")
		recMeOK := httptest.NewRecorder()
		cMeOK := e.NewContext(reqMeOK, recMeOK)
		if err := h.me(cMeOK); err != nil {
			t.Fatalf("me returned err=%v", err)
		}
		if recMeOK.Code != http.StatusOK {
			t.Fatalf("expected 200 me bearer success, got %d", recMeOK.Code)
		}

		// me cookie-only path (no bearer header)
		svc.introspectSeq = []struct {
			out adomain.Introspection
			err error
		}{{out: adomain.Introspection{Active: true, UserID: uid, TenantID: tenantID}, err: nil}}
		reqMeCookieOnly := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		reqMeCookieOnly.Header.Set("X-Auth-Mode", "cookie")
		reqMeCookieOnly.AddCookie(&http.Cookie{Name: "guard_access_token", Value: "cookie-token"})
		recMeCookieOnly := httptest.NewRecorder()
		cMeCookieOnly := e.NewContext(reqMeCookieOnly, recMeCookieOnly)
		if err := h.me(cMeCookieOnly); err != nil {
			t.Fatalf("me returned err=%v", err)
		}
		if recMeCookieOnly.Code != http.StatusOK {
			t.Fatalf("expected 200 me cookie-only success, got %d", recMeCookieOnly.Code)
		}

		// me cookie-only invalid token path
		svc.introspectSeq = []struct {
			out adomain.Introspection
			err error
		}{{out: adomain.Introspection{}, err: errors.New("invalid cookie")}}
		reqMeCookieInvalid := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		reqMeCookieInvalid.Header.Set("X-Auth-Mode", "cookie")
		reqMeCookieInvalid.AddCookie(&http.Cookie{Name: "guard_access_token", Value: "cookie-token"})
		recMeCookieInvalid := httptest.NewRecorder()
		cMeCookieInvalid := e.NewContext(reqMeCookieInvalid, recMeCookieInvalid)
		if err := h.me(cMeCookieInvalid); err != nil {
			t.Fatalf("me returned err=%v", err)
		}
		if recMeCookieInvalid.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 me cookie invalid, got %d", recMeCookieInvalid.Code)
		}

		// cookie-mode logout with cookie token and service error
		svc.logoutErr = errors.New("logout cookie failed")
		reqLogoutCookieErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBufferString(`{}`))
		reqLogoutCookieErr.Header.Set("Content-Type", "application/json")
		reqLogoutCookieErr.Header.Set("X-Auth-Mode", "cookie")
		reqLogoutCookieErr.AddCookie(&http.Cookie{Name: "guard_refresh_token", Value: "cookie-rt"})
		recLogoutCookieErr := httptest.NewRecorder()
		cLogoutCookieErr := e.NewContext(reqLogoutCookieErr, recLogoutCookieErr)
		if err := h.logout(cLogoutCookieErr); err != nil {
			t.Fatalf("logout returned err=%v", err)
		}
		if recLogoutCookieErr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 cookie logout service error, got %d", recLogoutCookieErr.Code)
		}
		svc.logoutErr = nil

		// cookie-mode refresh with cookie token and service error
		svc.refreshErr = errors.New("refresh cookie failed")
		reqRefreshCookieErr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{}`))
		reqRefreshCookieErr.Header.Set("Content-Type", "application/json")
		reqRefreshCookieErr.Header.Set("X-Auth-Mode", "cookie")
		reqRefreshCookieErr.AddCookie(&http.Cookie{Name: "guard_refresh_token", Value: "cookie-rt"})
		recRefreshCookieErr := httptest.NewRecorder()
		cRefreshCookieErr := e.NewContext(reqRefreshCookieErr, recRefreshCookieErr)
		if err := h.refresh(cRefreshCookieErr); err != nil {
			t.Fatalf("refresh returned err=%v", err)
		}
		if recRefreshCookieErr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 cookie refresh service error, got %d", recRefreshCookieErr.Code)
		}
		svc.refreshErr = nil

		// Debug-enabled refresh/logout branches
		t.Setenv("AUTH_DEBUG", "1")
		svc.refreshOut = adomain.AccessTokens{AccessToken: "dbg-at", RefreshToken: "dbg-rt"}
		reqRefreshDebug := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(`{"refresh_token":"dbg"}`))
		reqRefreshDebug.Header.Set("Content-Type", "application/json")
		recRefreshDebug := httptest.NewRecorder()
		cRefreshDebug := e.NewContext(reqRefreshDebug, recRefreshDebug)
		if err := h.refresh(cRefreshDebug); err != nil {
			t.Fatalf("refresh returned err=%v", err)
		}
		if recRefreshDebug.Code != http.StatusOK {
			t.Fatalf("expected 200 debug refresh success, got %d", recRefreshDebug.Code)
		}

		reqLogoutDebug := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewBufferString(`{"refresh_token":"dbg"}`))
		reqLogoutDebug.Header.Set("Content-Type", "application/json")
		recLogoutDebug := httptest.NewRecorder()
		cLogoutDebug := e.NewContext(reqLogoutDebug, recLogoutDebug)
		if err := h.logout(cLogoutDebug); err != nil {
			t.Fatalf("logout returned err=%v", err)
		}
		if recLogoutDebug.Code != http.StatusNoContent {
			t.Fatalf("expected 204 debug logout success, got %d", recLogoutDebug.Code)
		}
	})
}
