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
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type selfServiceStub struct {
	adomain.Service

	introspection adomain.Introspection
	introspectErr error

	meOut adomain.UserProfile
	meErr error

	updateErr error

	sessionsOut []adomain.RefreshToken
	sessionsErr error

	revokeErr error

	mfaEnrolled bool
	mfaErr      error
}

func (s *selfServiceStub) Introspect(context.Context, string) (adomain.Introspection, error) {
	if s.introspectErr != nil {
		return adomain.Introspection{}, s.introspectErr
	}
	return s.introspection, nil
}

func (s *selfServiceStub) Me(context.Context, uuid.UUID, uuid.UUID) (adomain.UserProfile, error) {
	if s.meErr != nil {
		return adomain.UserProfile{}, s.meErr
	}
	return s.meOut, nil
}

func (s *selfServiceStub) UpdateUserNames(context.Context, uuid.UUID, string, string) error { return s.updateErr }

func (s *selfServiceStub) ListUserSessions(context.Context, uuid.UUID, uuid.UUID) ([]adomain.RefreshToken, error) {
	if s.sessionsErr != nil {
		return nil, s.sessionsErr
	}
	return s.sessionsOut, nil
}

func (s *selfServiceStub) RevokeSession(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error { return s.revokeErr }

func (s *selfServiceStub) IsMFAEnrolled(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return s.mfaEnrolled, s.mfaErr
}

func TestSelfServiceHandlers_ExtraBranches(t *testing.T) {
	e := echo.New()
	uid := uuid.New()
	tid := uuid.New()
	svc := &selfServiceStub{introspection: adomain.Introspection{Active: true, UserID: uid, TenantID: tid}, meOut: adomain.UserProfile{ID: uid, TenantID: tid, FirstName: "A", LastName: "B"}}
	h := &Controller{svc: svc}
	authHeader := "Bearer token"

	t.Run("selfProfile error and success", func(t *testing.T) {
		svc.meErr = errors.New("load profile failed")
		reqErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/self/profile", nil)
		reqErr.Header.Set("Authorization", authHeader)
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		if err := h.selfProfile(cErr); err != nil {
			t.Fatalf("selfProfile returned err=%v", err)
		}
		if recErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d body=%s", recErr.Code, recErr.Body.String())
		}

		svc.meErr = nil
		reqOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/self/profile", nil)
		reqOK.Header.Set("Authorization", authHeader)
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.selfProfile(cOK); err != nil {
			t.Fatalf("selfProfile returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", recOK.Code, recOK.Body.String())
		}
	})

	t.Run("selfUpdateProfile validation and error branches", func(t *testing.T) {
		reqInvalid := httptest.NewRequest(http.MethodPut, "/api/v1/auth/self/profile", bytes.NewBufferString("{"))
		reqInvalid.Header.Set("Content-Type", "application/json")
		reqInvalid.Header.Set("Authorization", authHeader)
		recInvalid := httptest.NewRecorder()
		cInvalid := e.NewContext(reqInvalid, recInvalid)
		if err := h.selfUpdateProfile(cInvalid); err != nil {
			t.Fatalf("selfUpdateProfile returned err=%v", err)
		}
		if recInvalid.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid json, got %d", recInvalid.Code)
		}

		reqNone := httptest.NewRequest(http.MethodPut, "/api/v1/auth/self/profile", bytes.NewBufferString(`{}`))
		reqNone.Header.Set("Content-Type", "application/json")
		reqNone.Header.Set("Authorization", authHeader)
		recNone := httptest.NewRecorder()
		cNone := e.NewContext(reqNone, recNone)
		if err := h.selfUpdateProfile(cNone); err != nil {
			t.Fatalf("selfUpdateProfile returned err=%v", err)
		}
		if recNone.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 nothing-to-update, got %d", recNone.Code)
		}

		svc.meErr = errors.New("profile lookup failed")
		reqMeErr := httptest.NewRequest(http.MethodPut, "/api/v1/auth/self/profile", bytes.NewBufferString(`{"first_name":"N"}`))
		reqMeErr.Header.Set("Content-Type", "application/json")
		reqMeErr.Header.Set("Authorization", authHeader)
		recMeErr := httptest.NewRecorder()
		cMeErr := e.NewContext(reqMeErr, recMeErr)
		if err := h.selfUpdateProfile(cMeErr); err != nil {
			t.Fatalf("selfUpdateProfile returned err=%v", err)
		}
		if recMeErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 me error, got %d", recMeErr.Code)
		}

		svc.meErr = nil
		svc.updateErr = errors.New("update failed")
		reqUpdErr := httptest.NewRequest(http.MethodPut, "/api/v1/auth/self/profile", bytes.NewBufferString(`{"first_name":"N"}`))
		reqUpdErr.Header.Set("Content-Type", "application/json")
		reqUpdErr.Header.Set("Authorization", authHeader)
		recUpdErr := httptest.NewRecorder()
		cUpdErr := e.NewContext(reqUpdErr, recUpdErr)
		if err := h.selfUpdateProfile(cUpdErr); err != nil {
			t.Fatalf("selfUpdateProfile returned err=%v", err)
		}
		if recUpdErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 update error, got %d", recUpdErr.Code)
		}

		svc.updateErr = nil
		reqOK := httptest.NewRequest(http.MethodPut, "/api/v1/auth/self/profile", bytes.NewBufferString(`{"first_name":"N"}`))
		reqOK.Header.Set("Content-Type", "application/json")
		reqOK.Header.Set("Authorization", authHeader)
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		if err := h.selfUpdateProfile(cOK); err != nil {
			t.Fatalf("selfUpdateProfile returned err=%v", err)
		}
		if recOK.Code != http.StatusOK {
			t.Fatalf("expected 200 update success, got %d body=%s", recOK.Code, recOK.Body.String())
		}
	})

	t.Run("sessions and mfa status branches", func(t *testing.T) {
		svc.sessionsErr = errors.New("list sessions failed")
		reqSessErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/self/sessions", nil)
		reqSessErr.Header.Set("Authorization", authHeader)
		recSessErr := httptest.NewRecorder()
		cSessErr := e.NewContext(reqSessErr, recSessErr)
		if err := h.selfListSessions(cSessErr); err != nil {
			t.Fatalf("selfListSessions returned err=%v", err)
		}
		if recSessErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 sessions error, got %d", recSessErr.Code)
		}

		svc.sessionsErr = nil
		svc.sessionsOut = []adomain.RefreshToken{{ID: uuid.New(), UserID: uid, TenantID: tid, AuthMethod: "password", CreatedAt: time.Now()}}
		reqSessOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/self/sessions", nil)
		reqSessOK.Header.Set("Authorization", authHeader)
		recSessOK := httptest.NewRecorder()
		cSessOK := e.NewContext(reqSessOK, recSessOK)
		if err := h.selfListSessions(cSessOK); err != nil {
			t.Fatalf("selfListSessions returned err=%v", err)
		}
		if recSessOK.Code != http.StatusOK {
			t.Fatalf("expected 200 sessions success, got %d", recSessOK.Code)
		}

		svc.mfaErr = errors.New("mfa failed")
		reqMFAErr := httptest.NewRequest(http.MethodGet, "/api/v1/auth/self/mfa", nil)
		reqMFAErr.Header.Set("Authorization", authHeader)
		recMFAErr := httptest.NewRecorder()
		cMFAErr := e.NewContext(reqMFAErr, recMFAErr)
		if err := h.selfMFAStatus(cMFAErr); err != nil {
			t.Fatalf("selfMFAStatus returned err=%v", err)
		}
		if recMFAErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 mfa error, got %d", recMFAErr.Code)
		}

		svc.mfaErr = nil
		svc.mfaEnrolled = true
		reqMFAOK := httptest.NewRequest(http.MethodGet, "/api/v1/auth/self/mfa", nil)
		reqMFAOK.Header.Set("Authorization", authHeader)
		recMFAOK := httptest.NewRecorder()
		cMFAOK := e.NewContext(reqMFAOK, recMFAOK)
		if err := h.selfMFAStatus(cMFAOK); err != nil {
			t.Fatalf("selfMFAStatus returned err=%v", err)
		}
		if recMFAOK.Code != http.StatusOK {
			t.Fatalf("expected 200 mfa status success, got %d", recMFAOK.Code)
		}
	})

	t.Run("selfRevokeSession and passkey disabled branches", func(t *testing.T) {
		reqBadID := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/self/sessions/bad", nil)
		reqBadID.Header.Set("Authorization", authHeader)
		recBadID := httptest.NewRecorder()
		cBadID := e.NewContext(reqBadID, recBadID)
		cBadID.SetParamNames("id")
		cBadID.SetParamValues("bad")
		if err := h.selfRevokeSession(cBadID); err != nil {
			t.Fatalf("selfRevokeSession returned err=%v", err)
		}
		if recBadID.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 invalid session id, got %d", recBadID.Code)
		}

		sessionID := uuid.New()
		svc.revokeErr = errors.New("revoke failed")
		reqErr := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/self/sessions/"+sessionID.String(), nil)
		reqErr.Header.Set("Authorization", authHeader)
		recErr := httptest.NewRecorder()
		cErr := e.NewContext(reqErr, recErr)
		cErr.SetParamNames("id")
		cErr.SetParamValues(sessionID.String())
		if err := h.selfRevokeSession(cErr); err != nil {
			t.Fatalf("selfRevokeSession returned err=%v", err)
		}
		if recErr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 revoke error, got %d", recErr.Code)
		}

		svc.revokeErr = nil
		reqOK := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/self/sessions/"+sessionID.String(), nil)
		reqOK.Header.Set("Authorization", authHeader)
		recOK := httptest.NewRecorder()
		cOK := e.NewContext(reqOK, recOK)
		cOK.SetParamNames("id")
		cOK.SetParamValues(sessionID.String())
		if err := h.selfRevokeSession(cOK); err != nil {
			t.Fatalf("selfRevokeSession returned err=%v", err)
		}
		if recOK.Code != http.StatusNoContent {
			t.Fatalf("expected 204 revoke success, got %d", recOK.Code)
		}

		reqPassList := httptest.NewRequest(http.MethodGet, "/api/v1/auth/self/passkeys", nil)
		reqPassList.Header.Set("Authorization", authHeader)
		recPassList := httptest.NewRecorder()
		cPassList := e.NewContext(reqPassList, recPassList)
		if err := h.selfListPasskeys(cPassList); err != nil {
			t.Fatalf("selfListPasskeys returned err=%v", err)
		}
		if recPassList.Code != http.StatusOK {
			t.Fatalf("expected 200 passkeys list fallback, got %d", recPassList.Code)
		}

		reqPassReg := httptest.NewRequest(http.MethodPost, "/api/v1/auth/self/passkeys", bytes.NewBufferString(`{"credential_id":"x","public_key":"y"}`))
		reqPassReg.Header.Set("Authorization", authHeader)
		reqPassReg.Header.Set("Content-Type", "application/json")
		recPassReg := httptest.NewRecorder()
		cPassReg := e.NewContext(reqPassReg, recPassReg)
		if err := h.selfRegisterPasskey(cPassReg); err != nil {
			t.Fatalf("selfRegisterPasskey returned err=%v", err)
		}
		if recPassReg.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 passkey register unavailable, got %d", recPassReg.Code)
		}

		reqPassDel := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/self/passkeys/"+uuid.New().String(), nil)
		reqPassDel.Header.Set("Authorization", authHeader)
		recPassDel := httptest.NewRecorder()
		cPassDel := e.NewContext(reqPassDel, recPassDel)
		cPassDel.SetParamNames("id")
		cPassDel.SetParamValues(uuid.New().String())
		if err := h.selfDeletePasskey(cPassDel); err != nil {
			t.Fatalf("selfDeletePasskey returned err=%v", err)
		}
		if recPassDel.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 passkey delete unavailable, got %d", recPassDel.Code)
		}
	})
}
