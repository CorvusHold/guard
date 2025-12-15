package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

func TestHTTP_Sessions_List_And_Revoke(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-sessions-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// wire services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	email := "user.sessions.itest@ex.com"
	password := "Password!123"

	// Signup
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", srec.Code, srec.Body.String())
	}

	// Login (captures UA, IP) and get tokens
	lBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	lb, _ := json.Marshal(lBody)
	lreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/login", bytes.NewReader(lb))
	lreq.Header.Set("Content-Type", "application/json")
	lreq.Header.Set("X-Auth-Mode", "bearer")
	lreq.Header.Set("User-Agent", "itest-agent")
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", lrec.Code, lrec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(lrec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}

	// --- sessionsList ---
	// 401 missing token
	req401 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	rec401 := httptest.NewRecorder()
	e.ServeHTTP(rec401, req401)
	if rec401.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec401.Code, rec401.Body.String())
	}

	// 200 success
	req200 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	req200.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rec200 := httptest.NewRecorder()
	e.ServeHTTP(rec200, req200)
	if rec200.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec200.Code, rec200.Body.String())
	}
	var sl sessionsListResp
	if err := json.NewDecoder(bytes.NewReader(rec200.Body.Bytes())).Decode(&sl); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(sl.Sessions) == 0 {
		t.Fatalf("expected at least 1 session")
	}

	// find a non-revoked session to revoke
	sid := sl.Sessions[0].ID
	for _, s := range sl.Sessions {
		if !s.Revoked {
			sid = s.ID
			break
		}
	}

	// --- sessionRevoke ---
	// 401 missing token
	r401 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions/"+sid.String()+"/revoke", nil)
	rrec401 := httptest.NewRecorder()
	e.ServeHTTP(rrec401, r401)
	if rrec401.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rrec401.Code, rrec401.Body.String())
	}

	// 400 invalid id
	r400 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions/not-a-uuid/revoke", nil)
	r400.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rrec400 := httptest.NewRecorder()
	e.ServeHTTP(rrec400, r400)
	if rrec400.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rrec400.Code, rrec400.Body.String())
	}

	// 204 success
	r200 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/sessions/"+sid.String()+"/revoke", nil)
	r200.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	rrec200 := httptest.NewRecorder()
	e.ServeHTTP(rrec200, r200)
	if rrec200.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rrec200.Code, rrec200.Body.String())
	}

	// verify via list that session is revoked
	reqList2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sessions", nil)
	reqList2.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	recList2 := httptest.NewRecorder()
	e.ServeHTTP(recList2, reqList2)
	if recList2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recList2.Code, recList2.Body.String())
	}
	var sl2 sessionsListResp
	if err := json.NewDecoder(bytes.NewReader(recList2.Body.Bytes())).Decode(&sl2); err != nil {
		t.Fatalf("decode sessions2: %v", err)
	}
	found := false
	for _, s := range sl2.Sessions {
		if s.ID == sid {
			found = true
			if !s.Revoked {
				t.Fatalf("expected session %s revoked after revoke", sid)
			}
		}
	}
	if !found {
		t.Fatalf("revoked session id not found in listing")
	}
}
