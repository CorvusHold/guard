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

// 401: Missing/invalid token for admin RBAC endpoints
func TestHTTP_RBAC_Admin_Unauthorized(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

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

	// No Authorization header
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/admin/rbac/permissions", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	// Malformed Authorization header
	req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/admin/rbac/permissions", nil)
	req2.Header.Set("Authorization", "Bearer invalid-token")
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid token, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// 403: Token is valid but user lacks admin role
func TestHTTP_RBAC_Admin_Forbidden_NonAdmin(t *testing.T) {
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
	name := "http-rbac-nonadmin-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

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

	userEmail := "nonadmin.rbac.itest@ex.com"
	password := "Password!123"

	// Sign up a normal user
	body := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     userEmail,
		"password":  password,
	}
	bb, _ := json.Marshal(body)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(bb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("signup: expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var toks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&toks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if toks.AccessToken == "" {
		t.Fatalf("expected access token")
	}

	// Try listing roles as non-admin
	lreq := httptest.NewRequest(http.MethodGet, "/v1/auth/admin/rbac/roles?tenant_id="+tenantID.String(), nil)
	lreq.Header.Set("Authorization", "Bearer "+toks.AccessToken)
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d: %s", lrec.Code, lrec.Body.String())
	}
}

// 400: Validation errors (bad UUIDs and invalid JSON)
func TestHTTP_RBAC_Admin_ValidationErrors(t *testing.T) {
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
	name := "http-rbac-validate-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

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

	adminEmail := "admin.rbac.validate@ex.com"
	password := "Password!123"

	// Create admin user
	sBody := map[string]string{"tenant_id": tenantID.String(), "email": adminEmail, "password": password}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	sreq.Header.Set("X-Auth-Mode", "bearer")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("signup: expected 201, got %d: %s", srec.Code, srec.Body.String())
	}
	var stoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&stoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}

	// Grant admin role
	aiAdmin, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, adminEmail)
	if err != nil {
		t.Fatalf("lookup admin identity: %v", err)
	}
	if err := auth.UpdateUserRoles(ctx, aiAdmin.UserID, []string{"admin"}); err != nil {
		t.Fatalf("grant admin: %v", err)
	}

	// Invalid UUID in path: update role
	upd := map[string]string{"tenant_id": tenantID.String(), "name": "x", "description": "y"}
	ub, _ := json.Marshal(upd)
	ureq := httptest.NewRequest(http.MethodPatch, "/v1/auth/admin/rbac/roles/not-a-uuid", bytes.NewReader(ub))
	ureq.Header.Set("Content-Type", "application/json")
	ureq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	urec := httptest.NewRecorder()
	e.ServeHTTP(urec, ureq)
	if urec.Code != http.StatusBadRequest {
		t.Fatalf("update role bad uuid: expected 400, got %d: %s", urec.Code, urec.Body.String())
	}

	// Invalid tenant_id UUID in body: create role
	cr := map[string]string{"tenant_id": "bad-uuid", "name": "qa", "description": "d"}
	cb, _ := json.Marshal(cr)
	creq := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/rbac/roles", bytes.NewReader(cb))
	creq.Header.Set("Content-Type", "application/json")
	creq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	crec := httptest.NewRecorder()
	e.ServeHTTP(crec, creq)
	if crec.Code != http.StatusBadRequest {
		t.Fatalf("create role bad tenant_id: expected 400, got %d: %s", crec.Code, crec.Body.String())
	}

	// Invalid JSON: upsert role permission
	preq := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/rbac/roles/"+uuid.NewString()+"/permissions", bytes.NewBufferString("{bad json"))
	preq.Header.Set("Content-Type", "application/json")
	preq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	prec := httptest.NewRecorder()
	e.ServeHTTP(prec, preq)
	if prec.Code != http.StatusBadRequest {
		t.Fatalf("upsert perm invalid json: expected 400, got %d: %s", prec.Code, prec.Body.String())
	}

	// Invalid user UUID in path: assign role
	assign := map[string]string{"tenant_id": tenantID.String(), "role_id": uuid.NewString()}
	ab, _ := json.Marshal(assign)
	aReq := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/rbac/users/not-a-uuid/roles", bytes.NewReader(ab))
	aReq.Header.Set("Content-Type", "application/json")
	aReq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	aRec := httptest.NewRecorder()
	e.ServeHTTP(aRec, aReq)
	if aRec.Code != http.StatusBadRequest {
		t.Fatalf("assign role bad user id: expected 400, got %d: %s", aRec.Code, aRec.Body.String())
	}

	// Invalid tenant_id in resolve query
	rreq := httptest.NewRequest(http.MethodGet, "/v1/auth/admin/rbac/users/"+aiAdmin.UserID.String()+"/permissions/resolve?tenant_id=bad-uuid", nil)
	rreq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	rrec := httptest.NewRecorder()
	e.ServeHTTP(rrec, rreq)
	if rrec.Code != http.StatusBadRequest {
		t.Fatalf("resolve bad tenant_id: expected 400, got %d: %s", rrec.Code, rrec.Body.String())
	}
}
