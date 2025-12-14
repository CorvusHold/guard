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

// Integration coverage for RBAC v2 admin endpoints
func TestHTTP_RBAC_Admin_Integration(t *testing.T) {
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
	name := "http-rbac-admin-itest-" + tenantID.String()
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

	adminEmail := "admin.rbac.itest@ex.com"
	password := "Password!123"
	targetEmail := "target.rbac.itest@ex.com"

	// Create admin user (signup) and get tokens
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     adminEmail,
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
	var stoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&stoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if stoks.AccessToken == "" {
		t.Fatalf("expected access token for admin")
	}

	// Grant admin role to admin user via service
	aiAdmin, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, adminEmail)
	if err != nil {
		t.Fatalf("lookup admin identity: %v", err)
	}
	if err := auth.UpdateUserRoles(ctx, aiAdmin.UserID, []string{"admin"}); err != nil {
		t.Fatalf("grant admin role: %v", err)
	}

	// Create target user
	tsBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     targetEmail,
		"password":  password,
	}
	tsb, _ := json.Marshal(tsBody)
	tsreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(tsb))
	tsreq.Header.Set("Content-Type", "application/json")
	tsreq.Header.Set("X-Auth-Mode", "bearer")
	tsrec := httptest.NewRecorder()
	e.ServeHTTP(tsrec, tsreq)
	if tsrec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", tsrec.Code, tsrec.Body.String())
	}
	aiTarget, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, targetEmail)
	if err != nil {
		t.Fatalf("lookup target identity: %v", err)
	}

	// 1) List permissions (admin)
	reqPerms := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/permissions", nil)
	reqPerms.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	recPerms := httptest.NewRecorder()
	e.ServeHTTP(recPerms, reqPerms)
	if recPerms.Code != http.StatusOK {
		t.Fatalf("permissions: expected 200, got %d: %s", recPerms.Code, recPerms.Body.String())
	}
	var permsResp struct {
		Permissions []struct {
			Key string `json:"key"`
		} `json:"permissions"`
	}
	if err := json.NewDecoder(bytes.NewReader(recPerms.Body.Bytes())).Decode(&permsResp); err != nil {
		t.Fatalf("decode perms: %v", err)
	}
	if len(permsResp.Permissions) == 0 {
		t.Fatalf("expected non-empty permissions")
	}

	// 2) Create role
	createBody := map[string]string{
		"tenant_id":   tenantID.String(),
		"name":        "qa-assign-" + uuid.NewString(),
		"description": "QA Assign Role",
	}
	cb, _ := json.Marshal(createBody)
	creq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles", bytes.NewReader(cb))
	creq.Header.Set("Content-Type", "application/json")
	creq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	crec := httptest.NewRecorder()
	e.ServeHTTP(crec, creq)
	if crec.Code != http.StatusCreated {
		t.Fatalf("create role: expected 201, got %d: %s", crec.Code, crec.Body.String())
	}
	var roleItem struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(bytes.NewReader(crec.Body.Bytes())).Decode(&roleItem); err != nil {
		t.Fatalf("decode role: %v", err)
	}
	roleID := roleItem.ID

	// 3) List roles should include created role
	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/roles?tenant_id="+tenantID.String(), nil)
	lreq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	lrec := httptest.NewRecorder()
	e.ServeHTTP(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("list roles: expected 200, got %d: %s", lrec.Code, lrec.Body.String())
	}

	// 4) Update role
	updBody := map[string]string{
		"tenant_id":   tenantID.String(),
		"name":        "qa-assign-upd",
		"description": "updated",
	}
	ub, _ := json.Marshal(updBody)
	ureq := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/rbac/roles/"+roleID.String(), bytes.NewReader(ub))
	ureq.Header.Set("Content-Type", "application/json")
	ureq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	urec := httptest.NewRecorder()
	e.ServeHTTP(urec, ureq)
	if urec.Code != http.StatusOK {
		t.Fatalf("update role: expected 200, got %d: %s", urec.Code, urec.Body.String())
	}

	// 5) Upsert role-permission (users:read, tenant scope)
	permBody := map[string]string{
		"permission_key": "users:read",
		"scope_type":     "tenant",
	}
	pb, _ := json.Marshal(permBody)
	preq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"/permissions", bytes.NewReader(pb))
	preq.Header.Set("Content-Type", "application/json")
	preq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	prec := httptest.NewRecorder()
	e.ServeHTTP(prec, preq)
	if prec.Code != http.StatusNoContent {
		t.Fatalf("upsert role permission: expected 204, got %d: %s", prec.Code, prec.Body.String())
	}

	// 6) Assign role to target user
	assignBody := map[string]string{
		"tenant_id": tenantID.String(),
		"role_id":   roleID.String(),
	}
	ab, _ := json.Marshal(assignBody)
	aReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/rbac/users/"+aiTarget.UserID.String()+"/roles", bytes.NewReader(ab))
	aReq.Header.Set("Content-Type", "application/json")
	aReq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	aRec := httptest.NewRecorder()
	e.ServeHTTP(aRec, aReq)
	if aRec.Code != http.StatusNoContent {
		t.Fatalf("assign role: expected 204, got %d: %s", aRec.Code, aRec.Body.String())
	}

	// 7) Resolve user permissions should include users:read
	rreq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+aiTarget.UserID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
	rreq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	rrec := httptest.NewRecorder()
	e.ServeHTTP(rrec, rreq)
	if rrec.Code != http.StatusOK {
		t.Fatalf("resolve perms: expected 200, got %d: %s", rrec.Code, rrec.Body.String())
	}
	var rresp struct {
		Grants []struct {
			Key string `json:"key"`
		} `json:"grants"`
	}
	if err := json.NewDecoder(bytes.NewReader(rrec.Body.Bytes())).Decode(&rresp); err != nil {
		t.Fatalf("decode resolve: %v", err)
	}
	found := false
	for _, g := range rresp.Grants {
		if g.Key == "users:read" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected users:read in resolved grants: %+v", rresp.Grants)
	}

	// 8) Remove role permission and re-check resolution
	db, _ := json.Marshal(permBody)
	dreq := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"/permissions", bytes.NewReader(db))
	dreq.Header.Set("Content-Type", "application/json")
	dreq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	drec := httptest.NewRecorder()
	e.ServeHTTP(drec, dreq)
	if drec.Code != http.StatusNoContent {
		t.Fatalf("delete role permission: expected 204, got %d: %s", drec.Code, drec.Body.String())
	}

	rreq2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/rbac/users/"+aiTarget.UserID.String()+"/permissions/resolve?tenant_id="+tenantID.String(), nil)
	rreq2.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	rrec2 := httptest.NewRecorder()
	e.ServeHTTP(rrec2, rreq2)
	if rrec2.Code != http.StatusOK {
		t.Fatalf("resolve after delete: expected 200, got %d: %s", rrec2.Code, rrec2.Body.String())
	}
	var rresp2 struct {
		Grants []struct {
			Key string `json:"key"`
		} `json:"grants"`
	}
	if err := json.NewDecoder(bytes.NewReader(rrec2.Body.Bytes())).Decode(&rresp2); err != nil {
		t.Fatalf("decode resolve2: %v", err)
	}
	for _, g := range rresp2.Grants {
		if g.Key == "users:read" {
			t.Fatalf("unexpected users:read after delete")
		}
	}

	// 9) Delete role
	dreq2 := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/admin/rbac/roles/"+roleID.String()+"?tenant_id="+tenantID.String(), nil)
	dreq2.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	drec2 := httptest.NewRecorder()
	e.ServeHTTP(drec2, dreq2)
	if drec2.Code != http.StatusNoContent {
		t.Fatalf("delete role: expected 204, got %d: %s", drec2.Code, drec2.Body.String())
	}
}
