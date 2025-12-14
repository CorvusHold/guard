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

func TestHTTP_Admin_Users_List_Update_BlockUnblock(t *testing.T) {
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
	name := "http-admin-users-itest-" + tenantID.String()
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

	adminEmail := "admin.users.itest@ex.com"
	userEmail := "user.users.itest@ex.com"
	password := "Password!123"

	// Signup admin
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
	var adminToks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&adminToks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if adminToks.AccessToken == "" {
		t.Fatalf("expected access token for admin")
	}

	// Grant admin role
	aiAdmin, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, adminEmail)
	if err != nil {
		t.Fatalf("lookup admin identity: %v", err)
	}
	if err := auth.UpdateUserRoles(ctx, aiAdmin.UserID, []string{"admin"}); err != nil {
		t.Fatalf("grant admin: %v", err)
	}

	// Signup normal user
	uBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     userEmail,
		"password":  password,
	}
	ub, _ := json.Marshal(uBody)
	ureq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password/signup", bytes.NewReader(ub))
	ureq.Header.Set("Content-Type", "application/json")
	ureq.Header.Set("X-Auth-Mode", "bearer")
	urec := httptest.NewRecorder()
	e.ServeHTTP(urec, ureq)
	if urec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", urec.Code, urec.Body.String())
	}
	var userToks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(urec.Body.Bytes())).Decode(&userToks); err != nil {
		t.Fatalf("decode user tokens: %v", err)
	}
	aiUser, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, userEmail)
	if err != nil {
		t.Fatalf("lookup user identity: %v", err)
	}

	// --- adminListUsers ---
	// 401 missing token
	req401 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users?tenant_id="+tenantID.String(), nil)
	rec401 := httptest.NewRecorder()
	e.ServeHTTP(rec401, req401)
	if rec401.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec401.Code, rec401.Body.String())
	}

	// 403 non-admin token
	req403 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users?tenant_id="+tenantID.String(), nil)
	req403.Header.Set("Authorization", "Bearer "+userToks.AccessToken)
	rec403 := httptest.NewRecorder()
	e.ServeHTTP(rec403, req403)
	if rec403.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec403.Code, rec403.Body.String())
	}

	// 400 missing tenant_id
	req400 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users", nil)
	req400.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	rec400 := httptest.NewRecorder()
	e.ServeHTTP(rec400, req400)
	if rec400.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec400.Code, rec400.Body.String())
	}

	// 200 success
	req200 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/admin/users?tenant_id="+tenantID.String(), nil)
	req200.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	rec200 := httptest.NewRecorder()
	e.ServeHTTP(rec200, req200)
	if rec200.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec200.Code, rec200.Body.String())
	}
	var list adminUsersResp
	if err := json.NewDecoder(bytes.NewReader(rec200.Body.Bytes())).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Users) < 2 {
		t.Fatalf("expected at least 2 users, got %d", len(list.Users))
	}

	// --- adminUpdateNames ---
	// 401
	nb := []byte(`{"first_name":"Alice","last_name":"User"}`)
	reqUN401 := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/users/"+aiUser.UserID.String(), bytes.NewReader(nb))
	reqUN401.Header.Set("Content-Type", "application/json")
	recUN401 := httptest.NewRecorder()
	e.ServeHTTP(recUN401, reqUN401)
	if recUN401.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recUN401.Code, recUN401.Body.String())
	}

	// 403
	reqUN403 := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/users/"+aiUser.UserID.String(), bytes.NewReader(nb))
	reqUN403.Header.Set("Content-Type", "application/json")
	reqUN403.Header.Set("Authorization", "Bearer "+userToks.AccessToken)
	recUN403 := httptest.NewRecorder()
	e.ServeHTTP(recUN403, reqUN403)
	if recUN403.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", recUN403.Code, recUN403.Body.String())
	}

	// 400 invalid user id
	reqUN400 := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/users/not-a-uuid", bytes.NewReader(nb))
	reqUN400.Header.Set("Content-Type", "application/json")
	reqUN400.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	recUN400 := httptest.NewRecorder()
	e.ServeHTTP(recUN400, reqUN400)
	if recUN400.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recUN400.Code, recUN400.Body.String())
	}

	// 400 invalid JSON
	badBody := []byte("not-json")
	reqUNBad := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/users/"+aiUser.UserID.String(), bytes.NewReader(badBody))
	reqUNBad.Header.Set("Content-Type", "application/json")
	reqUNBad.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	recUNBad := httptest.NewRecorder()
	e.ServeHTTP(recUNBad, reqUNBad)
	if recUNBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recUNBad.Code, recUNBad.Body.String())
	}

	// 204 success
	reqUN204 := httptest.NewRequest(http.MethodPatch, "/api/v1/auth/admin/users/"+aiUser.UserID.String(), bytes.NewReader(nb))
	reqUN204.Header.Set("Content-Type", "application/json")
	reqUN204.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	recUN204 := httptest.NewRecorder()
	e.ServeHTTP(recUN204, reqUN204)
	if recUN204.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", recUN204.Code, recUN204.Body.String())
	}
	u, err := repo.GetUserByID(ctx, aiUser.UserID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.FirstName != "Alice" || u.LastName != "User" {
		t.Fatalf("names not updated: %s %s", u.FirstName, u.LastName)
	}

	// --- adminBlockUser / adminUnblockUser ---
	// block
	reqBlock := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/"+aiUser.UserID.String()+"/block", nil)
	reqBlock.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	recBlock := httptest.NewRecorder()
	e.ServeHTTP(recBlock, reqBlock)
	if recBlock.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", recBlock.Code, recBlock.Body.String())
	}
	u1, _ := repo.GetUserByID(ctx, aiUser.UserID)
	if u1.IsActive {
		t.Fatalf("expected user to be inactive after block")
	}

	// unblock
	reqUnblock := httptest.NewRequest(http.MethodPost, "/api/v1/auth/admin/users/"+aiUser.UserID.String()+"/unblock", nil)
	reqUnblock.Header.Set("Authorization", "Bearer "+adminToks.AccessToken)
	recUnblock := httptest.NewRecorder()
	e.ServeHTTP(recUnblock, reqUnblock)
	if recUnblock.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", recUnblock.Code, recUnblock.Body.String())
	}
	u2, _ := repo.GetUserByID(ctx, aiUser.UserID)
	if !u2.IsActive {
		t.Fatalf("expected user to be active after unblock")
	}
}
