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

func TestHTTP_Admin_UpdateRoles(t *testing.T) {
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
	name := "http-admin-roles-itest-" + tenantID.String()
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

	adminEmail := "admin.roles.itest@ex.com"
	password := "Password!123"
	targetEmail := "target.roles.itest@ex.com"

	// Create admin user (signup) and get tokens
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     adminEmail,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
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
	tsreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(tsb))
	tsreq.Header.Set("Content-Type", "application/json")
	tsrec := httptest.NewRecorder()
	e.ServeHTTP(tsrec, tsreq)
	if tsrec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", tsrec.Code, tsrec.Body.String())
	}
	aiTarget, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, targetEmail)
	if err != nil {
		t.Fatalf("lookup target identity: %v", err)
	}

	// 401: missing token
	b, _ := json.Marshal(map[string]any{"roles": []string{"member"}})
	req401 := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/users/"+aiTarget.UserID.String()+"/roles", bytes.NewReader(b))
	rec401 := httptest.NewRecorder()
	e.ServeHTTP(rec401, req401)
	if rec401.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec401.Code, rec401.Body.String())
	}

	// 403: non-admin token (use target user's token from signup)
	var ttoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(tsrec.Body.Bytes())).Decode(&ttoks); err != nil {
		t.Fatalf("decode target tokens: %v", err)
	}
	req403 := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/users/"+aiTarget.UserID.String()+"/roles", bytes.NewReader(b))
	req403.Header.Set("Authorization", "Bearer "+ttoks.AccessToken)
	rec403 := httptest.NewRecorder()
	e.ServeHTTP(rec403, req403)
	if rec403.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec403.Code, rec403.Body.String())
	}

	// 400: invalid user id
	req400 := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/users/not-a-uuid/roles", bytes.NewReader(b))
	req400.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	rec400 := httptest.NewRecorder()
	e.ServeHTTP(rec400, req400)
	if rec400.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec400.Code, rec400.Body.String())
	}

	// 400: invalid JSON body
	badBody := []byte("not-json")
	reqBad := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/users/"+aiTarget.UserID.String()+"/roles", bytes.NewReader(badBody))
	reqBad.Header.Set("Content-Type", "application/json")
	reqBad.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	recBad := httptest.NewRecorder()
	e.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid json, got %d: %s", recBad.Code, recBad.Body.String())
	}

	// 400: empty roles array should fail validation
	emptyRolesBody, _ := json.Marshal(map[string]any{"roles": []string{}})
	reqEmpty := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/users/"+aiTarget.UserID.String()+"/roles", bytes.NewReader(emptyRolesBody))
	reqEmpty.Header.Set("Content-Type", "application/json")
	reqEmpty.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	recEmpty := httptest.NewRecorder()
	e.ServeHTTP(recEmpty, reqEmpty)
	if recEmpty.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 empty roles, got %d: %s", recEmpty.Code, recEmpty.Body.String())
	}

	// 204: success and verify roles updated in DB
	rolesBody, _ := json.Marshal(map[string]any{"roles": []string{"member", "editor"}})
	req204 := httptest.NewRequest(http.MethodPost, "/v1/auth/admin/users/"+aiTarget.UserID.String()+"/roles", bytes.NewReader(rolesBody))
	req204.Header.Set("Content-Type", "application/json")
	req204.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	rec204 := httptest.NewRecorder()
	e.ServeHTTP(rec204, req204)
	if rec204.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec204.Code, rec204.Body.String())
	}
	u, err := repo.GetUserByID(ctx, aiTarget.UserID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if len(u.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %v", u.Roles)
	}
	if u.Roles[0] != "member" || u.Roles[1] != "editor" {
		t.Fatalf("roles mismatch: %v", u.Roles)
	}

	// Verify roles reflected via /v1/auth/me using target user's token
	meReq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+ttoks.AccessToken)
	meRec := httptest.NewRecorder()
	e.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /me, got %d: %s", meRec.Code, meRec.Body.String())
	}
	var meResp struct {
		Roles []string `json:"roles"`
	}
	if err := json.NewDecoder(bytes.NewReader(meRec.Body.Bytes())).Decode(&meResp); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	if len(meResp.Roles) != 2 || meResp.Roles[0] != "member" || meResp.Roles[1] != "editor" {
		t.Fatalf("/me roles mismatch: %v", meResp.Roles)
	}
}
