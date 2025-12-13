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

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	amw "github.com/corvusHold/guard/internal/auth/middleware"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
	settingsctrl "github.com/corvusHold/guard/internal/settings/controller"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
)

type staticSettingsService struct{}

// staticSettingsService implements settings.Service but always returns the provided default values,
// effectively ignoring any tenant-specific overrides.
func (staticSettingsService) GetString(_ context.Context, _ string, _ *uuid.UUID, def string) (string, error) {
	return def, nil
}

func (staticSettingsService) GetDuration(_ context.Context, _ string, _ *uuid.UUID, def time.Duration) (time.Duration, error) {
	return def, nil
}

func (staticSettingsService) GetInt(_ context.Context, _ string, _ *uuid.UUID, def int) (int, error) {
	return def, nil
}

func TestHTTP_Introspect_Me_Revoke(t *testing.T) {
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
	name := "http-introspect-me-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// services
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

	email := "user.me.itest@example.com"
	password := "Password!123"

	// signup
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
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
	if stoks.AccessToken == "" || stoks.RefreshToken == "" {
		t.Fatalf("expected tokens")
	}

	// introspect using Authorization header
	ireq := httptest.NewRequest(http.MethodPost, "/v1/auth/introspect", nil)
	ireq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	irec := httptest.NewRecorder()
	e.ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", irec.Code, irec.Body.String())
	}
	var iout domain.Introspection
	if err := json.NewDecoder(bytes.NewReader(irec.Body.Bytes())).Decode(&iout); err != nil {
		t.Fatalf("decode introspect: %v", err)
	}
	if !iout.Active {
		t.Fatalf("expected active=true in introspection")
	}

	// me endpoint
	mreq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	mreq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	mrec := httptest.NewRecorder()
	e.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", mrec.Code, mrec.Body.String())
	}
	var profile domain.UserProfile
	if err := json.NewDecoder(bytes.NewReader(mrec.Body.Bytes())).Decode(&profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if profile.Email != email {
		t.Fatalf("email mismatch: %v", profile.Email)
	}

	// revoke refresh token and ensure refresh fails
	rb, _ := json.Marshal(map[string]string{"token": stoks.RefreshToken, "token_type": "refresh"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/revoke", bytes.NewReader(rb))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// now attempt refresh with revoked token
	rf, _ := json.Marshal(map[string]string{"refresh_token": stoks.RefreshToken})
	rreq := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(rf))
	rreq.Header.Set("Content-Type", "application/json")
	rreq.Header.Set("X-Auth-Mode", "bearer")
	rrec := httptest.NewRecorder()
	e.ServeHTTP(rrec, rreq)
	if rrec.Code == http.StatusOK {
		t.Fatalf("expected refresh to fail after revoke; got 200: %s", rrec.Body.String())
	}
}

func TestHTTP_Introspect_TenantSpecificSigningKey(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	// Create tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-introspect-tenant-key-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// Services for issuing tokens (honor tenant-specific settings)
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

	// Wire settings controller so we can set tenant-specific signing key via HTTP API
	sc := settingsctrl.New(sr, settings)
	sc.WithJWT(amw.NewJWT(cfg))
	adminUserID := uuid.New()
	sc.WithRoleFetcher(func(ctx context.Context, userID, tID uuid.UUID) ([]string, error) {
		if userID == adminUserID && tID == tenantID {
			return []string{"admin"}, nil
		}
		return nil, nil
	})
	sc.Register(e)

	// Set tenant-specific JWT signing key (different from default) via settings HTTP API
	tenantSigningKey := "tenant-specific-secret-key-for-testing-123456"
	claims := jwt.MapClaims{
		"sub": adminUserID.String(),
		"ten": tenantID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(cfg.JWTSigningKey))
	if err != nil {
		t.Fatalf("sign settings jwt: %v", err)
	}
	setBody := map[string]string{"jwt_signing_key": tenantSigningKey}
	setPayload, _ := json.Marshal(setBody)
	setReq := httptest.NewRequest(http.MethodPut, "/v1/tenants/"+tenantID.String()+"/settings", bytes.NewReader(setPayload))
	setReq.Header.Set("Authorization", "Bearer "+signed)
	setReq.Header.Set("Content-Type", "application/json")
	setRec := httptest.NewRecorder()
	e.ServeHTTP(setRec, setReq)
	if setRec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from settings PUT, got %d: %s", setRec.Code, setRec.Body.String())
	}

	email := "user.tenant.key.itest@example.com"
	password := "Password!123"

	// Signup with tenant that has custom signing key using the first server
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
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
	if stoks.AccessToken == "" || stoks.RefreshToken == "" {
		t.Fatalf("expected tokens")
	}

	// Introspect token on the first server (should succeed with tenant-specific signing key)
	ireq := httptest.NewRequest(http.MethodPost, "/v1/auth/introspect", nil)
	ireq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	irec := httptest.NewRecorder()
	e.ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("introspect failed with tenant-specific key: expected 200, got %d: %s", irec.Code, irec.Body.String())
	}
	var iout domain.Introspection
	if err := json.NewDecoder(bytes.NewReader(irec.Body.Bytes())).Decode(&iout); err != nil {
		t.Fatalf("decode introspect: %v", err)
	}
	if !iout.Active {
		t.Fatalf("expected active=true in introspection with tenant-specific key")
	}
	if iout.Email != email {
		t.Fatalf("email mismatch: expected %s, got %s", email, iout.Email)
	}
	if iout.TenantID != tenantID {
		t.Fatalf("tenant mismatch: expected %s, got %s", tenantID, iout.TenantID)
	}

	// Also verify /me endpoint works with tenant-specific signing key on the first server
	mreq := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	mreq.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	mrec := httptest.NewRecorder()
	e.ServeHTTP(mrec, mreq)
	if mrec.Code != http.StatusOK {
		t.Fatalf("/me failed with tenant-specific key: expected 200, got %d: %s", mrec.Code, mrec.Body.String())
	}
	var profile domain.UserProfile
	if err := json.NewDecoder(bytes.NewReader(mrec.Body.Bytes())).Decode(&profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if profile.Email != email {
		t.Fatalf("email mismatch in /me: %v", profile.Email)
	}

	// Now construct a second auth service/controller that only uses the global signing key
	staticSettings := staticSettingsService{}
	cfgGlobalOnly := cfg
	cfgGlobalOnly.JWTSigningKey = "global-signing-key-only-instance"
	auth2 := svc.New(repo, cfgGlobalOnly, staticSettings)
	magic2 := svc.NewMagic(repo, cfgGlobalOnly, staticSettings, &fakeEmail{})
	sso2 := svc.NewSSO(repo, cfgGlobalOnly, staticSettings)

	e2 := echo.New()
	e2.Validator = noopValidator{}
	c2 := New(auth2, magic2, sso2)
	c2.Register(e2)

	// Against the second server, the same access token (signed with tenant-specific key) should fail introspection
	ireq2 := httptest.NewRequest(http.MethodPost, "/v1/auth/introspect", nil)
	ireq2.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	irec2 := httptest.NewRecorder()
	e2.ServeHTTP(irec2, ireq2)
	if irec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected introspect to fail on global-key-only instance; got %d: %s", irec2.Code, irec2.Body.String())
	}

	// /me should also fail on the second server with the mismatched signing key
	mreq2 := httptest.NewRequest(http.MethodGet, "/v1/auth/me", nil)
	mreq2.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	mrec2 := httptest.NewRecorder()
	e2.ServeHTTP(mrec2, mreq2)
	if mrec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected /me to fail on global-key-only instance; got %d: %s", mrec2.Code, mrec2.Body.String())
	}
}
