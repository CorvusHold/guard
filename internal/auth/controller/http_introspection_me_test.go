//go:build integration
// +build integration

package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	domain "github.com/corvusHold/guard/internal/auth/domain"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	svc "github.com/corvusHold/guard/internal/auth/service"
	"github.com/corvusHold/guard/internal/config"
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

func loadIntegrationES256Config(t *testing.T) config.Config {
	t.Helper()

	keyPath := writeTestECKeyPEM(t)

	t.Setenv("JWT_SIGNING_ALGORITHM", "ES256")
	t.Setenv("JWT_PRIVATE_KEY_PATH", keyPath)

	cfg, err := config.Load()
	require.NoError(t, err)
	return cfg
}

func writeTestECKeyPEM(t *testing.T) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	keyFile, err := os.CreateTemp("", "guard-introspect-jwt-*.pem")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(keyFile.Name()) })
	_, err = keyFile.Write(pemBytes)
	require.NoError(t, err)
	require.NoError(t, keyFile.Close())

	return keyFile.Name()
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
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// services
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg := loadIntegrationES256Config(t)
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
	if stoks.AccessToken == "" || stoks.RefreshToken == "" {
		t.Fatalf("expected tokens")
	}

	// introspect using Authorization header
	ireq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/introspect", nil)
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
	mreq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/revoke", bytes.NewReader(rb))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	// now attempt refresh with revoked token
	rf, _ := json.Marshal(map[string]string{"refresh_token": stoks.RefreshToken})
	rreq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(rf))
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
	if err := tr.Create(ctx, tenantID, name, nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// Services for issuing tokens (honor tenant-specific settings)
	repo := authrepo.New(pool)
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	cfg := loadIntegrationES256Config(t)
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso)
	c.Register(e)

	email := "user.tenant.key.itest@example.com"
	password := "Password!123"

	// Signup and issue tokens from the first server
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
	var stoks tokensResponse
	if err := json.NewDecoder(bytes.NewReader(srec.Body.Bytes())).Decode(&stoks); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if stoks.AccessToken == "" || stoks.RefreshToken == "" {
		t.Fatalf("expected tokens")
	}

	// Introspect token on the first server (should succeed with tenant-specific signing key)
	ireq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/introspect", nil)
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
	mreq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
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
	cfgGlobalOnly.JWTSigningAlgorithm = "ES256"
	cfgGlobalOnly.JWTPrivateKeyPath = writeTestECKeyPEM(t)
	cfgGlobalOnly.JWTSigningKey = ""
	auth2 := svc.New(repo, cfgGlobalOnly, staticSettings)
	magic2 := svc.NewMagic(repo, cfgGlobalOnly, staticSettings, &fakeEmail{})
	sso2 := svc.NewSSO(repo, cfgGlobalOnly, staticSettings)

	e2 := echo.New()
	e2.Validator = noopValidator{}
	c2 := New(auth2, magic2, sso2)
	c2.Register(e2)

	// Against the second server, the same access token (signed with tenant-specific key) should fail introspection
	ireq2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/introspect", nil)
	ireq2.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	irec2 := httptest.NewRecorder()
	e2.ServeHTTP(irec2, ireq2)
	if irec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected introspect to fail on global-key-only instance; got %d: %s", irec2.Code, irec2.Body.String())
	}

	// /me should also fail on the second server with the mismatched signing key
	mreq2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	mreq2.Header.Set("Authorization", "Bearer "+stoks.AccessToken)
	mrec2 := httptest.NewRecorder()
	e2.ServeHTTP(mrec2, mreq2)
	if mrec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected /me to fail on global-key-only instance; got %d: %s", mrec2.Code, mrec2.Body.String())
	}
}
