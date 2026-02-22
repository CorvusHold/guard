package controller

import (
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
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	amw "github.com/corvusHold/guard/internal/auth/middleware"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
)

func loadIntegrationJWTConfig(t *testing.T) config.Config {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal ec private key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	f, err := os.CreateTemp("", "guard-settings-jwt-*.pem")
	if err != nil {
		t.Fatalf("create temp pem: %v", err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		t.Fatalf("write temp pem: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp pem: %v", err)
	}
	keyPath := f.Name()
	t.Cleanup(func() { _ = os.Remove(keyPath) })

	oldAlg, hadAlg := os.LookupEnv("JWT_SIGNING_ALGORITHM")
	oldPath, hadPath := os.LookupEnv("JWT_PRIVATE_KEY_PATH")
	if err := os.Setenv("JWT_SIGNING_ALGORITHM", "ES256"); err != nil {
		t.Fatalf("set JWT_SIGNING_ALGORITHM: %v", err)
	}
	if err := os.Setenv("JWT_PRIVATE_KEY_PATH", keyPath); err != nil {
		t.Fatalf("set JWT_PRIVATE_KEY_PATH: %v", err)
	}
	t.Cleanup(func() {
		if hadAlg {
			_ = os.Setenv("JWT_SIGNING_ALGORITHM", oldAlg)
		} else {
			_ = os.Unsetenv("JWT_SIGNING_ALGORITHM")
		}
		if hadPath {
			_ = os.Setenv("JWT_PRIVATE_KEY_PATH", oldPath)
		} else {
			_ = os.Unsetenv("JWT_PRIVATE_KEY_PATH")
		}
	})

	cfg, err := config.Load()
	require.NoError(t, err)
	return cfg
}

// publisherFunc helps implement evdomain.Publisher in tests via a func.
type publisherFunc func(ctx context.Context, e evdomain.Event) error

func (f publisherFunc) Publish(ctx context.Context, e evdomain.Event) error { return f(ctx, e) }

func TestSettings_GET_MasksSecrets(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "settings-get-mask-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// Seed secret values; GET should mask them
	_ = sr.Upsert(ctx, sdomain.KeyWorkOSClientSecret, &tenantID, "supersecret1234", true)
	_ = sr.Upsert(ctx, sdomain.KeyWorkOSAPIKey, &tenantID, "apikey9876", true)
	_ = sr.Upsert(ctx, sdomain.KeyJWTSigning, &tenantID, "jwtsecretkey9999", true)

	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg, userID, tenantID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/settings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Expect masked last 4 characters
	if got := resp["workos_client_secret"]; got != "****1234" {
		t.Fatalf("expected masked client secret ****1234, got %v", got)
	}
	if got := resp["workos_api_key"]; got != "****9876" {
		t.Fatalf("expected masked api key ****9876, got %v", got)
	}
	if _, ok := resp["jwt_signing_key"]; ok {
		t.Fatalf("expected jwt_signing_key to be omitted from GET response")
	}
}

func TestSettings_GET_RateLimit_429(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "settings-get-rl-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// set aggressive RL overrides for GET: limit=1 per 60s
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsGetLimit, &tenantID, "1", false)
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsGetWindow, &tenantID, "60s", false)

	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg, userID, tenantID)
	// first GET allowed
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/settings", nil)
	req1.Header.Set("Authorization", "Bearer "+tok)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// second GET within window should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/settings", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if h := rec2.Header().Get("Retry-After"); h == "" {
		t.Fatalf("expected Retry-After header on 429")
	}
}

func makeJWT(t *testing.T, cfg config.Config, sub uuid.UUID, ten uuid.UUID) string {
	t.Helper()
	if cfg.JWTPrivateKeyPath == "" {
		t.Fatalf("JWT_PRIVATE_KEY_PATH must be set for ES256 test token signing")
	}
	keyBytes, err := os.ReadFile(cfg.JWTPrivateKeyPath)
	if err != nil {
		t.Fatalf("read jwt private key: %v", err)
	}
	priv, err := jwt.ParseECPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatalf("parse jwt private key: %v", err)
	}
	claims := jwt.MapClaims{
		"sub": sub.String(),
		"ten": ten.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func TestSettings_GET_RequiresAuth_401(t *testing.T) {
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
	if err := tr.Create(ctx, tenantID, "settings-auth-401-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// settings deps
	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/settings", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSettings_TenantMismatch_403(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantA := uuid.New()
	if err := tr.Create(ctx, tenantA, "settings-tenant-a-"+tenantA.String(), nil); err != nil {
		t.Fatalf("tenant a: %v", err)
	}
	tenantB := uuid.New()
	if err := tr.Create(ctx, tenantB, "settings-tenant-b-"+tenantB.String(), nil); err != nil {
		t.Fatalf("tenant b: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg, userID, tenantA)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantB.String()+"/settings", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSettings_PUT_RBAC_Forbidden_403(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "settings-rbac-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))
	// role fetcher returns non-admin/owner
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
		return []string{"member"}, nil
	})

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg, userID, tenantID)
	body := strings.NewReader(`{"sso_provider":"dev"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/settings", body)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSettings_PUT_ValidationErrors_400(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "settings-validate-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))
	// admin role
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) { return []string{"admin"}, nil })

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg, userID, tenantID)
	cases := []struct{ name, payload, wantErr string }{
		{"invalid_provider", `{"sso_provider":"foo"}`, "invalid sso_provider"},
		{"invalid_ttl", `{"sso_state_ttl":"notdur"}`, "invalid sso_state_ttl"},
		{"invalid_allowlist", `{"sso_redirect_allowlist":"notaurl"}`, "invalid sso_redirect_allowlist"},
		{"invalid_jwt_signing_key", `{"jwt_signing_key":"short"}`, "invalid jwt_signing_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(tc.payload))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
			}
			var m map[string]string
			_ = json.NewDecoder(rec.Body).Decode(&m)
			if m["error"] != tc.wantErr {
				t.Fatalf("expected error %q, got %+v", tc.wantErr, m)
			}
		})
	}
}

func TestSettings_PUT_Success_AuditRedaction(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "settings-audit-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) { return []string{"owner"}, nil })
	var events []evdomain.Event
	c.WithPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg, userID, tenantID)
	payload := `{
		"sso_provider":"workos",
		"workos_client_id":"cid",
		"workos_client_secret":"csec",
		"workos_api_key":"akey",
		"sso_state_ttl":"10m",
		"sso_redirect_allowlist":"https://allowed.example/"
	}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	// assert audit redaction
	found := false
	for _, ev := range events {
		if ev.Type == "settings.update.success" && ev.TenantID == tenantID {
			if ev.Meta["sso.workos.client_secret"] == "redacted" && ev.Meta["sso.workos.api_key"] == "redacted" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected settings.update.success event with redacted secrets")
	}
}

func TestSettings_PUT_RateLimit_429(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("skipping integration test: DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	tr := trepo.New(pool)
	tenantID := uuid.New()
	if err := tr.Create(ctx, tenantID, "settings-rl-"+tenantID.String(), nil); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// set aggressive RL overrides for this tenant: limit=1 per 60s
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsPutLimit, &tenantID, "1", false)
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsPutWindow, &tenantID, "60s", false)

	s := ssvc.New(sr)
	c := New(sr, s)
	cfg := loadIntegrationJWTConfig(t)
	c.WithJWT(amw.NewJWT(cfg))
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) { return []string{"admin"}, nil })

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg, userID, tenantID)
	payload := `{"sso_provider":"dev"}`
	// first request allowed
	req1 := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(payload))
	req1.Header.Set("Authorization", "Bearer "+tok)
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// second request within window should be rate limited
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(payload))
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", rec2.Code, rec2.Body.String())
	}
	if h := rec2.Header().Get("Retry-After"); h == "" {
		t.Fatalf("expected Retry-After header on 429")
	}
}
