package controller

import (
	"context"
	"encoding/json"
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

	amw "github.com/corvusHold/guard/internal/auth/middleware"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
)

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
	if err := tr.Create(ctx, tenantID, "settings-get-mask-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// Seed secret values; GET should mask them
	_ = sr.Upsert(ctx, sdomain.KeyWorkOSClientSecret, &tenantID, "supersecret1234", true)
	_ = sr.Upsert(ctx, sdomain.KeyWorkOSAPIKey, &tenantID, "apikey9876", true)

	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg.JWTSigningKey, userID, tenantID)
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenantID.String()+"/settings", nil)
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
	if err := tr.Create(ctx, tenantID, "settings-get-rl-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// set aggressive RL overrides for GET: limit=1 per 60s
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsGetLimit, &tenantID, "1", false)
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsGetWindow, &tenantID, "60s", false)

	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg.JWTSigningKey, userID, tenantID)
	// first GET allowed
	req1 := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenantID.String()+"/settings", nil)
	req1.Header.Set("Authorization", "Bearer "+tok)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// second GET within window should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenantID.String()+"/settings", nil)
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

func makeJWT(t *testing.T, key string, sub uuid.UUID, ten uuid.UUID) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": sub.String(),
		"ten": ten.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(key))
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
	if err := tr.Create(ctx, tenantID, "settings-auth-401-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// settings deps
	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenantID.String()+"/settings", nil)
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
	if err := tr.Create(ctx, tenantA, "settings-tenant-a-"+tenantA.String()); err != nil {
		t.Fatalf("tenant a: %v", err)
	}
	tenantB := uuid.New()
	if err := tr.Create(ctx, tenantB, "settings-tenant-b-"+tenantB.String()); err != nil {
		t.Fatalf("tenant b: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg.JWTSigningKey, userID, tenantA)
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenantB.String()+"/settings", nil)
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
	if err := tr.Create(ctx, tenantID, "settings-rbac-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))
	// role fetcher returns non-admin/owner
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
		return []string{"member"}, nil
	})

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg.JWTSigningKey, userID, tenantID)
	body := strings.NewReader(`{"sso_provider":"dev"}`)
	req := httptest.NewRequest(http.MethodPut, "/v1/tenants/"+tenantID.String()+"/settings", body)
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
	if err := tr.Create(ctx, tenantID, "settings-validate-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))
	// admin role
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) { return []string{"admin"}, nil })

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg.JWTSigningKey, userID, tenantID)
	cases := []struct{ name, payload, wantErr string }{
		{"invalid_provider", `{"sso_provider":"foo"}`, "invalid sso_provider"},
		{"invalid_ttl", `{"sso_state_ttl":"notdur"}`, "invalid sso_state_ttl"},
		{"invalid_allowlist", `{"sso_redirect_allowlist":"notaurl"}`, "invalid sso_redirect_allowlist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(tc.payload))
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
	if err := tr.Create(ctx, tenantID, "settings-audit-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) { return []string{"owner"}, nil })
	var events []evdomain.Event
	c.WithPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg.JWTSigningKey, userID, tenantID)
	payload := `{
		"sso_provider":"workos",
		"workos_client_id":"cid",
		"workos_client_secret":"csec",
		"workos_api_key":"akey",
		"sso_state_ttl":"10m",
		"sso_redirect_allowlist":"https://allowed.example/"
	}`
	req := httptest.NewRequest(http.MethodPut, "/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(payload))
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
	if err := tr.Create(ctx, tenantID, "settings-rl-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// set aggressive RL overrides for this tenant: limit=1 per 60s
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsPutLimit, &tenantID, "1", false)
	_ = sr.Upsert(ctx, sdomain.KeyRLSettingsPutWindow, &tenantID, "60s", false)

	s := ssvc.New(sr)
	c := New(sr, s)
	cfg, _ := config.Load()
	c.WithJWT(amw.NewJWT(cfg))
	c.WithRoleFetcher(func(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) { return []string{"admin"}, nil })

	e := echo.New()
	c.Register(e)

	userID := uuid.New()
	tok := makeJWT(t, cfg.JWTSigningKey, userID, tenantID)
	payload := `{"sso_provider":"dev"}`
	// first request allowed
	req1 := httptest.NewRequest(http.MethodPut, "/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(payload))
	req1.Header.Set("Authorization", "Bearer "+tok)
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// second request within window should be rate limited
	req2 := httptest.NewRequest(http.MethodPut, "/v1/tenants/"+tenantID.String()+"/settings", strings.NewReader(payload))
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
