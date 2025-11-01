package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	svc "github.com/corvusHold/guard/internal/auth/service"
	authrepo "github.com/corvusHold/guard/internal/auth/repository"
	"github.com/corvusHold/guard/internal/config"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jarcoal/httpmock"
	"github.com/labstack/echo/v4"
)

type noopValidatorWorkOS struct{}

func TestHTTP_SSO_WorkOS_StateReplay_401(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-replay-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 3)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
        events = append(events, e)
        return nil
    }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start to get valid state
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")
    if state == "" { t.Fatalf("expected state from start") }

    // Mock WorkOS success once
    httpmock.Activate()
    httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
        func(r *http.Request) (*http.Response, error) {
            resp := httpmock.NewStringResponse(200, `{
                "access_token": "tok_workos_test",
                "profile": { "id": "prof_123", "email": "replay@example.com", "first_name": "A", "last_name": "B" }
            }`)
            return resp, nil
        },
    )

    // First callback succeeds
    cbQS := url.Values{}
    cbQS.Set("code", "code1")
    cbQS.Set("state", state)
    req1 := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?"+cbQS.Encode(), nil)
    rec1 := httptest.NewRecorder()
    e.ServeHTTP(rec1, req1)
    if rec1.Code != http.StatusOK { t.Fatalf("expected 200, got %d: %s", rec1.Code, rec1.Body.String()) }

    httpmock.DeactivateAndReset()

    // Second callback with same state must fail (state consumed)
    req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?"+cbQS.Encode(), nil)
    rec2 := httptest.NewRecorder()
    e.ServeHTTP(rec2, req2)
    if rec2.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec2.Code, rec2.Body.String())
    }
    // assert failure audit for invalid_state on replay
    seen := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "invalid_state" {
            seen = true
        }
    }
    if !seen { t.Fatalf("expected auth.sso.login.failure invalid_state on replay") }
}

func TestHTTP_SSO_WorkOS_StateExpiry_401(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-expiry-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)
    // state TTL to 1s
    _ = sr.Upsert(ctx, "sso.state_ttl", &tenantID, "1s", false)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    events := make([]evdomain.Event, 0, 2)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start to get state
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")
    if state == "" { t.Fatalf("expected state from start") }

    // Wait for TTL to expire
    time.Sleep(2 * time.Second)

    // Callback should now fail with invalid/expired state
    cbQS := url.Values{}
    cbQS.Set("code", "code-any")
    cbQS.Set("state", state)
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?"+cbQS.Encode(), nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert invalid_state due to expiry
    ok := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "invalid_state" { ok = true }
    }
    if !ok { t.Fatalf("expected auth.sso.login.failure invalid_state after expiry") }
}

func TestHTTP_SSO_WorkOS_Callback_MissingState(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    // tenant + settings
    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-missingstate-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Missing state entirely
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?code=abc", nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert missing_state failure audit
    found := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "missing_state" { found = true }
    }
    if !found { t.Fatalf("expected auth.sso.login.failure missing_state") }
}

func TestHTTP_SSO_WorkOS_Callback_MissingCode_WithValidState(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-missingcode-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Call start to create a valid state in Redis
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")
    if state == "" { t.Fatalf("expected state from start") }

    // Callback without code but with valid state
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?state="+state, nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert code_required failure audit
    found := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "code_required" { found = true }
    }
    if !found { t.Fatalf("expected auth.sso.login.failure code_required") }
}

func TestHTTP_SSO_WorkOS_Callback_TokenExchangeFailure(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-tokenfail-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start to get state
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")

    // Mock token exchange failure
    httpmock.Activate()
    defer httpmock.DeactivateAndReset()
    httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
        func(r *http.Request) (*http.Response, error) {
            resp := httpmock.NewStringResponse(400, `{"error":"invalid_grant"}`)
            return resp, nil
        },
    )

    // Callback expecting failure
    cbQS := url.Values{}
    cbQS.Set("code", "bad_code")
    cbQS.Set("state", state)
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?"+cbQS.Encode(), nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert token_exchange_failed audit
    ok := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "token_exchange_failed" { ok = true }
    }
    if !ok { t.Fatalf("expected auth.sso.login.failure token_exchange_failed") }
}
func (noopValidatorWorkOS) Validate(i interface{}) error { return nil }

type tokensResponseWorkOS struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func TestHTTP_SSO_WorkOS_StartAndCallback(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
		t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil { t.Fatalf("db connect: %v", err) }
	defer pool.Close()

	// tenant
	tr := trepo.New(pool)
	tenantID := uuid.New()
	name := "http-sso-workos-itest-" + tenantID.String()
	if err := tr.Create(ctx, tenantID, name); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	// settings
	sr := srepo.New(pool)
	settings := ssvc.New(sr)
	// set per-tenant for Start
	if err := sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false); err != nil {
		t.Fatalf("upsert tenant sso.provider: %v", err)
	}
	if err := sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client_test_123", true); err != nil {
		t.Fatalf("upsert client_id: %v", err)
	}
	if err := sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret_test_456", true); err != nil {
		t.Fatalf("upsert client_secret: %v", err)
	}

	// services and echo
	repo := authrepo.New(pool)
	cfg, _ := config.Load()
	magic := svc.NewMagic(repo, cfg, settings, nil)
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)

	// capture audit events
	events := make([]evdomain.Event, 0, 1)
	sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
		events = append(events, e)
		return nil
	}))

	e := echo.New()
	e.Validator = noopValidatorWorkOS{}
	c := New(auth, magic, sso)
	c.Register(e)

	// Start: expect redirect to WorkOS authorize
	qs := url.Values{}
	qs.Set("tenant_id", tenantID.String())
	qs.Set("connection_id", "conn_123")
	qs.Set("organization_id", "org_456")
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" { t.Fatalf("expected redirect Location") }
	authURL, err := url.Parse(loc)
	if err != nil { t.Fatalf("parse location: %v", err) }
	if authURL.Scheme != "https" || authURL.Host != "api.workos.com" || authURL.Path != "/sso/authorize" {
		t.Fatalf("unexpected authorize URL: %s", loc)
	}
	q := authURL.Query()
	if q.Get("response_type") != "code" { t.Fatalf("missing/invalid response_type: %s", q.Get("response_type")) }
	if q.Get("client_id") == "" { t.Fatalf("missing client_id") }
	if q.Get("redirect_uri") == "" { t.Fatalf("missing redirect_uri") }
	if q.Get("state") == "" { t.Fatalf("missing state") }
	if q.Get("connection") != "conn_123" { t.Fatalf("expected connection=conn_123, got %s", q.Get("connection")) }
	if q.Get("organization") != "org_456" { t.Fatalf("expected organization=org_456, got %s", q.Get("organization")) }

	state := q.Get("state")

	// Mock WorkOS token exchange
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
		func(r *http.Request) (*http.Response, error) {
			// Assert form payload contains expected redirect_uri
			b, _ := io.ReadAll(r.Body)
			_ = r.Body.Close()
			formVals, _ := url.ParseQuery(string(b))
			expectedRedirect := cfg.PublicBaseURL + "/v1/auth/sso/google/callback"
			if formVals.Get("redirect_uri") != expectedRedirect {
				return httpmock.NewStringResponse(400, `{"error":"bad_redirect_uri"}`), nil
			}
			resp := httpmock.NewStringResponse(200, `{
				"access_token": "tok_workos_test",
				"profile": {
					"id": "prof_123",
					"email": "user.workos.itest@example.com",
					"first_name": "Work",
					"last_name": "OS"
				}
			}`)
			return resp, nil
		},
	)

	// Callback with code + state
	cbQS := url.Values{}
	cbQS.Set("code", "code_test_abc")
	cbQS.Set("state", state)
	req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?"+cbQS.Encode(), nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var trsp tokensResponseWorkOS
	if err := json.NewDecoder(rec2.Body).Decode(&trsp); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if trsp.AccessToken == "" || trsp.RefreshToken == "" {
		t.Fatalf("expected non-empty tokens: %+v", trsp)
	}

	// Assert refresh token persisted (hash matches)
	h := sha256.Sum256([]byte(trsp.RefreshToken))
	hashB64 := base64.RawURLEncoding.EncodeToString(h[:])
	if _, err := repo.GetRefreshTokenByHash(ctx, hashB64); err != nil {
		t.Fatalf("refresh token not persisted: %v", err)
	}

	// Assert identity exists for tenant/email
	ai, err := repo.GetAuthIdentityByEmailTenant(ctx, tenantID, "user.workos.itest@example.com")
	if err != nil {
		t.Fatalf("identity not created: %v", err)
	}

	// Assert JWT claims: sub, ten, exp around configured TTL
	parts := strings.Split(trsp.AccessToken, ".")
	if len(parts) < 2 { t.Fatalf("invalid jwt format") }
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil { t.Fatalf("decode jwt payload: %v", err) }
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil { t.Fatalf("unmarshal claims: %v", err) }
	if claims["sub"] != ai.UserID.String() { t.Fatalf("sub mismatch: %v", claims["sub"]) }
	if claims["ten"] != tenantID.String() { t.Fatalf("ten mismatch: %v", claims["ten"]) }
	// exp within tolerance of now + accessTTL
	accessTTL, _ := settings.GetDuration(ctx, sdomain.KeyAccessTTL, &tenantID, time.Minute*15)
	now := time.Now().Unix()
	expF, ok := claims["exp"].(float64)
	if !ok { t.Fatalf("exp claim not number: %T", claims["exp"]) }
	exp := int64(expF)
	min := now + int64(accessTTL/time.Second) - 30 // 30s tolerance
	max := now + int64(accessTTL/time.Second) + 30
	if exp < min || exp > max {
		t.Fatalf("exp out of expected window: got %d not in [%d,%d]", exp, min, max)
	}
    // iss/aud should match PUBLIC_BASE_URL
    if iss, _ := claims["iss"].(string); iss != cfg.PublicBaseURL {
        t.Fatalf("iss mismatch: expected %s, got %v", cfg.PublicBaseURL, claims["iss"]) }
    if aud, _ := claims["aud"].(string); aud != cfg.PublicBaseURL {
        t.Fatalf("aud mismatch: expected %s, got %v", cfg.PublicBaseURL, claims["aud"]) }

    // audit event published
    if len(events) == 0 { t.Fatalf("expected an audit event") }
    found := false
    for _, e := range events {
        if e.Type == "auth.sso.login.success" && e.TenantID == tenantID && e.UserID == ai.UserID {
            if e.Meta["provider"] != "google" { t.Fatalf("provider mismatch: %v", e.Meta["provider"]) }
            if e.Meta["email"] != "user.workos.itest@example.com" { t.Fatalf("email mismatch: %v", e.Meta["email"]) }
            found = true
        }
    }
    if !found { t.Fatalf("expected auth.sso.login.success event for user") }
}

// Additional failure-shape tests for WorkOS token exchange
func TestHTTP_SSO_WorkOS_TokenExchange_Unauthorized_401(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-401-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start to get state
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")

    httpmock.Activate()
    defer httpmock.DeactivateAndReset()
    httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
        func(r *http.Request) (*http.Response, error) {
            return httpmock.NewStringResponse(401, `{"error":"unauthorized"}`), nil
        },
    )

    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?code=x&state="+state, nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert token_exchange_failed audit
    ok := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "token_exchange_failed" { ok = true }
    }
    if !ok { t.Fatalf("expected auth.sso.login.failure token_exchange_failed") }
}

func TestHTTP_SSO_WorkOS_TokenExchange_ServerError_401(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-500-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start to get state
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")

    httpmock.Activate()
    defer httpmock.DeactivateAndReset()
    httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
        func(r *http.Request) (*http.Response, error) {
            return httpmock.NewStringResponse(500, `{"error":"server_error"}`), nil
        },
    )

    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?code=x&state="+state, nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert token_exchange_failed audit
    ok := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "token_exchange_failed" { ok = true }
    }
    if !ok { t.Fatalf("expected auth.sso.login.failure token_exchange_failed") }
}

func TestHTTP_SSO_WorkOS_TokenExchange_TransportError_401(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-tperr-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start to get state
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")

    httpmock.Activate()
    defer httpmock.DeactivateAndReset()
    httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
        func(r *http.Request) (*http.Response, error) {
            return nil, fmt.Errorf("dial timeout")
        },
    )

    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?code=x&state="+state, nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert token_exchange_transport_error audit
    ok := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "token_exchange_transport_error" { ok = true }
    }
    if !ok { t.Fatalf("expected auth.sso.login.failure token_exchange_transport_error") }
}

func TestHTTP_SSO_WorkOS_Callback_InvalidState_401(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-badstate-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error { events = append(events, e); return nil }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Random state (not present in Redis)
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?code=x&state="+strings.Repeat("a", 16), nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert invalid_state failure audit
    seen := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "invalid_state" { seen = true }
    }
    if !seen { t.Fatalf("expected auth.sso.login.failure invalid_state") }
}

func TestHTTP_SSO_WorkOS_ProfileMissingEmail_401(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-noemail-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    // capture audit events
    events := make([]evdomain.Event, 0, 1)
    sso := svc.NewSSO(repo, cfg, settings)
    sso.SetPublisher(publisherFunc(func(ctx context.Context, e evdomain.Event) error {
        events = append(events, e)
        return nil
    }))
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start to get state
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    reqStart := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    recStart := httptest.NewRecorder()
    e.ServeHTTP(recStart, reqStart)
    if recStart.Code != http.StatusFound { t.Fatalf("start not 302: %d", recStart.Code) }
    loc := recStart.Header().Get("Location")
    u, _ := url.Parse(loc)
    state := u.Query().Get("state")

    // Mock WorkOS token exchange with empty email
    httpmock.Activate()
    defer httpmock.DeactivateAndReset()
    httpmock.RegisterResponder("POST", "https://api.workos.com/sso/token",
        func(r *http.Request) (*http.Response, error) {
            resp := httpmock.NewStringResponse(200, `{
                "access_token": "tok_workos_test",
                "profile": { "id": "prof_123", "email": "", "first_name": "X", "last_name": "Y" }
            }`)
            return resp, nil
        },
    )

    // Callback expecting 401 due to missing email
    cbQS := url.Values{}
    cbQS.Set("code", "code_test_abc")
    cbQS.Set("state", state)
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?"+cbQS.Encode(), nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
    // assert profile_missing_email audit
    ok := false
    for _, ev := range events {
        if ev.Type == "auth.sso.login.failure" && ev.Meta["reason"] == "profile_missing_email" { ok = true }
    }
    if !ok { t.Fatalf("expected auth.sso.login.failure profile_missing_email") }
}

func TestHTTP_SSO_WorkOS_Start_UsesTenantDefaultsWhenMissing(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-def-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)
    // tenant-scoped defaults
    _ = sr.Upsert(ctx, "sso.workos.default_connection_id", &tenantID, "conn_def_123", false)
    _ = sr.Upsert(ctx, "sso.workos.default_organization_id", &tenantID, "org_def_456", false)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    sso := svc.NewSSO(repo, cfg, settings)
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start without explicit connection_id or organization_id
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusFound { t.Fatalf("start not 302: %d", rec.Code) }
    loc := rec.Header().Get("Location")
    u, _ := url.Parse(loc)
    q := u.Query()
    if q.Get("connection") != "conn_def_123" {
        t.Fatalf("expected default connection=conn_def_123, got %s", q.Get("connection"))
    }
    if q.Get("organization") != "org_def_456" {
        t.Fatalf("expected default organization=org_def_456, got %s", q.Get("organization"))
    }
}

func TestHTTP_SSO_WorkOS_Start_ExplicitParamsOverrideDefaults(t *testing.T) {
    if os.Getenv("DATABASE_URL") == "" || os.Getenv("REDIS_ADDR") == "" {
        t.Skip("skipping integration test: DATABASE_URL or REDIS_ADDR not set")
    }
    ctx := context.Background()
    pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
    if err != nil { t.Fatalf("db connect: %v", err) }
    defer pool.Close()

    tr := trepo.New(pool)
    tenantID := uuid.New()
    _ = tr.Create(ctx, tenantID, "http-sso-workos-override-"+tenantID.String())
    time.Sleep(25 * time.Millisecond)
    sr := srepo.New(pool)
    _ = sr.Upsert(ctx, "sso.provider", &tenantID, "workos", false)
    _ = sr.Upsert(ctx, "sso.workos.client_id", &tenantID, "client", true)
    _ = sr.Upsert(ctx, "sso.workos.client_secret", &tenantID, "secret", true)
    // tenant defaults present but should be overridden
    _ = sr.Upsert(ctx, "sso.workos.default_connection_id", &tenantID, "conn_def_x", false)
    _ = sr.Upsert(ctx, "sso.workos.default_organization_id", &tenantID, "org_def_y", false)

    repo := authrepo.New(pool)
    cfg, _ := config.Load()
    settings := ssvc.New(sr)
    e := echo.New()
    e.Validator = noopValidatorWorkOS{}
    sso := svc.NewSSO(repo, cfg, settings)
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), sso)
    c.Register(e)

    // Start with explicit connection_id and organization_id
    qs := url.Values{}
    qs.Set("tenant_id", tenantID.String())
    qs.Set("connection_id", "conn_explicit")
    qs.Set("organization_id", "org_explicit")
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?"+qs.Encode(), nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusFound { t.Fatalf("start not 302: %d", rec.Code) }
    loc := rec.Header().Get("Location")
    u, _ := url.Parse(loc)
    q := u.Query()
    if q.Get("connection") != "conn_explicit" {
        t.Fatalf("expected connection=conn_explicit, got %s", q.Get("connection"))
    }
    if q.Get("organization") != "org_explicit" {
        t.Fatalf("expected organization=org_explicit, got %s", q.Get("organization"))
    }
}
