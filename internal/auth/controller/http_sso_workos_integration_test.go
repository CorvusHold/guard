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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
    c.Register(e)

    // Missing state entirely
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?code=abc", nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
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
			expectedRedirect := os.Getenv("PUBLIC_BASE_URL") + "/v1/auth/sso/google/callback"
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
    if iss, _ := claims["iss"].(string); iss != os.Getenv("PUBLIC_BASE_URL") {
        t.Fatalf("iss mismatch: %v", claims["iss"]) }
    if aud, _ := claims["aud"].(string); aud != os.Getenv("PUBLIC_BASE_URL") {
        t.Fatalf("aud mismatch: %v", claims["aud"]) }

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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
    c.Register(e)

    // Random state (not present in Redis)
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/callback?code=x&state="+strings.Repeat("a", 16), nil)
    rec := httptest.NewRecorder()
    e.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
    }
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
    c := New(svc.New(repo, cfg, settings), svc.NewMagic(repo, cfg, settings, nil), svc.NewSSO(repo, cfg, settings))
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
}
