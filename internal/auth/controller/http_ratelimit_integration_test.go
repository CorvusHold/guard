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
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	srepo "github.com/corvusHold/guard/internal/settings/repository"
	ssvc "github.com/corvusHold/guard/internal/settings/service"
	trepo "github.com/corvusHold/guard/internal/tenants/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

func TestHTTP_RateLimit_Login_PerTenantOrIP(t *testing.T) {
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
	name := "http-rl-itest-" + tenantID.String()
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
	c := New(auth, magic, sso).WithRateLimit(settings, nil)
	c.Register(e)

	email := "rl.user@example.com"
	password := "Password!123"

	// 1) signup once
	sBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	sb, _ := json.Marshal(sBody)
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("signup expected 201, got %d: %s", srec.Code, srec.Body.String())
	}

	// 2) login three times quickly -> third should be 429 (limit=2/min)
	lBody := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     email,
		"password":  password,
	}
	lb, _ := json.Marshal(lBody)

	// first
	r1 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK && w1.Code != http.StatusAccepted { // allow MFA case too
		t.Fatalf("login#1 expected 200/202, got %d: %s", w1.Code, w1.Body.String())
	}

	// second
	r2 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK && w2.Code != http.StatusAccepted {
		t.Fatalf("login#2 expected 200/202, got %d: %s", w2.Code, w2.Body.String())
	}

	// third -> expect 429
	r3 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	e.ServeHTTP(w3, r3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("login#3 expected 429, got %d: %s", w3.Code, w3.Body.String())
	}
}

func TestHTTP_RateLimit_Magic_Send(t *testing.T) {
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
	if err := tr.Create(ctx, tenantID, "http-rl-magic-send-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// override magic send limit to 1 per window
	sr := srepo.New(pool)
	if err := sr.Upsert(ctx, sdomain.KeyRLMagicLimit, &tenantID, "1", false); err != nil {
		t.Fatalf("upsert magic limit: %v", err)
	}

	repo := authrepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	auth := svc.New(repo, cfg, settings)
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso).WithRateLimit(settings, nil)
	c.Register(e)

	// first send -> 202
	body := map[string]string{
		"tenant_id": tenantID.String(),
		"email":     "rl.magic@example.com",
	}
	b, _ := json.Marshal(body)
	r1 := httptest.NewRequest(http.MethodPost, "/v1/auth/magic/send?tenant_id="+tenantID.String(), bytes.NewReader(b))
	r1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, r1)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("magic send#1 expected 202, got %d: %s", w1.Code, w1.Body.String())
	}

	// second send in window -> 429
	r2 := httptest.NewRequest(http.MethodPost, "/v1/auth/magic/send?tenant_id="+tenantID.String(), bytes.NewReader(b))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("magic send#2 expected 429, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestHTTP_RateLimit_MFA_Verify(t *testing.T) {
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
	if err := tr.Create(ctx, tenantID, "http-rl-mfa-verify-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// override MFA verify limit to 1 per window
	if err := sr.Upsert(ctx, sdomain.KeyRLMFALimit, &tenantID, "1", false); err != nil {
		t.Fatalf("upsert mfa limit: %v", err)
	}

	repo := authrepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso).WithRateLimit(settings, nil)
	c.Register(e)

	// first verify -> expect 400 (invalid), but allowed by RL
	v1b, _ := json.Marshal(map[string]string{
		"challenge_token": "invalid",
		"code":            "000000",
		"method":          "totp",
	})
	r1 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify?tenant_id="+tenantID.String(), bytes.NewReader(v1b))
	r1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, r1)
	if w1.Code == http.StatusTooManyRequests {
		t.Fatalf("mfa verify#1 unexpected 429: %s", w1.Body.String())
	}

	// second verify in window -> 429 due to RL
	r2 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify?tenant_id="+tenantID.String(), bytes.NewReader(v1b))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("mfa verify#2 expected 429, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestHTTP_RateLimit_SSO_Start(t *testing.T) {
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
	if err := tr.Create(ctx, tenantID, "http-rl-sso-start-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	if err := sr.Upsert(ctx, sdomain.KeyRLSsoLimit, &tenantID, "1", false); err != nil {
		t.Fatalf("upsert sso limit: %v", err)
	}

	repo := authrepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso).WithRateLimit(settings, nil)
	c.Register(e)

	// first start -> expect 302 or 400 depending on provider config, but allowed by RL
	r1 := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?tenant_id="+tenantID.String()+"&redirect_url=https://example.com/callback", nil)
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, r1)
	if w1.Code == http.StatusTooManyRequests {
		t.Fatalf("sso start#1 unexpected 429: %s", w1.Body.String())
	}

	// second start in window -> 429
	r2 := httptest.NewRequest(http.MethodGet, "/v1/auth/sso/google/start?tenant_id="+tenantID.String()+"&redirect_url=https://example.com/callback", nil)
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("sso start#2 expected 429, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestHTTP_RateLimit_Login_TenantOverrideLimit(t *testing.T) {
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
	if err := tr.Create(ctx, tenantID, "http-rl-override-limit-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// settings override: limit=1 per window for login
	sr := srepo.New(pool)
	if err := sr.Upsert(ctx, sdomain.KeyRLLoginLimit, &tenantID, "1", false); err != nil {
		t.Fatalf("upsert setting: %v", err)
	}

	// services
	repo := authrepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso).WithRateLimit(settings, nil)
	c.Register(e)

	email := "rl.override.limit@example.com"
	password := "Password!123"

	// signup once
	sb, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "email": email, "password": password})
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("signup expected 201, got %d: %s", srec.Code, srec.Body.String())
	}

	lb, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "email": email, "password": password})

	// first login -> allowed
	r1 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK && w1.Code != http.StatusAccepted {
		t.Fatalf("login#1 expected 200/202, got %d: %s", w1.Code, w1.Body.String())
	}

	// second login in same window -> 429 because limit=1
	r2 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("login#2 expected 429 due to tenant override limit=1, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestHTTP_RateLimit_Login_TenantOverrideWindow(t *testing.T) {
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
	if err := tr.Create(ctx, tenantID, "http-rl-override-window-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	sr := srepo.New(pool)
	// limit=2 per 2s window for login
	if err := sr.Upsert(ctx, sdomain.KeyRLLoginLimit, &tenantID, "2", false); err != nil {
		t.Fatalf("upsert limit: %v", err)
	}
	if err := sr.Upsert(ctx, sdomain.KeyRLLoginWindow, &tenantID, "2s", false); err != nil {
		t.Fatalf("upsert window: %v", err)
	}

	repo := authrepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso).WithRateLimit(settings, nil)
	c.Register(e)

	email := "rl.override.window@example.com"
	password := "Password!123"

	sb, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "email": email, "password": password})
	sreq := httptest.NewRequest(http.MethodPost, "/v1/auth/password/signup", bytes.NewReader(sb))
	sreq.Header.Set("Content-Type", "application/json")
	srec := httptest.NewRecorder()
	e.ServeHTTP(srec, sreq)
	if srec.Code != http.StatusCreated {
		t.Fatalf("signup expected 201, got %d: %s", srec.Code, srec.Body.String())
	}

	lb, _ := json.Marshal(map[string]string{"tenant_id": tenantID.String(), "email": email, "password": password})

	// request #1
	r1 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK && w1.Code != http.StatusAccepted {
		t.Fatalf("login#1 expected 200/202, got %d: %s", w1.Code, w1.Body.String())
	}
	// request #2 (still within 2s) -> allowed
	r2 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK && w2.Code != http.StatusAccepted {
		t.Fatalf("login#2 expected 200/202, got %d: %s", w2.Code, w2.Body.String())
	}
	// request #3 -> 429
	r3 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	e.ServeHTTP(w3, r3)
	if w3.Code != http.StatusTooManyRequests {
		t.Fatalf("login#3 expected 429, got %d: %s", w3.Code, w3.Body.String())
	}
	// wait for window to reset, then allowed again
	time.Sleep(2200 * time.Millisecond)
	r4 := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login?tenant_id="+tenantID.String(), bytes.NewReader(lb))
	r4.Header.Set("Content-Type", "application/json")
	w4 := httptest.NewRecorder()
	e.ServeHTTP(w4, r4)
	if w4.Code != http.StatusOK && w4.Code != http.StatusAccepted {
		t.Fatalf("login#4 after window expected 200/202, got %d: %s", w4.Code, w4.Body.String())
	}
}

func TestHTTP_RateLimit_MFA_Verify_11th429_ShortWindow(t *testing.T) {
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
	if err := tr.Create(ctx, tenantID, "http-rl-mfa-verify-11th429-"+tenantID.String()); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// small delay to ensure tenant visibility in settings reads (mirrors other tests)
	time.Sleep(25 * time.Millisecond)

	// settings overrides: limit=10 per 1s window for MFA verify
	sr := srepo.New(pool)
	if err := sr.Upsert(ctx, sdomain.KeyRLMFALimit, &tenantID, "10", false); err != nil {
		t.Fatalf("upsert mfa limit: %v", err)
	}
	if err := sr.Upsert(ctx, sdomain.KeyRLMFAWindow, &tenantID, "1s", false); err != nil {
		t.Fatalf("upsert mfa window: %v", err)
	}

	// services and HTTP wiring
	repo := authrepo.New(pool)
	settings := ssvc.New(sr)
	cfg, _ := config.Load()
	auth := svc.New(repo, cfg, settings)
	magic := svc.NewMagic(repo, cfg, settings, &fakeEmail{})
	sso := svc.NewSSO(repo, cfg, settings)

	e := echo.New()
	e.Validator = noopValidator{}
	c := New(auth, magic, sso).WithRateLimit(settings, nil)
	c.Register(e)

	body, _ := json.Marshal(map[string]string{
		"challenge_token": "invalid.challenge.token",
		"code":            "000000",
		"method":          "totp",
	})

	// First 10 requests should not be 429 (likely 400 due to invalid payload)
	for i := 1; i <= 10; i++ {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify?tenant_id="+tenantID.String(), bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("mfa verify #%d unexpectedly 429: %s", i, w.Body.String())
		}
	}

	// 11th request within the same 1s window should be 429
	r11 := httptest.NewRequest(http.MethodPost, "/v1/auth/mfa/verify?tenant_id="+tenantID.String(), bytes.NewReader(body))
	r11.Header.Set("Content-Type", "application/json")
	w11 := httptest.NewRecorder()
	e.ServeHTTP(w11, r11)
	if w11.Code != http.StatusTooManyRequests {
		t.Fatalf("mfa verify #11 expected 429, got %d: %s", w11.Code, w11.Body.String())
	}
}
