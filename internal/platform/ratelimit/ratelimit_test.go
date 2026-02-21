package ratelimit

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

type storeStub struct {
	allowed    bool
	retryAfter int
	err        error
	key        string
	limit      int
	window     time.Duration
}

func (f *storeStub) Allow(c echo.Context, key string, limit int, window time.Duration) (bool, int, error) {
	_ = c
	f.key = key
	f.limit = limit
	f.window = window
	return f.allowed, f.retryAfter, f.err
}

func newCtx(method, target string, body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	return c, rec
}

func okHandler(c echo.Context) error {
	return c.String(http.StatusOK, "ok")
}

func TestMiddleware_BlocksAfterLimit(t *testing.T) {
	mw := Middleware(Policy{
		Name:   "auth:login",
		Window: time.Hour,
		Limit:  1,
		Key: func(c echo.Context) string {
			return "k:" + c.RealIP()
		},
	})
	h := mw(okHandler)

	c1, rec1 := newCtx(http.MethodGet, "/v1/auth/password/login", "")
	if err := h(c1); err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected first request 200, got %d", rec1.Code)
	}

	c2, rec2 := newCtx(http.MethodGet, "/v1/auth/password/login", "")
	if err := h(c2); err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request 429, got %d", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on blocked request")
	}
}

func TestMiddlewareWithStore_FailOpenOnStoreError(t *testing.T) {
	store := &storeStub{allowed: false, err: errors.New("store unavailable")}
	mw := MiddlewareWithStore(Policy{Name: "auth:login", Window: time.Minute, Limit: 2, Key: func(c echo.Context) string { return "global" }}, store)
	h := mw(okHandler)

	c, rec := newCtx(http.MethodGet, "/x", "")
	if err := h(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected fail-open 200 response, got %d", rec.Code)
	}
}

func TestMiddlewareWithStore_BlockedSetsRetryAfter(t *testing.T) {
	store := &storeStub{allowed: false, retryAfter: 7}
	mw := MiddlewareWithStore(Policy{Name: "auth:login", Window: time.Minute, Limit: 2, Key: func(c echo.Context) string { return "auth:ten:t1" }}, store)
	h := mw(okHandler)

	c, rec := newCtx(http.MethodGet, "/x", "")
	if err := h(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 response, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "7" {
		t.Fatalf("expected Retry-After=7, got %q", rec.Header().Get("Retry-After"))
	}
}

func TestKeyTenantOrIP_UsesQueryThenJSONThenIP(t *testing.T) {
	k := KeyTenantOrIP("auth")

	cQuery, _ := newCtx(http.MethodGet, "/x?tenant_id=t-query", "")
	if got := k(cQuery); got != "auth:ten:t-query" {
		t.Fatalf("expected query tenant key, got %q", got)
	}

	cJSON, _ := newCtx(http.MethodPost, "/x", `{"tenant_id":"t-body"}`)
	cJSON.Request().Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if got := k(cJSON); got != "auth:ten:t-body" {
		t.Fatalf("expected body tenant key, got %q", got)
	}

	cIP, _ := newCtx(http.MethodGet, "/x", "")
	cIP.Request().Header.Set(echo.HeaderXForwardedFor, "10.0.0.8")
	if got := k(cIP); got != "auth:ip:10.0.0.8" {
		t.Fatalf("expected ip key fallback, got %q", got)
	}
}

func TestStrconvItoa_AndIntToBytes(t *testing.T) {
	if got := strconvItoa(0); got != "0" {
		t.Fatalf("expected 0, got %q", got)
	}
	if got := strconvItoa(42); got != "42" {
		t.Fatalf("expected 42, got %q", got)
	}
	if got := strconvItoa(-7); got != "-7" {
		t.Fatalf("expected -7, got %q", got)
	}
}

func TestMiddleware_DynamicLimitWindowOverrides(t *testing.T) {
	mw := Middleware(Policy{
		Name:   "auth:magic",
		Window: time.Hour,
		Limit:  1,
		WindowFunc: func(echo.Context) time.Duration {
			return time.Minute
		},
		LimitFunc: func(echo.Context) int {
			return 2
		},
		Key: func(echo.Context) string { return "same-key" },
	})
	h := mw(okHandler)

	for i := 0; i < 2; i++ {
		c, rec := newCtx(http.MethodGet, "/x", "")
		if err := h(c); err != nil {
			t.Fatalf("request %d returned error: %v", i+1, err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestMiddlewareWithStore_AllowPathWithDebug(t *testing.T) {
	store := &storeStub{allowed: true}
	old := os.Getenv("RATELIMIT_DEBUG")
	_ = os.Setenv("RATELIMIT_DEBUG", "1")
	defer func() { _ = os.Setenv("RATELIMIT_DEBUG", old) }()

	mw := MiddlewareWithStore(Policy{Name: "auth:login", Window: time.Minute, Limit: 2}, store)
	h := mw(okHandler)

	c, rec := newCtx(http.MethodGet, "/x", "")
	if err := h(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rec.Code)
	}
	if store.key != "global" {
		t.Fatalf("expected default key 'global', got %q", store.key)
	}
}

func TestMiddlewareWithStore_BlockedWithoutPositiveRetryAfter(t *testing.T) {
	store := &storeStub{allowed: false, retryAfter: 0}
	mw := MiddlewareWithStore(Policy{Name: "auth:login", Window: time.Minute, Limit: 1}, store)
	h := mw(okHandler)

	c, rec := newCtx(http.MethodGet, "/x", "")
	if err := h(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 response, got %d", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "" {
		t.Fatalf("expected empty Retry-After header when retryAfter<=0, got %q", got)
	}
}

func TestMiddleware_DefaultPolicyValuesAndWindowReset(t *testing.T) {
	// zero values trigger default minute/60 settings.
	mw := Middleware(Policy{})
	h := mw(okHandler)

	c, rec := newCtx(http.MethodGet, "/x", "")
	if err := h(c); err != nil {
		t.Fatalf("default policy request failed: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected default policy allow, got %d", rec.Code)
	}

	// tiny explicit window validates reset behavior after elapsed window.
	mw2 := Middleware(Policy{Window: 5 * time.Millisecond, Limit: 1, Key: func(echo.Context) string { return "reset-key" }})
	h2 := mw2(okHandler)
	c1, rec1 := newCtx(http.MethodGet, "/x", "")
	if err := h2(c1); err != nil || rec1.Code != http.StatusOK {
		t.Fatalf("first tiny-window request failed: err=%v code=%d", err, rec1.Code)
	}
	time.Sleep(10 * time.Millisecond)
	c2, rec2 := newCtx(http.MethodGet, "/x", "")
	if err := h2(c2); err != nil || rec2.Code != http.StatusOK {
		t.Fatalf("expected reset window allow, err=%v code=%d", err, rec2.Code)
	}
}

func TestMiddlewareWithStore_DynamicOverridesPropagateToStore(t *testing.T) {
	store := &storeStub{allowed: false, retryAfter: 9}
	mw := MiddlewareWithStore(Policy{
		Name:       "auth:mfa",
		Window:     time.Minute,
		Limit:      1,
		WindowFunc: func(echo.Context) time.Duration { return 2 * time.Minute },
		LimitFunc:  func(echo.Context) int { return 5 },
		Key:        func(echo.Context) string { return "auth:ten:tenant-a" },
	}, store)
	h := mw(okHandler)

	c, rec := newCtx(http.MethodGet, "/x", "")
	if err := h(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 response, got %d", rec.Code)
	}
	if store.limit != 5 || store.window != 2*time.Minute {
		t.Fatalf("expected dynamic values sent to store, got limit=%d window=%s", store.limit, store.window)
	}
	if rec.Header().Get("Retry-After") != "9" {
		t.Fatalf("expected Retry-After=9, got %q", rec.Header().Get("Retry-After"))
	}
}

func TestKeyTenantOrIP_PreservesRLPrefixAndMalformedJSONFallback(t *testing.T) {
	k := KeyTenantOrIP("auth")

	cPref, _ := newCtx(http.MethodGet, "/x?tenant_id=rl-tenant-1", "")
	if got := k(cPref); got != "auth:ten:rl-tenant-1" {
		t.Fatalf("expected rl-prefixed tenant key preserved, got %q", got)
	}

	cBadJSON, _ := newCtx(http.MethodPost, "/x", `{"tenant_id":`)
	cBadJSON.Request().Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	cBadJSON.Request().Header.Set(echo.HeaderXForwardedFor, "10.9.8.7")
	if got := k(cBadJSON); got != "auth:ip:10.9.8.7" {
		t.Fatalf("expected malformed json fallback to ip, got %q", got)
	}
}
