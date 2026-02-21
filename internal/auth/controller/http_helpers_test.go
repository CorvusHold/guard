package controller

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/corvusHold/guard/internal/config"
	"github.com/labstack/echo/v4"
)

func TestDetectAuthMode(t *testing.T) {
	e := echo.New()
	cases := []struct {
		name   string
		header string
		def    string
		expect string
	}{
		{name: "header cookie", header: "cookie", def: "bearer", expect: "cookie"},
		{name: "header bearer", header: "bearer", def: "cookie", expect: "bearer"},
		{name: "header json maps to bearer", header: "json", def: "cookie", expect: "bearer"},
		{name: "invalid header default cookie", header: "weird", def: "cookie", expect: "cookie"},
		{name: "invalid header default bearer", header: "weird", def: "bearer", expect: "bearer"},
		{name: "trim + case normalize", header: "  CoOkIe  ", def: "bearer", expect: "cookie"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Auth-Mode", tc.header)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			if got := detectAuthMode(c, tc.def); got != tc.expect {
				t.Fatalf("detectAuthMode()=%q, want %q", got, tc.expect)
			}
		})
	}
}

func TestRedactedBodyAndRefreshTokenValidationError(t *testing.T) {
	if got := redactedBody(nil); got != "<empty>" {
		t.Fatalf("redactedBody(nil)=%q", got)
	}
	if got := redactedBody([]byte("abc")); got != "<redacted len=3>" {
		t.Fatalf("redactedBody len output=%q", got)
	}

	errBody := refreshTokenValidationError("")
	if errBody.Error != "refresh_token required" {
		t.Fatalf("expected refresh_token required, got %q", errBody.Error)
	}
	if len(errBody.Fields["refresh_token"]) == 0 {
		t.Fatal("expected refresh_token validation message")
	}
	if errBody.Fields["refresh_token"][0] != "required" {
		t.Fatalf("unexpected default refresh_token message: %#v", errBody.Fields["refresh_token"])
	}
}

func TestShouldUseSecureCookie(t *testing.T) {
	e := echo.New()
	mkCtx := func() echo.Context {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		return e.NewContext(req, rec)
	}

	c1 := mkCtx()
	if !shouldUseSecureCookie(c1, config.Config{ForceHTTPS: true}) {
		t.Fatal("expected secure cookie with ForceHTTPS")
	}

	c2 := mkCtx()
	c2.Request().TLS = &tls.ConnectionState{}
	if !shouldUseSecureCookie(c2, config.Config{}) {
		t.Fatal("expected secure cookie when TLS is present")
	}

	c3 := mkCtx()
	c3.Request().Header.Set("X-Forwarded-Proto", "https,http")
	if !shouldUseSecureCookie(c3, config.Config{}) {
		t.Fatal("expected secure cookie with https forwarded proto")
	}

	c4 := mkCtx()
	if !shouldUseSecureCookie(c4, config.Config{PublicBaseURL: "https://example.com"}) {
		t.Fatal("expected secure cookie for https public base url")
	}

	c5 := mkCtx()
	if shouldUseSecureCookie(c5, config.Config{PublicBaseURL: "http://example.com"}) {
		t.Fatal("did not expect secure cookie for non-https signals")
	}
}

func TestRespondWithTokens_BearerAndCookieModes(t *testing.T) {
	e := echo.New()
	cfg := config.Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		CookieSameSite:  http.SameSiteLaxMode,
	}

	// Bearer mode should return tokens in JSON body
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if err := respondWithTokens(c, cfg, "bearer", http.StatusCreated, "at", "rt"); err != nil {
		t.Fatalf("respondWithTokens bearer error: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}
	var payload authExchangeResp
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode bearer payload: %v", err)
	}
	if payload.AccessToken != "at" || payload.RefreshToken != "rt" || payload.Success {
		t.Fatalf("unexpected bearer payload: %+v", payload)
	}

	// Cookie mode should set cookies and return success-only payload
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-Proto", "https")
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)
	if err := respondWithTokens(c2, cfg, "cookie", 0, "cookie-at", "cookie-rt"); err != nil {
		t.Fatalf("respondWithTokens cookie error: %v", err)
	}
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected default 200, got %d", rec2.Code)
	}
	var payload2 authExchangeResp
	if err := json.Unmarshal(rec2.Body.Bytes(), &payload2); err != nil {
		t.Fatalf("decode cookie payload: %v", err)
	}
	if !payload2.Success || payload2.AccessToken != "" || payload2.RefreshToken != "" {
		t.Fatalf("unexpected cookie payload: %+v", payload2)
	}

	cookies := rec2.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected at least 2 cookies, got %d", len(cookies))
	}
	seenAccess, seenRefresh := false, false
	for _, ck := range cookies {
		switch ck.Name {
		case guardAccessTokenCookieName:
			seenAccess = true
			if ck.Value != "cookie-at" || !ck.HttpOnly || !ck.Secure {
				t.Fatalf("unexpected access cookie: %+v", ck)
			}
		case guardRefreshTokenCookieName:
			seenRefresh = true
			if ck.Value != "cookie-rt" || !ck.HttpOnly || !ck.Secure {
				t.Fatalf("unexpected refresh cookie: %+v", ck)
			}
		}
	}
	if !seenAccess || !seenRefresh {
		t.Fatalf("missing expected token cookies; access=%v refresh=%v", seenAccess, seenRefresh)
	}
}

func TestClearTokenCookies(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	clearTokenCookies(c, config.Config{CookieSameSite: http.SameSiteStrictMode})
	cookies := rec.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected clearing cookies, got %d", len(cookies))
	}
	for _, ck := range cookies {
		if ck.Name == guardAccessTokenCookieName || ck.Name == guardRefreshTokenCookieName {
			if ck.MaxAge != -1 || ck.Value != "" {
				t.Fatalf("expected clearing cookie semantics, got %+v", ck)
			}
		}
	}
}
