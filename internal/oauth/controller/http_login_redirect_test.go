package controller

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/corvusHold/guard/internal/config"
)

func TestBuildLoginURL_UsesPublicBaseURL(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=gc_test", nil)
	req.Header.Set("Referer", "http://localhost:3000/some-app-route")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := &Controller{cfg: config.Config{PublicBaseURL: "http://localhost:8080", DefaultAuthMode: "cookie", CORSAllowedOrigins: []string{"http://localhost:3000"}}}
	got := h.buildLoginURL(c)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("expected valid URL, got parse error: %v", err)
	}

	if u.Scheme != "http" || u.Host != "localhost:8080" || u.Path != "/login" {
		t.Fatalf("expected login redirect to PublicBaseURL host/path, got %s", got)
	}
	if q := u.Query(); q.Get("return_to") == "" || q.Get("guard-base-url") != "http://example.com" || q.Get("auth-mode") != "cookie" {
		t.Fatalf("unexpected query params in login redirect: %s", u.RawQuery)
	}
}

func TestBuildLoginURL_DoesNotUseOriginOrRefererOverride(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest("GET", "/oauth/authorize?response_type=code&client_id=gc_test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Referer", "http://localhost:3000/some-app-route")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := &Controller{cfg: config.Config{PublicBaseURL: "http://127.0.0.1:8080", DefaultAuthMode: "cookie", CORSAllowedOrigins: []string{"http://localhost:3000"}}}
	got := h.buildLoginURL(c)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("expected valid URL, got parse error: %v", err)
	}

	if u.Scheme != "http" || u.Host != "127.0.0.1:8080" || u.Path != "/login" {
		t.Fatalf("expected login redirect to PublicBaseURL host/path, got %s", got)
	}
	if q := u.Query(); q.Get("guard-base-url") != "http://example.com" || q.Get("auth-mode") != "cookie" {
		t.Fatalf("unexpected query params in login redirect: %s", u.RawQuery)
	}
}

func TestBuildLoginURL_FallsBackToRequestHost(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest("GET", "http://127.0.0.1:8080/oauth/authorize?client_id=gc_test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := &Controller{cfg: config.Config{}}
	got := h.buildLoginURL(c)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("expected valid URL, got parse error: %v", err)
	}

	if u.Scheme != "http" || u.Host != "127.0.0.1:8080" || u.Path != "/login" {
		t.Fatalf("expected login redirect to request host, got %s", got)
	}
	if q := u.Query(); q.Get("guard-base-url") != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected guard-base-url in login redirect: %s", u.RawQuery)
	}
}
