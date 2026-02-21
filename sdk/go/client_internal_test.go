package guard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type stubTokenStore struct {
	access  string
	refresh string
	setErr  error
	setCall int
}

func (s *stubTokenStore) Get(context.Context) (string, string) { return s.access, s.refresh }
func (s *stubTokenStore) Set(_ context.Context, access, refresh string) error {
	s.setCall++
	s.access = access
	s.refresh = refresh
	return s.setErr
}
func (s *stubTokenStore) Clear(context.Context) error { s.access, s.refresh = "", ""; return nil }

func TestWithCookieJar_OnNilAndExistingHTTPClient(t *testing.T) {
	gc := &GuardClient{}
	if err := WithCookieJar()(gc); err != nil {
		t.Fatalf("WithCookieJar on nil client: %v", err)
	}
	cli, ok := gc.httpClient.(*http.Client)
	if !ok || cli.Jar == nil {
		t.Fatalf("expected http client with cookie jar, got %#v", gc.httpClient)
	}

	existing := &http.Client{}
	gc2 := &GuardClient{httpClient: existing}
	if err := WithCookieJar()(gc2); err != nil {
		t.Fatalf("WithCookieJar on existing client: %v", err)
	}
	if existing.Jar == nil {
		t.Fatal("expected jar injected into existing http.Client")
	}
}

func TestAuthEditor_BearerCookieAndAPIKey(t *testing.T) {
	ts := &stubTokenStore{access: "a-token"}
	gc := &GuardClient{tokens: ts, authMode: AuthModeBearer, apiKey: "k1"}
	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	if err := gc.authEditor(context.Background(), req); err != nil {
		t.Fatalf("authEditor bearer: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer a-token" {
		t.Fatalf("expected Authorization header, got %q", got)
	}
	if got := req.Header.Get("X-Guard-API-Key"); got != "k1" {
		t.Fatalf("expected API key header, got %q", got)
	}
	if got := req.Header.Get("X-Auth-Mode"); got != "bearer" {
		t.Fatalf("expected bearer mode header, got %q", got)
	}

	gc.authMode = AuthModeCookie
	req2 := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	if err := gc.authEditor(context.Background(), req2); err != nil {
		t.Fatalf("authEditor cookie: %v", err)
	}
	if got := req2.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected no Authorization in cookie mode, got %q", got)
	}
	if got := req2.Header.Get("X-Auth-Mode"); got != "cookie" {
		t.Fatalf("expected cookie mode header, got %q", got)
	}
}

func TestPersistAccessRefresh(t *testing.T) {
	a := "access"
	r := "refresh"
	ts := &stubTokenStore{}
	gc := &GuardClient{tokens: ts, authMode: AuthModeBearer}

	if err := gc.persistAccessRefresh(context.Background(), &a, &r); err != nil {
		t.Fatalf("persistAccessRefresh failed: %v", err)
	}
	if ts.setCall != 1 || ts.access != a || ts.refresh != r {
		t.Fatalf("unexpected token store writes: %+v", ts)
	}

	// no-op when both tokens empty
	empty := ""
	if err := gc.persistAccessRefresh(context.Background(), &empty, &empty); err != nil {
		t.Fatalf("persistAccessRefresh empty failed: %v", err)
	}
	if ts.setCall != 1 {
		t.Fatalf("expected no extra set call, got %d", ts.setCall)
	}

	gc.authMode = AuthModeCookie
	if err := gc.persistAccessRefresh(context.Background(), &a, &r); err != nil {
		t.Fatalf("cookie mode persist should no-op, got %v", err)
	}
	if ts.setCall != 1 {
		t.Fatalf("expected cookie mode to skip writes, got %d", ts.setCall)
	}
}

func TestPersistAccessRefresh_PropagatesStoreError(t *testing.T) {
	a := "access"
	ts := &stubTokenStore{setErr: errors.New("store failed")}
	gc := &GuardClient{tokens: ts, authMode: AuthModeBearer}
	if err := gc.persistAccessRefresh(context.Background(), &a, nil); err == nil || err.Error() != "store failed" {
		t.Fatalf("expected store error, got %v", err)
	}
}

func TestBuildOAuth2AuthorizeURL_ValidationAndSuccess(t *testing.T) {
	gc := &GuardClient{baseURL: "https://guard.example.com"}
	_, err := gc.BuildOAuth2AuthorizeURL(OAuth2AuthorizeParams{})
	if err == nil {
		t.Fatal("expected validation error for missing client_id")
	}

	prompt := "login"
	loginHint := "user@example.com"
	u, err := gc.BuildOAuth2AuthorizeURL(OAuth2AuthorizeParams{
		ClientID:            "cid",
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid profile",
		State:               "st",
		Nonce:               "nonce",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Prompt:              &prompt,
		LoginHint:           &loginHint,
	})
	if err != nil {
		t.Fatalf("BuildOAuth2AuthorizeURL returned error: %v", err)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("parse built URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("client_id") != "cid" || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected query values: %s", parsed.RawQuery)
	}
	if q.Get("prompt") != "login" || q.Get("login_hint") != "user@example.com" {
		t.Fatalf("expected optional query params present: %s", parsed.RawQuery)
	}

	_, err = gc.BuildOAuth2AuthorizeURL(OAuth2AuthorizeParams{
		ClientID:            "cid",
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid",
		State:               "st",
		Nonce:               "nonce",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "bad",
	})
	if err == nil {
		t.Fatal("expected invalid code_challenge_method error")
	}
}

func TestBuildOAuth2AuthorizeURL_DefaultChallengeMethod(t *testing.T) {
	gc := &GuardClient{baseURL: "https://guard.example.com"}
	u, err := gc.BuildOAuth2AuthorizeURL(OAuth2AuthorizeParams{
		ClientID:      "cid",
		RedirectURI:   "https://app.example.com/cb",
		Scope:         "openid",
		State:         "st",
		Nonce:         "nonce",
		CodeChallenge: "challenge",
	})
	if err != nil {
		t.Fatalf("BuildOAuth2AuthorizeURL returned error: %v", err)
	}
	parsed, _ := url.Parse(u)
	if got := parsed.Query().Get("code_challenge_method"); got != "S256" {
		t.Fatalf("expected default S256 method, got %q", got)
	}
}
