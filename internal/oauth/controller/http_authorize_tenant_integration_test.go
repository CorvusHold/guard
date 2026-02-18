//go:build integration

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	"github.com/corvusHold/guard/internal/config"
	"github.com/corvusHold/guard/internal/oauth/domain"
	"github.com/corvusHold/guard/internal/oauth/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type integrationAuthorizeRepoStub struct {
	domain.Repository
	client domain.OAuthClient
}

func (s *integrationAuthorizeRepoStub) GetOAuthClientByClientID(_ context.Context, clientID string) (domain.OAuthClient, error) {
	if clientID != s.client.ClientID {
		return domain.OAuthClient{}, errors.New("invalid client_id")
	}
	return s.client, nil
}

type integrationAuthorizeAuthServiceStub struct {
	authdomain.Service
	introspection authdomain.Introspection
}

func (s *integrationAuthorizeAuthServiceStub) Introspect(_ context.Context, _ string) (authdomain.Introspection, error) {
	return s.introspection, nil
}

func TestIntegrationAuthorize_DeniesMismatchedTenantSession(t *testing.T) {
	clientTenantID := uuid.New()
	userTenantID := uuid.New()

	repo := &integrationAuthorizeRepoStub{client: domain.OAuthClient{
		ClientID:     "gc_integration_mismatch",
		TenantID:     clientTenantID,
		ClientType:   "public",
		RedirectURIs: []string{"http://localhost:3004/oauth/callback"},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		IsActive:     true,
	}}
	svc := service.New(repo)
	authSvc := &integrationAuthorizeAuthServiceStub{introspection: authdomain.Introspection{
		Active:   true,
		UserID:   uuid.New(),
		TenantID: userTenantID,
	}}
	h := &Controller{
		svc:     svc,
		authSvc: authSvc,
		cfg:     config.Config{PublicBaseURL: "http://localhost:8082", DefaultAuthMode: "cookie"},
	}

	state := "state-tenant-mismatch"
	q := url.Values{}
	q.Set("client_id", "gc_integration_mismatch")
	q.Set("redirect_uri", "http://localhost:3004/oauth/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email offline_access")
	q.Set("state", state)
	q.Set("nonce", "nonce-123")
	q.Set("code_challenge", "challenge-123")
	q.Set("code_challenge_method", "S256")

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Header.Set("Authorization", "Bearer integration-token")
	rec := httptest.NewRecorder()

	e := echo.New()
	c := e.NewContext(req, rec)
	if err := h.authorize(c); err != nil {
		t.Fatalf("authorize returned error: %v", err)
	}
	assertTenantMismatchRedirect(t, rec, state, "localhost:3004", "/oauth/callback")
}

func TestIntegrationAuthorizeDecision_DeniesMismatchedTenantSession(t *testing.T) {
	clientTenantID := uuid.New()
	userTenantID := uuid.New()

	repo := &integrationAuthorizeRepoStub{client: domain.OAuthClient{
		ClientID:     "gc_integration_mismatch_decision",
		TenantID:     clientTenantID,
		ClientType:   "public",
		RedirectURIs: []string{"http://localhost:3004/oauth/callback"},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		IsActive:     true,
	}}
	svc := service.New(repo)
	authSvc := &integrationAuthorizeAuthServiceStub{introspection: authdomain.Introspection{
		Active:   true,
		UserID:   uuid.New(),
		TenantID: userTenantID,
	}}
	h := &Controller{
		svc:     svc,
		authSvc: authSvc,
		cfg:     config.Config{PublicBaseURL: "http://localhost:8082", DefaultAuthMode: "cookie"},
	}

	state := "state-tenant-mismatch-decision"
	body, _ := json.Marshal(map[string]any{
		"approved":              true,
		"consent_challenge":     "dummy-challenge",
		"client_id":             "gc_integration_mismatch_decision",
		"redirect_uri":          "http://localhost:3004/oauth/callback",
		"response_type":         "code",
		"scope":                 "openid profile email offline_access",
		"state":                 state,
		"nonce":                 "nonce-123",
		"code_challenge":        "challenge-123",
		"code_challenge_method": "S256",
	})
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize/decision", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer integration-token")
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e := echo.New()
	c := e.NewContext(req, rec)
	if err := h.authorizeDecision(c); err != nil {
		t.Fatalf("authorizeDecision returned error: %v", err)
	}
	assertTenantMismatchRedirect(t, rec, state, "localhost:3004", "/oauth/callback")
}

func assertTenantMismatchRedirect(t *testing.T, rec *httptest.ResponseRecorder, expectedState, expectedHost, expectedPath string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d body=%s", rec.Code, rec.Body.String())
	}

	redirectLocation := rec.Header().Get("Location")
	if redirectLocation == "" {
		t.Fatalf("expected Location header")
	}
	u, err := url.Parse(redirectLocation)
	if err != nil {
		t.Fatalf("invalid redirect location %q: %v", redirectLocation, err)
	}
	if u.Scheme != "http" || u.Host != expectedHost || u.Path != expectedPath {
		t.Fatalf("expected redirect to callback URI, got %s", redirectLocation)
	}
	if got := u.Query().Get("error"); got != "access_denied" {
		t.Fatalf("expected error=access_denied, got %q", got)
	}
	if got := u.Query().Get("state"); got != expectedState {
		t.Fatalf("expected state=%s, got %q", expectedState, got)
	}
	if got := u.Query().Get("error_description"); !strings.Contains(got, "not allowed to access this client tenant") {
		t.Fatalf("expected tenant mismatch description, got %q", got)
	}
}
