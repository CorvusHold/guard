package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/corvusHold/guard/internal/oauth/domain"
)

func TestOAuthHelpers_GeneratorsAndParsers(t *testing.T) {
	cid, err := generateClientID()
	if err != nil {
		t.Fatalf("generateClientID: %v", err)
	}
	if !strings.HasPrefix(cid, "gc_") {
		t.Fatalf("expected gc_ prefix, got %q", cid)
	}

	secret, err := generateClientSecret()
	if err != nil {
		t.Fatalf("generateClientSecret: %v", err)
	}
	if !strings.HasPrefix(secret, "gcs_") {
		t.Fatalf("expected gcs_ prefix, got %q", secret)
	}

	code, err := generateAuthorizationCode()
	if err != nil {
		t.Fatalf("generateAuthorizationCode: %v", err)
	}
	if code == "" {
		t.Fatal("expected non-empty authorization code")
	}

	if got := computeS256Challenge("abc"); got == "" {
		t.Fatal("expected non-empty S256 challenge")
	}
	if scopes := parseScopes(""); scopes != nil {
		t.Fatalf("expected nil scopes for empty input, got %#v", scopes)
	}
	if scopes := parseScopes("openid profile"); len(scopes) != 2 {
		t.Fatalf("expected two scopes, got %#v", scopes)
	}
	if !containsString([]string{"a", "b"}, "a") || containsString([]string{"a", "b"}, "x") {
		t.Fatal("containsString helper returned unexpected result")
	}
	if !isValidRedirectURI([]string{"https://ok/cb"}, "https://ok/cb") || isValidRedirectURI([]string{"https://ok/cb"}, "https://bad/cb") {
		t.Fatal("isValidRedirectURI helper returned unexpected result")
	}
}

func TestCreateClient_DefaultsAndRedirectValidation(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)

	client, _, err := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     uuid.New(),
		Name:         "Default App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	})
	if err != nil {
		t.Fatalf("CreateClient default path: %v", err)
	}
	if client.ClientType != "confidential" {
		t.Fatalf("expected default client_type confidential, got %q", client.ClientType)
	}
	if len(client.Scopes) == 0 || len(client.GrantTypes) == 0 {
		t.Fatalf("expected default scopes/grants, got scopes=%v grants=%v", client.Scopes, client.GrantTypes)
	}

	_, _, err = svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     uuid.New(),
		Name:         "Bad Redirect",
		RedirectURIs: []string{"https://example.com/callback#frag"},
	})
	if err == nil {
		t.Fatal("expected redirect URI fragment validation error")
	}
}

func TestAuthorizeAndTokenValidationEdgeCases(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)
	tenantID := uuid.New()

	client, secret, err := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "confidential",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	// Missing required authorize fields
	if _, err := svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{}); err == nil {
		t.Fatal("expected client_id required error")
	}
	if _, err := svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{ClientID: client.ClientID, ResponseType: "code"}); err == nil {
		t.Fatal("expected redirect_uri required error")
	}

	// Deactivated client path
	c := repo.clients[client.ClientID]
	c.IsActive = false
	repo.clients[client.ClientID] = c
	repo.byID[c.ID] = c
	if _, err := svc.ValidateAuthorizeRequest(context.Background(), domain.AuthorizeInput{
		ClientID: client.ClientID, RedirectURI: "https://example.com/callback", ResponseType: "code", Scope: "openid",
	}); err == nil {
		t.Fatal("expected deactivated client error")
	}
	c.IsActive = true
	repo.clients[client.ClientID] = c
	repo.byID[c.ID] = c

	res, err := svc.CreateAuthorizationCode(context.Background(), domain.AuthorizeInput{
		ClientID:    client.ClientID,
		RedirectURI: "https://example.com/callback",
		UserID:      uuid.New(),
		TenantID:    tenantID,
		// empty scope should default to openid
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}

	if _, _, err := svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{Code: res.Code}); err == nil {
		t.Fatal("expected missing redirect/client id validation error")
	}

	// wrong secret branch
	if _, _, err := svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         res.Code,
		RedirectURI:  "https://example.com/callback",
		ClientID:     client.ClientID,
		ClientSecret: secret + "-bad",
	}); err == nil {
		t.Fatal("expected invalid client_secret error")
	}
}

func TestConsentLifecycleAndAuthenticateClientErrors(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)
	userID := uuid.New()
	tenantID := uuid.New()

	if svc.HasConsent(context.Background(), userID, tenantID, "cid", []string{"openid"}) {
		t.Fatal("expected HasConsent false when no consent exists")
	}

	if err := svc.SaveConsent(context.Background(), userID, tenantID, "cid", []string{"openid", "profile"}); err != nil {
		t.Fatalf("SaveConsent: %v", err)
	}
	if !svc.HasConsent(context.Background(), userID, tenantID, "cid", []string{"openid"}) {
		t.Fatal("expected HasConsent true for granted scope")
	}
	if svc.HasConsent(context.Background(), userID, tenantID, "cid", []string{"email"}) {
		t.Fatal("expected HasConsent false for missing granted scope")
	}
	if err := svc.RevokeConsent(context.Background(), userID, tenantID, "cid"); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if svc.HasConsent(context.Background(), userID, tenantID, "cid", []string{"openid"}) {
		t.Fatal("expected HasConsent false after revoke")
	}

	// AuthenticateClient missing creds
	if _, err := svc.AuthenticateClient(context.Background(), "", ""); err == nil {
		t.Fatal("expected client_id/client_secret required error")
	}

	// Confidential client without client_credentials grant
	client, secret, err := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "limited-client",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if _, err := svc.AuthenticateClient(context.Background(), client.ClientID, secret); err == nil {
		t.Fatal("expected client_credentials grant authorization error")
	}

	// Deactivated client path
	c := repo.clients[client.ClientID]
	c.IsActive = false
	repo.clients[client.ClientID] = c
	repo.byID[c.ID] = c
	if _, err := svc.AuthenticateClient(context.Background(), client.ClientID, secret); err == nil {
		t.Fatal("expected deactivated client error")
	}
}

func TestExchangeAuthorizationCode_ExpiredAndConsumedPaths(t *testing.T) {
	repo := newMockRepo()
	svc := New(repo)
	tenantID := uuid.New()
	userID := uuid.New()
	client, secret, err := svc.CreateClient(context.Background(), domain.CreateOAuthClientInput{
		TenantID:     tenantID,
		Name:         "expirable",
		ClientType:   "confidential",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
	})
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	result, err := svc.CreateAuthorizationCode(context.Background(), domain.AuthorizeInput{
		ClientID:    client.ClientID,
		RedirectURI: "https://example.com/callback",
		Scope:       "openid",
		UserID:      userID,
		TenantID:    tenantID,
	})
	if err != nil {
		t.Fatalf("CreateAuthorizationCode: %v", err)
	}

	codeHash := computeS256Challenge(result.Code)
	ac := repo.codes[codeHash]
	now := time.Now().Add(-time.Minute)
	ac.ExpiresAt = now
	repo.codes[codeHash] = ac
	if _, _, err := svc.ExchangeAuthorizationCode(context.Background(), domain.TokenRequest{
		GrantType:    "authorization_code",
		Code:         result.Code,
		RedirectURI:  "https://example.com/callback",
		ClientID:     client.ClientID,
		ClientSecret: secret,
	}); err == nil {
		t.Fatal("expected expired authorization code error")
	}
}
