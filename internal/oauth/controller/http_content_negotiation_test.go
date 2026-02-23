package controller

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestPrefersHTMLResponse(t *testing.T) {
	e := echo.New()

	reqHTML := httptest.NewRequest("GET", "/oauth/authorize", nil)
	reqHTML.Header.Set("Accept", "text/html,application/xhtml+xml")
	cHTML := e.NewContext(reqHTML, httptest.NewRecorder())
	if !prefersHTMLResponse(cHTML) {
		t.Fatalf("expected HTML preference when Accept contains text/html")
	}

	reqJSON := httptest.NewRequest("GET", "/oauth/authorize", nil)
	reqJSON.Header.Set("Accept", "application/json")
	cJSON := e.NewContext(reqJSON, httptest.NewRecorder())
	if prefersHTMLResponse(cJSON) {
		t.Fatalf("expected non-HTML preference for application/json")
	}
}

func TestBuildConsentHTML_ContainsDecisionForm(t *testing.T) {
	htmlDoc := buildConsentHTML(authorizeDecisionReq{
		ConsentChallenge:    "challenge-123",
		ClientID:            "gc_test",
		RedirectURI:         "http://localhost:3004/oauth/callback",
		ResponseType:        "code",
		Scope:               "openid profile",
		State:               "state-123",
		Nonce:               "nonce-123",
		CodeChallenge:       "pkce",
		CodeChallengeMethod: "S256",
	}, "Demo App", "", []consentScopeDetail{{Scope: "openid", Description: "Verify your identity"}})

	mustContain := []string{
		"<form method=\"post\" action=\"/oauth/authorize/decision\">",
		"name=\"consent_challenge\" value=\"challenge-123\"",
		"name=\"client_id\" value=\"gc_test\"",
		"name=\"redirect_uri\" value=\"http://localhost:3004/oauth/callback\"",
		"name=\"approved\" value=\"true\"",
		"name=\"approved\" value=\"false\"",
	}

	for _, needle := range mustContain {
		if !strings.Contains(htmlDoc, needle) {
			t.Fatalf("expected consent HTML to contain %q", needle)
		}
	}
}
