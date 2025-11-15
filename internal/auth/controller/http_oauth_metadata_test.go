package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corvusHold/guard/internal/config"
	"github.com/labstack/echo/v4"
)

func TestHTTP_OAuth2Metadata(t *testing.T) {
	testCases := []struct {
		name            string
		defaultAuthMode string
		expectedDefault string
	}{
		{
			name:            "default bearer mode",
			defaultAuthMode: "bearer",
			expectedDefault: "bearer",
		},
		{
			name:            "cookie mode",
			defaultAuthMode: "cookie",
			expectedDefault: "cookie",
		},
		{
			name:            "empty defaults to bearer",
			defaultAuthMode: "",
			expectedDefault: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{
				PublicBaseURL:   "https://api.example.com",
				JWTSigningKey:   "test-key",
				AccessTokenTTL:  900,
				RefreshTokenTTL: 2592000,
				DefaultAuthMode: tc.defaultAuthMode,
			}

			c := &Controller{cfg: cfg}

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			// Call the handler directly
			if err := c.OAuth2Metadata(ctx); err != nil {
				t.Fatalf("handler error: %v", err)
			}

			// Verify response
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}

			var metadata oauth2MetadataResp
			if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
				t.Fatalf("decode metadata: %v", err)
			}

			// Verify required fields
			if metadata.Issuer != "https://api.example.com" {
				t.Errorf("expected issuer 'https://api.example.com', got '%s'", metadata.Issuer)
			}

			if metadata.TokenEndpoint != "https://api.example.com/v1/auth/refresh" {
				t.Errorf("expected token_endpoint 'https://api.example.com/v1/auth/refresh', got '%s'", metadata.TokenEndpoint)
			}

			if metadata.IntrospectionEndpoint != "https://api.example.com/v1/auth/introspect" {
				t.Errorf("expected introspection_endpoint, got '%s'", metadata.IntrospectionEndpoint)
			}

			if metadata.RevocationEndpoint != "https://api.example.com/v1/auth/revoke" {
				t.Errorf("expected revocation_endpoint, got '%s'", metadata.RevocationEndpoint)
			}

			if metadata.UserinfoEndpoint != "https://api.example.com/v1/auth/me" {
				t.Errorf("expected userinfo_endpoint, got '%s'", metadata.UserinfoEndpoint)
			}

			// Verify Guard-specific extensions
			if len(metadata.GuardAuthModesSupported) != 2 {
				t.Errorf("expected 2 auth modes, got %d", len(metadata.GuardAuthModesSupported))
			}

			hasBearer := false
			hasCookie := false
			for _, mode := range metadata.GuardAuthModesSupported {
				if mode == "bearer" {
					hasBearer = true
				}
				if mode == "cookie" {
					hasCookie = true
				}
			}

			if !hasBearer {
				t.Error("expected 'bearer' in guard_auth_modes_supported")
			}

			if !hasCookie {
				t.Error("expected 'cookie' in guard_auth_modes_supported")
			}

			// Verify default auth mode
			if metadata.GuardAuthModeDefault != tc.expectedDefault {
				t.Errorf("expected guard_auth_mode_default '%s', got '%s'", tc.expectedDefault, metadata.GuardAuthModeDefault)
			}

			if metadata.GuardVersion != "1.0.0" {
				t.Errorf("expected guard_version '1.0.0', got '%s'", metadata.GuardVersion)
			}

			// Verify grant types
			expectedGrantTypes := map[string]bool{
				"password":      true,
				"refresh_token": true,
				"urn:guard:params:oauth:grant-type:magic-link": true,
				"urn:guard:params:oauth:grant-type:sso":        true,
			}

			for _, gt := range metadata.GrantTypesSupported {
				if !expectedGrantTypes[gt] {
					t.Errorf("unexpected grant type: %s", gt)
				}
			}

			// Verify scopes
			expectedScopes := map[string]bool{
				"openid":  true,
				"profile": true,
				"email":   true,
			}

			for _, scope := range metadata.ScopesSupported {
				if !expectedScopes[scope] {
					t.Errorf("unexpected scope: %s", scope)
				}
			}
		})
	}
}
