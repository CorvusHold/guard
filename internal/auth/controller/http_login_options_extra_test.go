package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adomain "github.com/corvusHold/guard/internal/auth/domain"
	sdomain "github.com/corvusHold/guard/internal/settings/domain"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type loginOptionsSvcStub struct {
	adomain.Service

	findTenantsOut []adomain.TenantInfo
	findTenantsErr error

	getUserOut *adomain.User
	getUserErr error

	listProvidersOut []adomain.PublicSSOProvider
	listProvidersErr error

	listSessionsOut []adomain.RefreshToken
	listSessionsErr error
}

func (s *loginOptionsSvcStub) FindTenantsByUserEmail(ctx context.Context, email string) ([]adomain.TenantInfo, error) {
	if s.findTenantsErr != nil {
		return nil, s.findTenantsErr
	}
	return s.findTenantsOut, nil
}

func (s *loginOptionsSvcStub) GetUserByEmail(ctx context.Context, email, tenantID string) (*adomain.User, error) {
	if s.getUserErr != nil {
		return nil, s.getUserErr
	}
	return s.getUserOut, nil
}

func (s *loginOptionsSvcStub) ListSSOProvidersPublic(ctx context.Context, tenantID uuid.UUID) ([]adomain.PublicSSOProvider, error) {
	if s.listProvidersErr != nil {
		return nil, s.listProvidersErr
	}
	return s.listProvidersOut, nil
}

func (s *loginOptionsSvcStub) ListUserSessions(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) ([]adomain.RefreshToken, error) {
	if s.listSessionsErr != nil {
		return nil, s.listSessionsErr
	}
	return s.listSessionsOut, nil
}

type loginOptionsSettingsStub struct {
	values map[string]string
}

func (s loginOptionsSettingsStub) GetString(ctx context.Context, key string, tenantID *uuid.UUID, def string) (string, error) {
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return def, nil
}

func (s loginOptionsSettingsStub) GetDuration(context.Context, string, *uuid.UUID, time.Duration) (time.Duration, error) {
	return 0, nil
}

func (s loginOptionsSettingsStub) GetInt(context.Context, string, *uuid.UUID, int) (int, error) { return 0, nil }

func TestLoginOptions_Helpers_Extra(t *testing.T) {
	if got := normalizeLoginMethod(" magic-link "); got != "magic_link" {
		t.Fatalf("expected magic_link, got %q", got)
	}
	if got := normalizeLoginMethod("unknown"); got != "" {
		t.Fatalf("expected empty for unknown method, got %q", got)
	}

	if got := buildSSOLoginURL("", "tid", "okta"); got != "" {
		t.Fatalf("expected empty URL for empty base, got %q", got)
	}
	if got := buildSSOLoginURL("https://app.example/", "tid", "okta"); got != "https://app.example/api/v1/auth/sso/t/tid/okta/login" {
		t.Fatalf("unexpected login URL: %q", got)
	}

	if got := getSSOProviderLogo("Acme Okta", "oidc"); got != "/assets/sso/okta.svg" {
		t.Fatalf("expected okta logo, got %q", got)
	}
	if got := getSSOProviderLogo("Unknown", "saml"); got != "/assets/sso/saml-generic.svg" {
		t.Fatalf("expected saml generic logo, got %q", got)
	}
}

func TestLoginOptions_Handler_ExtraBranches(t *testing.T) {
	e := echo.New()
	tenantID := uuid.New()
	userID := uuid.New()
	svc := &loginOptionsSvcStub{
		findTenantsOut: []adomain.TenantInfo{{ID: tenantID.String(), Name: "Tenant A"}},
		getUserOut:     &adomain.User{ID: userID},
		listProvidersOut: []adomain.PublicSSOProvider{
			{Slug: "okta", Name: "Okta", ProviderType: "oidc", Domains: []string{"example.com"}},
		},
		listSessionsOut: []adomain.RefreshToken{{AuthMethod: "password", CreatedAt: time.Now().Add(-time.Hour)}},
	}
	h := &Controller{
		svc:      svc,
		settings: loginOptionsSettingsStub{values: map[string]string{sdomain.KeySSORequired: "true", sdomain.KeySignupEnabled: "false", sdomain.KeyTenantLogoURL: "https://cdn/logo.svg"}},
	}

	t.Run("invalid tenant id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-options?tenant_id=bad", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.getLoginOptions(c); err != nil {
			t.Fatalf("getLoginOptions returned err=%v", err)
		}
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("domain matched sso with required policy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-options?email=user@example.com", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		if err := h.getLoginOptions(c); err != nil {
			t.Fatalf("getLoginOptions returned err=%v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
		}
		var out LoginOptionsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !out.SSORequired || !out.SSOOnly || out.PreferredMethod != "sso" {
			t.Fatalf("expected sso-only recommendation, got %+v", out)
		}
		if out.PasswordEnabled || out.MagicLinkEnabled || out.SignupEnabled {
			t.Fatalf("expected password/magic disabled and signup false, got %+v", out)
		}
		if out.DomainMatchedSSO == nil || out.DomainMatchedSSO.Slug != "okta" {
			t.Fatalf("expected domain matched okta provider, got %+v", out.DomainMatchedSSO)
		}
		if len(out.RecommendedMethods) == 0 || out.RecommendedMethods[0] != "sso" {
			t.Fatalf("expected sso to be top recommendation, got %+v", out.RecommendedMethods)
		}
	})
}
