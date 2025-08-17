package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Service provides typed access to application/tenant settings with override.
type Service interface {
	GetString(ctx context.Context, key string, tenantID *uuid.UUID, def string) (string, error)
	GetDuration(ctx context.Context, key string, tenantID *uuid.UUID, def time.Duration) (time.Duration, error)
	GetInt(ctx context.Context, key string, tenantID *uuid.UUID, def int) (int, error)
}

// Repository abstracts storage of app settings.
type Repository interface {
	// Get returns (value, found, err) for an exact key and optional tenant.
	Get(ctx context.Context, key string, tenantID *uuid.UUID) (string, bool, error)
	// Upsert stores a key for an optional tenant.
	Upsert(ctx context.Context, key string, tenantID *uuid.UUID, value string, secret bool) error
}

// Common keys
const (
	KeyJWTSigning      = "auth.jwt_signing_key"
	KeyAccessTTL       = "auth.access_token_ttl"
	KeyRefreshTTL      = "auth.refresh_token_ttl"
	KeyJWTIssuer       = "auth.jwt_issuer"
	KeyJWTAudience     = "auth.jwt_audience"
	KeyMagicLinkTTL    = "auth.magic_link_ttl"
	KeyPublicBaseURL   = "app.public_base_url"
	KeyEmailProvider   = "email.provider"
	KeySMTPHost        = "email.smtp.host"
	KeySMTPPort        = "email.smtp.port"
	KeySMTPUsername    = "email.smtp.username"
	KeySMTPPassword    = "email.smtp.password"
	KeySMTPFrom        = "email.smtp.from"
	KeyBrevoAPIKey     = "email.brevo.api_key"
	KeyBrevoSender     = "email.brevo.sender"
	KeySSOProvider     = "sso.provider" // values: dev | workos
	KeyWorkOSAPIKey    = "sso.workos.api_key"
	KeyWorkOSClientID  = "sso.workos.client_id"
	KeyWorkOSClientSecret = "sso.workos.client_secret"
    // SSO hardening
    // KeySSOStateTTL controls the TTL for SSO OAuth state values stored in Redis (e.g., "10m").
    KeySSOStateTTL     = "sso.state_ttl"
    // KeySSORedirectAllowlist is a comma-separated list of allowed redirect URL prefixes for SSO start requests.
    // Example: "https://app.example.com,https://staging.example.com"
    KeySSORedirectAllowlist = "sso.redirect_allowlist"

    // Rate limiting keys (per-endpoint). All are optional and support tenant overrides.
    // Windows use Go duration strings (e.g., "1m", "10s"). Limits are integers.
    KeyRLSignupLimit  = "auth.ratelimit.signup.limit"
    KeyRLSignupWindow = "auth.ratelimit.signup.window"
    KeyRLLoginLimit  = "auth.ratelimit.login.limit"
    KeyRLLoginWindow = "auth.ratelimit.login.window"
    KeyRLMagicLimit  = "auth.ratelimit.magic.limit"
    KeyRLMagicWindow = "auth.ratelimit.magic.window"
    KeyRLSsoLimit    = "auth.ratelimit.sso.limit"
    KeyRLSsoWindow   = "auth.ratelimit.sso.window"
    KeyRLTokenLimit  = "auth.ratelimit.token.limit"
    KeyRLTokenWindow = "auth.ratelimit.token.window"
    KeyRLMFALimit    = "auth.ratelimit.mfa.limit"
    KeyRLMFAWindow   = "auth.ratelimit.mfa.window"
)

// Settings API rate limiting keys (optional, support tenant overrides).
const (
    // GET /v1/tenants/:id/settings
    KeyRLSettingsGetLimit  = "settings.ratelimit.get.limit"
    KeyRLSettingsGetWindow = "settings.ratelimit.get.window"
    // PUT /v1/tenants/:id/settings
    KeyRLSettingsPutLimit  = "settings.ratelimit.put.limit"
    KeyRLSettingsPutWindow = "settings.ratelimit.put.window"
)
