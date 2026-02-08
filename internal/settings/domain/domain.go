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
	KeyJWTSigning         = "auth.jwt_signing_key"
	KeyAccessTTL          = "auth.access_token_ttl"
	KeyRefreshTTL         = "auth.refresh_token_ttl"
	KeyJWTIssuer          = "auth.jwt_issuer"
	KeyJWTAudience        = "auth.jwt_audience"
	KeyMagicLinkTTL       = "auth.magic_link_ttl"
	KeyPublicBaseURL      = "app.public_base_url"
	KeyEmailProvider      = "email.provider"
	KeySMTPHost           = "email.smtp.host"
	KeySMTPPort           = "email.smtp.port"
	KeySMTPUsername       = "email.smtp.username"
	KeySMTPPassword       = "email.smtp.password"
	KeySMTPFrom           = "email.smtp.from"
	KeyBrevoAPIKey        = "email.brevo.api_key"
	KeyBrevoSender        = "email.brevo.sender"
	KeySSOProvider        = "sso.provider" // values: dev | workos
	KeyWorkOSAPIKey       = "sso.workos.api_key"
	KeyWorkOSClientID     = "sso.workos.client_id"
	KeyWorkOSClientSecret = "sso.workos.client_secret"
	// API base URL for WorkOS, default https://api.workos.com
	KeyWorkOSAPIBaseURL = "sso.workos.api_base_url"
	// Optional defaults to target a WorkOS SSO flow without passing query params on start
	KeyWorkOSDefaultConnectionID   = "sso.workos.default_connection_id"
	KeyWorkOSDefaultOrganizationID = "sso.workos.default_organization_id"
	// SSO hardening
	// KeySSOStateTTL controls the TTL for SSO OAuth state values stored in Redis (e.g., "10m").
	KeySSOStateTTL = "sso.state_ttl"
	// KeySSORedirectAllowlist is a comma-separated list of allowed redirect URL prefixes for SSO start requests.
	// Example: "https://app.example.com,https://staging.example.com"
	KeySSORedirectAllowlist = "sso.redirect_allowlist"

	// Per-tenant CORS allowlist for browser apps calling the API.
	// Comma-separated list of exact origins, e.g., "https://app.example.com,https://staging.example.com".
	// This augments the global env CORS_ALLOWED_ORIGINS. Endpoints without a tenant context still rely on the global list.
	KeyAppCORSAllowedOrigins = "app.cors_allowed_origins"

	// Rate limiting keys (per-endpoint). All are optional and support tenant overrides.
	// Windows use Go duration strings (e.g., "1m", "10s"). Limits are integers.
	KeyRLSignupLimit  = "auth.ratelimit.signup.limit"
	KeyRLSignupWindow = "auth.ratelimit.signup.window"
	KeyRLLoginLimit   = "auth.ratelimit.login.limit"
	KeyRLLoginWindow  = "auth.ratelimit.login.window"
	KeyRLMagicLimit   = "auth.ratelimit.magic.limit"
	KeyRLMagicWindow  = "auth.ratelimit.magic.window"
	KeyRLSsoLimit     = "auth.ratelimit.sso.limit"
	KeyRLSsoWindow    = "auth.ratelimit.sso.window"
	KeyRLTokenLimit   = "auth.ratelimit.token.limit"
	KeyRLTokenWindow  = "auth.ratelimit.token.window"
	KeyRLMFALimit     = "auth.ratelimit.mfa.limit"
	KeyRLMFAWindow    = "auth.ratelimit.mfa.window"

	// Account lockout
	KeyLockoutThreshold = "auth.lockout.threshold" // Max failed attempts before lockout, default "5"
	KeyLockoutDuration  = "auth.lockout.duration"  // Duration of lockout, default "15m"

	// Session idle timeout
	KeySessionIdleTimeout = "auth.session.idle_timeout" // Duration of inactivity before session expires, default "72h"

	// SCIM provisioning
	KeySCIMBearerToken = "scim.bearer_token" // Bearer token for SCIM 2.0 API authentication (per-tenant)

	// Password policy
	KeyPasswordMinLength        = "auth.password.min_length"        // Minimum password length, default "8"
	KeyPasswordRequireUppercase = "auth.password.require_uppercase" // Require uppercase letter, default "false"
	KeyPasswordRequireLowercase = "auth.password.require_lowercase" // Require lowercase letter, default "false"
	KeyPasswordRequireDigit     = "auth.password.require_digit"     // Require digit, default "false"
	KeyPasswordRequireSpecial   = "auth.password.require_special"   // Require special character, default "false"

	// Signup control
	KeySignupEnabled = "auth.signup_enabled" // "true" or "false", default "true"

	// Tenant branding
	KeyTenantLogoURL = "app.tenant_logo_url" // URL to tenant logo for login page branding

	// Invitation settings
	KeyInvitationTTL = "auth.invitation_ttl" // Duration string, default 7 days (e.g., "168h")

	// Email sending toggle. When "false", Guard skips sending emails but still
	// publishes rich events via webhooks so external services can send their own.
	KeyEmailEnabled = "email.enabled" // "true" (default) or "false"
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
