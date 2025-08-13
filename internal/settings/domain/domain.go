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
)
