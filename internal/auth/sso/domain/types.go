package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ProviderType represents the type of SSO provider.
type ProviderType string

const (
	// ProviderTypeOIDC represents an OpenID Connect provider.
	ProviderTypeOIDC ProviderType = "oidc"
	// ProviderTypeSAML represents a SAML 2.0 provider.
	ProviderTypeSAML ProviderType = "saml"
	// ProviderTypeOAuth2 represents a generic OAuth 2.0 provider.
	ProviderTypeOAuth2 ProviderType = "oauth2"
	// ProviderTypeWorkOS represents a WorkOS connection.
	ProviderTypeWorkOS ProviderType = "workos"
	// ProviderTypeDev represents a development/testing provider.
	ProviderTypeDev ProviderType = "dev"
)

// SSOProvider is the core interface all SSO providers must implement.
// It defines the contract for initiating authentication flows and handling
// callbacks from identity providers.
type SSOProvider interface {
	// Start initiates the SSO authentication flow.
	// It returns the authorization URL to redirect the user to and any
	// state that needs to be persisted (e.g., nonce, PKCE verifier, state).
	Start(ctx context.Context, opts StartOptions) (*StartResult, error)

	// Callback handles the identity provider callback and extracts the user profile.
	// It validates the callback, exchanges tokens if needed, and returns
	// the authenticated user's profile.
	Callback(ctx context.Context, req CallbackRequest) (*Profile, error)

	// GetMetadata returns provider metadata.
	// For SAML, this returns SP metadata (entity ID, ACS URL, certificates).
	// For OIDC, this returns discovered configuration.
	GetMetadata(ctx context.Context) (*Metadata, error)

	// ValidateConfig validates the provider configuration.
	// It should check that all required fields are present and valid.
	ValidateConfig() error

	// Type returns the provider type.
	Type() ProviderType
}

// StartOptions contains options for starting an SSO authentication flow.
type StartOptions struct {
	// RedirectURL is the URL to redirect to after successful authentication.
	RedirectURL string

	// State is an optional opaque value for CSRF protection.
	// If empty, the provider should generate one.
	State string

	// Scopes are the OAuth/OIDC scopes to request (e.g., "openid", "profile", "email").
	// If empty, the provider should use defaults from config.
	Scopes []string

	// ForceAuthn forces the user to re-authenticate even if they have a valid session.
	ForceAuthn bool

	// LoginHint provides a hint about the user's identifier (e.g., email address).
	LoginHint string
}

// StartResult contains the result of starting an SSO authentication flow.
type StartResult struct {
	// AuthorizationURL is the URL to redirect the user to for authentication.
	AuthorizationURL string

	// State is the CSRF protection state that was generated or provided.
	// The application must store this and verify it in the callback.
	State string

	// Nonce is a unique value used to prevent replay attacks (OIDC only).
	// The application must store this and verify it in the ID token.
	Nonce string

	// PKCEVerifier is the PKCE code verifier (OIDC only).
	// The application must store this and use it during token exchange.
	PKCEVerifier string

	// SAMLRequest is the encoded SAML AuthnRequest (SAML only).
	SAMLRequest string

	// RelayState is the SAML relay state (SAML only).
	RelayState string
}

// CallbackRequest contains the callback data from the identity provider.
type CallbackRequest struct {
	// Code is the authorization code (OIDC/OAuth2).
	Code string

	// State is the CSRF protection state from the initial request.
	State string

	// Nonce is the nonce from the initial request (OIDC only).
	// Must match the nonce in the ID token.
	Nonce string

	// PKCEVerifier is the PKCE code verifier (OIDC only).
	PKCEVerifier string

	// SAMLResponse is the encoded SAML response (SAML only).
	SAMLResponse string

	// RelayState is the SAML relay state (SAML only).
	RelayState string

	// RedirectURL is the redirect URL that was used in the initial request.
	// Required for OIDC token exchange.
	RedirectURL string
}

// Profile represents the user profile extracted from the identity provider.
type Profile struct {
	// Subject is the unique identifier for the user at the identity provider.
	// This is typically the "sub" claim in OIDC or "NameID" in SAML.
	Subject string

	// Email is the user's email address.
	Email string

	// EmailVerified indicates whether the email address has been verified by the IdP.
	EmailVerified bool

	// FirstName is the user's first name.
	FirstName string

	// LastName is the user's last name.
	LastName string

	// Name is the user's full name.
	Name string

	// Picture is a URL to the user's profile picture.
	Picture string

	// Locale is the user's preferred locale (e.g., "en-US").
	Locale string

	// Groups are the groups the user belongs to (if provided by IdP).
	Groups []string

	// RawAttributes contains all raw attributes from the IdP.
	// The keys are attribute names and values are the raw JSON values.
	RawAttributes map[string]interface{}

	// IDToken is the raw ID token (OIDC only).
	IDToken string

	// AccessToken is the access token from the IdP (optional).
	AccessToken string

	// RefreshToken is the refresh token from the IdP (optional).
	RefreshToken string

	// ExpiresAt is when the access token expires.
	ExpiresAt *time.Time
}

// Config represents the configuration for an SSO provider.
type Config struct {
	// ID is the unique identifier for this provider configuration.
	ID uuid.UUID

	// TenantID is the tenant this provider belongs to.
	TenantID uuid.UUID

	// Name is the human-readable name of this provider.
	Name string

	// Slug is a URL-friendly identifier for this provider.
	Slug string

	// ProviderType is the type of provider (oidc, saml, oauth2, etc.).
	ProviderType ProviderType

	// Enabled indicates whether this provider is active.
	Enabled bool

	// AllowSignup indicates whether new users can sign up via this provider.
	AllowSignup bool

	// TrustEmailVerified indicates whether to trust the email_verified claim from the IdP.
	TrustEmailVerified bool

	// Domains is a list of email domains that are allowed to use this provider.
	// If empty, all domains are allowed.
	Domains []string

	// AttributeMapping defines how to map IdP attributes to user profile fields.
	// The key is the target field (e.g., "email", "first_name") and the value
	// is an array of possible source attributes to try in order.
	AttributeMapping map[string][]string

	// OIDC/OAuth2 specific fields
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserinfoEndpoint      string
	JWKSUri               string
	ClientID              string
	ClientSecret          string
	Scopes                []string
	ResponseType          string
	ResponseMode          string

	// SAML specific fields
	EntityID               string
	ACSUrl                 string
	SLOUrl                 string
	IdPMetadataURL         string
	IdPMetadataXML         string
	IdPEntityID            string
	IdPSSOUrl              string
	IdPSLOUrl              string
	IdPCertificate         string
	SPCertificate          string
	SPPrivateKey           string
	SPCertificateExpiresAt *time.Time
	WantAssertionsSigned   bool
	WantResponseSigned     bool
	SignRequests           bool
	ForceAuthn             bool

	// Timestamps
	CreatedAt time.Time
	UpdatedAt time.Time
	CreatedBy uuid.UUID
	UpdatedBy uuid.UUID
}

// Metadata represents provider metadata.
type Metadata struct {
	// ProviderType is the type of provider.
	ProviderType ProviderType

	// OIDC metadata
	Issuer                string   `json:"issuer,omitempty"`
	AuthorizationEndpoint string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	JWKSUri               string   `json:"jwks_uri,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`

	// SAML metadata
	EntityID          string    `json:"entity_id,omitempty"`
	ACSUrl            string    `json:"acs_url,omitempty"`
	SLOUrl            string    `json:"slo_url,omitempty"`
	SPCertificate     string    `json:"sp_certificate,omitempty"`
	CertificateExpiry *time.Time `json:"certificate_expiry,omitempty"`
	MetadataXML       string    `json:"metadata_xml,omitempty"`
}

// DefaultAttributeMapping returns the default attribute mapping for common IdP attributes.
func DefaultAttributeMapping() map[string][]string {
	return map[string][]string{
		"email":      {"email", "mail", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
		"first_name": {"given_name", "givenName", "firstName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"},
		"last_name":  {"family_name", "familyName", "lastName", "surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"},
		"name":       {"name", "displayName", "cn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"},
		"picture":    {"picture", "photo", "avatar"},
		"groups":     {"groups", "memberOf", "http://schemas.xmlsoap.org/claims/Group"},
	}
}

// ApplyAttributeMapping applies the attribute mapping to extract profile fields from raw attributes.
func ApplyAttributeMapping(profile *Profile, mapping map[string][]string) {
	if mapping == nil {
		mapping = DefaultAttributeMapping()
	}

	// Helper to get the first non-empty value from the raw attributes
	getValue := func(keys []string) interface{} {
		for _, key := range keys {
			if val, ok := profile.RawAttributes[key]; ok && val != nil {
				return val
			}
		}
		return nil
	}

	// Helper to convert interface{} to string
	toString := func(val interface{}) string {
		if val == nil {
			return ""
		}
		if s, ok := val.(string); ok {
			return s
		}
		return ""
	}

	// Helper to convert interface{} to []string
	toStringSlice := func(val interface{}) []string {
		if val == nil {
			return nil
		}
		switch v := val.(type) {
		case []string:
			return v
		case []interface{}:
			result := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		case string:
			return []string{v}
		default:
			return nil
		}
	}

	// Apply mappings
	if profile.Email == "" {
		if keys, ok := mapping["email"]; ok {
			profile.Email = toString(getValue(keys))
		}
	}
	if profile.FirstName == "" {
		if keys, ok := mapping["first_name"]; ok {
			profile.FirstName = toString(getValue(keys))
		}
	}
	if profile.LastName == "" {
		if keys, ok := mapping["last_name"]; ok {
			profile.LastName = toString(getValue(keys))
		}
	}
	if profile.Name == "" {
		if keys, ok := mapping["name"]; ok {
			profile.Name = toString(getValue(keys))
		}
	}
	if profile.Picture == "" {
		if keys, ok := mapping["picture"]; ok {
			profile.Picture = toString(getValue(keys))
		}
	}
	if len(profile.Groups) == 0 {
		if keys, ok := mapping["groups"]; ok {
			profile.Groups = toStringSlice(getValue(keys))
		}
	}
}
