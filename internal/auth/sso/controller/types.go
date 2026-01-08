package controller

import (
	"time"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
	"github.com/google/uuid"
)

// createProviderRequest is the request body for creating an SSO provider.
type createProviderRequest struct {
	TenantID           uuid.UUID           `json:"tenant_id"`
	Name               string              `json:"name"`
	Slug               string              `json:"slug"`
	ProviderType       domain.ProviderType `json:"provider_type"`
	Enabled            bool                `json:"enabled"`
	AllowSignup        bool                `json:"allow_signup"`
	TrustEmailVerified bool                `json:"trust_email_verified"`
	Domains            []string            `json:"domains"`
	AttributeMapping   map[string][]string `json:"attribute_mapping"`

	// OIDC/OAuth2 fields
	Issuer                string   `json:"issuer,omitempty"`
	AuthorizationEndpoint string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	JWKSUri               string   `json:"jwks_uri,omitempty"`
	ClientID              string   `json:"client_id,omitempty"`
	ClientSecret          string   `json:"client_secret,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
	ResponseType          string   `json:"response_type,omitempty"`
	ResponseMode          string   `json:"response_mode,omitempty"`

	// SAML fields
	EntityID               string     `json:"entity_id,omitempty"`
	ACSUrl                 string     `json:"acs_url,omitempty"`
	SLOUrl                 string     `json:"slo_url,omitempty"`
	IdPMetadataURL         string     `json:"idp_metadata_url,omitempty"`
	IdPMetadataXML         string     `json:"idp_metadata_xml,omitempty"`
	IdPEntityID            string     `json:"idp_entity_id,omitempty"`
	IdPSSOUrl              string     `json:"idp_sso_url,omitempty"`
	IdPSLOUrl              string     `json:"idp_slo_url,omitempty"`
	IdPCertificate         string     `json:"idp_certificate,omitempty"`
	SPCertificate          string     `json:"sp_certificate,omitempty"`
	SPPrivateKey           string     `json:"sp_private_key,omitempty"`
	SPCertificateExpiresAt *time.Time `json:"sp_certificate_expires_at,omitempty"`
	WantAssertionsSigned   bool       `json:"want_assertions_signed,omitempty"`
	WantResponseSigned     bool       `json:"want_response_signed,omitempty"`
	SignRequests           bool       `json:"sign_requests,omitempty"`
	ForceAuthn             bool       `json:"force_authn,omitempty"`
}

// updateProviderRequest is the request body for updating an SSO provider.
type updateProviderRequest struct {
	Name               *string             `json:"name,omitempty"`
	Enabled            *bool               `json:"enabled,omitempty"`
	AllowSignup        *bool               `json:"allow_signup,omitempty"`
	TrustEmailVerified *bool               `json:"trust_email_verified,omitempty"`
	LinkingPolicy      *string             `json:"linking_policy,omitempty" enums:"never,verified_email,always"` // Policy for linking SSO identities to existing accounts
	Domains            []string            `json:"domains,omitempty"`
	AttributeMapping   map[string][]string `json:"attribute_mapping,omitempty"`

	// OIDC/OAuth2 fields
	Issuer                *string  `json:"issuer,omitempty"`
	AuthorizationEndpoint *string  `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         *string  `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      *string  `json:"userinfo_endpoint,omitempty"`
	JWKSUri               *string  `json:"jwks_uri,omitempty"`
	ClientID              *string  `json:"client_id,omitempty"`
	ClientSecret          *string  `json:"client_secret,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
	ResponseType          *string  `json:"response_type,omitempty"`
	ResponseMode          *string  `json:"response_mode,omitempty"`

	// SAML fields
	EntityID               *string    `json:"entity_id,omitempty"`
	ACSUrl                 *string    `json:"acs_url,omitempty"`
	SLOUrl                 *string    `json:"slo_url,omitempty"`
	IdPMetadataURL         *string    `json:"idp_metadata_url,omitempty"`
	IdPMetadataXML         *string    `json:"idp_metadata_xml,omitempty"`
	IdPEntityID            *string    `json:"idp_entity_id,omitempty"`
	IdPSSOUrl              *string    `json:"idp_sso_url,omitempty"`
	IdPSLOUrl              *string    `json:"idp_slo_url,omitempty"`
	IdPCertificate         *string    `json:"idp_certificate,omitempty"`
	SPCertificate          *string    `json:"sp_certificate,omitempty"`
	SPPrivateKey           *string    `json:"sp_private_key,omitempty"`
	SPCertificateExpiresAt *time.Time `json:"sp_certificate_expires_at,omitempty"`
	WantAssertionsSigned   *bool      `json:"want_assertions_signed,omitempty"`
	WantResponseSigned     *bool      `json:"want_response_signed,omitempty"`
	SignRequests           *bool      `json:"sign_requests,omitempty"`
	ForceAuthn             *bool      `json:"force_authn,omitempty"`
}
