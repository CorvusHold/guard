package domain

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a requested entity does not exist.
var ErrNotFound = errors.New("not found")

// OAuthClient represents a registered OAuth 2.0 client application.
type OAuthClient struct {
	ID               uuid.UUID `json:"id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"`
	ClientType       string    `json:"client_type"` // confidential | public
	Name             string    `json:"name"`
	RedirectURIs     []string  `json:"redirect_uris"`
	Scopes           []string  `json:"scopes"`
	GrantTypes       []string  `json:"grant_types"`
	LogoURI          string    `json:"logo_uri,omitempty"`
	IsActive         bool      `json:"is_active"`
	CreatedBy        uuid.UUID `json:"created_by,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// AuthorizationCode represents a short-lived OAuth 2.0 authorization code.
type AuthorizationCode struct {
	ID                  uuid.UUID  `json:"id"`
	ClientID            string     `json:"client_id"`
	UserID              uuid.UUID  `json:"user_id"`
	TenantID            uuid.UUID  `json:"tenant_id"`
	CodeHash            string     `json:"-"`
	RedirectURI         string     `json:"redirect_uri"`
	Scopes              []string   `json:"scopes"`
	Nonce               string     `json:"nonce,omitempty"`
	CodeChallenge       string     `json:"-"`
	CodeChallengeMethod string     `json:"-"`
	ExpiresAt           time.Time  `json:"expires_at"`
	ConsumedAt          *time.Time `json:"consumed_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// CreateOAuthClientInput contains the fields needed to register a new OAuth client.
type CreateOAuthClientInput struct {
	TenantID     uuid.UUID
	Name         string
	ClientType   string // confidential | public
	RedirectURIs []string
	Scopes       []string
	GrantTypes   []string
	LogoURI      string
	CreatedBy    uuid.UUID
}

// UpdateOAuthClientInput contains the fields that can be updated on an OAuth client.
type UpdateOAuthClientInput struct {
	Name         *string
	RedirectURIs []string
	Scopes       []string
	GrantTypes   []string
	LogoURI      *string
	IsActive     *bool
}

// AuthorizeInput contains the parameters for an authorization request.
type AuthorizeInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              uuid.UUID
	TenantID            uuid.UUID
}

// AuthorizeResult contains the result of a successful authorization.
type AuthorizeResult struct {
	Code        string
	State       string
	RedirectURI string
}

// TokenRequest contains the parameters for a token exchange.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// TokenResponse is the standard OAuth 2.0 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Supported scopes
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

// ScopeDescriptions maps scopes to human-readable descriptions for the consent screen.
var ScopeDescriptions = map[string]string{
	ScopeOpenID:        "Verify your identity",
	ScopeProfile:       "Access your name and profile info",
	ScopeEmail:         "Access your email address",
	ScopeOfflineAccess: "Stay signed in (refresh tokens)",
}

// ConsentGrant represents a persisted user consent for an OAuth client.
type ConsentGrant struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	ClientID  string     `json:"client_id"`
	Scopes    []string   `json:"scopes"`
	GrantedAt time.Time  `json:"granted_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Repository defines the data access interface for OAuth entities.
type Repository interface {
	CreateOAuthClient(ctx context.Context, client OAuthClient) (OAuthClient, error)
	GetOAuthClientByClientID(ctx context.Context, clientID string) (OAuthClient, error)
	GetOAuthClientByID(ctx context.Context, id, tenantID uuid.UUID) (OAuthClient, error)
	ListOAuthClientsByTenant(ctx context.Context, tenantID uuid.UUID) ([]OAuthClient, error)
	UpdateOAuthClient(ctx context.Context, id, tenantID uuid.UUID, in UpdateOAuthClientInput) error
	DeleteOAuthClient(ctx context.Context, id, tenantID uuid.UUID) error

	CreateAuthorizationCode(ctx context.Context, code AuthorizationCode) (AuthorizationCode, error)
	GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (AuthorizationCode, error)
	ConsumeAuthorizationCode(ctx context.Context, codeHash string) error

	UpsertConsentGrant(ctx context.Context, userID, tenantID uuid.UUID, clientID string, scopes []string) (ConsentGrant, error)
	GetConsentGrant(ctx context.Context, userID uuid.UUID, clientID string) (ConsentGrant, error)
	RevokeConsentGrant(ctx context.Context, userID uuid.UUID, clientID string) error
}
