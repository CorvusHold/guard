package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
)

// OIDCProvider implements the SSOProvider interface for OpenID Connect.
type OIDCProvider struct {
	config       *domain.Config
	provider     *oidc.Provider
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// NewOIDCProvider creates a new OIDC provider instance.
// It performs OIDC discovery to fetch the provider's configuration
// and sets up token verification.
func NewOIDCProvider(ctx context.Context, config *domain.Config) (*OIDCProvider, error) {
	if err := validateOIDCConfig(config); err != nil {
		return nil, fmt.Errorf("invalid OIDC configuration: %w", err)
	}

	// Discover OIDC configuration from issuer
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC configuration from %s: %w", config.Issuer, err)
	}

	// Build OAuth2 configuration
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}

	// If scopes are not configured, use default OIDC scopes
	if len(oauth2Config.Scopes) == 0 {
		oauth2Config.Scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	return &OIDCProvider{
		config:       config,
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
	}, nil
}

// Type returns the provider type.
func (p *OIDCProvider) Type() domain.ProviderType {
	return domain.ProviderTypeOIDC
}

// ValidateConfig validates the OIDC provider configuration.
func (p *OIDCProvider) ValidateConfig() error {
	return validateOIDCConfig(p.config)
}

// validateOIDCConfig validates the OIDC configuration.
func validateOIDCConfig(config *domain.Config) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}
	if config.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if config.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if config.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	return nil
}

// Start initiates the OIDC authentication flow.
// It generates a secure nonce, PKCE verifier, state (if not provided),
// and returns the authorization URL.
func (p *OIDCProvider) Start(ctx context.Context, opts domain.StartOptions) (*domain.StartResult, error) {
	// Generate nonce for replay protection
	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Generate PKCE verifier and challenge
	pkceVerifier, err := generatePKCEVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	pkceChallenge := generatePKCEChallenge(pkceVerifier)

	// Generate state if not provided
	state := opts.State
	if state == "" {
		state, err = generateState()
		if err != nil {
			return nil, fmt.Errorf("failed to generate state: %w", err)
		}
	}

	// Build authorization URL options
	authCodeOpts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}

	// Add optional parameters
	if opts.ForceAuthn {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("prompt", "login"))
	}
	if opts.LoginHint != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("login_hint", opts.LoginHint))
	}

	// Use custom scopes if provided, otherwise use config scopes
	scopes := p.oauth2Config.Scopes
	if len(opts.Scopes) > 0 {
		scopes = opts.Scopes
	}

	// Build the authorization URL
	oauth2Config := *p.oauth2Config
	oauth2Config.RedirectURL = opts.RedirectURL
	oauth2Config.Scopes = scopes

	authURL := oauth2Config.AuthCodeURL(state, authCodeOpts...)

	return &domain.StartResult{
		AuthorizationURL: authURL,
		State:            state,
		Nonce:            nonce,
		PKCEVerifier:     pkceVerifier,
	}, nil
}

// Callback handles the OIDC callback.
// It exchanges the authorization code for tokens, verifies the ID token,
// and extracts the user profile.
func (p *OIDCProvider) Callback(ctx context.Context, req domain.CallbackRequest) (*domain.Profile, error) {
	if req.Code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}
	if req.PKCEVerifier == "" {
		return nil, fmt.Errorf("PKCE verifier is required")
	}
	if req.Nonce == "" {
		return nil, fmt.Errorf("nonce is required")
	}

	// Exchange authorization code for tokens
	oauth2Config := *p.oauth2Config
	oauth2Config.RedirectURL = req.RedirectURL

	token, err := oauth2Config.Exchange(
		ctx,
		req.Code,
		oauth2.SetAuthURLParam("code_verifier", req.PKCEVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	// Verify ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce
	if idToken.Nonce != req.Nonce {
		return nil, fmt.Errorf("nonce mismatch: expected %s, got %s", req.Nonce, idToken.Nonce)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
	}

	// Build profile from claims
	profile := &domain.Profile{
		Subject:       idToken.Subject,
		RawAttributes: claims,
		IDToken:       rawIDToken,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
	}

	if token.Expiry.Unix() > 0 {
		profile.ExpiresAt = &token.Expiry
	}

	// Extract standard OIDC claims
	if email, ok := claims["email"].(string); ok {
		profile.Email = email
	}
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		profile.EmailVerified = emailVerified
	}
	if givenName, ok := claims["given_name"].(string); ok {
		profile.FirstName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		profile.LastName = familyName
	}
	if name, ok := claims["name"].(string); ok {
		profile.Name = name
	}
	if picture, ok := claims["picture"].(string); ok {
		profile.Picture = picture
	}
	if locale, ok := claims["locale"].(string); ok {
		profile.Locale = locale
	}

	// Extract groups if present
	if groups, ok := claims["groups"].([]interface{}); ok {
		profile.Groups = make([]string, 0, len(groups))
		for _, g := range groups {
			if groupStr, ok := g.(string); ok {
				profile.Groups = append(profile.Groups, groupStr)
			}
		}
	}

	// Apply custom attribute mapping if configured
	if p.config.AttributeMapping != nil && len(p.config.AttributeMapping) > 0 {
		domain.ApplyAttributeMapping(profile, p.config.AttributeMapping)
	}

	return profile, nil
}

// GetMetadata returns the OIDC provider metadata.
func (p *OIDCProvider) GetMetadata(ctx context.Context) (*domain.Metadata, error) {
	endpoint := p.provider.Endpoint()

	// Get optional fields from discovery (ignore errors)
	var claims struct {
		ScopesSupported []string `json:"scopes_supported"`
		JWKSUri         string   `json:"jwks_uri"`
	}
	_ = p.provider.Claims(&claims)

	return &domain.Metadata{
		ProviderType:          domain.ProviderTypeOIDC,
		Issuer:                p.config.Issuer,
		AuthorizationEndpoint: endpoint.AuthURL,
		TokenEndpoint:         endpoint.TokenURL,
		JWKSUri:               claims.JWKSUri,
		ScopesSupported:       claims.ScopesSupported,
	}, nil
}

// generateNonce generates a cryptographically secure random nonce.
// The nonce is used to prevent replay attacks in OIDC flows.
func generateNonce() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateState generates a cryptographically secure random state.
// The state is used for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 32) // 256 bits
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generatePKCEVerifier generates a cryptographically secure PKCE code verifier.
// The verifier must be between 43 and 128 characters.
func generatePKCEVerifier() (string, error) {
	b := make([]byte, 32) // 256 bits -> 43 characters when base64url encoded
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to read random bytes: %w", err)
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}

// generatePKCEChallenge generates the PKCE code challenge from the verifier.
// It uses the S256 method (SHA-256 hash of the verifier).
func generatePKCEChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(h.Sum(nil))
}

// FetchUserInfo fetches additional user information from the userinfo endpoint.
// This is useful when the ID token doesn't contain all the claims you need.
func (p *OIDCProvider) FetchUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	userInfo, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: accessToken,
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	var claims map[string]interface{}
	if err := userInfo.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims from user info: %w", err)
	}

	return claims, nil
}

// MarshalConfig marshals the provider config to JSON for storage.
func MarshalConfig(config *domain.Config) ([]byte, error) {
	return json.Marshal(config)
}

// UnmarshalConfig unmarshals the provider config from JSON.
func UnmarshalConfig(data []byte) (*domain.Config, error) {
	var config domain.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &config, nil
}
