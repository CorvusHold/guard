package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/corvusHold/guard/internal/oauth/domain"
)

const (
	// authorizationCodeTTL is the lifetime of an authorization code (RFC 6749 §4.1.2 recommends max 10 minutes).
	authorizationCodeTTL = 10 * time.Minute
)

// Service implements OAuth 2.0 provider business logic.
type Service struct {
	repo domain.Repository
}

// New creates a new OAuth service.
func New(repo domain.Repository) *Service {
	return &Service{repo: repo}
}

// --- Client Management ---

// CreateClient registers a new OAuth client and returns it with the raw client_secret (shown once).
func (s *Service) CreateClient(ctx context.Context, in domain.CreateOAuthClientInput) (domain.OAuthClient, string, error) {
	if in.Name == "" {
		return domain.OAuthClient{}, "", errors.New("name is required")
	}
	if len(in.RedirectURIs) == 0 {
		return domain.OAuthClient{}, "", errors.New("at least one redirect_uri is required")
	}
	if in.ClientType == "" {
		in.ClientType = "confidential"
	}
	if in.ClientType != "confidential" && in.ClientType != "public" {
		return domain.OAuthClient{}, "", errors.New("client_type must be 'confidential' or 'public'")
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{domain.ScopeOpenID, domain.ScopeProfile, domain.ScopeEmail}
	}
	if len(in.GrantTypes) == 0 {
		in.GrantTypes = []string{"authorization_code", "refresh_token"}
	}

	// Generate client_id
	clientID, err := generateClientID()
	if err != nil {
		return domain.OAuthClient{}, "", err
	}

	// Generate client_secret for confidential clients
	var rawSecret string
	var secretHash string
	if in.ClientType == "confidential" {
		rawSecret, err = generateClientSecret()
		if err != nil {
			return domain.OAuthClient{}, "", err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
		if err != nil {
			return domain.OAuthClient{}, "", err
		}
		secretHash = string(hash)
	}

	client := domain.OAuthClient{
		ID:               uuid.New(),
		TenantID:         in.TenantID,
		ClientID:         clientID,
		ClientSecretHash: secretHash,
		ClientType:       in.ClientType,
		Name:             in.Name,
		RedirectURIs:     in.RedirectURIs,
		Scopes:           in.Scopes,
		GrantTypes:       in.GrantTypes,
		LogoURI:          in.LogoURI,
		IsActive:         true,
		CreatedBy:        in.CreatedBy,
	}

	created, err := s.repo.CreateOAuthClient(ctx, client)
	if err != nil {
		return domain.OAuthClient{}, "", err
	}
	return created, rawSecret, nil
}

// GetClient retrieves an OAuth client by ID within a tenant.
func (s *Service) GetClient(ctx context.Context, id, tenantID uuid.UUID) (domain.OAuthClient, error) {
	return s.repo.GetOAuthClientByID(ctx, id, tenantID)
}

// GetClientByClientID retrieves an active OAuth client by its public client_id.
func (s *Service) GetClientByClientID(ctx context.Context, clientID string) (domain.OAuthClient, error) {
	return s.repo.GetOAuthClientByClientID(ctx, clientID)
}

// ListClients returns all OAuth clients for a tenant.
func (s *Service) ListClients(ctx context.Context, tenantID uuid.UUID) ([]domain.OAuthClient, error) {
	return s.repo.ListOAuthClientsByTenant(ctx, tenantID)
}

// UpdateClient updates an OAuth client.
func (s *Service) UpdateClient(ctx context.Context, id, tenantID uuid.UUID, in domain.UpdateOAuthClientInput) error {
	return s.repo.UpdateOAuthClient(ctx, id, tenantID, in)
}

// DeleteClient deletes an OAuth client.
func (s *Service) DeleteClient(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.repo.DeleteOAuthClient(ctx, id, tenantID)
}

// --- Authorization Code Flow ---

// ValidateAuthorizeRequest validates the parameters of an authorization request.
func (s *Service) ValidateAuthorizeRequest(ctx context.Context, in domain.AuthorizeInput) (domain.OAuthClient, error) {
	if in.ClientID == "" {
		return domain.OAuthClient{}, errors.New("client_id is required")
	}
	if in.ResponseType != "code" {
		return domain.OAuthClient{}, errors.New("unsupported response_type; only 'code' is supported")
	}
	if in.RedirectURI == "" {
		return domain.OAuthClient{}, errors.New("redirect_uri is required")
	}

	client, err := s.repo.GetOAuthClientByClientID(ctx, in.ClientID)
	if err != nil {
		return domain.OAuthClient{}, errors.New("invalid client_id")
	}

	// Validate redirect_uri
	if !isValidRedirectURI(client.RedirectURIs, in.RedirectURI) {
		return domain.OAuthClient{}, errors.New("redirect_uri does not match registered URIs")
	}

	// Validate scopes
	requestedScopes := parseScopes(in.Scope)
	for _, scope := range requestedScopes {
		if !containsString(client.Scopes, scope) {
			return domain.OAuthClient{}, errors.New("requested scope '" + scope + "' not allowed for this client")
		}
	}

	// PKCE required for public clients
	if client.ClientType == "public" && in.CodeChallenge == "" {
		return domain.OAuthClient{}, errors.New("code_challenge is required for public clients (PKCE)")
	}
	if in.CodeChallenge != "" && in.CodeChallengeMethod != "S256" {
		return domain.OAuthClient{}, errors.New("only S256 code_challenge_method is supported")
	}

	// Validate grant type
	if !containsString(client.GrantTypes, "authorization_code") {
		return domain.OAuthClient{}, errors.New("client is not authorized for authorization_code grant")
	}

	return client, nil
}

// CreateAuthorizationCode generates and stores a new authorization code.
func (s *Service) CreateAuthorizationCode(ctx context.Context, in domain.AuthorizeInput) (domain.AuthorizeResult, error) {
	// Generate random code
	rawCode, err := generateAuthorizationCode()
	if err != nil {
		return domain.AuthorizeResult{}, err
	}

	// Hash the code for storage
	h := sha256.Sum256([]byte(rawCode))
	codeHash := base64.RawURLEncoding.EncodeToString(h[:])

	scopes := parseScopes(in.Scope)
	if len(scopes) == 0 {
		scopes = []string{domain.ScopeOpenID}
	}

	code := domain.AuthorizationCode{
		ID:                  uuid.New(),
		ClientID:            in.ClientID,
		UserID:              in.UserID,
		TenantID:            in.TenantID,
		CodeHash:            codeHash,
		RedirectURI:         in.RedirectURI,
		Scopes:              scopes,
		Nonce:               in.Nonce,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: in.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(authorizationCodeTTL),
	}

	if _, err := s.repo.CreateAuthorizationCode(ctx, code); err != nil {
		return domain.AuthorizeResult{}, err
	}

	return domain.AuthorizeResult{
		Code:        rawCode,
		State:       in.State,
		RedirectURI: in.RedirectURI,
	}, nil
}

// ExchangeAuthorizationCode validates and exchanges an authorization code for tokens.
// Returns the code details; the caller (controller) is responsible for issuing tokens.
func (s *Service) ExchangeAuthorizationCode(ctx context.Context, req domain.TokenRequest) (domain.AuthorizationCode, domain.OAuthClient, error) {
	if req.Code == "" {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("code is required")
	}
	if req.RedirectURI == "" {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("redirect_uri is required")
	}
	if req.ClientID == "" {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("client_id is required")
	}

	// Hash the code to look it up
	h := sha256.Sum256([]byte(req.Code))
	codeHash := base64.RawURLEncoding.EncodeToString(h[:])

	code, err := s.repo.GetAuthorizationCodeByHash(ctx, codeHash)
	if err != nil {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("invalid or expired authorization code")
	}

	// Validate client_id matches
	if code.ClientID != req.ClientID {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("client_id mismatch")
	}

	// Validate redirect_uri matches exactly
	if code.RedirectURI != req.RedirectURI {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("redirect_uri mismatch")
	}

	// Get the client
	client, err := s.repo.GetOAuthClientByClientID(ctx, req.ClientID)
	if err != nil {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("invalid client")
	}

	// Authenticate confidential clients
	if client.ClientType == "confidential" {
		if req.ClientSecret == "" {
			return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("client_secret is required for confidential clients")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(req.ClientSecret)); err != nil {
			return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("invalid client_secret")
		}
	}

	// Validate PKCE code_verifier
	if code.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("code_verifier is required")
		}
		challenge := computeS256Challenge(req.CodeVerifier)
		if challenge != code.CodeChallenge {
			return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("invalid code_verifier")
		}
	}

	// Consume the code (single-use)
	if err := s.repo.ConsumeAuthorizationCode(ctx, codeHash); err != nil {
		return domain.AuthorizationCode{}, domain.OAuthClient{}, errors.New("failed to consume authorization code")
	}

	return code, client, nil
}

// AuthenticateClient validates client credentials for client_credentials grant.
func (s *Service) AuthenticateClient(ctx context.Context, clientID, clientSecret string) (domain.OAuthClient, error) {
	if clientID == "" || clientSecret == "" {
		return domain.OAuthClient{}, errors.New("client_id and client_secret are required")
	}

	client, err := s.repo.GetOAuthClientByClientID(ctx, clientID)
	if err != nil {
		return domain.OAuthClient{}, errors.New("invalid client")
	}

	if client.ClientType != "confidential" {
		return domain.OAuthClient{}, errors.New("client_credentials grant requires a confidential client")
	}

	if !containsString(client.GrantTypes, "client_credentials") {
		return domain.OAuthClient{}, errors.New("client is not authorized for client_credentials grant")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(clientSecret)); err != nil {
		return domain.OAuthClient{}, errors.New("invalid client_secret")
	}

	return client, nil
}

// --- Helpers ---

func generateClientID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "gc_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "gcs_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func generateAuthorizationCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	parts := strings.Fields(scope)
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func containsString(arr []string, s string) bool {
	for _, v := range arr {
		if v == s {
			return true
		}
	}
	return false
}

func isValidRedirectURI(registered []string, uri string) bool {
	for _, r := range registered {
		if r == uri {
			return true
		}
	}
	return false
}

// HasConsent checks if the user has previously granted consent for the given client and scopes.
// Returns true if all requested scopes are covered by an existing grant.
func (s *Service) HasConsent(ctx context.Context, userID uuid.UUID, clientID string, scopes []string) bool {
	grant, err := s.repo.GetConsentGrant(ctx, userID, clientID)
	if err != nil {
		return false
	}
	for _, scope := range scopes {
		if !containsString(grant.Scopes, scope) {
			return false
		}
	}
	return true
}

// SaveConsent persists a user's consent for a client+scopes combination.
func (s *Service) SaveConsent(ctx context.Context, userID, tenantID uuid.UUID, clientID string, scopes []string) error {
	_, err := s.repo.UpsertConsentGrant(ctx, userID, tenantID, clientID, scopes)
	return err
}

// RevokeConsent revokes a user's consent for a client.
func (s *Service) RevokeConsent(ctx context.Context, userID uuid.UUID, clientID string) error {
	return s.repo.RevokeConsentGrant(ctx, userID, clientID)
}
