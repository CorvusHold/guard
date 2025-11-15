package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
	"github.com/corvusHold/guard/internal/auth/sso/provider"
	"github.com/corvusHold/guard/internal/auth/sso/state"
	authdomain "github.com/corvusHold/guard/internal/auth/domain"
	db "github.com/corvusHold/guard/internal/db/sqlc"
	evdomain "github.com/corvusHold/guard/internal/events/domain"
	"github.com/corvusHold/guard/internal/metrics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// SSOService orchestrates SSO authentication flows.
type SSOService struct {
	pool         *pgxpool.Pool
	queries      *db.Queries
	stateManager state.StateManager
	providers    map[uuid.UUID]domain.SSOProvider // Cache of initialized providers
	mu           sync.RWMutex
	baseURL      string
	log          zerolog.Logger
	pub          evdomain.Publisher
}

// New creates a new SSO service.
func New(pool *pgxpool.Pool, redisClient *redis.Client, baseURL string) *SSOService {
	return &SSOService{
		pool:         pool,
		queries:      db.New(pool),
		stateManager: state.NewRedisStateManager(redisClient, "sso:state:", 10*time.Minute),
		providers:    make(map[uuid.UUID]domain.SSOProvider),
		baseURL:      strings.TrimSuffix(baseURL, "/"),
		log:          zerolog.Nop(),
	}
}

// SetLogger sets the logger for the service.
func (s *SSOService) SetLogger(log zerolog.Logger) {
	s.log = log
}

// SetPublisher sets the event publisher for the service.
func (s *SSOService) SetPublisher(pub evdomain.Publisher) {
	s.pub = pub
}

// InitiateSSORequest contains the request parameters for initiating SSO.
type InitiateSSORequest struct {
	TenantID    uuid.UUID
	ProviderSlug string
	RedirectURL string
	IPAddress   string
	UserAgent   string
	LoginHint   string
	ForceAuthn  bool
}

// InitiateSSOResponse contains the response for initiating SSO.
type InitiateSSOResponse struct {
	AuthorizationURL string
	State            string
}

// InitiateSSO initiates an SSO authentication flow.
func (s *SSOService) InitiateSSO(ctx context.Context, req InitiateSSORequest) (*InitiateSSOResponse, error) {
	s.log.Info().
		Str("provider_slug", req.ProviderSlug).
		Str("tenant_id", req.TenantID.String()).
		Str("ip_address", req.IPAddress).
		Msg("initiating SSO flow")

	// Validate provider slug
	if err := domain.ValidateProviderSlug(req.ProviderSlug); err != nil {
		s.log.Warn().Err(err).Str("slug", req.ProviderSlug).Msg("invalid provider slug")
		return nil, domain.ErrConfigValidation{Field: "slug", Message: err.Error()}
	}

	// Load provider configuration
	config, err := s.getProviderBySlug(ctx, req.TenantID, req.ProviderSlug)
	if err != nil {
		s.log.Warn().Err(err).Str("slug", req.ProviderSlug).Msg("provider not found")
		return nil, domain.ErrProviderNotFound{ProviderSlug: req.ProviderSlug}
	}

	// Check if provider is enabled
	if !config.Enabled {
		s.log.Warn().
			Str("provider_slug", config.Slug).
			Str("provider_id", config.ID.String()).
			Msg("provider is disabled")
		return nil, domain.ErrProviderDisabled{ProviderSlug: config.Slug}
	}

	// Get or initialize provider
	provider, err := s.getOrInitProvider(ctx, config)
	if err != nil {
		s.log.Error().Err(err).
			Str("provider_id", config.ID.String()).
			Msg("failed to initialize provider")
		return nil, fmt.Errorf("failed to initialize provider: %w", err)
	}

	// Generate state token
	stateToken, err := state.GenerateStateToken()
	if err != nil {
		s.log.Error().Err(err).Msg("failed to generate state token")
		return nil, fmt.Errorf("failed to generate state token: %w", err)
	}

	// Build callback URL
	callbackURL := fmt.Sprintf("%s/auth/sso/%s/callback", s.baseURL, config.Slug)

	// Start SSO flow
	startOpts := domain.StartOptions{
		RedirectURL: callbackURL,
		State:       stateToken,
		Scopes:      config.Scopes,
		ForceAuthn:  req.ForceAuthn || config.ForceAuthn,
		LoginHint:   req.LoginHint,
	}

	result, err := provider.Start(ctx, startOpts)
	if err != nil {
		s.log.Error().Err(err).
			Str("provider_id", config.ID.String()).
			Msg("failed to start SSO flow")
		return nil, fmt.Errorf("failed to start SSO flow: %w", err)
	}

	// Store state in Redis
	stateData := &state.State{
		Token:        result.State,
		ProviderID:   config.ID,
		TenantID:     req.TenantID,
		Nonce:        result.Nonce,
		PKCEVerifier: result.PKCEVerifier,
		RedirectURL:  req.RedirectURL,
		RelayState:   result.RelayState,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
	}

	if err := s.stateManager.CreateState(ctx, stateData); err != nil {
		s.log.Error().Err(err).Msg("failed to store state")
		return nil, fmt.Errorf("failed to store state: %w", err)
	}

	// Create auth attempt record for auditing
	if err := s.createAuthAttempt(ctx, config.ID, req.TenantID, result.State, req.IPAddress, req.UserAgent); err != nil {
		s.log.Warn().Err(err).Msg("failed to create auth attempt record")
	}

	// Record metrics
	metrics.IncSSOInitiate(string(config.ProviderType), config.Slug, req.TenantID.String())

	s.log.Info().
		Str("provider_id", config.ID.String()).
		Str("provider_slug", config.Slug).
		Str("provider_type", string(config.ProviderType)).
		Str("tenant_id", req.TenantID.String()).
		Msg("SSO flow initiated successfully")

	return &InitiateSSOResponse{
		AuthorizationURL: result.AuthorizationURL,
		State:            result.State,
	}, nil
}

// CallbackRequest contains the request parameters for handling SSO callback.
type CallbackRequest struct {
	TenantID     uuid.UUID
	ProviderSlug string
	Code         string
	State        string
	SAMLResponse string
	RelayState   string
	IPAddress    string
	UserAgent    string
}

// CallbackResponse contains the response for handling SSO callback.
type CallbackResponse struct {
	User         *authdomain.User
	Profile      *domain.Profile
	IsNewUser    bool
	IdentityID   uuid.UUID
	SessionToken string // Optional: generated session token
}

// HandleCallback handles the SSO callback from the identity provider.
func (s *SSOService) HandleCallback(ctx context.Context, req CallbackRequest) (*CallbackResponse, error) {
	start := time.Now()
	var config *domain.Config
	var callbackErr error

	// Defer metrics and audit event publishing
	defer func() {
		if config != nil {
			status := "success"
			if callbackErr != nil {
				status = "failure"
			}
			metrics.IncSSOCallback(string(config.ProviderType), config.Slug, status)
			metrics.ObserveSSOAuthDuration(string(config.ProviderType), status, time.Since(start).Seconds())
		}
	}()

	// Verify and retrieve state (atomic get-delete to prevent replay)
	stateToken := req.State
	if stateToken == "" && req.RelayState != "" {
		// SAML uses RelayState
		stateToken = req.RelayState
	}

	stateData, err := s.stateManager.GetAndDelete(ctx, stateToken)
	if err != nil {
		s.log.Warn().Err(err).Str("state", stateToken).Msg("invalid or expired state")
		callbackErr = domain.ErrInvalidState{}
		return nil, callbackErr
	}

	// Verify tenant ID matches
	if stateData.TenantID != req.TenantID {
		s.log.Warn().
			Str("state_tenant_id", stateData.TenantID.String()).
			Str("request_tenant_id", req.TenantID.String()).
			Msg("tenant ID mismatch in SSO callback")
		callbackErr = fmt.Errorf("tenant ID mismatch")
		return nil, callbackErr
	}

	// Load provider configuration
	config, err = s.getProviderByID(ctx, req.TenantID, stateData.ProviderID)
	if err != nil {
		s.log.Error().Err(err).
			Str("provider_id", stateData.ProviderID.String()).
			Msg("failed to load provider")
		callbackErr = domain.ErrProviderNotFound{ProviderSlug: stateData.ProviderID.String()}
		return nil, callbackErr
	}

	// IP/UserAgent validation - log warnings if mismatch (non-blocking)
	if stateData.IPAddress != "" && stateData.IPAddress != req.IPAddress {
		s.log.Warn().
			Str("stored_ip", stateData.IPAddress).
			Str("request_ip", req.IPAddress).
			Str("provider_slug", config.Slug).
			Msg("IP address mismatch in SSO callback")
	}

	if stateData.UserAgent != "" && stateData.UserAgent != req.UserAgent {
		s.log.Warn().
			Str("stored_user_agent", stateData.UserAgent).
			Str("request_user_agent", req.UserAgent).
			Str("provider_slug", config.Slug).
			Msg("User agent mismatch in SSO callback")
	}

	// Get or initialize provider
	provider, err := s.getOrInitProvider(ctx, config)
	if err != nil {
		s.log.Error().Err(err).
			Str("provider_id", config.ID.String()).
			Msg("failed to initialize provider")
		callbackErr = fmt.Errorf("failed to initialize provider: %w", err)

		// Publish failure audit event
		_ = s.pub.Publish(ctx, evdomain.Event{
			Type:     "auth.sso.login.failure",
			TenantID: req.TenantID,
			UserID:   uuid.Nil,
			Meta: map[string]string{
				"provider_type": string(config.ProviderType),
				"provider_slug": config.Slug,
				"provider_id":   config.ID.String(),
				"error_code":    "provider_init_failed",
				"error_message": err.Error(),
				"ip":            req.IPAddress,
				"user_agent":    req.UserAgent,
			},
			Time: time.Now(),
		})

		return nil, callbackErr
	}

	// Build callback URL
	callbackURL := fmt.Sprintf("%s/auth/sso/%s/callback", s.baseURL, config.Slug)

	// Call provider callback handler
	callbackReq := domain.CallbackRequest{
		Code:         req.Code,
		State:        req.State,
		Nonce:        stateData.Nonce,
		PKCEVerifier: stateData.PKCEVerifier,
		SAMLResponse: req.SAMLResponse,
		RelayState:   req.RelayState,
		RedirectURL:  callbackURL,
	}

	profile, err := provider.Callback(ctx, callbackReq)
	if err != nil {
		s.log.Error().Err(err).
			Str("provider_id", config.ID.String()).
			Msg("provider callback failed")
		s.updateAuthAttempt(ctx, stateData.ProviderID, stateToken, "failed", "callback_error", err.Error(), nil)
		callbackErr = fmt.Errorf("provider callback failed: %w", err)

		// Publish failure audit event
		_ = s.pub.Publish(ctx, evdomain.Event{
			Type:     "auth.sso.login.failure",
			TenantID: req.TenantID,
			UserID:   uuid.Nil,
			Meta: map[string]string{
				"provider_type": string(config.ProviderType),
				"provider_slug": config.Slug,
				"provider_id":   config.ID.String(),
				"error_code":    "callback_error",
				"error_message": err.Error(),
				"ip":            req.IPAddress,
				"user_agent":    req.UserAgent,
			},
			Time: time.Now(),
		})

		return nil, callbackErr
	}

	// Validate email domain if configured using domain.IsEmailDomainAllowed
	if !domain.IsEmailDomainAllowed(profile.Email, config.Domains) {
		emailDomain := domain.ExtractEmailDomain(profile.Email)
		s.log.Warn().
			Str("email", profile.Email).
			Str("domain", emailDomain).
			Strs("allowed_domains", config.Domains).
			Str("provider_slug", config.Slug).
			Msg("email domain not allowed")
		s.updateAuthAttempt(ctx, stateData.ProviderID, stateToken, "failed", "domain_not_allowed", "email domain not allowed", nil)
		callbackErr = domain.ErrDomainNotAllowed{
			Email:          profile.Email,
			Domain:         emailDomain,
			AllowedDomains: config.Domains,
		}

		// Publish failure audit event
		_ = s.pub.Publish(ctx, evdomain.Event{
			Type:     "auth.sso.login.failure",
			TenantID: req.TenantID,
			UserID:   uuid.Nil,
			Meta: map[string]string{
				"provider_type": string(config.ProviderType),
				"provider_slug": config.Slug,
				"provider_id":   config.ID.String(),
				"error_code":    "domain_not_allowed",
				"error_message": callbackErr.Error(),
				"email":         profile.Email,
				"domain":        emailDomain,
				"ip":            req.IPAddress,
				"user_agent":    req.UserAgent,
			},
			Time: time.Now(),
		})

		return nil, callbackErr
	}

	// Link or create user
	linker := NewIdentityLinker(s.pool, s.queries, s.log)
	linkResult, err := linker.LinkOrCreateUser(ctx, LinkOrCreateUserRequest{
		TenantID:           req.TenantID,
		ProviderID:         config.ID,
		Profile:            profile,
		AllowSignup:        config.AllowSignup,
		TrustEmailVerified: config.TrustEmailVerified,
	})
	if err != nil {
		s.log.Error().Err(err).
			Str("provider_id", config.ID.String()).
			Str("email", profile.Email).
			Msg("failed to link user")
		s.updateAuthAttempt(ctx, stateData.ProviderID, stateToken, "failed", "user_link_error", err.Error(), nil)
		callbackErr = fmt.Errorf("failed to link user: %w", err)

		// Publish failure audit event
		_ = s.pub.Publish(ctx, evdomain.Event{
			Type:     "auth.sso.login.failure",
			TenantID: req.TenantID,
			UserID:   uuid.Nil,
			Meta: map[string]string{
				"provider_type": string(config.ProviderType),
				"provider_slug": config.Slug,
				"provider_id":   config.ID.String(),
				"error_code":    "user_link_error",
				"error_message": err.Error(),
				"email":         profile.Email,
				"ip":            req.IPAddress,
				"user_agent":    req.UserAgent,
			},
			Time: time.Now(),
		})

		return nil, callbackErr
	}

	// Update auth attempt with success
	s.updateAuthAttempt(ctx, stateData.ProviderID, stateToken, "success", "", "", &linkResult.User.ID)

	// Create SSO session
	if err := s.createSSOSession(ctx, req.TenantID, config.ID, linkResult.User.ID, profile); err != nil {
		s.log.Warn().Err(err).Msg("failed to create SSO session record")
	}

	s.log.Info().
		Str("provider_id", config.ID.String()).
		Str("provider_slug", config.Slug).
		Str("user_id", linkResult.User.ID.String()).
		Bool("is_new_user", linkResult.IsNewUser).
		Msg("SSO callback successful")

	// Publish success audit event
	_ = s.pub.Publish(ctx, evdomain.Event{
		Type:     "auth.sso.login.success",
		TenantID: req.TenantID,
		UserID:   linkResult.User.ID,
		Meta: map[string]string{
			"provider_type": string(config.ProviderType),
			"provider_slug": config.Slug,
			"provider_id":   config.ID.String(),
			"is_new_user":   fmt.Sprintf("%v", linkResult.IsNewUser),
			"email":         profile.Email,
			"ip":            req.IPAddress,
			"user_agent":    req.UserAgent,
		},
		Time: time.Now(),
	})

	return &CallbackResponse{
		User:       linkResult.User,
		Profile:    profile,
		IsNewUser:  linkResult.IsNewUser,
		IdentityID: linkResult.IdentityID,
	}, nil
}

// GetProviderMetadata returns provider metadata (for SAML SP metadata endpoint).
func (s *SSOService) GetProviderMetadata(ctx context.Context, tenantID uuid.UUID, providerSlug string) (*domain.Metadata, error) {
	// Load provider configuration
	config, err := s.getProviderBySlug(ctx, tenantID, providerSlug)
	if err != nil {
		return nil, fmt.Errorf("failed to load provider: %w", err)
	}

	// Get or initialize provider
	provider, err := s.getOrInitProvider(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize provider: %w", err)
	}

	// Get metadata
	metadata, err := provider.GetMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %w", err)
	}

	return metadata, nil
}

// Admin methods

// CreateProviderRequest contains the request parameters for creating a provider.
type CreateProviderRequest struct {
	TenantID           uuid.UUID
	Name               string
	Slug               string
	ProviderType       domain.ProviderType
	Enabled            bool
	AllowSignup        bool
	TrustEmailVerified bool
	Domains            []string
	AttributeMapping   map[string][]string
	CreatedBy          uuid.UUID

	// OIDC/OAuth2 fields
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

	// SAML fields
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
}

// CreateProvider creates a new SSO provider configuration.
func (s *SSOService) CreateProvider(ctx context.Context, req CreateProviderRequest) (*domain.Config, error) {
	// Build domain config for validation
	config := s.buildConfig(req)

	// Initialize provider to test configuration
	provider, err := s.initializeProvider(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to validate provider configuration: %w", err)
	}

	// Validate configuration
	if err := provider.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid provider configuration: %w", err)
	}

	// Marshal attribute mapping
	var attributeMappingJSON []byte
	if len(req.AttributeMapping) > 0 {
		attributeMappingJSON, err = json.Marshal(req.AttributeMapping)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attribute mapping: %w", err)
		}
	}

	// Convert domain config to DB params
	dbProvider, err := s.queries.CreateSSOProvider(ctx, db.CreateSSOProviderParams{
		TenantID:               toPgUUID(req.TenantID),
		Name:                   req.Name,
		Slug:                   req.Slug,
		ProviderType:           string(req.ProviderType),
		Issuer:                 toPgText(req.Issuer),
		AuthorizationEndpoint:  toPgText(req.AuthorizationEndpoint),
		TokenEndpoint:          toPgText(req.TokenEndpoint),
		UserinfoEndpoint:       toPgText(req.UserinfoEndpoint),
		JwksUri:                toPgText(req.JWKSUri),
		ClientID:               toPgText(req.ClientID),
		ClientSecret:           toPgText(req.ClientSecret),
		Scopes:                 req.Scopes,
		ResponseType:           toPgText(req.ResponseType),
		ResponseMode:           toPgText(req.ResponseMode),
		EntityID:               toPgText(req.EntityID),
		AcsUrl:                 toPgText(req.ACSUrl),
		SloUrl:                 toPgText(req.SLOUrl),
		IdpMetadataUrl:         toPgText(req.IdPMetadataURL),
		IdpMetadataXml:         toPgText(req.IdPMetadataXML),
		IdpEntityID:            toPgText(req.IdPEntityID),
		IdpSsoUrl:              toPgText(req.IdPSSOUrl),
		IdpSloUrl:              toPgText(req.IdPSLOUrl),
		IdpCertificate:         toPgText(req.IdPCertificate),
		SpCertificate:          toPgText(req.SPCertificate),
		SpPrivateKey:           toPgText(req.SPPrivateKey),
		SpCertificateExpiresAt: toPgTimestamp(req.SPCertificateExpiresAt),
		WantAssertionsSigned:   toPgBool(req.WantAssertionsSigned),
		WantResponseSigned:     toPgBool(req.WantResponseSigned),
		SignRequests:           toPgBool(req.SignRequests),
		ForceAuthn:             toPgBool(req.ForceAuthn),
		AttributeMapping:       attributeMappingJSON,
		Enabled:                toPgBool(req.Enabled),
		AllowSignup:            toPgBool(req.AllowSignup),
		TrustEmailVerified:     toPgBool(req.TrustEmailVerified),
		Domains:                req.Domains,
		CreatedBy:              toPgUUID(req.CreatedBy),
		UpdatedBy:              toPgUUID(req.CreatedBy),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	// Convert DB model to domain model
	createdConfig := s.dbProviderToConfig(dbProvider)

	// Cache the provider
	s.mu.Lock()
	s.providers[createdConfig.ID] = provider
	s.mu.Unlock()

	s.log.Info().
		Str("provider_id", createdConfig.ID.String()).
		Str("provider_type", string(createdConfig.ProviderType)).
		Str("name", createdConfig.Name).
		Msg("SSO provider created")

	return createdConfig, nil
}

// GetProvider retrieves a provider configuration by ID.
func (s *SSOService) GetProvider(ctx context.Context, tenantID, providerID uuid.UUID) (*domain.Config, error) {
	return s.getProviderByID(ctx, tenantID, providerID)
}

// ListProviders lists all providers for a tenant.
func (s *SSOService) ListProviders(ctx context.Context, tenantID uuid.UUID, limit, offset int32) ([]*domain.Config, error) {
	dbProviders, err := s.queries.ListSSOProviders(ctx, db.ListSSOProvidersParams{
		TenantID: toPgUUID(tenantID),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list providers: %w", err)
	}

	configs := make([]*domain.Config, 0, len(dbProviders))
	for _, dbProvider := range dbProviders {
		configs = append(configs, s.dbProviderToConfig(dbProvider))
	}

	return configs, nil
}

// DeleteProvider deletes a provider configuration.
func (s *SSOService) DeleteProvider(ctx context.Context, tenantID, providerID uuid.UUID) error {
	// Remove from cache
	s.mu.Lock()
	delete(s.providers, providerID)
	s.mu.Unlock()

	// Delete from database
	if err := s.queries.DeleteSSOProvider(ctx, db.DeleteSSOProviderParams{
		ID:       toPgUUID(providerID),
		TenantID: toPgUUID(tenantID),
	}); err != nil {
		return fmt.Errorf("failed to delete provider: %w", err)
	}

	s.log.Info().
		Str("provider_id", providerID.String()).
		Msg("SSO provider deleted")

	return nil
}

// UpdateProviderRequest contains the request parameters for updating a provider.
// All fields except ID and TenantID are optional. Nil values mean "don't update".
type UpdateProviderRequest struct {
	Name                   *string
	Enabled                *bool
	AllowSignup            *bool
	TrustEmailVerified     *bool
	Domains                []string
	AttributeMapping       map[string][]string
	Issuer                 *string
	AuthorizationEndpoint  *string
	TokenEndpoint          *string
	UserinfoEndpoint       *string
	JWKSUri                *string
	ClientID               *string
	ClientSecret           *string
	Scopes                 []string
	ResponseType           *string
	ResponseMode           *string
	EntityID               *string
	ACSUrl                 *string
	SLOUrl                 *string
	IdPMetadataURL         *string
	IdPMetadataXML         *string
	IdPEntityID            *string
	IdPSSOUrl              *string
	IdPSLOUrl              *string
	IdPCertificate         *string
	SPCertificate          *string
	SPPrivateKey           *string
	SPCertificateExpiresAt *time.Time
	WantAssertionsSigned   *bool
	WantResponseSigned     *bool
	SignRequests           *bool
	ForceAuthn             *bool
}

// UpdateProvider updates an existing provider configuration.
func (s *SSOService) UpdateProvider(ctx context.Context, tenantID, providerID uuid.UUID, req UpdateProviderRequest) (*domain.Config, error) {
	// Load existing provider
	existing, err := s.GetProvider(ctx, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to load provider: %w", err)
	}

	// Merge updates (only non-nil fields)
	updated := *existing // Copy the existing config

	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.AllowSignup != nil {
		updated.AllowSignup = *req.AllowSignup
	}
	if req.TrustEmailVerified != nil {
		updated.TrustEmailVerified = *req.TrustEmailVerified
	}
	if req.Domains != nil {
		updated.Domains = req.Domains
	}
	if req.AttributeMapping != nil {
		updated.AttributeMapping = req.AttributeMapping
	}

	// OIDC fields
	if req.Issuer != nil {
		updated.Issuer = *req.Issuer
	}
	if req.AuthorizationEndpoint != nil {
		updated.AuthorizationEndpoint = *req.AuthorizationEndpoint
	}
	if req.TokenEndpoint != nil {
		updated.TokenEndpoint = *req.TokenEndpoint
	}
	if req.UserinfoEndpoint != nil {
		updated.UserinfoEndpoint = *req.UserinfoEndpoint
	}
	if req.JWKSUri != nil {
		updated.JWKSUri = *req.JWKSUri
	}
	if req.ClientID != nil {
		updated.ClientID = *req.ClientID
	}
	if req.ClientSecret != nil {
		updated.ClientSecret = *req.ClientSecret
	}
	if req.Scopes != nil {
		updated.Scopes = req.Scopes
	}
	if req.ResponseType != nil {
		updated.ResponseType = *req.ResponseType
	}
	if req.ResponseMode != nil {
		updated.ResponseMode = *req.ResponseMode
	}

	// SAML fields
	if req.EntityID != nil {
		updated.EntityID = *req.EntityID
	}
	if req.ACSUrl != nil {
		updated.ACSUrl = *req.ACSUrl
	}
	if req.SLOUrl != nil {
		updated.SLOUrl = *req.SLOUrl
	}
	if req.IdPMetadataURL != nil {
		updated.IdPMetadataURL = *req.IdPMetadataURL
	}
	if req.IdPMetadataXML != nil {
		updated.IdPMetadataXML = *req.IdPMetadataXML
	}
	if req.IdPEntityID != nil {
		updated.IdPEntityID = *req.IdPEntityID
	}
	if req.IdPSSOUrl != nil {
		updated.IdPSSOUrl = *req.IdPSSOUrl
	}
	if req.IdPSLOUrl != nil {
		updated.IdPSLOUrl = *req.IdPSLOUrl
	}
	if req.IdPCertificate != nil {
		updated.IdPCertificate = *req.IdPCertificate
	}
	if req.SPCertificate != nil {
		updated.SPCertificate = *req.SPCertificate
	}
	if req.SPPrivateKey != nil {
		updated.SPPrivateKey = *req.SPPrivateKey
	}
	if req.SPCertificateExpiresAt != nil {
		updated.SPCertificateExpiresAt = req.SPCertificateExpiresAt
	}
	if req.WantAssertionsSigned != nil {
		updated.WantAssertionsSigned = *req.WantAssertionsSigned
	}
	if req.WantResponseSigned != nil {
		updated.WantResponseSigned = *req.WantResponseSigned
	}
	if req.SignRequests != nil {
		updated.SignRequests = *req.SignRequests
	}
	if req.ForceAuthn != nil {
		updated.ForceAuthn = *req.ForceAuthn
	}

	// Validate updated configuration by initializing provider
	provider, err := s.initializeProvider(ctx, &updated)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	if err := provider.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Update in database (using the same CreateProvider params structure)
	// We need to convert back to the database format
	var attributeMappingJSON []byte
	if updated.AttributeMapping != nil {
		attributeMappingJSON, _ = json.Marshal(updated.AttributeMapping)
	}

	// Update the provider in the database
	updateParams := db.UpdateSSOProviderParams{
		ID:                     toPgUUID(providerID),
		TenantID:               toPgUUID(tenantID),
		Name:                   toPgText(updated.Name),
		Enabled:                toPgBool(updated.Enabled),
		AllowSignup:            toPgBool(updated.AllowSignup),
		TrustEmailVerified:     toPgBool(updated.TrustEmailVerified),
		Domains:                updated.Domains,
		AttributeMapping:       attributeMappingJSON,
		Issuer:                 toPgText(updated.Issuer),
		AuthorizationEndpoint:  toPgText(updated.AuthorizationEndpoint),
		TokenEndpoint:          toPgText(updated.TokenEndpoint),
		UserinfoEndpoint:       toPgText(updated.UserinfoEndpoint),
		JwksUri:                toPgText(updated.JWKSUri),
		ClientID:               toPgText(updated.ClientID),
		ClientSecret:           toPgText(updated.ClientSecret),
		Scopes:                 updated.Scopes,
		ResponseType:           toPgText(updated.ResponseType),
		ResponseMode:           toPgText(updated.ResponseMode),
		EntityID:               toPgText(updated.EntityID),
		AcsUrl:                 toPgText(updated.ACSUrl),
		SloUrl:                 toPgText(updated.SLOUrl),
		IdpMetadataUrl:         toPgText(updated.IdPMetadataURL),
		IdpMetadataXml:         toPgText(updated.IdPMetadataXML),
		IdpEntityID:            toPgText(updated.IdPEntityID),
		IdpSsoUrl:              toPgText(updated.IdPSSOUrl),
		IdpSloUrl:              toPgText(updated.IdPSLOUrl),
		IdpCertificate:         toPgText(updated.IdPCertificate),
		SpCertificate:          toPgText(updated.SPCertificate),
		SpPrivateKey:           toPgText(updated.SPPrivateKey),
		SpCertificateExpiresAt: toPgTimestamp(updated.SPCertificateExpiresAt),
		WantAssertionsSigned:   toPgBool(updated.WantAssertionsSigned),
		WantResponseSigned:     toPgBool(updated.WantResponseSigned),
		SignRequests:           toPgBool(updated.SignRequests),
		ForceAuthn:             toPgBool(updated.ForceAuthn),
	}

	err = s.queries.UpdateSSOProvider(ctx, updateParams)
	if err != nil {
		return nil, fmt.Errorf("failed to update provider: %w", err)
	}

	// Invalidate cache
	s.mu.Lock()
	delete(s.providers, providerID)
	s.mu.Unlock()

	// Re-fetch the updated provider
	updatedConfig, err := s.GetProvider(ctx, tenantID, providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve updated provider: %w", err)
	}

	s.log.Info().
		Str("provider_id", providerID.String()).
		Str("name", updatedConfig.Name).
		Msg("SSO provider updated")

	return updatedConfig, nil
}

// Helper methods

func (s *SSOService) getProviderBySlug(ctx context.Context, tenantID uuid.UUID, slug string) (*domain.Config, error) {
	dbProvider, err := s.queries.GetSSOProviderBySlug(ctx, db.GetSSOProviderBySlugParams{
		TenantID: toPgUUID(tenantID),
		Slug:     slug,
	})
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}

	return s.dbProviderToConfig(dbProvider), nil
}

func (s *SSOService) getProviderByID(ctx context.Context, tenantID, providerID uuid.UUID) (*domain.Config, error) {
	dbProvider, err := s.queries.GetSSOProvider(ctx, db.GetSSOProviderParams{
		ID:       toPgUUID(providerID),
		TenantID: toPgUUID(tenantID),
	})
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}

	return s.dbProviderToConfig(dbProvider), nil
}

func (s *SSOService) getOrInitProvider(ctx context.Context, config *domain.Config) (domain.SSOProvider, error) {
	// Check cache first
	s.mu.RLock()
	if p, ok := s.providers[config.ID]; ok {
		s.mu.RUnlock()
		return p, nil
	}
	s.mu.RUnlock()

	// Initialize provider
	s.mu.Lock()
	defer s.mu.Unlock()

	// Double-check after acquiring write lock
	if p, ok := s.providers[config.ID]; ok {
		return p, nil
	}

	p, err := s.initializeProvider(ctx, config)
	if err != nil {
		return nil, err
	}

	s.providers[config.ID] = p
	return p, nil
}

func (s *SSOService) initializeProvider(ctx context.Context, config *domain.Config) (domain.SSOProvider, error) {
	switch config.ProviderType {
	case domain.ProviderTypeOIDC:
		return provider.NewOIDCProvider(ctx, config)
	case domain.ProviderTypeSAML:
		// For SAML, we need to build the callback URLs
		if config.ACSUrl == "" {
			config.ACSUrl = fmt.Sprintf("%s/auth/sso/%s/callback", s.baseURL, config.Slug)
		}
		if config.EntityID == "" {
			config.EntityID = fmt.Sprintf("%s/auth/sso/%s/metadata", s.baseURL, config.Slug)
		}
		return provider.NewSAMLProvider(ctx, config)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", config.ProviderType)
	}
}

func (s *SSOService) createAuthAttempt(ctx context.Context, providerID, tenantID uuid.UUID, state, ipAddress, userAgent string) error {
	_, err := s.queries.CreateSSOAuthAttempt(ctx, db.CreateSSOAuthAttemptParams{
		TenantID:   toPgUUID(tenantID),
		ProviderID: toPgUUID(providerID),
		UserID:     pgtype.UUID{Valid: false},
		State:      toPgText(state),
		Status:     "initiated",
		IpAddress:  parseIPAddr(ipAddress),
		UserAgent:  toPgText(userAgent),
	})
	return err
}

func (s *SSOService) updateAuthAttempt(ctx context.Context, providerID uuid.UUID, state, status, errorCode, errorMessage string, userID *uuid.UUID) {
	var userIDPg pgtype.UUID
	if userID != nil {
		userIDPg = toPgUUID(*userID)
	}

	// Find the attempt by state
	attempt, err := s.queries.GetSSOAuthAttemptByState(ctx, toPgText(state))
	if err != nil {
		s.log.Warn().Err(err).Msg("failed to find auth attempt")
		return
	}

	if err := s.queries.UpdateSSOAuthAttempt(ctx, db.UpdateSSOAuthAttemptParams{
		Status:       status,
		ErrorCode:    toPgText(errorCode),
		ErrorMessage: toPgText(errorMessage),
		UserID:       userIDPg,
		ID:           attempt.ID,
	}); err != nil {
		s.log.Warn().Err(err).Msg("failed to update auth attempt")
	}
}

func (s *SSOService) createSSOSession(ctx context.Context, tenantID, providerID, userID uuid.UUID, profile *domain.Profile) error {
	// Calculate expiration from profile
	var expiresAt pgtype.Timestamptz
	if profile.ExpiresAt != nil {
		expiresAt = toPgTimestamp(profile.ExpiresAt)
	}

	_, err := s.queries.CreateSSOSession(ctx, db.CreateSSOSessionParams{
		TenantID:     toPgUUID(tenantID),
		ProviderID:   toPgUUID(providerID),
		UserID:       toPgUUID(userID),
		SessionIndex: pgtype.Text{Valid: false}, // SAML session index (if available)
		NameID:       toPgText(profile.Subject),
		IDTokenHint:  toPgText(profile.IDToken),
		ExpiresAt:    expiresAt,
	})
	return err
}

func (s *SSOService) buildConfig(req CreateProviderRequest) *domain.Config {
	return &domain.Config{
		ID:                     uuid.New(),
		TenantID:               req.TenantID,
		Name:                   req.Name,
		Slug:                   req.Slug,
		ProviderType:           req.ProviderType,
		Enabled:                req.Enabled,
		AllowSignup:            req.AllowSignup,
		TrustEmailVerified:     req.TrustEmailVerified,
		Domains:                req.Domains,
		AttributeMapping:       req.AttributeMapping,
		Issuer:                 req.Issuer,
		AuthorizationEndpoint:  req.AuthorizationEndpoint,
		TokenEndpoint:          req.TokenEndpoint,
		UserinfoEndpoint:       req.UserinfoEndpoint,
		JWKSUri:                req.JWKSUri,
		ClientID:               req.ClientID,
		ClientSecret:           req.ClientSecret,
		Scopes:                 req.Scopes,
		ResponseType:           req.ResponseType,
		ResponseMode:           req.ResponseMode,
		EntityID:               req.EntityID,
		ACSUrl:                 req.ACSUrl,
		SLOUrl:                 req.SLOUrl,
		IdPMetadataURL:         req.IdPMetadataURL,
		IdPMetadataXML:         req.IdPMetadataXML,
		IdPEntityID:            req.IdPEntityID,
		IdPSSOUrl:              req.IdPSSOUrl,
		IdPSLOUrl:              req.IdPSLOUrl,
		IdPCertificate:         req.IdPCertificate,
		SPCertificate:          req.SPCertificate,
		SPPrivateKey:           req.SPPrivateKey,
		SPCertificateExpiresAt: req.SPCertificateExpiresAt,
		WantAssertionsSigned:   req.WantAssertionsSigned,
		WantResponseSigned:     req.WantResponseSigned,
		SignRequests:           req.SignRequests,
		ForceAuthn:             req.ForceAuthn,
		CreatedBy:              req.CreatedBy,
		UpdatedBy:              req.CreatedBy,
	}
}

func (s *SSOService) dbProviderToConfig(p db.SsoProvider) *domain.Config {
	var attributeMapping map[string][]string
	if len(p.AttributeMapping) > 0 {
		_ = json.Unmarshal(p.AttributeMapping, &attributeMapping)
	}

	var spCertExpiresAt *time.Time
	if p.SpCertificateExpiresAt.Valid {
		t := p.SpCertificateExpiresAt.Time
		spCertExpiresAt = &t
	}

	return &domain.Config{
		ID:                     toUUID(p.ID),
		TenantID:               toUUID(p.TenantID),
		Name:                   p.Name,
		Slug:                   p.Slug,
		ProviderType:           domain.ProviderType(p.ProviderType),
		Enabled:                fromPgBool(p.Enabled),
		AllowSignup:            fromPgBool(p.AllowSignup),
		TrustEmailVerified:     fromPgBool(p.TrustEmailVerified),
		Domains:                p.Domains,
		AttributeMapping:       attributeMapping,
		Issuer:                 p.Issuer.String,
		AuthorizationEndpoint:  p.AuthorizationEndpoint.String,
		TokenEndpoint:          p.TokenEndpoint.String,
		UserinfoEndpoint:       p.UserinfoEndpoint.String,
		JWKSUri:                p.JwksUri.String,
		ClientID:               p.ClientID.String,
		ClientSecret:           p.ClientSecret.String,
		Scopes:                 p.Scopes,
		ResponseType:           p.ResponseType.String,
		ResponseMode:           p.ResponseMode.String,
		EntityID:               p.EntityID.String,
		ACSUrl:                 p.AcsUrl.String,
		SLOUrl:                 p.SloUrl.String,
		IdPMetadataURL:         p.IdpMetadataUrl.String,
		IdPMetadataXML:         p.IdpMetadataXml.String,
		IdPEntityID:            p.IdpEntityID.String,
		IdPSSOUrl:              p.IdpSsoUrl.String,
		IdPSLOUrl:              p.IdpSloUrl.String,
		IdPCertificate:         p.IdpCertificate.String,
		SPCertificate:          p.SpCertificate.String,
		SPPrivateKey:           p.SpPrivateKey.String,
		SPCertificateExpiresAt: spCertExpiresAt,
		WantAssertionsSigned:   fromPgBool(p.WantAssertionsSigned),
		WantResponseSigned:     fromPgBool(p.WantResponseSigned),
		SignRequests:           fromPgBool(p.SignRequests),
		ForceAuthn:             fromPgBool(p.ForceAuthn),
		CreatedAt:              p.CreatedAt.Time,
		UpdatedAt:              p.UpdatedAt.Time,
		CreatedBy:              toUUID(p.CreatedBy),
		UpdatedBy:              toUUID(p.UpdatedBy),
	}
}

// Helper functions for pgtype conversion
func toPgUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil}
}

func toUUID(pg pgtype.UUID) uuid.UUID {
	if !pg.Valid {
		return uuid.Nil
	}
	return pg.Bytes
}

func toPgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func toPgBool(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

func fromPgBool(pg pgtype.Bool) bool {
	return pg.Valid && pg.Bool
}

func toPgTimestamp(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{Valid: false}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// extractDomain extracts the domain from an email address.
func extractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// parseIPAddr parses an IP address string to *netip.Addr.
func parseIPAddr(ipStr string) *netip.Addr {
	if ipStr == "" {
		return nil
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return nil
	}
	return &addr
}
