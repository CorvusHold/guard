package guard

import (
	"context"
	"errors"
	"net/http"
)

// SSOProvider represents an SSO provider configuration.
type SSOProvider struct {
	ID                 string
	TenantID           string
	Name               string
	Slug               string
	ProviderType       string // "oidc" or "saml"
	Enabled            bool
	AllowSignup        bool
	TrustEmailVerified bool
	Domains            []string
	AttributeMapping   map[string]interface{}

	// OIDC fields
	Issuer                *string
	AuthorizationEndpoint *string
	TokenEndpoint         *string
	UserinfoEndpoint      *string
	JWKSURI               *string
	ClientID              *string
	ClientSecret          *string
	Scopes                []string
	ResponseType          *string
	ResponseMode          *string

	// SAML fields
	EntityID             *string
	ACSURL               *string
	SLOURL               *string
	IDPMetadataURL       *string
	IDPMetadataXML       *string
	IDPEntityID          *string
	IDPSSOURL            *string
	IDPSLOURL            *string
	IDPCertificate       *string
	SPCertificate        *string
	SPPrivateKey         *string
	WantAssertionsSigned *bool
	WantResponseSigned   *bool
	SignRequests         *bool
	ForceAuthn           *bool

	CreatedAt string
	UpdatedAt string
}

// CreateSSOProviderRequest contains the parameters for creating a new SSO provider.
type CreateSSOProviderRequest struct {
	TenantID           string
	Name               string
	Slug               string
	ProviderType       string
	Enabled            *bool
	AllowSignup        *bool
	TrustEmailVerified *bool
	Domains            []string
	AttributeMapping   map[string]interface{}

	// OIDC fields
	Issuer                *string
	AuthorizationEndpoint *string
	TokenEndpoint         *string
	UserinfoEndpoint      *string
	JWKSURI               *string
	ClientID              *string
	ClientSecret          *string
	Scopes                []string
	ResponseType          *string
	ResponseMode          *string

	// SAML fields
	EntityID             *string
	ACSURL               *string
	SLOURL               *string
	IDPMetadataURL       *string
	IDPMetadataXML       *string
	IDPEntityID          *string
	IDPSSOURL            *string
	IDPSLOURL            *string
	IDPCertificate       *string
	SPCertificate        *string
	SPPrivateKey         *string
	WantAssertionsSigned *bool
	WantResponseSigned   *bool
	SignRequests         *bool
	ForceAuthn           *bool
}

// UpdateSSOProviderRequest contains the fields that can be updated for an SSO provider.
type UpdateSSOProviderRequest struct {
	Name               *string
	Enabled            *bool
	AllowSignup        *bool
	TrustEmailVerified *bool
	Domains            *[]string
	AttributeMapping   map[string]interface{}

	// OIDC fields
	Issuer                *string
	AuthorizationEndpoint *string
	TokenEndpoint         *string
	UserinfoEndpoint      *string
	JWKSURI               *string
	ClientID              *string
	ClientSecret          *string
	Scopes                *[]string
	ResponseType          *string
	ResponseMode          *string

	// SAML fields
	EntityID             *string
	ACSURL               *string
	SLOURL               *string
	IDPMetadataURL       *string
	IDPMetadataXML       *string
	IDPEntityID          *string
	IDPSSOURL            *string
	IDPSLOURL            *string
	IDPCertificate       *string
	SPCertificate        *string
	SPPrivateKey         *string
	WantAssertionsSigned *bool
	WantResponseSigned   *bool
	SignRequests         *bool
	ForceAuthn           *bool
}

// TestSSOProviderResponse contains the result of testing an SSO provider.
type TestSSOProviderResponse struct {
	Success  bool
	Metadata map[string]interface{}
	Error    *string
}

// ListSSOProviders retrieves all SSO providers for a tenant. Requires admin role.
func (c *GuardClient) ListSSOProviders(ctx context.Context, tenantID string) ([]SSOProvider, error) {
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	params := &GetV1SsoProvidersParams{TenantId: &tenantID}
	resp, err := c.inner.GetV1SsoProvidersWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	var providers []SSOProvider
	if resp.JSON200.Providers != nil {
		for _, p := range *resp.JSON200.Providers {
			provider := mapSSOProviderFromResponse(&p)
			providers = append(providers, provider)
		}
	}

	return providers, nil
}

// GetSSOProvider retrieves a specific SSO provider by ID. Requires admin role.
func (c *GuardClient) GetSSOProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	resp, err := c.inner.GetV1SsoProvidersIdWithResponse(ctx, providerID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	provider := mapSSOProviderFromResponse(resp.JSON200)
	return &provider, nil
}

// CreateSSOProvider creates a new SSO provider. Requires admin role.
func (c *GuardClient) CreateSSOProvider(ctx context.Context, req CreateSSOProviderRequest) (*SSOProvider, error) {
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = c.tenantID
	}
	if tenantID == "" {
		return nil, errors.New("tenant ID required")
	}

	body := ControllerCreateSsoProviderReq{
		TenantId:              tenantID,
		Name:                  req.Name,
		Slug:                  req.Slug,
		ProviderType:          req.ProviderType,
		Enabled:               req.Enabled,
		AllowSignup:           req.AllowSignup,
		TrustEmailVerified:    req.TrustEmailVerified,
		Domains:               &req.Domains,
		AttributeMapping:      &req.AttributeMapping,
		Issuer:                req.Issuer,
		AuthorizationEndpoint: req.AuthorizationEndpoint,
		TokenEndpoint:         req.TokenEndpoint,
		UserinfoEndpoint:      req.UserinfoEndpoint,
		JwksUri:               req.JWKSURI,
		ClientId:              req.ClientID,
		ClientSecret:          req.ClientSecret,
		Scopes:                &req.Scopes,
		ResponseType:          req.ResponseType,
		ResponseMode:          req.ResponseMode,
		EntityId:              req.EntityID,
		AcsUrl:                req.ACSURL,
		SloUrl:                req.SLOURL,
		IdpMetadataUrl:        req.IDPMetadataURL,
		IdpMetadataXml:        req.IDPMetadataXML,
		IdpEntityId:           req.IDPEntityID,
		IdpSsoUrl:             req.IDPSSOURL,
		IdpSloUrl:             req.IDPSLOURL,
		IdpCertificate:        req.IDPCertificate,
		SpCertificate:         req.SPCertificate,
		SpPrivateKey:          req.SPPrivateKey,
		WantAssertionsSigned:  req.WantAssertionsSigned,
		WantResponseSigned:    req.WantResponseSigned,
		SignRequests:          req.SignRequests,
		ForceAuthn:            req.ForceAuthn,
	}

	resp, err := c.inner.PostV1SsoProvidersWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil && resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	// Handle both 201 Created and 200 OK responses
	var result *ControllerSsoProviderItem
	if resp.JSON201 != nil {
		result = resp.JSON201
	} else {
		result = resp.JSON200
	}

	provider := mapSSOProviderFromResponse(result)
	return &provider, nil
}

// UpdateSSOProvider updates an existing SSO provider. Requires admin role.
func (c *GuardClient) UpdateSSOProvider(ctx context.Context, providerID string, req UpdateSSOProviderRequest) error {
	body := ControllerUpdateSsoProviderReq{
		Name:                  req.Name,
		Enabled:               req.Enabled,
		AllowSignup:           req.AllowSignup,
		TrustEmailVerified:    req.TrustEmailVerified,
		Domains:               req.Domains,
		AttributeMapping:      &req.AttributeMapping,
		Issuer:                req.Issuer,
		AuthorizationEndpoint: req.AuthorizationEndpoint,
		TokenEndpoint:         req.TokenEndpoint,
		UserinfoEndpoint:      req.UserinfoEndpoint,
		JwksUri:               req.JWKSURI,
		ClientId:              req.ClientID,
		ClientSecret:          req.ClientSecret,
		Scopes:                req.Scopes,
		ResponseType:          req.ResponseType,
		ResponseMode:          req.ResponseMode,
		EntityId:              req.EntityID,
		AcsUrl:                req.ACSURL,
		SloUrl:                req.SLOURL,
		IdpMetadataUrl:        req.IDPMetadataURL,
		IdpMetadataXml:        req.IDPMetadataXML,
		IdpEntityId:           req.IDPEntityID,
		IdpSsoUrl:             req.IDPSSOURL,
		IdpSloUrl:             req.IDPSLOURL,
		IdpCertificate:        req.IDPCertificate,
		SpCertificate:         req.SPCertificate,
		SpPrivateKey:          req.SPPrivateKey,
		WantAssertionsSigned:  req.WantAssertionsSigned,
		WantResponseSigned:    req.WantResponseSigned,
		SignRequests:          req.SignRequests,
		ForceAuthn:            req.ForceAuthn,
	}

	resp, err := c.inner.PutV1SsoProvidersIdWithResponse(ctx, providerID, body)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// DeleteSSOProvider deletes an SSO provider. Requires admin role.
func (c *GuardClient) DeleteSSOProvider(ctx context.Context, providerID string) error {
	resp, err := c.inner.DeleteV1SsoProvidersIdWithResponse(ctx, providerID)
	if err != nil {
		return err
	}
	if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
		return errors.New(resp.Status())
	}
	return nil
}

// TestSSOProvider tests an SSO provider's configuration. Requires admin role.
func (c *GuardClient) TestSSOProvider(ctx context.Context, providerID string) (*TestSSOProviderResponse, error) {
	resp, err := c.inner.PostV1SsoProvidersIdTestWithResponse(ctx, providerID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	result := &TestSSOProviderResponse{
		Success: false,
	}
	if resp.JSON200.Success != nil {
		result.Success = *resp.JSON200.Success
	}
	if resp.JSON200.Metadata != nil {
		result.Metadata = *resp.JSON200.Metadata
	}
	if resp.JSON200.Error != nil {
		result.Error = resp.JSON200.Error
	}

	return result, nil
}

// mapSSOProviderFromResponse converts the generated type to our SDK type
func mapSSOProviderFromResponse(p *ControllerSsoProviderItem) SSOProvider {
	provider := SSOProvider{
		ID:           p.Id,
		TenantID:     p.TenantId,
		Name:         p.Name,
		Slug:         p.Slug,
		ProviderType: p.ProviderType,
	}

	if p.Enabled != nil {
		provider.Enabled = *p.Enabled
	}
	if p.AllowSignup != nil {
		provider.AllowSignup = *p.AllowSignup
	}
	if p.TrustEmailVerified != nil {
		provider.TrustEmailVerified = *p.TrustEmailVerified
	}
	if p.Domains != nil {
		provider.Domains = *p.Domains
	}
	if p.AttributeMapping != nil {
		provider.AttributeMapping = *p.AttributeMapping
	}

	// OIDC fields
	provider.Issuer = p.Issuer
	provider.AuthorizationEndpoint = p.AuthorizationEndpoint
	provider.TokenEndpoint = p.TokenEndpoint
	provider.UserinfoEndpoint = p.UserinfoEndpoint
	provider.JWKSURI = p.JwksUri
	provider.ClientID = p.ClientId
	provider.ClientSecret = p.ClientSecret
	if p.Scopes != nil {
		provider.Scopes = *p.Scopes
	}
	provider.ResponseType = p.ResponseType
	provider.ResponseMode = p.ResponseMode

	// SAML fields
	provider.EntityID = p.EntityId
	provider.ACSURL = p.AcsUrl
	provider.SLOURL = p.SloUrl
	provider.IDPMetadataURL = p.IdpMetadataUrl
	provider.IDPMetadataXML = p.IdpMetadataXml
	provider.IDPEntityID = p.IdpEntityId
	provider.IDPSSOURL = p.IdpSsoUrl
	provider.IDPSLOURL = p.IdpSloUrl
	provider.IDPCertificate = p.IdpCertificate
	provider.SPCertificate = p.SpCertificate
	provider.SPPrivateKey = p.SpPrivateKey
	provider.WantAssertionsSigned = p.WantAssertionsSigned
	provider.WantResponseSigned = p.WantResponseSigned
	provider.SignRequests = p.SignRequests
	provider.ForceAuthn = p.ForceAuthn

	if p.CreatedAt != nil {
		provider.CreatedAt = *p.CreatedAt
	}
	if p.UpdatedAt != nil {
		provider.UpdatedAt = *p.UpdatedAt
	}

	return provider
}
