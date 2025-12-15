package guard

import (
	"context"
	"errors"
) // errors is used in error handling throughout the file

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

// ListSSOProviders lists all SSO providers for the authenticated tenant.
func (c *GuardClient) ListSSOProviders(ctx context.Context, tenantID *string) ([]SSOProvider, error) {
	params := &GetApiV1SsoProvidersParams{}
	if tenantID != nil {
		params.TenantId = tenantID
	}

	resp, err := c.inner.GetApiV1SsoProvidersWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	// Map the response
	providers := make([]SSOProvider, 0)
	if providersList, ok := (*resp.JSON200)["providers"].([]interface{}); ok {
		result := make([]SSOProvider, len(providersList))
		for i, p := range providersList {
			if pm, ok := p.(map[string]interface{}); ok {
				result[i] = mapSSOProviderFromResponse(pm)
			}
		}
		return result, nil
	}

	return providers, nil
}

// GetSSOProvider retrieves a specific SSO provider by ID.
func (c *GuardClient) GetSSOProvider(ctx context.Context, providerID string) (*SSOProvider, error) {
	resp, err := c.inner.GetApiV1SsoProvidersIdWithResponse(ctx, providerID)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	provider := mapSSOProviderFromResponse(*resp.JSON200)
	return &provider, nil
}

// CreateSSOProvider creates a new SSO provider configuration.
func (c *GuardClient) CreateSSOProvider(ctx context.Context, req CreateSSOProviderRequest) (*SSOProvider, error) {
	providerType := DomainProviderType(req.ProviderType)
	// Convert attribute mapping from map[string]interface{} to *map[string][]string
	var attrMapping *map[string][]string
	if req.AttributeMapping != nil {
		converted := make(map[string][]string)
		for k, v := range req.AttributeMapping {
			if arr, ok := v.([]string); ok {
				converted[k] = arr
			}
		}
		attrMapping = &converted
	}
	body := PostApiV1SsoProvidersJSONRequestBody{
		TenantId:              &req.TenantID,
		Name:                  &req.Name,
		Slug:                  &req.Slug,
		ProviderType:          &providerType,
		Enabled:               req.Enabled,
		AllowSignup:           req.AllowSignup,
		TrustEmailVerified:    req.TrustEmailVerified,
		Domains:               &req.Domains,
		AttributeMapping:      attrMapping,
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

	resp, err := c.inner.PostApiV1SsoProvidersWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}

	if resp.JSON201 == nil {
		return nil, errors.New(resp.Status())
	}

	provider := mapSSOProviderFromResponse(*resp.JSON201)
	return &provider, nil
}

// UpdateSSOProvider updates an existing SSO provider configuration.
func (c *GuardClient) UpdateSSOProvider(ctx context.Context, providerID string, req UpdateSSOProviderRequest) (*SSOProvider, error) {
	// Convert attribute mapping from map[string]interface{} to *map[string][]string
	var attrMapping *map[string][]string
	if req.AttributeMapping != nil {
		converted := make(map[string][]string)
		for k, v := range req.AttributeMapping {
			if arr, ok := v.([]string); ok {
				converted[k] = arr
			}
		}
		attrMapping = &converted
	}
	body := PutApiV1SsoProvidersIdJSONRequestBody{
		Name:                  req.Name,
		Enabled:               req.Enabled,
		AllowSignup:           req.AllowSignup,
		TrustEmailVerified:    req.TrustEmailVerified,
		Domains:               req.Domains,
		AttributeMapping:      attrMapping,
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

	resp, err := c.inner.PutApiV1SsoProvidersIdWithResponse(ctx, providerID, body)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	provider := mapSSOProviderFromResponse(*resp.JSON200)
	return &provider, nil
}

// DeleteSSOProvider deletes an SSO provider configuration.
func (c *GuardClient) DeleteSSOProvider(ctx context.Context, providerID string) error {
	resp, err := c.inner.DeleteApiV1SsoProvidersIdWithResponse(ctx, providerID)
	if err != nil {
		return err
	}

	if resp.StatusCode() != 204 {
		return errors.New(resp.Status())
	}

	return nil
}

// TestSSOProvider tests an SSO provider configuration for connectivity.
func (c *GuardClient) TestSSOProvider(ctx context.Context, providerID string) (*TestSSOProviderResponse, error) {
	resp, err := c.inner.PostApiV1SsoProvidersIdTestWithResponse(ctx, providerID)
	if err != nil {
		return nil, err
	}

	if resp.JSON200 == nil {
		return nil, errors.New(resp.Status())
	}

	result := &TestSSOProviderResponse{
		Success: false,
	}

	if success, ok := (*resp.JSON200)["success"].(bool); ok {
		result.Success = success
	}

	if errMsg, ok := (*resp.JSON200)["error"].(string); ok {
		result.Error = &errMsg
	}

	if metadata, ok := (*resp.JSON200)["metadata"]; ok {
		if m, ok := metadata.(map[string]interface{}); ok {
			result.Metadata = m
		}
	}

	return result, nil
}

// mapSSOProviderFromResponse maps a response body to an SSOProvider struct.
func mapSSOProviderFromResponse(data map[string]interface{}) SSOProvider {
	provider := SSOProvider{}

	if v, ok := data["id"].(string); ok {
		provider.ID = v
	}
	if v, ok := data["tenant_id"].(string); ok {
		provider.TenantID = v
	}
	if v, ok := data["name"].(string); ok {
		provider.Name = v
	}
	if v, ok := data["slug"].(string); ok {
		provider.Slug = v
	}
	if v, ok := data["provider_type"].(string); ok {
		provider.ProviderType = v
	}
	if v, ok := data["enabled"].(bool); ok {
		provider.Enabled = v
	}
	if v, ok := data["allow_signup"].(bool); ok {
		provider.AllowSignup = v
	}
	if v, ok := data["trust_email_verified"].(bool); ok {
		provider.TrustEmailVerified = v
	}
	if v, ok := data["domains"].([]interface{}); ok {
		domains := make([]string, len(v))
		for i, d := range v {
			if s, ok := d.(string); ok {
				domains[i] = s
			}
		}
		provider.Domains = domains
	}
	if v, ok := data["attribute_mapping"].(map[string]interface{}); ok {
		provider.AttributeMapping = v
	}

	// OIDC fields
	if v, ok := data["issuer"].(string); ok {
		provider.Issuer = &v
	}
	if v, ok := data["authorization_endpoint"].(string); ok {
		provider.AuthorizationEndpoint = &v
	}
	if v, ok := data["token_endpoint"].(string); ok {
		provider.TokenEndpoint = &v
	}
	if v, ok := data["userinfo_endpoint"].(string); ok {
		provider.UserinfoEndpoint = &v
	}
	if v, ok := data["jwks_uri"].(string); ok {
		provider.JWKSURI = &v
	}
	if v, ok := data["client_id"].(string); ok {
		provider.ClientID = &v
	}
	if v, ok := data["client_secret"].(string); ok {
		provider.ClientSecret = &v
	}
	if v, ok := data["scopes"].([]interface{}); ok {
		scopes := make([]string, len(v))
		for i, s := range v {
			if str, ok := s.(string); ok {
				scopes[i] = str
			}
		}
		provider.Scopes = scopes
	}
	if v, ok := data["response_type"].(string); ok {
		provider.ResponseType = &v
	}
	if v, ok := data["response_mode"].(string); ok {
		provider.ResponseMode = &v
	}

	// SAML fields
	if v, ok := data["entity_id"].(string); ok {
		provider.EntityID = &v
	}
	if v, ok := data["acs_url"].(string); ok {
		provider.ACSURL = &v
	}
	if v, ok := data["slo_url"].(string); ok {
		provider.SLOURL = &v
	}
	if v, ok := data["idp_metadata_url"].(string); ok {
		provider.IDPMetadataURL = &v
	}
	if v, ok := data["idp_metadata_xml"].(string); ok {
		provider.IDPMetadataXML = &v
	}
	if v, ok := data["idp_entity_id"].(string); ok {
		provider.IDPEntityID = &v
	}
	if v, ok := data["idp_sso_url"].(string); ok {
		provider.IDPSSOURL = &v
	}
	if v, ok := data["idp_slo_url"].(string); ok {
		provider.IDPSLOURL = &v
	}
	if v, ok := data["idp_certificate"].(string); ok {
		provider.IDPCertificate = &v
	}
	if v, ok := data["sp_certificate"].(string); ok {
		provider.SPCertificate = &v
	}
	if v, ok := data["sp_private_key"].(string); ok {
		provider.SPPrivateKey = &v
	}
	if v, ok := data["want_assertions_signed"].(bool); ok {
		provider.WantAssertionsSigned = &v
	}
	if v, ok := data["want_response_signed"].(bool); ok {
		provider.WantResponseSigned = &v
	}
	if v, ok := data["sign_requests"].(bool); ok {
		provider.SignRequests = &v
	}
	if v, ok := data["force_authn"].(bool); ok {
		provider.ForceAuthn = &v
	}

	if v, ok := data["created_at"].(string); ok {
		provider.CreatedAt = v
	}
	if v, ok := data["updated_at"].(string); ok {
		provider.UpdatedAt = v
	}

	return provider
}
