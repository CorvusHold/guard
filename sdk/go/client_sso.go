package guard

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

// NOTE: SSO Provider admin CRUD methods (List, Get, Create, Update, Delete, Test)
// are temporarily disabled as the backend endpoints are not yet exposed in the OpenAPI spec.
// These will be re-enabled in a future release when the backend routes are added to Swagger.
// See: ADR 0008 for details on the Go SDK standardization plan
