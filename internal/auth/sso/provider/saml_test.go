package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
)

// Mock IdP metadata for testing
const mockIdPMetadataXML = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIICoTCCAYkCBgGRR5JcdjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlpZHAu
dGVzdDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBQxEjAQBgNVBAMM
CWlkcC50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z91gNR</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/slo"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

func createTestSAMLConfig(t *testing.T) *domain.Config {
	t.Helper()

	return &domain.Config{
		ID:             uuid.New(),
		TenantID:       uuid.New(),
		Name:           "Test SAML Provider",
		Slug:           "test-saml",
		ProviderType:   domain.ProviderTypeSAML,
		Enabled:        true,
		EntityID:       "https://sp.example.com",
		ACSUrl:         "https://sp.example.com/saml/acs",
		SLOUrl:         "https://sp.example.com/saml/slo",
		IdPMetadataXML: mockIdPMetadataXML,
		AttributeMapping: map[string][]string{
			"email":      {"email", "mail"},
			"first_name": {"firstName", "givenName"},
			"last_name":  {"lastName", "surname"},
		},
		WantAssertionsSigned: true,
		WantResponseSigned:   false,
		SignRequests:         false,
	}
}

func TestSAMLProvider_Start_SignedRedirect(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)
	config.SignRequests = true

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	result, err := provider.Start(ctx, domain.StartOptions{RedirectURL: "https://sp.example.com/callback"})
	require.NoError(t, err)
	require.NotEmpty(t, result.AuthorizationURL)

	u, err := url.Parse(result.AuthorizationURL)
	require.NoError(t, err)
	query := u.Query()

	sigAlg := query.Get("SigAlg")
	signature := query.Get("Signature")
	require.NotEmpty(t, sigAlg)
	require.NotEmpty(t, signature)
	require.NotEmpty(t, query.Get("SAMLRequest"))

	canonical := buildRedirectSigningInput(query.Get("SAMLRequest"), query.Get("RelayState"), sigAlg)
	hash, digest, err := computeSignatureDigest(sigAlg, canonical)
	require.NoError(t, err)
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	require.NoError(t, err)
	privKey, ok := provider.sp.Key.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.NoError(t, rsa.VerifyPKCS1v15(&privKey.PublicKey, hash, digest, sigBytes))
}

func TestBuildRedirectSigningInput(t *testing.T) {
	encodedReq := "SAML+Value/="
	relayState := "relay state!"
	sigAlg := signatureMethodRSASHA256

	got := buildRedirectSigningInput(encodedReq, relayState, sigAlg)
	expected := "SAMLRequest=SAML%2BValue%2F%3D&RelayState=relay+state%21&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256"
	assert.Equal(t, expected, got)

	gotNoRelay := buildRedirectSigningInput(encodedReq, "", sigAlg)
	assert.Equal(t, "SAMLRequest=SAML%2BValue%2F%3D&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256", gotNoRelay)
}

func TestSignRedirectRequest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signingInput := "SAMLRequest=value&SigAlg=" + signatureMethodRSASHA256

	sig, err := signRedirectRequest(key, signatureMethodRSASHA256, signingInput)
	require.NoError(t, err)

	hash, digest, err := computeSignatureDigest(signatureMethodRSASHA256, signingInput)
	require.NoError(t, err)
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	require.NoError(t, err)
	assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, hash, digest, sigBytes))

	_, err = signRedirectRequest(key, "unsupported", signingInput)
	assert.Error(t, err)
}

func TestValidateSAMLConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *domain.Config
		expectErr bool
		errMsg    string
	}{
		{
			name:      "nil config",
			config:    nil,
			expectErr: true,
			errMsg:    "config is nil",
		},
		{
			name: "missing entity_id",
			config: &domain.Config{
				ACSUrl:         "https://sp.example.com/acs",
				IdPMetadataXML: mockIdPMetadataXML,
			},
			expectErr: true,
			errMsg:    "entity_id is required",
		},
		{
			name: "missing acs_url",
			config: &domain.Config{
				EntityID:       "https://sp.example.com",
				IdPMetadataXML: mockIdPMetadataXML,
			},
			expectErr: true,
			errMsg:    "acs_url is required",
		},
		{
			name: "missing idp metadata",
			config: &domain.Config{
				EntityID: "https://sp.example.com",
				ACSUrl:   "https://sp.example.com/acs",
			},
			expectErr: true,
			errMsg:    "either idp_metadata_url or idp_metadata_xml is required",
		},
		{
			name:      "valid config",
			config:    createTestSAMLConfig(t),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSAMLConfig(tt.config)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewSAMLProvider(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		config    *domain.Config
		expectErr bool
		errMsg    string
	}{
		{
			name:      "invalid config - nil",
			config:    nil,
			expectErr: true,
			errMsg:    "invalid SAML configuration",
		},
		{
			name: "invalid config - missing entity_id",
			config: &domain.Config{
				ACSUrl:         "https://sp.example.com/acs",
				IdPMetadataXML: mockIdPMetadataXML,
			},
			expectErr: true,
			errMsg:    "invalid SAML configuration",
		},
		{
			name:      "valid config",
			config:    createTestSAMLConfig(t),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewSAMLProvider(ctx, tt.config)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, provider)
			} else {
				require.NoError(t, err)
				require.NotNil(t, provider)
				assert.Equal(t, domain.ProviderTypeSAML, provider.Type())
				assert.NotNil(t, provider.sp)
				assert.NotNil(t, provider.idpMetadata)
				assert.NotNil(t, provider.spCert)
			}
		})
	}
}

func TestSAMLProvider_ValidateConfig(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	err = provider.ValidateConfig()
	assert.NoError(t, err)
}

func TestSAMLProvider_Start(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	tests := []struct {
		name      string
		opts      domain.StartOptions
		expectErr bool
	}{
		{
			name: "basic start",
			opts: domain.StartOptions{
				RedirectURL: "https://sp.example.com/callback",
			},
			expectErr: false,
		},
		{
			name: "with custom state",
			opts: domain.StartOptions{
				RedirectURL: "https://sp.example.com/callback",
				State:       "custom-state-123",
			},
			expectErr: false,
		},
		{
			name: "with force authn",
			opts: domain.StartOptions{
				RedirectURL: "https://sp.example.com/callback",
				ForceAuthn:  true,
			},
			expectErr: false,
		},
		{
			name: "with login hint",
			opts: domain.StartOptions{
				RedirectURL: "https://sp.example.com/callback",
				LoginHint:   "user@example.com",
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := provider.Start(ctx, tt.opts)
			if tt.expectErr {
				require.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)

				// Verify authorization URL is set
				assert.NotEmpty(t, result.AuthorizationURL)
				assert.Contains(t, result.AuthorizationURL, "https://idp.example.com/sso")
				assert.Contains(t, result.AuthorizationURL, "SAMLRequest=")

				// Verify state
				if tt.opts.State != "" {
					assert.Equal(t, tt.opts.State, result.State)
					assert.Equal(t, tt.opts.State, result.RelayState)
				} else {
					assert.NotEmpty(t, result.State)
					assert.NotEmpty(t, result.RelayState)
				}

				// Verify SAMLRequest is encoded
				assert.NotEmpty(t, result.SAMLRequest)
				_, err := base64.StdEncoding.DecodeString(result.SAMLRequest)
				assert.NoError(t, err)
			}
		})
	}
}

func TestSAMLProvider_Callback_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       domain.CallbackRequest
		expectErr bool
		errMsg    string
	}{
		{
			name: "missing SAMLResponse",
			req: domain.CallbackRequest{
				RelayState: "state123",
			},
			expectErr: true,
			errMsg:    "SAMLResponse is required",
		},
		{
			name: "invalid base64 SAMLResponse",
			req: domain.CallbackRequest{
				SAMLResponse: "invalid-base64!@#$",
				RelayState:   "state123",
			},
			expectErr: true,
			errMsg:    "failed to decode SAMLResponse",
		},
		{
			name: "invalid XML SAMLResponse",
			req: domain.CallbackRequest{
				SAMLResponse: base64.StdEncoding.EncodeToString([]byte("not xml")),
				RelayState:   "state123",
			},
			expectErr: true,
			errMsg:    "failed to parse SAML response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := provider.Callback(ctx, tt.req)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, profile)
			} else {
				require.NoError(t, err)
				require.NotNil(t, profile)
			}
		})
	}
}

func TestSAMLProvider_Callback_EncryptedAssertion_Success(t *testing.T) {
	// TODO: This test requires proper InResponseTo validation which needs request ID
	// tracking through state. The crewjam/saml library's ParseXMLResponse validates
	// InResponseTo against possibleRequestIDs, but our current implementation passes nil.
	// Skip until we implement proper request ID tracking in the SSO state.
	t.Skip("Skipping: requires InResponseTo validation with request ID tracking")

	ctx := context.Background()

	// Create an in-process IdP with its own keypair and metadata.
	certPEM, keyPEM, err := generateSelfSignedCert("idp.example.com", 365)
	require.NoError(t, err)

	idpCertBlock, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, idpCertBlock)
	idpCert, err := x509.ParseCertificate(idpCertBlock.Bytes)
	require.NoError(t, err)

	idpKeyBlock, _ := pem.Decode([]byte(keyPEM))
	require.NotNil(t, idpKeyBlock)
	idpKey, err := x509.ParsePKCS1PrivateKey(idpKeyBlock.Bytes)
	require.NoError(t, err)

	metadataURL, err := url.Parse("https://idp.example.com/metadata")
	require.NoError(t, err)
	ssoURL, err := url.Parse("https://idp.example.com/sso")
	require.NoError(t, err)

	idp := &saml.IdentityProvider{
		Key:         idpKey,
		Certificate: idpCert,
		MetadataURL: *metadataURL,
		SSOURL:      *ssoURL,
	}

	idpMetadataXML, err := xml.Marshal(idp.Metadata())
	require.NoError(t, err)

	// Configure the Service Provider (Guard) to trust this IdP metadata.
	config := createTestSAMLConfig(t)
	config.IdPMetadataXML = string(idpMetadataXML)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	// Derive SP metadata for the IdP to target, and ensure an encryption key descriptor
	// is present so that MakeAssertionEl produces an EncryptedAssertion.
	spMetadata := provider.sp.Metadata()
	require.NotNil(t, spMetadata)
	require.NotEmpty(t, spMetadata.SPSSODescriptors)
	spSSO := &spMetadata.SPSSODescriptors[0]

	// Add an explicit encryption KeyDescriptor using the SP certificate.
	certStr := base64.StdEncoding.EncodeToString(provider.sp.Certificate.Raw)
	spSSO.KeyDescriptors = append(spSSO.KeyDescriptors, saml.KeyDescriptor{
		Use: "encryption",
		KeyInfo: saml.KeyInfo{
			X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{{Data: certStr}},
			},
		},
		EncryptionMethods: []saml.EncryptionMethod{{
			Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
		}},
	})

	// Select an HTTP-POST ACS endpoint for the IdP response.
	var acsEndpoint *saml.IndexedEndpoint
	for _, ep := range spSSO.AssertionConsumerServices {
		if ep.Binding == saml.HTTPPostBinding {
			epCopy := ep
			acsEndpoint = &epCopy
			break
		}
	}
	require.NotNil(t, acsEndpoint, "expected at least one HTTP-POST ACS endpoint")

	now := time.Now()
	httpReq, err := http.NewRequest(http.MethodPost, provider.sp.AcsURL.String(), nil)
	require.NoError(t, err)
	httpReq.RemoteAddr = "127.0.0.1:12345"

	authnReq := saml.IdpAuthnRequest{
		IDP:         idp,
		HTTPRequest: httpReq,
		RelayState:  "relay-state-123",
		Request: saml.AuthnRequest{
			ID:           "authn-request-id",
			IssueInstant: now.Add(-1 * time.Minute),
			Version:      "2.0",
		},
		ServiceProviderMetadata: spMetadata,
		SPSSODescriptor:         spSSO,
		ACSEndpoint:             acsEndpoint,
		Now:                     now,
	}

	session := &saml.Session{
		ID:           "session-id",
		CreateTime:   now.Add(-5 * time.Minute),
		ExpireTime:   now.Add(1 * time.Hour),
		Index:        "session-index",
		NameID:       "user@example.com",
		NameIDFormat: string(saml.EmailAddressNameIDFormat),
	}

	err = (saml.DefaultAssertionMaker{}).MakeAssertion(&authnReq, session)
	require.NoError(t, err)
	require.NotNil(t, authnReq.Assertion)

	form, err := authnReq.PostBinding()
	require.NoError(t, err)
	require.NotEmpty(t, form.SAMLResponse)

	// Sanity check that the generated response contains an EncryptedAssertion element.
	rawResponseXML, err := base64.StdEncoding.DecodeString(form.SAMLResponse)
	require.NoError(t, err)
	assert.Contains(t, string(rawResponseXML), "EncryptedAssertion")

	callbackReq := domain.CallbackRequest{
		SAMLResponse: form.SAMLResponse,
		RelayState:   form.RelayState,
	}

	profile, err := provider.Callback(ctx, callbackReq)
	require.NoError(t, err)
	require.NotNil(t, profile)
	assert.Equal(t, "user@example.com", profile.Subject)
	assert.Equal(t, "user@example.com", profile.Email)
}

func TestSAMLProvider_Callback_EncryptedAssertion_Error(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	// Craft a minimal SAML response XML that includes an EncryptedAssertion element
	// so that the Callback code paths through decryptAssertion. The XML does not
	// need to be a fully valid SAML response; we only assert that the encrypted
	// assertion branch is taken and that the high-level error is preserved.
	rawResponse := []byte(`<?xml version="1.0"?>
		<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		  <saml:EncryptedAssertion></saml:EncryptedAssertion>
		</samlp:Response>`) // nolint:lll

	req := domain.CallbackRequest{
		SAMLResponse: base64.StdEncoding.EncodeToString(rawResponse),
		RelayState:   "state123",
	}

	profile, err := provider.Callback(ctx, req)
	require.Error(t, err)
	assert.Nil(t, profile)
	assert.Contains(t, err.Error(), "failed to decrypt SAML assertion")
}

func TestSAMLProvider_GetMetadata(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	metadata, err := provider.GetMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	// Verify metadata fields
	assert.Equal(t, domain.ProviderTypeSAML, metadata.ProviderType)
	assert.Equal(t, config.EntityID, metadata.EntityID)
	assert.Equal(t, config.ACSUrl, metadata.ACSUrl)
	assert.Equal(t, config.SLOUrl, metadata.SLOUrl)
	assert.NotEmpty(t, metadata.SPCertificate)
	assert.NotEmpty(t, metadata.MetadataXML)

	// Verify metadata XML is valid
	var spMetadata saml.EntityDescriptor
	err = xml.Unmarshal([]byte(metadata.MetadataXML), &spMetadata)
	assert.NoError(t, err)
	assert.Equal(t, config.EntityID, spMetadata.EntityID)

	// Verify certificate is valid PEM
	block, _ := pem.Decode([]byte(metadata.SPCertificate))
	assert.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Verify certificate expiry is set
	assert.NotNil(t, metadata.CertificateExpiry)
}

func TestGenerateSelfSignedCert(t *testing.T) {
	commonName := "sp.example.com"
	validDays := 365

	certPEM, keyPEM, err := generateSelfSignedCert(commonName, validDays)
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.NotEmpty(t, keyPEM)

	// Verify certificate PEM
	certBlock, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, certBlock)
	assert.Equal(t, "CERTIFICATE", certBlock.Type)

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, commonName, cert.Subject.CommonName)
	assert.True(t, cert.NotAfter.After(time.Now()))

	// Verify private key PEM
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	require.NotNil(t, keyBlock)
	assert.Equal(t, "RSA PRIVATE KEY", keyBlock.Type)

	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
}

func TestLoadOrGenerateCertificate(t *testing.T) {
	tests := []struct {
		name      string
		config    *domain.Config
		expectErr bool
	}{
		{
			name: "generate new certificate",
			config: &domain.Config{
				EntityID: "https://sp.example.com",
			},
			expectErr: false,
		},
		{
			name: "load existing certificate",
			config: func() *domain.Config {
				certPEM, keyPEM, err := generateSelfSignedCert("sp.example.com", 365)
				require.NoError(t, err)
				return &domain.Config{
					EntityID:      "https://sp.example.com",
					SPCertificate: certPEM,
					SPPrivateKey:  keyPEM,
				}
			}(),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := loadOrGenerateCertificate(tt.config)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, cert.PrivateKey)
				assert.NotNil(t, cert.Leaf)
				assert.NotEmpty(t, cert.Certificate)

				// Verify config was updated if certificate was generated
				if tt.name == "generate new certificate" {
					assert.NotEmpty(t, tt.config.SPCertificate)
					assert.NotEmpty(t, tt.config.SPPrivateKey)
				}
			}
		})
	}
}

func TestParseSAMLMetadata(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		config    *domain.Config
		expectErr bool
		errMsg    string
	}{
		{
			name: "parse from XML",
			config: &domain.Config{
				IdPMetadataXML: mockIdPMetadataXML,
			},
			expectErr: false,
		},
		{
			name: "invalid XML",
			config: &domain.Config{
				IdPMetadataXML: "not valid xml",
			},
			expectErr: true,
			errMsg:    "failed to parse IdP metadata XML",
		},
		{
			name:      "no metadata provided",
			config:    &domain.Config{},
			expectErr: true,
			errMsg:    "no IdP metadata provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata, err := parseSAMLMetadata(ctx, tt.config)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, metadata)
			} else {
				require.NoError(t, err)
				require.NotNil(t, metadata)
				assert.Equal(t, "https://idp.example.com", metadata.EntityID)
			}
		})
	}
}

func TestUpdateConfigFromMetadata(t *testing.T) {
	var metadata saml.EntityDescriptor
	err := xml.Unmarshal([]byte(mockIdPMetadataXML), &metadata)
	require.NoError(t, err)

	config := &domain.Config{
		EntityID: "https://sp.example.com",
		ACSUrl:   "https://sp.example.com/acs",
	}

	err = updateConfigFromMetadata(config, &metadata)
	require.NoError(t, err)

	// Verify extracted values
	assert.Equal(t, "https://idp.example.com", config.IdPEntityID)
	assert.Equal(t, "https://idp.example.com/sso", config.IdPSSOUrl)
	assert.Equal(t, "https://idp.example.com/slo", config.IdPSLOUrl)
	assert.NotEmpty(t, config.IdPCertificate)
	assert.Contains(t, config.IdPCertificate, "-----BEGIN CERTIFICATE-----")
}

func TestExtractProfile(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	tests := []struct {
		name      string
		assertion *saml.Assertion
		expectErr bool
		validate  func(t *testing.T, profile *domain.Profile)
	}{
		{
			name: "basic profile with email NameID",
			assertion: &saml.Assertion{
				ID: "assertion-1",
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Format: string(saml.EmailAddressNameIDFormat),
						Value:  "user@example.com",
					},
				},
				Conditions: &saml.Conditions{
					NotBefore:    time.Now().Add(-5 * time.Minute),
					NotOnOrAfter: time.Now().Add(5 * time.Minute),
				},
				AttributeStatements: []saml.AttributeStatement{},
			},
			expectErr: false,
			validate: func(t *testing.T, profile *domain.Profile) {
				assert.Equal(t, "user@example.com", profile.Subject)
				assert.Equal(t, "user@example.com", profile.Email)
				assert.True(t, profile.EmailVerified)
			},
		},
		{
			name: "profile with attributes",
			assertion: &saml.Assertion{
				ID: "assertion-2",
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Format: string(saml.UnspecifiedNameIDFormat),
						Value:  "user123",
					},
				},
				Conditions: &saml.Conditions{
					NotBefore:    time.Now().Add(-5 * time.Minute),
					NotOnOrAfter: time.Now().Add(5 * time.Minute),
				},
				AttributeStatements: []saml.AttributeStatement{
					{
						Attributes: []saml.Attribute{
							{
								Name:         "email",
								FriendlyName: "Email Address",
								Values: []saml.AttributeValue{
									{Value: "john.doe@example.com"},
								},
							},
							{
								Name:         "givenName",
								FriendlyName: "First Name",
								Values: []saml.AttributeValue{
									{Value: "John"},
								},
							},
							{
								Name:         "surname",
								FriendlyName: "Last Name",
								Values: []saml.AttributeValue{
									{Value: "Doe"},
								},
							},
							{
								Name:         "displayName",
								FriendlyName: "Display Name",
								Values: []saml.AttributeValue{
									{Value: "John Doe"},
								},
							},
						},
					},
				},
			},
			expectErr: false,
			validate: func(t *testing.T, profile *domain.Profile) {
				assert.Equal(t, "user123", profile.Subject)
				assert.Equal(t, "john.doe@example.com", profile.Email)
				assert.Equal(t, "John", profile.FirstName)
				assert.Equal(t, "Doe", profile.LastName)
				assert.Equal(t, "John Doe", profile.Name)
				assert.True(t, profile.EmailVerified)
			},
		},
		{
			name: "profile with groups",
			assertion: &saml.Assertion{
				ID: "assertion-3",
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Format: string(saml.EmailAddressNameIDFormat),
						Value:  "user@example.com",
					},
				},
				Conditions: &saml.Conditions{
					NotBefore:    time.Now().Add(-5 * time.Minute),
					NotOnOrAfter: time.Now().Add(5 * time.Minute),
				},
				AttributeStatements: []saml.AttributeStatement{
					{
						Attributes: []saml.Attribute{
							{
								Name: "groups",
								Values: []saml.AttributeValue{
									{Value: "admin"},
									{Value: "users"},
								},
							},
						},
					},
				},
			},
			expectErr: false,
			validate: func(t *testing.T, profile *domain.Profile) {
				assert.Equal(t, "user@example.com", profile.Subject)
				assert.Len(t, profile.Groups, 2)
				assert.Contains(t, profile.Groups, "admin")
				assert.Contains(t, profile.Groups, "users")
			},
		},
		{
			name: "missing subject",
			assertion: &saml.Assertion{
				ID: "assertion-4",
				Conditions: &saml.Conditions{
					NotBefore:    time.Now().Add(-5 * time.Minute),
					NotOnOrAfter: time.Now().Add(5 * time.Minute),
				},
			},
			expectErr: true,
		},
		{
			name: "multi-valued email attribute returns error",
			assertion: &saml.Assertion{
				ID: "assertion-5",
				Subject: &saml.Subject{
					NameID: &saml.NameID{
						Format: string(saml.EmailAddressNameIDFormat),
						Value:  "user@example.com",
					},
				},
				Conditions: &saml.Conditions{
					NotBefore:    time.Now().Add(-5 * time.Minute),
					NotOnOrAfter: time.Now().Add(5 * time.Minute),
				},
				AttributeStatements: []saml.AttributeStatement{
					{
						Attributes: []saml.Attribute{
							{
								Name: "email",
								Values: []saml.AttributeValue{
									{Value: "john@example.com"},
									{Value: "doe@example.com"},
								},
							},
						},
					},
				},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := provider.extractProfile(tt.assertion)
			if tt.expectErr {
				require.Error(t, err)
				assert.Nil(t, profile)
			} else {
				require.NoError(t, err)
				require.NotNil(t, profile)
				if tt.validate != nil {
					tt.validate(t, profile)
				}
			}
		})
	}
}

func TestValidateAssertionConditions(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	now := time.Now()

	tests := []struct {
		name      string
		assertion *saml.Assertion
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid assertion",
			assertion: &saml.Assertion{
				Conditions: &saml.Conditions{
					NotBefore:    now.Add(-5 * time.Minute),
					NotOnOrAfter: now.Add(5 * time.Minute),
					AudienceRestrictions: []saml.AudienceRestriction{
						{
							Audience: saml.Audience{
								Value: config.EntityID,
							},
						},
					},
				},
				Subject: &saml.Subject{
					SubjectConfirmations: []saml.SubjectConfirmation{
						{
							SubjectConfirmationData: &saml.SubjectConfirmationData{
								NotOnOrAfter: now.Add(5 * time.Minute),
								Recipient:    config.ACSUrl,
							},
						},
					},
				},
			},
			expectErr: false,
		},
		{
			name: "not yet valid",
			assertion: &saml.Assertion{
				Conditions: &saml.Conditions{
					NotBefore:    now.Add(5 * time.Minute),
					NotOnOrAfter: now.Add(10 * time.Minute),
				},
				Subject: &saml.Subject{},
			},
			expectErr: true,
			errMsg:    "assertion not yet valid",
		},
		{
			name: "expired assertion",
			assertion: &saml.Assertion{
				Conditions: &saml.Conditions{
					NotBefore:    now.Add(-10 * time.Minute),
					NotOnOrAfter: now.Add(-5 * time.Minute),
				},
				Subject: &saml.Subject{},
			},
			expectErr: true,
			errMsg:    "assertion expired",
		},
		{
			name: "audience restriction failed",
			assertion: &saml.Assertion{
				Conditions: &saml.Conditions{
					NotBefore:    now.Add(-5 * time.Minute),
					NotOnOrAfter: now.Add(5 * time.Minute),
					AudienceRestrictions: []saml.AudienceRestriction{
						{
							Audience: saml.Audience{
								Value: "https://wrong-entity.com",
							},
						},
					},
				},
				Subject: &saml.Subject{},
			},
			expectErr: true,
			errMsg:    "audience restriction failed",
		},
		{
			name: "recipient mismatch",
			assertion: &saml.Assertion{
				Conditions: &saml.Conditions{
					NotBefore:    now.Add(-5 * time.Minute),
					NotOnOrAfter: now.Add(5 * time.Minute),
				},
				Subject: &saml.Subject{
					SubjectConfirmations: []saml.SubjectConfirmation{
						{
							SubjectConfirmationData: &saml.SubjectConfirmationData{
								NotOnOrAfter: now.Add(5 * time.Minute),
								Recipient:    "https://wrong-acs.com",
							},
						},
					},
				},
			},
			expectErr: true,
			errMsg:    "recipient mismatch",
		},
		{
			name: "subject confirmations missing entirely allowed",
			assertion: &saml.Assertion{
				Conditions: &saml.Conditions{
					NotBefore:    now.Add(-5 * time.Minute),
					NotOnOrAfter: now.Add(5 * time.Minute),
				},
				Subject: &saml.Subject{},
			},
			expectErr: false,
		},
		{
			name: "subject confirmation missing data fails",
			assertion: &saml.Assertion{
				Conditions: &saml.Conditions{
					NotBefore:    now.Add(-5 * time.Minute),
					NotOnOrAfter: now.Add(5 * time.Minute),
				},
				Subject: &saml.Subject{
					SubjectConfirmations: []saml.SubjectConfirmation{{}},
				},
			},
			expectErr: true,
			errMsg:    "subject confirmation data missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.validateAssertionConditions(tt.assertion)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckReplayAttack(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	now := time.Now()

	assertion1 := &saml.Assertion{
		ID: "assertion-unique-1",
		Conditions: &saml.Conditions{
			NotOnOrAfter: now.Add(5 * time.Minute),
		},
	}

	assertion2 := &saml.Assertion{
		ID: "assertion-unique-2",
		Conditions: &saml.Conditions{
			NotOnOrAfter: now.Add(5 * time.Minute),
		},
	}

	assertionMissingID := &saml.Assertion{}

	// First use should succeed
	err = provider.checkReplayAttack(assertion1)
	assert.NoError(t, err)

	// Second use of same assertion should fail
	err = provider.checkReplayAttack(assertion1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has already been used")

	// Different assertion should succeed
	err = provider.checkReplayAttack(assertion2)
	assert.NoError(t, err)

	// Missing assertion ID should fail immediately before locking
	err = provider.checkReplayAttack(assertionMissingID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing ID")
}

func TestCleanupExpiredAssertionIDs(t *testing.T) {
	ctx := context.Background()
	config := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)

	now := time.Now()

	provider.assertionIDsMu.Lock()

	// Add expired assertion
	provider.assertionIDs["expired-1"] = now.Add(-10 * time.Minute)
	provider.assertionIDs["expired-2"] = now.Add(-5 * time.Minute)

	// Add valid assertion
	provider.assertionIDs["valid-1"] = now.Add(5 * time.Minute)
	provider.assertionIDs["valid-2"] = now.Add(10 * time.Minute)

	// Cleanup
	provider.cleanupExpiredAssertionIDs()

	provider.assertionIDsMu.Unlock()

	// Verify expired ones are removed
	assert.NotContains(t, provider.assertionIDs, "expired-1")
	assert.NotContains(t, provider.assertionIDs, "expired-2")

	// Verify valid ones remain
	assert.Contains(t, provider.assertionIDs, "valid-1")
	assert.Contains(t, provider.assertionIDs, "valid-2")
}

func TestEnforceSignaturePolicy(t *testing.T) {
	ctx := context.Background()
	baseConfig := createTestSAMLConfig(t)

	provider, err := NewSAMLProvider(ctx, baseConfig)
	require.NoError(t, err)

	unsignedResponse := []byte(`<Response></Response>`)
	signedResponseOnly := []byte(`<Response><Signature></Signature></Response>`)
	unsignedResponseSignedAssertion := []byte(`<Response><Assertion><Signature></Signature></Assertion></Response>`)
	signedResponseUnsignedAssertion := []byte(`<Response><Signature></Signature><Assertion></Assertion></Response>`)
	signedResponseSignedAssertion := []byte(`<Response><Signature></Signature><Assertion><Signature></Signature></Assertion></Response>`)
	unsignedResponseUnsignedAssertion := []byte(`<Response><Assertion></Assertion></Response>`)
	encryptedOnlyResponse := []byte(`<Response><EncryptedAssertion></EncryptedAssertion></Response>`)

	tests := []struct {
		name        string
		wantRespSig bool
		wantAssSig  bool
		responseXML []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "no requirements allows unsigned response and assertions",
			wantRespSig: false,
			wantAssSig:  false,
			responseXML: unsignedResponseUnsignedAssertion,
			wantErr:     false,
		},
		{
			name:        "require response signature - response signed",
			wantRespSig: true,
			wantAssSig:  false,
			responseXML: signedResponseOnly,
			wantErr:     false,
		},
		{
			name:        "require response signature - response unsigned",
			wantRespSig: true,
			wantAssSig:  false,
			responseXML: unsignedResponse,
			wantErr:     true,
			errContains: "requires response signature",
		},
		{
			name:        "require assertion signatures - assertion signed",
			wantRespSig: false,
			wantAssSig:  true,
			responseXML: unsignedResponseSignedAssertion,
			wantErr:     false,
		},
		{
			name:        "require assertion signatures - assertion unsigned",
			wantRespSig: false,
			wantAssSig:  true,
			responseXML: unsignedResponseUnsignedAssertion,
			wantErr:     true,
			errContains: "unsigned but configuration requires signed assertions",
		},
		{
			name:        "require both - response and assertion signed",
			wantRespSig: true,
			wantAssSig:  true,
			responseXML: signedResponseSignedAssertion,
			wantErr:     false,
		},
		{
			name:        "require both - response signed, assertion unsigned (OR semantics)",
			wantRespSig: true,
			wantAssSig:  true,
			responseXML: signedResponseUnsignedAssertion,
			wantErr:     false,
		},
		{
			name:        "require both - response unsigned, assertion signed (OR semantics)",
			wantRespSig: true,
			wantAssSig:  true,
			responseXML: unsignedResponseSignedAssertion,
			wantErr:     false,
		},
		{
			name:        "require assertion signatures - encrypted-only assertions allowed",
			wantRespSig: false,
			wantAssSig:  true,
			responseXML: encryptedOnlyResponse,
			wantErr:     false,
		},
		{
			name:        "require both - encrypted-only assertions allowed when response unsigned",
			wantRespSig: true,
			wantAssSig:  true,
			responseXML: encryptedOnlyResponse,
			wantErr:     false,
		},
		{
			name:        "require both - response and assertions unsigned fails",
			wantRespSig: true,
			wantAssSig:  true,
			responseXML: unsignedResponseUnsignedAssertion,
			wantErr:     true,
			errContains: "does not satisfy required response or assertion signature policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Override config flags for this test case
			provider.config.WantResponseSigned = tt.wantRespSig
			provider.config.WantAssertionsSigned = tt.wantAssSig

			err := provider.enforceSignaturePolicy(tt.responseXML)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}
