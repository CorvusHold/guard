//go:build integration
// +build integration

package provider

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
)

// TestSAMLProvider_FullFlow tests a complete SAML authentication flow
// with a mock/test SAML IdP.
// Note: This requires setting up a test IdP or using SAMLtest.id
func TestSAMLProvider_FullFlow(t *testing.T) {
	// Skip if no test IdP is available
	t.Skip("Integration test requires a SAML test IdP - use SAMLtest.id or similar")

	ctx := context.Background()

	// Example configuration for SAMLtest.id
	config := &domain.Config{
		ID:           uuid.New(),
		TenantID:     uuid.New(),
		Name:         "SAMLtest.id Provider",
		Slug:         "samltest",
		ProviderType: domain.ProviderTypeSAML,
		Enabled:      true,
		EntityID:     "https://sp.example.com",
		ACSUrl:       "https://sp.example.com/saml/acs",
		SLOUrl:       "https://sp.example.com/saml/slo",
		// You would fetch this from https://samltest.id/saml/idp
		IdPMetadataURL: "https://samltest.id/saml/idp",
		AttributeMapping: map[string][]string{
			"email":      {"email", "mail"},
			"first_name": {"firstName", "givenName"},
			"last_name":  {"lastName", "surname"},
		},
		WantAssertionsSigned: true,
		WantResponseSigned:   false,
		SignRequests:         false,
	}

	// Create SAML provider
	provider, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Step 1: Start authentication flow
	startResult, err := provider.Start(ctx, domain.StartOptions{
		RedirectURL: "https://sp.example.com/callback",
	})
	require.NoError(t, err)
	require.NotNil(t, startResult)

	// Verify start result
	assert.NotEmpty(t, startResult.AuthorizationURL)
	assert.NotEmpty(t, startResult.State)
	assert.NotEmpty(t, startResult.RelayState)
	assert.NotEmpty(t, startResult.SAMLRequest)

	t.Logf("Authorization URL: %s", startResult.AuthorizationURL)
	t.Logf("State: %s", startResult.State)

	// At this point, a real test would:
	// 1. Navigate to the authorization URL
	// 2. The IdP would authenticate the user
	// 3. The IdP would POST a SAML response to the ACS URL
	// 4. We would parse that response and call provider.Callback()

	// For a proper integration test, you would need:
	// - A test browser/HTTP client
	// - A test user account at the IdP
	// - To intercept the SAML response
	// - Then call provider.Callback() with the response

	// Step 2: Get SP metadata
	metadata, err := provider.GetMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	assert.Equal(t, domain.ProviderTypeSAML, metadata.ProviderType)
	assert.Equal(t, config.EntityID, metadata.EntityID)
	assert.Equal(t, config.ACSUrl, metadata.ACSUrl)
	assert.NotEmpty(t, metadata.SPCertificate)
	assert.NotEmpty(t, metadata.MetadataXML)

	t.Logf("SP Metadata:\n%s", metadata.MetadataXML)
}

// TestSAMLProvider_MetadataFetch tests fetching IdP metadata from a real URL.
// This test is safe to run as it only fetches public metadata.
func TestSAMLProvider_MetadataFetch(t *testing.T) {
	t.Skip("Integration test - uncomment to test against real IdPs")

	ctx := context.Background()

	testCases := []struct {
		name        string
		metadataURL string
	}{
		{
			name:        "SAMLtest.id",
			metadataURL: "https://samltest.id/saml/idp",
		},
		// Add other test IdPs here
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &domain.Config{
				EntityID:       "https://sp.example.com",
				ACSUrl:         "https://sp.example.com/saml/acs",
				IdPMetadataURL: tc.metadataURL,
			}

			metadata, err := parseSAMLMetadata(ctx, config)
			require.NoError(t, err)
			require.NotNil(t, metadata)

			// Verify we got valid metadata
			assert.NotEmpty(t, metadata.EntityID)
			t.Logf("IdP Entity ID: %s", metadata.EntityID)

			// Update config from metadata
			err = updateConfigFromMetadata(config, metadata)
			require.NoError(t, err)

			assert.NotEmpty(t, config.IdPEntityID)
			assert.NotEmpty(t, config.IdPSSOUrl)
			t.Logf("IdP SSO URL: %s", config.IdPSSOUrl)
		})
	}
}

// TestSAMLProvider_CertificateRotation tests certificate generation and rotation.
func TestSAMLProvider_CertificateRotation(t *testing.T) {
	ctx := context.Background()

	config := &domain.Config{
		ID:             uuid.New(),
		TenantID:       uuid.New(),
		Name:           "Test SAML Provider",
		Slug:           "test-saml",
		ProviderType:   domain.ProviderTypeSAML,
		Enabled:        true,
		EntityID:       "https://sp.example.com",
		ACSUrl:         "https://sp.example.com/saml/acs",
		IdPMetadataXML: mockIdPMetadataXML,
	}

	// First provider instance - generates certificate
	provider1, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, provider1)

	// Get metadata with first certificate
	metadata1, err := provider1.GetMetadata(ctx)
	require.NoError(t, err)
	cert1 := metadata1.SPCertificate

	// Verify certificate was generated
	assert.NotEmpty(t, config.SPCertificate)
	assert.NotEmpty(t, config.SPPrivateKey)

	// Create second provider instance - should use existing certificate
	provider2, err := NewSAMLProvider(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, provider2)

	// Get metadata with second provider
	metadata2, err := provider2.GetMetadata(ctx)
	require.NoError(t, err)
	cert2 := metadata2.SPCertificate

	// Verify both providers use the same certificate
	assert.Equal(t, cert1, cert2)
}
