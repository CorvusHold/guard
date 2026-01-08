package provider

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"

	"github.com/corvusHold/guard/internal/auth/sso/domain"
	"github.com/rs/zerolog"
)

// SAMLProvider implements the SSOProvider interface for SAML 2.0.
type SAMLProvider struct {
	config         *domain.Config
	sp             *saml.ServiceProvider
	idpMetadata    *saml.EntityDescriptor
	spCert         tls.Certificate
	assertionIDs   map[string]time.Time // For replay attack prevention
	assertionIDsMu sync.RWMutex         // Protects assertionIDs map
	log            zerolog.Logger
}

const (
	signatureMethodRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	signatureMethodRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	signatureMethodRSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
)

// NewSAMLProvider creates a new SAML provider instance.
// It parses the IdP metadata, loads or generates SP certificates,
// and configures the SAML Service Provider.
func NewSAMLProvider(ctx context.Context, config *domain.Config) (*SAMLProvider, error) {
	if err := validateSAMLConfig(config); err != nil {
		return nil, fmt.Errorf("invalid SAML configuration: %w", err)
	}

	// Load or generate SP certificate
	spCert, err := loadOrGenerateCertificate(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load SP certificate: %w", err)
	}

	// Parse IdP metadata
	idpMetadata, err := parseSAMLMetadata(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata: %w", err)
	}

	// Extract IdP information from metadata
	if err := updateConfigFromMetadata(config, idpMetadata); err != nil {
		return nil, fmt.Errorf("failed to extract IdP info from metadata: %w", err)
	}

	// Parse ACS URL
	acsURL, err := url.Parse(config.ACSUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid ACS URL: %w", err)
	}

	key, ok := spCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid SP certificate: private key must be RSA, got %T", spCert.PrivateKey)
	}

	// Create ServiceProvider
	sp := &saml.ServiceProvider{
		EntityID:          config.EntityID,
		Key:               key,
		Certificate:       spCert.Leaf,
		MetadataURL:       *acsURL, // Use ACS URL base for metadata
		AcsURL:            *acsURL,
		IDPMetadata:       idpMetadata,
		AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
		SignatureMethod:   "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		// Allow IdP-initiated SSO based on explicit config (needed for Azure AD "Test" button)
		AllowIDPInitiated: config.AllowIdpInitiated,
	}

	// Configure SLO if provided
	if config.SLOUrl != "" {
		sloURL, err := url.Parse(config.SLOUrl)
		if err != nil {
			return nil, fmt.Errorf("invalid SLO URL: %w", err)
		}
		sp.SloURL = *sloURL
	}

	return &SAMLProvider{
		config:       config,
		sp:           sp,
		idpMetadata:  idpMetadata,
		spCert:       spCert,
		assertionIDs: make(map[string]time.Time),
	}, nil
}

// SetLogger sets the logger for SAML provider.
func (p *SAMLProvider) SetLogger(log zerolog.Logger) {
	p.log = log
}

// Type returns the provider type.
func (p *SAMLProvider) Type() domain.ProviderType {
	return domain.ProviderTypeSAML
}

// ValidateConfig validates the SAML provider configuration.
func (p *SAMLProvider) ValidateConfig() error {
	return validateSAMLConfig(p.config)
}

// validateSAMLConfig validates the SAML configuration.
func validateSAMLConfig(config *domain.Config) error {
	if config == nil {
		return fmt.Errorf("config is nil")
	}
	if config.EntityID == "" {
		return fmt.Errorf("entity_id is required")
	}
	if config.ACSUrl == "" {
		return fmt.Errorf("acs_url is required")
	}
	if config.IdPMetadataURL == "" && config.IdPMetadataXML == "" {
		return fmt.Errorf("either idp_metadata_url or idp_metadata_xml is required")
	}
	return nil
}

func getAudiencesString(assertion *saml.Assertion) string {
	if assertion == nil || assertion.Conditions == nil {
		return "none"
	}
	if len(assertion.Conditions.AudienceRestrictions) == 0 {
		return "none"
	}
	audiences := make([]string, 0, len(assertion.Conditions.AudienceRestrictions))
	for _, r := range assertion.Conditions.AudienceRestrictions {
		if r.Audience.Value != "" {
			audiences = append(audiences, r.Audience.Value)
		}
	}
	if len(audiences) == 0 {
		return "none"
	}
	return strings.Join(audiences, ", ")
}

// Start initiates the SAML authentication flow.
// It generates a SAML AuthnRequest, signs it (if configured),
// and returns the redirect URL.
func (p *SAMLProvider) Start(ctx context.Context, opts domain.StartOptions) (*domain.StartResult, error) {
	// Generate relay state (equivalent to OAuth state for CSRF protection)
	relayState := opts.State
	if relayState == "" {
		var err error
		relayState, err = generateState()
		if err != nil {
			return nil, fmt.Errorf("failed to generate relay state: %w", err)
		}
	}

	// Build AuthnRequest
	req, err := p.sp.MakeAuthenticationRequest(
		p.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AuthnRequest: %w", err)
	}

	// Apply ForceAuthn if requested
	if opts.ForceAuthn || p.config.ForceAuthn {
		req.ForceAuthn = boolPtr(true)
	}

	// Apply LoginHint if provided (as Subject NameID)
	if opts.LoginHint != "" {
		req.Subject = &saml.Subject{
			NameID: &saml.NameID{
				Format: string(saml.EmailAddressNameIDFormat),
				Value:  opts.LoginHint,
			},
		}
	}

	// Build redirect URL with signed request
	redirectURL, err := buildAuthRequestURL(p.sp, req, relayState, p.config.SignRequests)
	if err != nil {
		return nil, fmt.Errorf("failed to build AuthnRequest URL: %w", err)
	}

	// Encode SAML request for storage (if needed for debugging)
	samlRequestXML, err := xml.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AuthnRequest: %w", err)
	}

	p.log.Debug().
		Str("provider_id", p.config.ID.String()).
		Str("sso_url", redirectURL).
		Str("relay_state", relayState).
		Msg("SAML flow initiated - redirecting to IdP")

	return &domain.StartResult{
		AuthorizationURL: redirectURL,
		State:            relayState,
		RelayState:       relayState,
		SAMLRequest:      base64.StdEncoding.EncodeToString(samlRequestXML),
	}, nil
}

// Callback handles the SAML callback.
// It parses the SAML response, validates signatures and assertions,
// extracts user attributes, and returns the user profile.
func (p *SAMLProvider) Callback(ctx context.Context, req domain.CallbackRequest) (*domain.Profile, error) {
	if req.SAMLResponse == "" {
		return nil, fmt.Errorf("SAMLResponse is required")
	}

	// Decode SAML response
	samlResponseXML, err := base64.StdEncoding.DecodeString(req.SAMLResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAMLResponse: %w", err)
	}

	p.log.Debug().
		Str("provider_id", p.config.ID.String()).
		Int("response_size", len(samlResponseXML)).
		Msg("SAML response received from IdP")

	if p.log.GetLevel() <= zerolog.DebugLevel {
		p.log.Debug().
			Str("provider_id", p.config.ID.String()).
			Str("saml_response", string(samlResponseXML)).
			Msg("Full SAML response XML (base64 decoded)")
	}

	// Let the crewjam/saml ServiceProvider handle XML parsing, signature
	// verification, condition checks, and encrypted assertion handling.
	// We still run our own additional condition checks and replay protection
	// below.
	var assertion *saml.Assertion
	if bytes.Contains(samlResponseXML, []byte("EncryptedAssertion")) {
		// Use decryptAssertion when the response contains an encrypted assertion.
		assertion, err = p.decryptAssertion(samlResponseXML)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt SAML assertion: %w", err)
		}
	} else {
		assertion, err = p.sp.ParseXMLResponse(samlResponseXML, nil, p.sp.AcsURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SAML response: %w", err)
		}
	}

	if assertion == nil {
		p.log.Warn().
			Str("provider_id", p.config.ID.String()).
			Msg("No assertion found in SAML response")
		return nil, fmt.Errorf("no assertion found in SAML response")
	}

	p.log.Debug().
		Str("provider_id", p.config.ID.String()).
		Str("assertion_id", assertion.ID).
		Str("subject", assertion.Subject.NameID.Value).
		Time("not_before", assertion.Conditions.NotBefore).
		Time("not_on_or_after", assertion.Conditions.NotOnOrAfter).
		Msg("SAML assertion parsed successfully")

	// Enforce configured signature requirements by inspecting the verified
	// SAML Response XML. At this point ParseXMLResponse has already validated
	// cryptographic signatures; this check only ensures that expected
	// signature placement (response vs assertions) matches configuration.
	if err := p.enforceSignaturePolicy(samlResponseXML); err != nil {
		p.log.Debug().
			Str("provider_id", p.config.ID.String()).
			Bool("want_response_signed", p.config.WantResponseSigned).
			Bool("want_assertions_signed", p.config.WantAssertionsSigned).
			Err(err).
			Msg("Signature policy enforcement failed")
		return nil, err
	}

	// Enforce configured signature requirements by inspecting the verified
	// SAML Response XML. At this point ParseXMLResponse has already validated
	// the cryptographic signatures; this check only ensures the expected
	// signature placement (response vs assertions) matches configuration.
	if err := p.enforceSignaturePolicy(samlResponseXML); err != nil {
		return nil, err
	}

	// Additional validation for assertion conditions specific to our requirements
	if err := p.validateAssertionConditions(assertion); err != nil {
		p.log.Error().
			Str("provider_id", p.config.ID.String()).
			Str("assertion_id", assertion.ID).
			Err(err).
			Msg("SAML assertion validation failed")
		return nil, fmt.Errorf("assertion validation failed: %w", err)
	}

	// Check for replay attacks
	if err := p.checkReplayAttack(assertion); err != nil {
		p.log.Warn().
			Str("provider_id", p.config.ID.String()).
			Str("assertion_id", assertion.ID).
			Err(err).
			Msg("Replay attack detected")
		return nil, fmt.Errorf("replay attack detected: %w", err)
	}

	// Extract user profile from assertion
	profile, err := p.extractProfile(assertion)
	if err != nil {
		p.log.Error().
			Str("provider_id", p.config.ID.String()).
			Str("assertion_id", assertion.ID).
			Err(err).
			Msg("Failed to extract user profile from SAML assertion")
		return nil, fmt.Errorf("failed to extract profile: %w", err)
	}

	p.log.Debug().
		Str("provider_id", p.config.ID.String()).
		Str("subject", profile.Subject).
		Str("email", profile.Email).
		Str("name", profile.Name).
		Strs("groups", profile.Groups).
		Msg("Extracted user profile from SAML assertion")

	// Apply custom attribute mapping if configured
	if len(p.config.AttributeMapping) > 0 {
		domain.ApplyAttributeMapping(profile, p.config.AttributeMapping)
	}

	return profile, nil
}

// GetMetadata returns the SAML Service Provider metadata.
func (p *SAMLProvider) GetMetadata(ctx context.Context) (*domain.Metadata, error) {
	// Generate SP metadata
	metadata := p.sp.Metadata()

	// Marshal to XML
	metadataXML, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SP metadata: %w", err)
	}

	// Get certificate expiry
	var certExpiry *time.Time
	if p.spCert.Leaf != nil {
		certExpiry = &p.spCert.Leaf.NotAfter
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: p.spCert.Leaf.Raw,
	})

	return &domain.Metadata{
		ProviderType:      domain.ProviderTypeSAML,
		EntityID:          p.config.EntityID,
		ACSUrl:            p.config.ACSUrl,
		SLOUrl:            p.config.SLOUrl,
		SPCertificate:     string(certPEM),
		CertificateExpiry: certExpiry,
		MetadataXML:       string(metadataXML),
	}, nil
}

// enforceSignaturePolicy enforces configured signature requirements by
// inspecting the SAML Response XML after it has been successfully
// verified by the ServiceProvider.
func (p *SAMLProvider) enforceSignaturePolicy(responseXML []byte) error {
	if !p.config.WantResponseSigned && !p.config.WantAssertionsSigned {
		return nil
	}

	type xmlSignature struct {
		XMLName xml.Name `xml:"Signature"`
	}

	type xmlAssertion struct {
		XMLName   xml.Name      `xml:"Assertion"`
		Signature *xmlSignature `xml:"Signature"`
	}

	type xmlResponse struct {
		XMLName    xml.Name       `xml:"Response"`
		Signature  *xmlSignature  `xml:"Signature"`
		Assertions []xmlAssertion `xml:"Assertion"`
	}

	var resp xmlResponse
	if err := xml.Unmarshal(responseXML, &resp); err != nil {
		return fmt.Errorf("failed to inspect SAML response for signature policy: %w", err)
	}

	responseSigned := resp.Signature != nil
	hasPlainAssertions := len(resp.Assertions) > 0
	allPlainAssertionsSigned := true
	for _, a := range resp.Assertions {
		if a.Signature == nil {
			allPlainAssertionsSigned = false
			break
		}
	}

	// If only response signatures are required, enforce strictly.
	if p.config.WantResponseSigned && !p.config.WantAssertionsSigned {
		if !responseSigned {
			return fmt.Errorf("SAML response is not signed but configuration requires response signature")
		}
		return nil
	}

	// If only assertion signatures are required, enforce strictly for any
	// plaintext assertions we can see. Encrypted assertions are already
	// validated by the ServiceProvider and are not re-checked here.
	if !p.config.WantResponseSigned && p.config.WantAssertionsSigned {
		if hasPlainAssertions && !allPlainAssertionsSigned {
			return fmt.Errorf("one or more SAML assertions are unsigned but configuration requires signed assertions")
		}
		return nil
	}

	// When both flags are true, treat them as an OR for compatibility with
	// real-world IdPs that may sign either the response or the assertions.
	// Consider the assertion side satisfied if there are no plaintext
	// assertions (e.g., only EncryptedAssertion is present) since
	// ServiceProvider.ParseXMLResponse has already validated them.
	assertionsSignedOK := !hasPlainAssertions || allPlainAssertionsSigned
	if responseSigned || assertionsSignedOK {
		return nil
	}

	return fmt.Errorf("SAML response does not satisfy required response or assertion signature policy")
}

// validateAssertionConditions validates the assertion conditions.
func (p *SAMLProvider) validateAssertionConditions(assertion *saml.Assertion) error {
	now := time.Now()

	p.log.Debug().
		Str("provider_id", p.config.ID.String()).
		Time("now", now).
		Time("not_before", assertion.Conditions.NotBefore).
		Time("not_on_or_after", assertion.Conditions.NotOnOrAfter).
		Str("audiences", getAudiencesString(assertion)).
		Msg("Validating SAML assertion conditions")

	if assertion.Conditions == nil {
		p.log.Warn().
			Str("provider_id", p.config.ID.String()).
			Msg("Assertion conditions missing - NotBefore not set")
		return fmt.Errorf("assertion conditions missing")
	}

	// Check NotBefore condition
	if !assertion.Conditions.NotBefore.IsZero() && assertion.Conditions.NotBefore.After(now) {
		p.log.Warn().
			Str("provider_id", p.config.ID.String()).
			Time("not_before", assertion.Conditions.NotBefore).
			Time("now", now).
			Msg("Assertion not yet valid - NotBefore in future")
		return fmt.Errorf("assertion not yet valid: NotBefore=%s, Now=%s",
			assertion.Conditions.NotBefore, now)
	}

	// Check NotOnOrAfter condition
	if !assertion.Conditions.NotOnOrAfter.IsZero() && assertion.Conditions.NotOnOrAfter.Before(now) {
		p.log.Warn().
			Str("provider_id", p.config.ID.String()).
			Time("not_on_or_after", assertion.Conditions.NotOnOrAfter).
			Time("now", now).
			Msg("Assertion expired - NotOnOrAfter in past")
		return fmt.Errorf("assertion expired: NotOnOrAfter=%s, Now=%s",
			assertion.Conditions.NotOnOrAfter, now)
	}

	// Verify Audience restriction
	if len(assertion.Conditions.AudienceRestrictions) > 0 {
		audienceValid := false
		for _, restriction := range assertion.Conditions.AudienceRestrictions {
			if restriction.Audience.Value == p.config.EntityID {
				audienceValid = true
				break
			}
		}
		if !audienceValid {
			p.log.Error().
				Str("provider_id", p.config.ID.String()).
				Str("expected_audience", p.config.EntityID).
				Str("audiences", getAudiencesString(assertion)).
				Msg("Audience restriction failed")
			return fmt.Errorf("audience restriction failed: expected %s", p.config.EntityID)
		}
	}

	// Verify SubjectConfirmation
	if assertion.Subject != nil && assertion.Subject.SubjectConfirmations != nil && len(assertion.Subject.SubjectConfirmations) > 0 {
		for _, confirmation := range assertion.Subject.SubjectConfirmations {
			if confirmation.SubjectConfirmationData == nil {
				p.log.Warn().
					Str("provider_id", p.config.ID.String()).
					Msg("Subject confirmation data missing")
				return fmt.Errorf("subject confirmation data missing")
			}
			if !confirmation.SubjectConfirmationData.NotOnOrAfter.IsZero() && confirmation.SubjectConfirmationData.NotOnOrAfter.Before(now) {
				p.log.Warn().
					Str("provider_id", p.config.ID.String()).
					Time("not_on_or_after", confirmation.SubjectConfirmationData.NotOnOrAfter).
					Time("now", now).
					Msg("Subject confirmation expired")
				return fmt.Errorf("subject confirmation expired")
			}
			if confirmation.SubjectConfirmationData.Recipient != "" && confirmation.SubjectConfirmationData.Recipient != p.config.ACSUrl {
				p.log.Error().
					Str("provider_id", p.config.ID.String()).
					Str("expected_recipient", p.config.ACSUrl).
					Str("actual_recipient", confirmation.SubjectConfirmationData.Recipient).
					Msg("Recipient mismatch in SAML response")
				return fmt.Errorf("recipient mismatch: expected %s, got %s",
					p.config.ACSUrl, confirmation.SubjectConfirmationData.Recipient)
			}
		}
	}

	return nil
}

// checkReplayAttack checks if the assertion has been used before.
func (p *SAMLProvider) checkReplayAttack(assertion *saml.Assertion) error {
	assertionID := assertion.ID
	if assertionID == "" {
		return fmt.Errorf("assertion missing ID")
	}

	// Use write lock for checking and updating
	p.assertionIDsMu.Lock()
	defer p.assertionIDsMu.Unlock()

	// Check if we've seen this assertion ID before
	if _, exists := p.assertionIDs[assertionID]; exists {
		return fmt.Errorf("assertion ID %s has already been used", assertionID)
	}

	// Store the assertion ID with its expiry time
	// Use NotOnOrAfter from Conditions if available, otherwise use a default expiry
	var expiryTime time.Time
	if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() {
		expiryTime = assertion.Conditions.NotOnOrAfter
	} else {
		// Default to 1 hour from now if no expiry is specified
		expiryTime = time.Now().Add(1 * time.Hour)
	}
	p.assertionIDs[assertionID] = expiryTime

	// Clean up expired assertion IDs (simple cleanup strategy)
	// In production, this should be done periodically in a background task
	p.cleanupExpiredAssertionIDs()

	return nil
}

// cleanupExpiredAssertionIDs removes expired assertion IDs from the replay cache.
// Must be called with assertionIDsMu write lock held.
func (p *SAMLProvider) cleanupExpiredAssertionIDs() {
	now := time.Now()
	for id, expiry := range p.assertionIDs {
		if expiry.Before(now) {
			delete(p.assertionIDs, id)
		}
	}
}

// decryptAssertion decrypts an encrypted assertion.
func (p *SAMLProvider) decryptAssertion(responseXML []byte) (*saml.Assertion, error) {
	// Note: Encrypted assertions handling is complex and requires additional implementation
	// For now, we'll delegate to the crewjam/saml ServiceProvider's ParseXMLResponse,
	// which already supports EncryptedAssertion elements when the SP is configured
	// with the appropriate key material.
	assertion, err := p.sp.ParseXMLResponse(responseXML, nil, p.sp.AcsURL)
	if err != nil {
		return nil, err
	}

	return assertion, nil
}

// extractProfile extracts the user profile from a SAML assertion.
func (p *SAMLProvider) extractProfile(assertion *saml.Assertion) (*domain.Profile, error) {
	profile := &domain.Profile{
		RawAttributes: make(map[string]interface{}),
	}

	// Extract Subject (NameID)
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		profile.Subject = assertion.Subject.NameID.Value

		// If NameID is an email, also set it as email
		if string(assertion.Subject.NameID.Format) == string(saml.EmailAddressNameIDFormat) {
			profile.Email = assertion.Subject.NameID.Value
			profile.EmailVerified = true // SAML assertions are trusted
		}
	}

	// Extract attributes from AttributeStatement
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			attrName := attr.Name

			// Extract attribute values
			var values []string
			for _, value := range attr.Values {
				values = append(values, value.Value)
			}

			// Store in RawAttributes using Name
			if len(values) == 1 {
				profile.RawAttributes[attrName] = values[0]
				// Also store with lowercase key for case-insensitive lookup
				profile.RawAttributes[strings.ToLower(attrName)] = values[0]
			} else if len(values) > 1 {
				profile.RawAttributes[attrName] = values
				profile.RawAttributes[strings.ToLower(attrName)] = values
			}

			// Also store by FriendlyName if present
			if attr.FriendlyName != "" {
				if len(values) == 1 {
					profile.RawAttributes[attr.FriendlyName] = values[0]
					profile.RawAttributes[strings.ToLower(attr.FriendlyName)] = values[0]
				} else if len(values) > 1 {
					profile.RawAttributes[attr.FriendlyName] = values
					profile.RawAttributes[strings.ToLower(attr.FriendlyName)] = values
				}
			}

			// Extract standard attributes using Name field
			switch strings.ToLower(attrName) {
			case "email", "mail", "emailaddress":
				if len(values) > 1 {
					return nil, fmt.Errorf("email attribute contains multiple values")
				}
				if len(values) == 1 {
					profile.Email = values[0]
					profile.EmailVerified = true
				}
			case "givenname", "firstname", "given_name":
				if len(values) > 0 {
					profile.FirstName = values[0]
				}
			case "surname", "lastname", "family_name", "sn":
				if len(values) > 0 {
					profile.LastName = values[0]
				}
			case "displayname", "name", "cn":
				if len(values) > 0 {
					profile.Name = values[0]
				}
			case "groups", "memberof":
				profile.Groups = values
			}
		}
	}

	// Construct full name if not present
	if profile.Name == "" && (profile.FirstName != "" || profile.LastName != "") {
		profile.Name = strings.TrimSpace(profile.FirstName + " " + profile.LastName)
	}

	// Validate that we have at least a subject
	if profile.Subject == "" {
		return nil, fmt.Errorf("no subject found in SAML assertion")
	}

	return profile, nil
}

// parseSAMLMetadata parses IdP metadata from URL or XML.
func parseSAMLMetadata(ctx context.Context, config *domain.Config) (*saml.EntityDescriptor, error) {
	var metadataXML []byte
	var err error

	if config.IdPMetadataURL != "" {
		// Fetch metadata from URL
		metadataXML, err = fetchMetadataFromURL(ctx, config.IdPMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch metadata from URL: %w", err)
		}
	} else if config.IdPMetadataXML != "" {
		// Use provided XML
		metadataXML = []byte(config.IdPMetadataXML)
	} else {
		return nil, fmt.Errorf("no IdP metadata provided")
	}

	// Parse metadata
	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(metadataXML, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse IdP metadata XML: %w", err)
	}

	return &metadata, nil
}

// fetchMetadataFromURL fetches SAML metadata from a URL.
func fetchMetadataFromURL(ctx context.Context, metadataURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			// surface close errors via panic-free log; use default logger
			log.Printf("fetchMetadataFromURL: failed to close response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	metadataXML, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata response: %w", err)
	}

	return metadataXML, nil
}

// updateConfigFromMetadata extracts IdP information from metadata.
func updateConfigFromMetadata(config *domain.Config, metadata *saml.EntityDescriptor) error {
	// Extract IdP Entity ID
	if config.IdPEntityID == "" {
		config.IdPEntityID = metadata.EntityID
	}

	// Find SSO service
	if len(metadata.IDPSSODescriptors) == 0 {
		return fmt.Errorf("no IDPSSODescriptor found in metadata")
	}

	idpSSO := &metadata.IDPSSODescriptors[0]

	// Extract SSO URL
	for _, sso := range idpSSO.SingleSignOnServices {
		if sso.Binding == saml.HTTPRedirectBinding || sso.Binding == saml.HTTPPostBinding {
			if config.IdPSSOUrl == "" {
				config.IdPSSOUrl = sso.Location
			}
			break
		}
	}

	// Extract SLO URL
	for _, slo := range idpSSO.SingleLogoutServices {
		if slo.Binding == saml.HTTPRedirectBinding || slo.Binding == saml.HTTPPostBinding {
			if config.IdPSLOUrl == "" {
				config.IdPSLOUrl = slo.Location
			}
			break
		}
	}

	// Extract IdP certificate
	if len(idpSSO.KeyDescriptors) > 0 {
		for _, keyDescriptor := range idpSSO.KeyDescriptors {
			if keyDescriptor.Use == "signing" || keyDescriptor.Use == "" {
				if len(keyDescriptor.KeyInfo.X509Data.X509Certificates) > 0 {
					if config.IdPCertificate == "" {
						certData := keyDescriptor.KeyInfo.X509Data.X509Certificates[0].Data
						config.IdPCertificate = fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----",
							certData)
					}
					break
				}
			}
		}
	}

	return nil
}

// loadOrGenerateCertificate loads the SP certificate or generates a new one.
func loadOrGenerateCertificate(config *domain.Config) (tls.Certificate, error) {
	// If both certificate and key are provided, load them
	if config.SPCertificate != "" && config.SPPrivateKey != "" {
		cert, err := tls.X509KeyPair([]byte(config.SPCertificate), []byte(config.SPPrivateKey))
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to load certificate and key: %w", err)
		}

		// Parse the certificate to get the leaf
		if cert.Leaf == nil {
			cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
			}
		}

		// Set certificate expiry in config for persistence
		if cert.Leaf != nil {
			config.SPCertificateExpiresAt = &cert.Leaf.NotAfter
		}

		return cert, nil
	}

	// Generate a self-signed certificate for development
	certPEM, keyPEM, err := generateSelfSignedCert(config.EntityID, 365)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}

	// Update config with generated certificate
	config.SPCertificate = certPEM
	config.SPPrivateKey = keyPEM

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load generated certificate: %w", err)
	}

	// Parse the certificate to get the leaf
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// Set certificate expiry in config for persistence
	if cert.Leaf != nil {
		config.SPCertificateExpiresAt = &cert.Leaf.NotAfter
	}

	return cert, nil
}

// generateSelfSignedCert generates a self-signed X.509 certificate for SAML SP.
func generateSelfSignedCert(commonName string, validDays int) (certPEM, keyPEM string, err error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate a random serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Guard SAML SP"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	certPEM = string(pem.EncodeToMemory(certPEMBlock))

	// Encode private key to PEM
	keyPEMBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	keyPEM = string(pem.EncodeToMemory(keyPEMBlock))

	return certPEM, keyPEM, nil
}

// buildAuthRequestURL builds the redirect URL for the SAML AuthnRequest.
func buildAuthRequestURL(sp *saml.ServiceProvider, req *saml.AuthnRequest, relayState string, signRequest bool) (string, error) {
	// Marshal the request to XML
	reqBuf, err := xml.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AuthnRequest: %w", err)
	}

	// Compress and encode the request (per SAML spec for HTTP-Redirect binding)
	encodedReq, err := compressAndEncode(reqBuf)
	if err != nil {
		return "", fmt.Errorf("failed to compress and encode request: %w", err)
	}

	// Build redirect URL
	redirectURL := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	u, err := url.Parse(redirectURL)
	if err != nil {
		return "", fmt.Errorf("invalid SSO URL: %w", err)
	}

	query := u.Query()
	query.Set("SAMLRequest", encodedReq)
	if relayState != "" {
		query.Set("RelayState", relayState)
	}

	if signRequest {
		sigAlg := sp.SignatureMethod
		if sigAlg == "" {
			sigAlg = signatureMethodRSASHA256
		}
		key, ok := sp.Key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("service provider key must be an RSA private key for signing")
		}
		signingInput := buildRedirectSigningInput(encodedReq, relayState, sigAlg)
		signature, err := signRedirectRequest(key, sigAlg, signingInput)
		if err != nil {
			return "", fmt.Errorf("failed to sign AuthnRequest: %w", err)
		}
		query.Set("SigAlg", sigAlg)
		query.Set("Signature", signature)
	}

	u.RawQuery = query.Encode()
	return u.String(), nil
}

// compressAndEncode compresses and base64 encodes data for SAML HTTP-Redirect binding.
func compressAndEncode(data []byte) (string, error) {
	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", fmt.Errorf("failed to create deflate writer: %w", err)
	}
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return "", fmt.Errorf("failed to write compressed data: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", fmt.Errorf("failed to flush compressed data: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded, nil
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}

// buildRedirectSigningInput constructs the canonical query string used for HTTP-Redirect signatures.
func buildRedirectSigningInput(encodedRequest, relayState, sigAlg string) string {
	var b strings.Builder
	b.WriteString("SAMLRequest=")
	b.WriteString(url.QueryEscape(encodedRequest))
	if relayState != "" {
		b.WriteString("&RelayState=")
		b.WriteString(url.QueryEscape(relayState))
	}
	b.WriteString("&SigAlg=")
	b.WriteString(url.QueryEscape(sigAlg))
	return b.String()
}

// signRedirectRequest signs the canonical query string per SAML HTTP-Redirect rules.
func signRedirectRequest(key *rsa.PrivateKey, sigAlg, signingInput string) (string, error) {
	hashType, digest, err := computeSignatureDigest(sigAlg, signingInput)
	if err != nil {
		return "", err
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hashType, digest)
	if err != nil {
		return "", fmt.Errorf("failed to sign redirect request: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// computeSignatureDigest hashes the signing input for the provided algorithm.
func computeSignatureDigest(sigAlg, signingInput string) (crypto.Hash, []byte, error) {
	switch sigAlg {
	case signatureMethodRSASHA1:
		sum := sha1.Sum([]byte(signingInput))
		return crypto.SHA1, sum[:], nil
	case signatureMethodRSASHA256:
		sum := sha256.Sum256([]byte(signingInput))
		return crypto.SHA256, sum[:], nil
	case signatureMethodRSASHA512:
		sum := sha512.Sum512([]byte(signingInput))
		return crypto.SHA512, sum[:], nil
	default:
		return 0, nil, fmt.Errorf("unsupported signature algorithm: %s", sigAlg)
	}
}
