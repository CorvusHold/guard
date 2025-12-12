# SAML 2.0 Implementation Guide

This document provides a comprehensive guide to Guard's SAML 2.0 Service Provider (SP) implementation.

## Table of Contents

- [Overview](#overview)
- [SAML Flow](#saml-flow)
- [Configuration](#configuration)
- [Service Provider Metadata](#service-provider-metadata)
- [Certificate Management](#certificate-management)
- [Attribute Mapping](#attribute-mapping)
- [Security Considerations](#security-considerations)
- [Common Errors](#common-errors)
- [Testing](#testing)

## Overview

SAML (Security Assertion Markup Language) 2.0 is an XML-based standard for exchanging authentication and authorization data between parties. Guard implements a SAML 2.0 Service Provider that can integrate with any SAML 2.0 compliant Identity Provider (IdP).

### Key Concepts

- **Service Provider (SP)**: The application requesting authentication (Guard)
- **Identity Provider (IdP)**: The system that authenticates users (e.g., Okta, Azure AD, OneLogin)
- **Assertion**: A statement from the IdP about the authenticated user
- **Metadata**: XML document describing SP or IdP configuration
- **ACS (Assertion Consumer Service)**: The endpoint that receives SAML responses
- **SSO (Single Sign-On)**: The URL where authentication requests are sent
- **SLO (Single Logout)**: Optional endpoint for logout

## SAML Flow

### SP-Initiated Flow

```mermaid
sequenceDiagram
    participant User
    participant Guard (SP)
    participant IdP

    User->>Guard (SP): 1. Access protected resource
    Guard (SP)->>Guard (SP): 2. Generate AuthnRequest
    Guard (SP)->>User: 3. Redirect to IdP with AuthnRequest
    User->>IdP: 4. Forward AuthnRequest
    IdP->>User: 5. Authenticate (login form)
    User->>IdP: 6. Submit credentials
    IdP->>IdP: 7. Generate SAML Assertion
    IdP->>User: 8. POST SAML Response to ACS
    User->>Guard (SP): 9. Forward SAML Response
    Guard (SP)->>Guard (SP): 10. Validate Response & Assertion
    Guard (SP)->>Guard (SP): 11. Extract user profile
    Guard (SP)->>User: 12. Grant access + session
```

### Detailed Steps

1. **User requests access**: User tries to access a protected resource
2. **Generate AuthnRequest**: Guard creates a SAML authentication request
3. **Redirect to IdP**: User is redirected to IdP's SSO URL with the encoded request
4. **IdP authenticates user**: IdP shows login form and validates credentials
5. **Generate Assertion**: IdP creates a signed assertion with user information
6. **POST Response**: IdP POSTs the SAML response to Guard's ACS URL
7. **Validate Response**: Guard verifies signatures and validates the assertion
8. **Extract Profile**: Guard extracts user attributes from the assertion
9. **Create Session**: Guard creates a user session and grants access

### Callback internals

At the ACS endpoint, Guard processes the incoming `SAMLResponse` as follows:

1. Base64-decodes the `SAMLResponse` payload from the HTTP POST.
2. Uses the configured `crewjam/saml` `ServiceProvider.ParseXMLResponse` to:
   - Parse the SAML Response XML.
   - Decrypt any `EncryptedAssertion` elements using the SP private key.
   - Validate digital signatures against the IdP metadata.
3. Enforces the configured signature policy using `WantResponseSigned` and
   `WantAssertionsSigned`, ensuring the Response and/or Assertions are
   signed according to the documented OR semantics.
4. Applies additional Guard-specific checks on the resulting assertion:
   - Assertion conditions (time bounds, audience, recipient, etc.).
   - Replay protection using the assertion ID.
5. Extracts the user profile from assertion attributes and applies
   `AttributeMapping` before creating the session.

## Configuration

### Required Fields

```go
config := &domain.Config{
    // Identity
    EntityID: "https://your-app.com/saml/metadata",  // Unique SP identifier
    ACSUrl:   "https://your-app.com/saml/acs",       // Assertion Consumer Service URL

    // IdP Metadata (choose one)
    IdPMetadataURL: "https://idp.example.com/metadata",  // Fetch from URL
    // OR
    IdPMetadataXML: "<?xml version=\"1.0\"?>...",        // Provide XML directly

    // Basic settings
    ProviderType: domain.ProviderTypeSAML,
    Enabled:      true,
}
```

### Optional Fields

```go
config := &domain.Config{
    // ... required fields ...

    // Single Logout
    SLOUrl: "https://your-app.com/saml/slo",  // Single Logout URL (optional)

    // Certificate Management
    SPCertificate: "-----BEGIN CERTIFICATE-----\n...",  // SP public certificate
    SPPrivateKey:  "-----BEGIN RSA PRIVATE KEY-----\n...", // SP private key

    // Security Options
    WantAssertionsSigned: true,   // Require signed assertions when present
    WantResponseSigned:   false,  // Require signed responses when true
    SignRequests:         false,  // Sign AuthnRequests
    ForceAuthn:           false,  // Force re-authentication

    // Attribute Mapping
    AttributeMapping: map[string][]string{
        "email":      {"email", "mail", "emailAddress"},
        "first_name": {"firstName", "givenName"},
        "last_name":  {"lastName", "surname"},
        "groups":     {"groups", "memberOf"},
    },
}
```

## Service Provider Metadata

### Generating SP Metadata

```go
provider, err := provider.NewSAMLProvider(ctx, config)
if err != nil {
    return err
}

metadata, err := provider.GetMetadata(ctx)
if err != nil {
    return err
}

// metadata.MetadataXML contains the SP metadata XML
fmt.Println(metadata.MetadataXML)
```

### Example SP Metadata

```xml
<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://your-app.com/saml/metadata">
  <SPSSODescriptor
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <!-- SP Certificate for signature verification -->
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>MIIDXTCCAkWgAwIBAgIJ...</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>

    <!-- Assertion Consumer Service -->
    <AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://your-app.com/saml/acs"
        index="1" />

    <!-- Single Logout Service (optional) -->
    <SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://your-app.com/saml/slo" />

  </SPSSODescriptor>
</EntityDescriptor>
```

### Providing Metadata to IdP

Most IdPs support two ways to configure an SP:

1. **Metadata URL**: Host your SP metadata at a public URL and provide that URL to the IdP
2. **Upload XML**: Download the metadata XML and upload it to the IdP

## Certificate Management

SAML requires X.509 certificates for signing and encryption.

### Auto-Generated Certificates

If you don't provide a certificate, Guard will automatically generate a self-signed certificate:

```go
config := &domain.Config{
    EntityID: "https://your-app.com/saml/metadata",
    ACSUrl:   "https://your-app.com/saml/acs",
    // No certificate provided - will be auto-generated
}

provider, err := provider.NewSAMLProvider(ctx, config)
// config.SPCertificate and config.SPPrivateKey are now populated
```

**Important**: Save the generated certificate and private key to your database so they persist across restarts.

### Providing Your Own Certificate

```go
config := &domain.Config{
    EntityID:      "https://your-app.com/saml/metadata",
    ACSUrl:        "https://your-app.com/saml/acs",
    SPCertificate: certPEM,  // PEM-encoded certificate
    SPPrivateKey:  keyPEM,   // PEM-encoded private key
}
```

### Generating a Certificate

Using OpenSSL:

```bash
# Generate private key
openssl genrsa -out sp-key.pem 2048

# Generate self-signed certificate (valid for 365 days)
openssl req -new -x509 -key sp-key.pem -out sp-cert.pem -days 365 \
    -subj "/CN=your-app.com/O=Your Organization"

# View certificate details
openssl x509 -in sp-cert.pem -text -noout
```

Using Go:

```go
import "github.com/corvusHold/guard/internal/auth/sso/provider"

certPEM, keyPEM, err := provider.GenerateSelfSignedCert(
    "your-app.com",  // Common Name
    365,             // Valid for 365 days
)
```

### Certificate Rotation

When rotating certificates:

1. Generate a new certificate
2. Update both the old and new certificates in your SP metadata
3. Notify IdP administrators to update their configuration
4. After grace period, remove old certificate

## Attribute Mapping

SAML assertions contain user attributes with varying names depending on the IdP.

### Default Attribute Mapping

Guard uses these default mappings:

```go
{
    "email": [
        "email",
        "mail",
        "emailAddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    ],
    "first_name": [
        "given_name",
        "givenName",
        "firstName",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
    ],
    "last_name": [
        "family_name",
        "familyName",
        "lastName",
        "surname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
    ],
    "name": [
        "name",
        "displayName",
        "cn",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    ],
    "groups": [
        "groups",
        "memberOf",
        "http://schemas.xmlsoap.org/claims/Group",
    ],
}
```

### Custom Attribute Mapping

Override default mappings for your IdP:

```go
config.AttributeMapping = map[string][]string{
    "email": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
    "first_name": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"},
    "last_name": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"},
    "department": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department"},
}
```

### Assertion Example

```xml
<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <Subject>
    <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      user@example.com
    </NameID>
  </Subject>

  <AttributeStatement>
    <Attribute Name="email">
      <AttributeValue>user@example.com</AttributeValue>
    </Attribute>
    <Attribute Name="givenName">
      <AttributeValue>John</AttributeValue>
    </Attribute>
    <Attribute Name="surname">
      <AttributeValue>Doe</AttributeValue>
    </Attribute>
    <Attribute Name="groups">
      <AttributeValue>admin</AttributeValue>
      <AttributeValue>users</AttributeValue>
    </Attribute>
  </AttributeStatement>
</Assertion>
```

## Security Considerations

### Signature Verification

**Always verify signatures** in production:

```go
config.WantAssertionsSigned = true  // Require signed assertions (or encrypted assertions)
config.WantResponseSigned = true    // Accept signed responses as well
```

Guard uses the underlying `crewjam/saml` ServiceProvider to:
- Decrypt SAML responses and `EncryptedAssertion` elements using the SP key
- Validate digital signatures on the SAML Response and/or Assertions
- Validate signature algorithms and certificate chains based on IdP metadata

On top of that, Guard applies **policy** using `WantResponseSigned` and
`WantAssertionsSigned`:

- **Both false** (default policy only):
  - Guard still requires a valid SAML signature somewhere (Response or
    Assertion) via `ServiceProvider.ParseXMLResponse`, but does not enforce
    where that signature must appear.
- **Only `WantResponseSigned` true**:
  - The SAML Response **must** be signed. If it is not, Guard returns an
    error similar to:

    `"SAML response is not signed but configuration requires response signature"`

- **Only `WantAssertionsSigned` true**:
  - Any plaintext `<Assertion>` elements in the Response **must** be signed.
  - Encrypted assertions are validated by the ServiceProvider after
    decryption and do not need an additional policy check.
  - If a plaintext assertion is unsigned, Guard returns an error similar to:

    `"one or more SAML assertions are unsigned but configuration requires signed assertions"`

- **Both `WantResponseSigned` and `WantAssertionsSigned` true**:
  - Guard accepts responses where **either**:
    - the Response itself is signed, **or**
    - all plaintext assertions are signed.
  - This OR semantics matches common IdP behavior (some IdPs sign the
    Response, some sign Assertions) and is more future-proof than requiring
    both simultaneously.

### Time Validation

Guard validates temporal conditions:
- `NotBefore`: Assertion not valid before this time
- `NotOnOrAfter`: Assertion expires after this time
- `SubjectConfirmationData.NotOnOrAfter`: Subject confirmation expires

### Replay Attack Prevention

Guard tracks used assertion IDs to prevent replay attacks:
- Each assertion ID can only be used once
- Expired assertion IDs are automatically cleaned up

### Audience Restriction

Guard verifies the assertion is intended for this SP:

```xml
<AudienceRestriction>
  <Audience>https://your-app.com/saml/metadata</Audience>
</AudienceRestriction>
```

The audience must match your `EntityID`.

### Recipient Validation

Guard verifies the response was sent to the correct endpoint:

```xml
<SubjectConfirmationData
    Recipient="https://your-app.com/saml/acs" />
```

The recipient must match your `ACSUrl`.

## Common Errors

### Invalid Signature

**Error**: `response signature verification failed` or `assertion signature verification failed`

**Causes**:
- IdP certificate mismatch
- Response was tampered with
- Clock skew between SP and IdP

**Solutions**:
1. Verify IdP metadata is up-to-date
2. Check IdP certificate hasn't expired
3. Synchronize clocks (use NTP)

### Assertion Expired

**Error**: `assertion expired: NotOnOrAfter=... Now=...`

**Causes**:
- Clock skew between SP and IdP
- Slow network/processing
- Old/cached response

**Solutions**:
1. Synchronize clocks
2. Increase assertion validity period at IdP
3. Ensure SAML responses are processed quickly

### Audience Restriction Failed

**Error**: `audience restriction failed: expected https://your-app.com`

**Causes**:
- EntityID mismatch
- Wrong SP configuration at IdP

**Solutions**:
1. Verify `EntityID` in config matches IdP configuration
2. Update SP metadata at IdP

### No Assertion Found

**Error**: `no assertion found in SAML response`

**Causes**:
- Authentication failed at IdP
- IdP misconfiguration (Response does not contain any `<Assertion>`)

**Solutions**:
1. Check IdP logs for authentication errors
2. Verify that the IdP configuration matches the Guard SP metadata (EntityID,
   ACS URL) and that it is configured to issue a SAML Assertion in the
   Response

## Testing

### Unit Tests

```bash
# Run SAML provider tests
go test ./internal/auth/sso/provider/ -v -run TestSAML

# Check coverage
go test ./internal/auth/sso/provider/ -cover
```

### Integration Tests

```bash
# Run integration tests (requires test IdP)
go test ./internal/auth/sso/provider/ -tags=integration -v
```

### Manual Testing with SAMLtest.id

SAMLtest.id provides a free test IdP:

1. Navigate to https://samltest.id
2. Click "Upload Metadata" and upload your SP metadata
3. Use the test credentials provided
4. Complete the login flow

### Debugging

Enable debug logging to see SAML messages:

```go
// Log AuthnRequest
startResult, _ := provider.Start(ctx, opts)
samlRequest, _ := base64.StdEncoding.DecodeString(startResult.SAMLRequest)
log.Printf("AuthnRequest: %s", samlRequest)

// Log SAML Response
samlResponse, _ := base64.StdEncoding.DecodeString(req.SAMLResponse)
log.Printf("SAMLResponse: %s", samlResponse)
```

## Additional Resources

- [SAML 2.0 Specification](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [SAML Bindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [SAMLtest.id](https://samltest.id/) - Free SAML test IdP
- [Okta SAML Setup](./providers/OKTA_SAML.md)
- [Azure AD SAML Setup](./providers/AZURE_AD_SAML.md)
