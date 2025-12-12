# OIDC Implementation Guide

## Overview

Guard's native OIDC (OpenID Connect) implementation provides enterprise-grade SSO authentication without external dependencies. This implementation follows the **OAuth 2.0 Authorization Code Flow with PKCE** and includes comprehensive security features.

## Architecture

### OIDC Authentication Flow

```
┌─────────┐                                           ┌──────────┐
│         │                                           │          │
│  User   │                                           │   IdP    │
│         │                                           │          │
└────┬────┘                                           └─────┬────┘
     │                                                      │
     │  1. Initiate Login                                  │
     ├──────────────────────────────────>                  │
     │                                    ┌──────────┐     │
     │                                    │          │     │
     │                                    │  Guard   │     │
     │                                    │          │     │
     │                                    └────┬─────┘     │
     │                                         │           │
     │  2. Generate Auth URL (with PKCE)       │           │
     │  <─────────────────────────────────────┤           │
     │                                         │           │
     │  3. Redirect to IdP                     │           │
     ├─────────────────────────────────────────────────────>
     │                                         │           │
     │  4. User Authenticates                  │           │
     │  <───────────────────────────────────────────────────>
     │                                         │           │
     │  5. Redirect to callback (with code)    │           │
     │  <─────────────────────────────────────────────────┤
     │                                         │           │
     │  6. Callback with code                  │           │
     ├──────────────────────────────────>     │           │
     │                                    │           │
     │                                    │  7. Exchange code + PKCE verifier for tokens
     │                                    ├──────────────────────────>
     │                                    │           │
     │                                    │  8. ID Token + Access Token
     │                                    │  <───────────────────────┤
     │                                    │           │
     │                                    │  9. Verify ID Token signature
     │                                    │     (JWKS, issuer, audience, nonce)
     │                                    │           │
     │  10. Issue Guard tokens             │           │
     │  <─────────────────────────────────┤           │
     │                                    │           │
```

### Components

1. **Domain Layer** (`internal/auth/sso/domain/`)
   - `types.go`: Core interfaces and domain types
   - Defines `SSOProvider` interface
   - Profile, Config, and Metadata types

2. **Provider Layer** (`internal/auth/sso/provider/`)
   - `oidc.go`: OIDC provider implementation
   - Implements discovery, authorization, token exchange, and verification
   - Handles attribute mapping

## Features

### Security Features

✅ **PKCE (Proof Key for Code Exchange)**
- Uses S256 method (SHA-256 challenge)
- Cryptographically secure verifier generation (256 bits)
- Prevents authorization code interception attacks

✅ **Nonce Validation**
- Prevents replay attacks
- 256-bit cryptographically random nonces
- Verified against ID token claims

✅ **State Parameter**
- CSRF protection
- 256-bit cryptographically random state
- Must be verified in callback

✅ **Token Verification**
- ID token signature verification using JWKS
- Issuer (iss) validation
- Audience (aud) validation
- Expiry (exp) validation
- Nonce validation

✅ **Secure Storage**
- Client secrets encrypted in database
- Tokens never logged
- Sensitive data redacted from logs

### OIDC Features

- **Discovery**: Automatic configuration via `.well-known/openid-configuration`
- **Standard Claims**: Supports all standard OIDC claims (sub, email, name, etc.)
- **Custom Claims**: Configurable attribute mapping for non-standard claims
- **Scopes**: Configurable scope requests (openid, profile, email, custom)
- **Force Authentication**: Optional `prompt=login` parameter
- **Login Hints**: Optional `login_hint` parameter for pre-filling email

## Configuration

### Provider Configuration

```go
type Config struct {
    // Basic settings
    ID           uuid.UUID
    TenantID     uuid.UUID
    Name         string       // Display name
    Slug         string       // URL-friendly identifier
    ProviderType ProviderType // "oidc"
    Enabled      bool

    // OIDC endpoints
    Issuer       string // e.g., "https://accounts.google.com"

    // OAuth2 credentials
    ClientID     string
    ClientSecret string
    Scopes       []string // Default: ["openid", "profile", "email"]

    // Attribute mapping (optional)
    AttributeMapping map[string][]string

    // User provisioning
    AllowSignup        bool // Allow new user registration via SSO
    TrustEmailVerified bool // Trust email_verified claim from IdP
    Domains            []string // Allowed email domains (empty = all allowed)
}
```

### Attribute Mapping

Map IdP-specific attribute names to Guard's user profile fields:

```go
AttributeMapping: map[string][]string{
    "email":      {"email", "mail", "emailAddress"},
    "first_name": {"given_name", "givenName", "firstName"},
    "last_name":  {"family_name", "surname", "lastName"},
    "name":       {"name", "displayName"},
    "picture":    {"picture", "photo", "avatar"},
    "groups":     {"groups", "memberOf"},
}
```

The system tries each attribute name in order until it finds a value.

### Default Attribute Mapping

If no custom mapping is provided, Guard uses sensible defaults:

```go
email:      ["email", "mail", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
first_name: ["given_name", "givenName", "firstName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"]
last_name:  ["family_name", "familyName", "lastName", "surname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"]
name:       ["name", "displayName", "cn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
picture:    ["picture", "photo", "avatar"]
groups:     ["groups", "memberOf", "http://schemas.xmlsoap.org/claims/Group"]
```

## Usage

### Creating an OIDC Provider

```go
import (
    "context"
    "github.com/corvusHold/guard/internal/auth/sso/domain"
    "github.com/corvusHold/guard/internal/auth/sso/provider"
)

ctx := context.Background()

config := &domain.Config{
    Issuer:       "https://accounts.google.com",
    ClientID:     "your-client-id.apps.googleusercontent.com",
    ClientSecret: "your-client-secret",
    Scopes:       []string{"openid", "profile", "email"},
}

// Create provider (performs OIDC discovery)
oidcProvider, err := provider.NewOIDCProvider(ctx, config)
if err != nil {
    // Handle error
}
```

### Starting Authentication Flow

```go
// Generate authorization URL
startResult, err := oidcProvider.Start(ctx, domain.StartOptions{
    RedirectURL: "https://yourapp.com/auth/callback",
    Scopes:      []string{"openid", "profile", "email"}, // Optional
    ForceAuthn:  false, // Set to true to force re-authentication
    LoginHint:   "user@example.com", // Optional
})

if err != nil {
    // Handle error
}

// Store these values in session for callback verification
session.Set("state", startResult.State)
session.Set("nonce", startResult.Nonce)
session.Set("pkce_verifier", startResult.PKCEVerifier)

// Redirect user to IdP
http.Redirect(w, r, startResult.AuthorizationURL, http.StatusFound)
```

### Handling Callback

```go
// Get values from query params
code := r.URL.Query().Get("code")
state := r.URL.Query().Get("state")

// Retrieve stored values from session
storedState := session.Get("state")
storedNonce := session.Get("nonce")
storedPKCEVerifier := session.Get("pkce_verifier")

// Verify state matches (CSRF protection)
if state != storedState {
    // Handle CSRF error
}

// Exchange code for tokens and verify
profile, err := oidcProvider.Callback(ctx, domain.CallbackRequest{
    Code:         code,
    State:        state,
    Nonce:        storedNonce,
    PKCEVerifier: storedPKCEVerifier,
    RedirectURL:  "https://yourapp.com/auth/callback",
})

if err != nil {
    // Handle error
}

// Profile contains user information
fmt.Println("User:", profile.Email, profile.FirstName, profile.LastName)
fmt.Println("Subject:", profile.Subject)
fmt.Println("Email Verified:", profile.EmailVerified)
fmt.Println("Groups:", profile.Groups)
```

## Supported Identity Providers

Guard's OIDC implementation is compatible with any standards-compliant OIDC provider:

- ✅ Google Workspace / Google Cloud Identity
- ✅ Microsoft Azure AD / Entra ID
- ✅ Okta
- ✅ Auth0
- ✅ Keycloak
- ✅ Amazon Cognito
- ✅ Ping Identity
- ✅ OneLogin
- ✅ Any OIDC 1.0 compliant provider

See the provider-specific setup guides in [`docs/sso/providers/`](./providers/) for detailed instructions.

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `failed to discover OIDC configuration` | Invalid issuer URL or IdP unavailable | Verify issuer URL is correct and accessible |
| `authorization code is required` | Missing code in callback | Check redirect URL configuration |
| `PKCE verifier is required` | Session lost or expired | Ensure session storage is working |
| `nonce is required` | Session lost or expired | Ensure session storage is working |
| `nonce mismatch` | Replay attack or session issue | Check session management |
| `failed to verify ID token` | Invalid signature or expired token | Check JWKS endpoint and clock sync |
| `no id_token in token response` | IdP not returning ID token | Ensure `openid` scope is requested |

### Error Response Example

```json
{
  "error": "invalid_request",
  "error_description": "PKCE verifier is required"
}
```

## Testing

### Unit Tests

```bash
go test ./internal/auth/sso/provider/ -v
```

### Integration Tests

```bash
go test -tags=integration ./internal/auth/sso/provider/ -v
```

### Coverage

```bash
go test -cover ./internal/auth/sso/provider/
```

## Security Considerations

### Production Checklist

- [ ] Use HTTPS for all redirect URIs
- [ ] Store client secrets encrypted in database
- [ ] Never log tokens or secrets
- [ ] Implement rate limiting on auth endpoints
- [ ] Set appropriate session timeouts
- [ ] Validate redirect URIs against allowlist
- [ ] Implement account linking for existing users
- [ ] Use secure session storage (encrypted cookies or Redis)
- [ ] Monitor for suspicious auth patterns
- [ ] Implement IP allowlisting for admin operations

### PKCE S256 Method

Guard uses the S256 method for PKCE, which is more secure than the plain method:

```
code_verifier = base64url(random(32 bytes))
code_challenge = base64url(sha256(code_verifier))
code_challenge_method = S256
```

### Token Validation

All ID tokens are verified for:
- **Signature**: Using JWKS from IdP
- **Issuer (iss)**: Must match configured issuer
- **Audience (aud)**: Must match client ID
- **Expiration (exp)**: Token must not be expired
- **Nonce**: Must match the nonce from authorization request

## Performance

### OIDC Discovery Caching

Discovery results are cached by the `go-oidc` library to minimize network calls.

### Recommended Optimizations

1. **Connection Pooling**: Use HTTP client with connection pooling
2. **Context Timeouts**: Set reasonable timeouts (5-10 seconds)
3. **Caching**: Cache JWKS responses (handled by `go-oidc`)
4. **Async Processing**: Process user provisioning asynchronously

## Troubleshooting

### Discovery Fails

```
Error: failed to discover OIDC configuration from https://example.com: Get "https://example.com/.well-known/openid-configuration": dial tcp: lookup example.com: no such host
```

**Solution**: Verify the issuer URL is correct and accessible from your server.

### Token Exchange Fails

```
Error: failed to exchange authorization code: oauth2: cannot fetch token: 400 Bad Request
```

**Solutions**:
- Verify client ID and secret are correct
- Check that PKCE verifier matches the challenge
- Ensure redirect URI matches exactly

### Nonce Mismatch

```
Error: nonce mismatch: expected abc123, got xyz789
```

**Solutions**:
- Check session storage is working correctly
- Verify nonce is stored before redirect
- Check for session timeout issues

## Advanced Features

### Custom Scopes

Request additional scopes beyond the standard OIDC scopes:

```go
startResult, err := oidcProvider.Start(ctx, domain.StartOptions{
    RedirectURL: "https://yourapp.com/callback",
    Scopes:      []string{"openid", "profile", "email", "groups", "custom:scope"},
})
```

### Fetch Additional User Info

If the ID token doesn't contain all needed claims:

```go
userInfo, err := oidcProvider.FetchUserInfo(ctx, profile.AccessToken)
if err != nil {
    // Handle error
}

// Merge additional claims into profile
for k, v := range userInfo {
    profile.RawAttributes[k] = v
}
```

### Force Re-authentication

Require the user to re-authenticate even if they have an active session:

```go
startResult, err := oidcProvider.Start(ctx, domain.StartOptions{
    RedirectURL: "https://yourapp.com/callback",
    ForceAuthn:  true, // Adds prompt=login to auth request
})
```

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OAuth 2.0 Authorization Code Flow](https://tools.ietf.org/html/rfc6749#section-4.1)
- [PKCE (RFC 7636)](https://tools.ietf.org/html/rfc7636)
- [go-oidc Library Documentation](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)
