# SSO Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Guard SSO implementation.

## Table of Contents

- [Common Issues](#common-issues)
- [Debug Mode](#debug-mode)
- [Testing Providers](#testing-providers)
- [Log Patterns](#log-patterns)
- [Getting Help](#getting-help)

## Common Issues

### 1. "Provider not found" error

**Symptoms:**
- HTTP 404 error when accessing `/auth/sso/:slug/login`
- Error message: `SSO provider '<slug>' not found`

**Causes:**
- Provider slug is incorrect or misspelled
- Provider belongs to a different tenant
- Provider has been deleted
- Provider is not enabled

**Solutions:**

1. **List all providers for the tenant:**
   ```bash
   curl -H "Authorization: Bearer <token>" \
     "http://localhost:8080/api/v1/sso/providers?tenant_id=<tenant_id>"
   ```

2. **Verify the slug matches exactly** (case-sensitive, lowercase recommended)

3. **Check provider status:**
   ```bash
   curl -H "Authorization: Bearer <token>" \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

4. **Ensure provider is enabled:**
   ```bash
   curl -X PUT -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"enabled": true}' \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

### 2. "Invalid state token" error

**Symptoms:**
- Callback fails with state validation error
- Error message: `invalid or expired SSO state token`

**Causes:**
- State token expired (default: 10 minutes)
- State token already used (single-use only)
- Redis connection lost
- Callback to wrong environment (dev vs. prod)
- IP address or user agent mismatch

**Solutions:**

1. **Check Redis connectivity:**
   ```bash
   redis-cli -h localhost -p 6379 ping
   # Expected: PONG
   ```

2. **Verify Redis contains state data:**
   ```bash
   redis-cli -h localhost -p 6379 KEYS "sso:state:*"
   ```

3. **Check callback URL configuration:**
   - Ensure the callback URL matches your environment
   - For local dev: `http://localhost:8080/auth/sso/:slug/callback`
   - For production: `https://auth.example.com/auth/sso/:slug/callback`

4. **Test with fresh authentication:**
   - State tokens are single-use
   - Start a new SSO flow rather than reusing old callback links

5. **Check for clock skew:**
   ```bash
   # Ensure system time is synchronized
   timedatectl status
   ```

6. **Review state token TTL in environment:**
   ```bash
   # Default is 10 minutes, can be adjusted
   export SSO_STATE_TTL=600  # seconds
   ```

### 3. OIDC Discovery Failed

**Symptoms:**
- Provider creation fails with "OIDC discovery failed"
- Configuration validation errors

**Causes:**
- Issuer URL is incorrect
- IdP is unreachable from Guard server
- Network/firewall blocking HTTPS requests
- Invalid or self-signed SSL certificate

**Solutions:**

1. **Test discovery endpoint manually:**
   ```bash
   curl https://<issuer>/.well-known/openid-configuration
   ```
   Expected: JSON response with `authorization_endpoint`, `token_endpoint`, etc.

2. **Verify issuer URL format:**
   - Should be HTTPS (required for production)
   - No trailing slash
   - Example: `https://accounts.google.com` ✅
   - Example: `https://accounts.google.com/` ❌

3. **Check network connectivity:**
   ```bash
   # From Guard server
   curl -I https://<issuer>
   ```

4. **Test DNS resolution:**
   ```bash
   nslookup <issuer_domain>
   dig <issuer_domain>
   ```

5. **Check SSL certificate:**
   ```bash
   openssl s_client -connect <issuer_host>:443 -servername <issuer_host>
   ```

6. **For development with self-signed certs:**
   ```bash
   # NOT recommended for production
   export SKIP_TLS_VERIFY=true
   ```

### 4. SAML Signature Verification Failed

**Symptoms:**
- Callback fails with "signature verification failed"
- Error in logs: `failed to verify SAML assertion signature`

**Causes:**
- IdP certificate mismatch or expired
- Clock skew between Guard and IdP
- SAML response tampered or corrupted
- Wrong certificate format in configuration

**Solutions:**

1. **Verify IdP certificate is current:**
   ```bash
   # Check certificate expiration
   openssl x509 -in idp_cert.pem -noout -dates
   ```

2. **Re-fetch IdP metadata:**
   ```bash
   curl https://<idp_metadata_url>
   ```

   Update provider with fresh metadata:
   ```bash
   curl -X PUT -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"idp_metadata_url": "https://..."}' \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

3. **Check system time synchronization:**
   ```bash
   # Enable NTP
   timedatectl set-ntp true

   # Check status
   timedatectl status
   ```

4. **Enable verbose SAML logging:**
   ```bash
   export LOG_LEVEL=debug
   export SAML_DEBUG=true
   ```

5. **Verify certificate format:**
   - Should be PEM format
   - Include `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`
   - No extra whitespace or line breaks

6. **Check assertion signing requirements:**
   ```bash
   # If IdP signs response but not assertion
   curl -X PUT -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "want_assertions_signed": false,
       "want_response_signed": true
     }' \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

### 5. Domain Not Allowed

**Symptoms:**
- Callback succeeds but returns "domain not allowed"
- User authenticated at IdP but rejected by Guard

**Causes:**
- User's email domain not in provider's `domains` list
- Email domain extraction failed
- Empty or misconfigured domains array

**Solutions:**

1. **Check provider domain configuration:**
   ```bash
   curl -H "Authorization: Bearer <token>" \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>" | jq '.domains'
   ```

2. **Update allowed domains:**
   ```bash
   curl -X PUT -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"domains": ["example.com", "example.org"]}' \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

3. **Allow all domains (not recommended for production):**
   ```bash
   curl -X PUT -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"domains": []}' \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

4. **Verify email claim mapping:**
   - Check that IdP is sending email in expected claim
   - For OIDC: usually `email` claim
   - For SAML: check attribute mapping (default: `email` or `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`)

5. **Check logs for email value:**
   ```bash
   grep "email.*domain" /var/log/guard/app.log
   ```

### 6. Signup Disabled Error

**Symptoms:**
- Callback fails with "signup disabled"
- Existing users can login but new users cannot

**Causes:**
- `allow_signup` is set to `false` in provider configuration
- User doesn't exist in Guard database

**Solutions:**

1. **Enable signup for provider:**
   ```bash
   curl -X PUT -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"allow_signup": true}' \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

2. **Pre-create user accounts:**
   ```bash
   # Create user via admin API or password signup
   curl -X POST -H "Authorization: Bearer <admin_token>" \
     -H "Content-Type: application/json" \
     -d '{
       "tenant_id": "<tenant_id>",
       "email": "user@example.com",
       "first_name": "John",
       "last_name": "Doe"
     }' \
     "http://localhost:8080/api/v1/admin/users"
   ```

3. **Check user existence:**
   ```bash
   curl -H "Authorization: Bearer <admin_token>" \
     "http://localhost:8080/api/v1/admin/users?email=user@example.com"
   ```

### 7. Email Already Exists with Different Provider

**Symptoms:**
- User tries to login via SSO but email is already used
- Error: "email already registered with different authentication method"

**Causes:**
- User previously signed up with password auth
- User used different SSO provider
- Identity linking is required

**Solutions:**

1. **Link existing identity:**
   - Users must first login with existing method
   - Then link SSO identity via account settings

2. **Check existing auth identities:**
   ```bash
   curl -H "Authorization: Bearer <admin_token>" \
     "http://localhost:8080/api/v1/admin/users/<user_id>/identities"
   ```

3. **For migration scenarios, manually link identities** (requires database access):
   ```sql
   INSERT INTO auth_identities (
     id, user_id, provider_type, provider_id, provider_user_id,
     email, email_verified, created_at, updated_at
   ) VALUES (
     gen_random_uuid(), '<user_id>', 'oidc', '<provider_id>',
     '<external_user_id>', '<email>', true, NOW(), NOW()
   );
   ```

### 8. Redirect URI Mismatch

**Symptoms:**
- IdP shows "redirect_uri mismatch" error
- Cannot complete OAuth/OIDC flow

**Causes:**
- Callback URL not registered in IdP configuration
- Callback URL scheme mismatch (http vs https)
- Trailing slash inconsistency

**Solutions:**

1. **Verify callback URL in IdP configuration:**
   - Google: Cloud Console → Credentials → OAuth 2.0 Client IDs
   - Okta: Applications → Your App → General → Login redirect URIs
   - Azure AD: App registrations → Your App → Authentication → Redirect URIs

2. **Expected callback URL format:**
   ```
   https://auth.example.com/auth/sso/<provider_slug>/callback
   ```

3. **For local development:**
   ```
   http://localhost:8080/auth/sso/<provider_slug>/callback
   ```

4. **Check PUBLIC_BASE_URL environment variable:**
   ```bash
   echo $PUBLIC_BASE_URL
   # Should match the domain used in callback URLs
   ```

### 9. Token Exchange Failed (OIDC)

**Symptoms:**
- Callback receives authorization code but token exchange fails
- Error: "failed to exchange authorization code"

**Causes:**
- Invalid client secret
- Authorization code expired
- PKCE verification failed
- Network timeout

**Solutions:**

1. **Verify client credentials:**
   ```bash
   curl -H "Authorization: Bearer <admin_token>" \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>" | jq '.client_id'
   ```

2. **Update client secret:**
   ```bash
   curl -X PUT -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"client_secret": "<new_secret>"}' \
     "http://localhost:8080/api/v1/sso/providers/<provider_id>"
   ```

3. **Check token endpoint:**
   ```bash
   curl https://<issuer>/.well-known/openid-configuration | jq '.token_endpoint'
   ```

4. **Test token endpoint connectivity:**
   ```bash
   curl -X POST https://<token_endpoint> \
     -d "grant_type=authorization_code&code=dummy"
   # Should return error but confirm endpoint is reachable
   ```

5. **Review PKCE configuration:**
   - Ensure IdP supports PKCE if enabled
   - Check PKCE method (S256 vs plain)

### 10. Rate Limit Exceeded

**Symptoms:**
- HTTP 429 error
- Error message: "rate limit exceeded"

**Causes:**
- Too many authentication attempts
- Automated testing without delays
- Potential abuse/attack

**Solutions:**

1. **Wait for rate limit window to reset:**
   - Check `X-RateLimit-Reset` header for reset time

2. **Review rate limit headers:**
   ```bash
   curl -I "http://localhost:8080/auth/sso/google/login?tenant_id=..."
   # Check X-RateLimit-Limit and X-RateLimit-Remaining
   ```

3. **Adjust rate limits for testing** (in code or config):
   ```go
   ratelimit.Policy{
     Name:   "sso:initiate",
     Limit:  100,  // Increase for testing
     Window: time.Minute,
   }
   ```

4. **Implement exponential backoff:**
   ```bash
   # Wait and retry
   sleep 60
   curl "http://localhost:8080/auth/sso/google/login?tenant_id=..."
   ```

## Debug Mode

Enable debug logging to get detailed information about SSO flows:

### Enable Debug Logging

```bash
export LOG_LEVEL=debug
```

### Restart Guard Service

```bash
# Systemd
sudo systemctl restart guard

# Docker
docker-compose restart guard

# Local development
./guard
```

### What Debug Mode Logs

- Full IdP responses (OIDC token response, SAML assertions)
- State token details (creation, validation, expiration)
- Profile attribute mapping
- Configuration validation details
- Network requests/responses
- Certificate parsing details
- JWT token claims

### Example Debug Output

```json
{
  "level": "debug",
  "time": "2025-11-14T10:30:45Z",
  "message": "SSO flow initiated",
  "provider_id": "123e4567-e89b-12d3-a456-426614174000",
  "provider_slug": "google",
  "provider_type": "oidc",
  "tenant_id": "tenant-123",
  "state_token": "abc123...",
  "redirect_url": "https://accounts.google.com/o/oauth2/v2/auth?..."
}
```

### Sensitive Data Warning

⚠️ **Debug logs may contain sensitive information:**
- Access tokens
- Client secrets
- User profile data
- Email addresses

**Never enable debug logging in production without proper log sanitization.**

## Testing Providers

Use the provider test endpoint to validate configuration:

### Test Provider Configuration

```bash
curl -X POST -H "Authorization: Bearer <admin_token>" \
  "http://localhost:8080/api/v1/sso/providers/<provider_id>/test"
```

### What Gets Tested

1. **Configuration validation:**
   - Required fields present
   - URLs properly formatted
   - Scopes/attributes valid

2. **Network connectivity:**
   - OIDC: Discovery endpoint reachable
   - SAML: Metadata URL accessible

3. **Certificate validation:**
   - Certificate parsing successful
   - Certificate not expired
   - Certificate chain valid

4. **Provider-specific checks:**
   - OIDC: Well-known configuration valid
   - SAML: Metadata XML parseable

### Example Test Response

```json
{
  "status": "success",
  "checks": [
    {
      "name": "configuration_validation",
      "status": "passed",
      "message": "All required fields present"
    },
    {
      "name": "oidc_discovery",
      "status": "passed",
      "message": "Discovery endpoint reachable",
      "details": {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token"
      }
    },
    {
      "name": "network_connectivity",
      "status": "passed",
      "message": "All endpoints reachable"
    }
  ]
}
```

### Test Failure Example

```json
{
  "status": "failed",
  "checks": [
    {
      "name": "oidc_discovery",
      "status": "failed",
      "message": "Failed to fetch discovery document",
      "error": "Get \"https://bad-issuer.com/.well-known/openid-configuration\": dial tcp: lookup bad-issuer.com: no such host"
    }
  ]
}
```

## Log Patterns

Search logs for common patterns to diagnose issues:

### SSO Initiation Issues

```bash
# Successful initiations
grep "SSO flow initiated" /var/log/guard/app.log

# Failed initiations
grep "failed to initiate SSO" /var/log/guard/app.log

# Provider not found
grep "provider not found" /var/log/guard/app.log
```

### Callback Issues

```bash
# All callbacks
grep "SSO callback" /var/log/guard/app.log

# Invalid state tokens
grep "state.*invalid\|invalid.*state" /var/log/guard/app.log

# Provider callback failures
grep "provider callback failed" /var/log/guard/app.log

# Token issuance
grep "tokens issued for SSO" /var/log/guard/app.log
```

### Provider Configuration Issues

```bash
# Configuration validation
grep "configuration validation failed" /var/log/guard/app.log

# Provider creation/update
grep "provider.*created\|provider.*updated" /var/log/guard/app.log

# Invalid configuration
grep "provider.*invalid" /var/log/guard/app.log
```

### Authentication Issues

```bash
# Successful authentications
grep "auth.sso.login.success" /var/log/guard/app.log

# Failed authentications
grep "auth.sso.login.failure" /var/log/guard/app.log

# Domain restrictions
grep "domain.*not allowed" /var/log/guard/app.log

# Signup disabled
grep "signup.*disabled" /var/log/guard/app.log
```

### OIDC-Specific Issues

```bash
# Discovery failures
grep "OIDC discovery failed" /var/log/guard/app.log

# Token exchange failures
grep "failed to exchange.*code" /var/log/guard/app.log

# ID token validation
grep "ID token.*invalid\|failed to verify ID token" /var/log/guard/app.log
```

### SAML-Specific Issues

```bash
# Metadata issues
grep "failed to.*metadata" /var/log/guard/app.log

# Signature verification
grep "signature.*failed\|failed.*verify.*signature" /var/log/guard/app.log

# Assertion validation
grep "assertion.*invalid\|failed.*validate.*assertion" /var/log/guard/app.log
```

### Using jq for JSON Logs

If logs are in JSON format:

```bash
# Filter by level
cat /var/log/guard/app.log | jq 'select(.level == "error")'

# Filter by message pattern
cat /var/log/guard/app.log | jq 'select(.message | contains("SSO"))'

# Filter by provider
cat /var/log/guard/app.log | jq 'select(.provider_slug == "google")'

# Show only specific fields
cat /var/log/guard/app.log | jq '{time, level, message, provider_slug, error}'
```

## Getting Help

If issues persist after troubleshooting:

### 1. Gather Information

Collect the following:

- **Provider configuration** (with secrets redacted):
  ```bash
  curl -H "Authorization: Bearer <token>" \
    "http://localhost:8080/api/v1/sso/providers/<provider_id>" | \
    jq 'del(.client_secret, .sp_private_key)'
  ```

- **Error messages** from logs:
  ```bash
  grep -A 10 -B 10 "error\|failed" /var/log/guard/app.log | tail -50
  ```

- **Relevant metrics**:
  ```bash
  curl http://localhost:8080/metrics | grep sso
  ```

- **Environment information**:
  ```bash
  # Guard version
  ./guard --version

  # Database version
  psql --version

  # Redis version
  redis-cli --version
  ```

### 2. Enable Debug Logging

```bash
export LOG_LEVEL=debug
# Restart Guard
# Reproduce the issue
# Collect debug logs
```

### 3. Check Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Deployment and configuration guide
- [SSO_API.md](../api/SSO_API.md) - Complete API reference
- [ADR-0001](../../docs/architecture/decisions/0001-native-sso-oidc-saml.md) - Architecture decisions

### 4. Open an Issue

Include in your issue:

1. **Description of the problem**
2. **Steps to reproduce**
3. **Provider type** (OIDC/SAML)
4. **Provider configuration** (secrets redacted)
5. **Error messages** and logs
6. **Expected vs actual behavior**
7. **Environment details** (OS, Guard version, dependencies)

### 5. Community Resources

- Check existing issues for similar problems
- Review test cases in `internal/auth/sso/integration_test.go`
- Consult provider-specific documentation (Google, Okta, Azure AD, etc.)

## Quick Reference

### Common Commands

```bash
# List all providers
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8080/api/v1/sso/providers?tenant_id=<tenant_id>"

# Get provider details
curl -H "Authorization: Bearer <token>" \
  "http://localhost:8080/api/v1/sso/providers/<provider_id>"

# Test provider
curl -X POST -H "Authorization: Bearer <token>" \
  "http://localhost:8080/api/v1/sso/providers/<provider_id>/test"

# Update provider
curl -X PUT -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}' \
  "http://localhost:8080/api/v1/sso/providers/<provider_id>"

# Check health
curl http://localhost:8080/health

# View metrics
curl http://localhost:8080/metrics | grep sso

# Check Redis
redis-cli -h localhost -p 6379 ping
redis-cli -h localhost -p 6379 KEYS "sso:state:*"

# Follow logs
tail -f /var/log/guard/app.log | grep -i sso
```

### Emergency Procedures

**Provider completely broken:**
```bash
# Disable immediately
curl -X PUT -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}' \
  "http://localhost:8080/api/v1/sso/providers/<provider_id>"
```

**All SSO down:**
```bash
# Users can still use password auth
# Check database and Redis connectivity
# Review recent changes/deployments
```

**State token issues:**
```bash
# Clear all state tokens (nuclear option)
redis-cli KEYS "sso:state:*" | xargs redis-cli DEL
```
