# IAM vNext Migration Guide (JWT Key Isolation)

This guide explains what existing integrators must change to support the new Guard IAM token model.

## Audience

- External applications consuming Guard as OAuth2/OIDC provider
- Teams using Guard SDKs (Go/TS)
- Teams running sample apps from `examples/`
- Teams operating Guard UI/admin workflows

## Breaking/Security-Relevant Changes

1. **JWT verification is ES256-first runtime behavior**
   - Do not validate Guard tokens with shared HMAC secrets.
   - Validate with JWKS only.

2. **Tenant-aware issuer/JWKS is required for multi-tenant correctness**
   - Issuer: `https://<guard-host>/t/<tenant_id>`
   - JWKS: `https://<guard-host>/t/<tenant_id>/.well-known/jwks.json`
   - Metadata: `/.well-known/oauth-authorization-server?tenant_id=<tenant_id>`

3. **Key rotation expectation**
   - Tokens include `kid`.
   - Verifiers must refresh JWKS when `kid` is unknown.

4. **Client auth hardening direction**
   - Confidential enterprise clients should default to `private_key_jwt`.
   - Keep secret-based methods only as explicit migration exceptions.

---

## Migration Checklist by Surface

### 1) External applications consuming Guard IAM

- [ ] Stop using shared HMAC (`JWT_SIGNING_KEY`) in app-side token validation.
- [ ] Switch issuer validation to tenant path issuer (`/t/<tenant_id>`).
- [ ] Switch JWKS URL to tenant endpoint (`/t/<tenant_id>/.well-known/jwks.json`).
- [ ] Enforce `alg=ES256` in JWT validators.
- [ ] Implement JWKS cache + refetch-on-unknown-kid behavior.
- [ ] Verify `iss` and `aud` on every token validation.

### 2) SDK consumers

- [ ] Upgrade to SDK release that supports tenant-aware JWKS verification.
- [ ] For Go SDK, use `NewTokenValidator(..., WithValidatorTenantID(...))`.
- [ ] Remove any custom HS256 fallback logic in service code.

### 3) Examples and samples

- [ ] Ensure sample env/config include tenant ID for issuer alignment.
- [ ] Ensure OIDC/JWKS examples point to tenant endpoints.
- [ ] Keep PKCE/state/nonce flows unchanged; only issuer/JWKS and validation assumptions change.

### 4) UI/admin operations

- [ ] Expose/document tenant issuer model used by OAuth/OIDC clients.
- [ ] Communicate that external clients must rely on discovery/JWKS rather than shared secrets.
- [ ] Default new confidential enterprise clients to hardened auth methods policy.

---

## Operational Rollout

1. Update integrator docs and SDK examples first.
2. Roll verifier changes to external apps (JWKS + ES256 + tenant issuer).
3. Validate with staging tenant metadata and token exchanges.
4. Monitor unknown-kid and token-validation errors during rollout.

---

## Validation Commands

```bash
# Tenant metadata
curl "https://guard.example.com/.well-known/oauth-authorization-server?tenant_id=<tenant_uuid>"

# Tenant discovery
curl "https://guard.example.com/t/<tenant_uuid>/.well-known/openid-configuration"

# Tenant JWKS
curl "https://guard.example.com/t/<tenant_uuid>/.well-known/jwks.json"
```

Use these endpoints as source-of-truth for external integrations.

---

## Troubleshooting Guide

### Common Migration Issues

#### 1. Token Validation Failures After Migration

**Symptom:** Tokens that worked before migration now fail with "invalid signature" or "invalid issuer"

**Causes and Solutions:**

**a) Still using HMAC (HS256) verification:**
```bash
# ❌ Wrong: Using shared secret (HS256)
jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
    return []byte(sharedSecret), nil
})

# ✅ Correct: Using JWKS (ES256)
jwks, _ := keyfunc.Get("https://guard.example.com/t/tenant-id/.well-known/jwks.json")
jwt.Parse(token, jwks.Keyfunc)
```

**b) Wrong issuer URL:**
```bash
# Check token issuer claim
echo $TOKEN | cut -d. -f2 | base64 -d | jq .iss

# Expected (tenant path mode):
# "https://guard.example.com/t/00000000-0000-0000-0000-000000000000"

# If you see global issuer, update to tenant-scoped issuer
```

**c) JWKS cache staleness:**
```bash
# Verify JWKS is accessible
curl https://guard.example.com/t/<tenant_id>/.well-known/jwks.json

# Implement JWKS refresh on unknown kid:
if err == "unknown kid" {
    jwks.Refresh()
    retry token.Parse()
}
```

**Fix Checklist:**
- [ ] Remove all HMAC secret-based verification
- [ ] Use tenant-scoped JWKS URL: `/t/{tenant_id}/.well-known/jwks.json`
- [ ] Validate issuer matches: `https://guard.host/t/{tenant_id}`
- [ ] Implement JWKS cache refresh on unknown `kid`
- [ ] Verify algorithm is `ES256` in token header

#### 2. Missing or Invalid kid (Key ID)

**Symptom:** "kid header not found" or "unknown kid"

**Diagnosis:**
```bash
# Inspect token header
echo $TOKEN | cut -d. -f1 | base64 -d | jq .

# Expected output:
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "abc123..."  # Must be present
}
```

**Solutions:**

a) **Guard not configured with ES256:**
```bash
# Check Guard configuration
echo $JWT_SIGNING_ALGORITHM  # Must be ES256
echo $JWT_PRIVATE_KEY_PATH   # Must point to valid key file

# Generate ES256 key if missing
openssl ecparam -genkey -name prime256v1 -noout -out jwt-es256-private.pem
```

b) **JWKS not returning the kid:**
```bash
# Fetch JWKS and check for kid
curl https://guard.example.com/t/<tenant_id>/.well-known/jwks.json | jq '.keys[] | .kid'

# If empty, Guard may not be populating kid correctly
# Check Guard logs for key loading errors
```

c) **Verifier doesn't support kid:**
```bash
# Upgrade JWT library to support JWKS with kid
# Most libraries: github.com/MicahParks/keyfunc (Go), jose (Node.js)
```

**Fix Checklist:**
- [ ] Ensure Guard is using ES256 with valid private key
- [ ] Verify JWKS endpoint returns keys with `kid` field
- [ ] Update JWT verification library to support JWKS with `kid`
- [ ] Implement JWKS cache refresh when unknown `kid` encountered

#### 3. CORS Errors When Fetching JWKS

**Symptom:** Browser console shows CORS error when fetching JWKS endpoint

**Cause:** JWKS endpoint not included in CORS allowlist

**Solution:**
```bash
# Update Guard CORS configuration
export CORS_ALLOWED_ORIGINS="https://app.example.com,https://staging.example.com"

# Or via Admin Settings UI:
# 1. Navigate to Settings > CORS
# 2. Add your application origin
# 3. Save

# Verify CORS headers
curl -H "Origin: https://app.example.com" \
     -H "Access-Control-Request-Method: GET" \
     -I https://guard.example.com/t/<tenant_id>/.well-known/jwks.json

# Should include:
# Access-Control-Allow-Origin: https://app.example.com
```

**Fix Checklist:**
- [ ] Add application origin to Guard CORS allowlist
- [ ] Ensure JWKS endpoint responds with proper CORS headers
- [ ] Test from browser console: `fetch('https://guard.../jwks.json')`

#### 4. Tenant ID Mismatch

**Symptom:** Token validates but contains wrong tenant ID, authorization failures

**Diagnosis:**
```bash
# Check tenant ID in token
echo $TOKEN | cut -d. -f2 | base64 -d | jq .ten

# Check expected tenant ID in your application
echo $EXPECTED_TENANT_ID

# They should match
```

**Solutions:**

a) **Using wrong tenant's JWKS endpoint:**
```bash
# ❌ Wrong: Using global or different tenant's JWKS
jwksURL := "https://guard.example.com/.well-known/jwks.json"  # No tenant!
jwksURL := "https://guard.example.com/t/wrong-tenant-id/.well-known/jwks.json"

# ✅ Correct: Using correct tenant's JWKS
jwksURL := fmt.Sprintf("https://guard.example.com/t/%s/.well-known/jwks.json", tenantID)
```

b) **Token issued for wrong tenant:**
```bash
# Verify login flow uses correct tenant ID in request
curl -X POST https://guard.example.com/api/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"***","tenant_id":"correct-tenant-uuid"}'
```

**Fix Checklist:**
- [ ] Verify JWKS URL includes correct tenant ID
- [ ] Validate `ten` claim in token matches expected tenant
- [ ] Ensure login/signup endpoints receive correct tenant context
- [ ] Check issuer claim includes correct tenant: `https://guard.host/t/{tenant_id}`

#### 5. Performance Degradation After Migration

**Symptom:** Token verification is slower after switching to ES256

**Expected Behavior:** ES256 is inherently slower than HS256 (see benchmarks in `internal/auth/keys/performance_benchmark_test.go`):
- HS256 signing: ~50-100μs per token
- ES256 signing: ~200-500μs per token
- HS256 verification: ~30-50μs per token
- ES256 verification: ~400-800μs per token

**This is normal and acceptable.** The security benefits outweigh the minor latency increase.

**Optimization Strategies:**

a) **Cache JWKS aggressively:**
```go
// ✅ Good: Cache JWKS for 1 hour, refresh on unknown kid
jwks := keyfunc.NewDefault(jwksURL, keyfunc.Options{
    RefreshInterval: 1 * time.Hour,
    RefreshRateLimit: 5 * time.Minute,
})

// ❌ Bad: Fetching JWKS on every request
```

b) **Avoid re-parsing tokens:**
```go
// ✅ Good: Parse token once, store claims in context
claims := parseAndValidateToken(token)
ctx = context.WithValue(ctx, "claims", claims)

// ❌ Bad: Parsing same token multiple times in request lifecycle
```

c) **Use connection pooling for JWKS fetches:**
```go
httpClient := &http.Client{
    Transport: &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
    },
    Timeout: 10 * time.Second,
}
```

**Fix Checklist:**
- [ ] Implement JWKS caching (1 hour minimum)
- [ ] Use connection pooling for HTTP requests
- [ ] Avoid redundant token parsing in request path
- [ ] Measure and accept ES256 baseline performance

#### 6. Key Rotation Causes Token Validation Failures

**Symptom:** Tokens fail validation after Guard key rotation

**Cause:** JWKS cache hasn't been updated with new public key

**Solutions:**

a) **Implement JWKS refresh on unknown kid:**
```go
token, err := jwt.Parse(tokenString, jwks.Keyfunc)
if err != nil && strings.Contains(err.Error(), "kid") {
    // Refresh JWKS and retry
    if refreshErr := jwks.Refresh(); refreshErr == nil {
        token, err = jwt.Parse(tokenString, jwks.Keyfunc)
    }
}
```

b) **Reduce JWKS cache TTL:**
```go
// More aggressive refresh for environments with frequent key rotation
jwks := keyfunc.NewDefault(jwksURL, keyfunc.Options{
    RefreshInterval: 15 * time.Minute,  // Instead of 1 hour
})
```

c) **Monitor JWKS changes:**
```bash
# Set up monitoring to alert when JWKS keys change
watch -n 300 'curl -s https://guard.example.com/t/<tenant_id>/.well-known/jwks.json | jq .keys[].kid'
```

**Fix Checklist:**
- [ ] Implement JWKS refresh on unknown `kid` error
- [ ] Set appropriate JWKS cache TTL for your rotation policy
- [ ] Monitor and alert on JWKS changes
- [ ] Coordinate key rotation with consuming services

#### 7. Environment-Specific Issues

**Development:**
```bash
# Common issue: Using production JWKS in development
# ✅ Solution: Use environment-specific URLs
GUARD_URL_DEV=http://localhost:8080
GUARD_URL_PROD=https://auth.example.com

JWKS_URL="${GUARD_URL}/t/${TENANT_ID}/.well-known/jwks.json"
```

**Docker/Kubernetes:**
```bash
# Common issue: Private key not mounted or wrong permissions
# Check key file in container
docker exec -it guard-container ls -la /etc/guard/keys/
docker exec -it guard-container cat /etc/guard/keys/jwt-es256-private.pem | head -n 1

# Should show: -----BEGIN EC PRIVATE KEY-----
# Permissions should be: -rw------- (600)
```

**Cloud Deployments:**
```bash
# Common issue: Secret manager permissions
# Verify Guard service account can access secrets
# AWS:
aws secretsmanager get-secret-value --secret-id guard/jwt-private-key

# GCP:
gcloud secrets versions access latest --secret=guard-jwt-private-key

# Azure:
az keyvault secret show --vault-name guard-vault --name jwt-private-key
```

---

## Rollback Procedures

If migration issues are critical, use this emergency rollback procedure:

### Immediate Rollback (Not Recommended)

⚠️ **WARNING:** Rolling back to HS256 is **not supported** in Guard vNext. ES256 is now mandatory. Instead, focus on fixing the migration issue.

### Recommended Recovery Steps

1. **Identify the specific failure:**
   ```bash
   # Check Guard logs
   kubectl logs -f deployment/guard | grep -i "jwt\|key\|token"

   # Check application logs
   grep -i "token validation\|signature\|jwks" /var/log/app.log
   ```

2. **Apply hotfix:**
   - If key missing: Deploy key immediately via secret manager
   - If JWKS unreachable: Check network/firewall rules
   - If wrong issuer: Update verifier configuration
   - If unknown kid: Force JWKS cache refresh

3. **Monitor recovery:**
   ```bash
   # Watch token validation success rate
   # Watch JWKS endpoint availability
   # Watch Guard application errors
   ```

4. **Post-mortem:**
   - Document the root cause
   - Update migration checklist
   - Improve deployment automation
   - Add monitoring/alerts to prevent recurrence

---

## Testing Your Migration

Before deploying to production, validate the migration in staging:

### Pre-Migration Testing

```bash
# 1. Verify Guard ES256 configuration
curl https://staging-guard.example.com/t/<tenant_id>/.well-known/jwks.json

# Should return ES256 keys with kid
jq '.keys[] | select(.alg == "ES256")'

# 2. Test token issuance
TOKEN=$(curl -X POST https://staging-guard.example.com/api/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"***","tenant_id":"<tenant_id>"}' \
  | jq -r .access_token)

# 3. Inspect token
echo $TOKEN | cut -d. -f1 | base64 -d | jq .  # Header (should show ES256 + kid)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .  # Payload (should show correct iss/ten)

# 4. Test token verification in your application
curl https://your-app-staging.example.com/api/protected \
  -H "Authorization: Bearer $TOKEN"

# Should return 200 OK
```

### Post-Migration Validation

```bash
# 1. Monitor error rates
# Check for 401 Unauthorized spikes
# Check for "invalid signature" errors

# 2. Verify JWKS cache behavior
# Rotate keys in staging
# Verify applications refresh JWKS and accept new tokens

# 3. Performance testing
# Run load tests
# Compare latency percentiles (p50, p95, p99)
# Ensure ES256 overhead is acceptable (<5ms added latency)
```

### Gradual Rollout Strategy

1. **Phase 1: Internal services** (Day 1-3)
   - Update internal microservices first
   - Monitor for issues in controlled environment

2. **Phase 2: Partner integrations** (Day 4-7)
   - Coordinate with partner teams
   - Provide migration support

3. **Phase 3: Public APIs** (Day 8-14)
   - Update public documentation
   - Monitor support tickets
   - Provide clear error messages

4. **Phase 4: Deprecate HS256 references** (Day 15+)
   - Remove HS256 documentation
   - Archive old migration guides
   - Clean up deprecated code paths

---

## Support and Resources

- **Migration Issues:** File issue at [github.com/CorvusHold/guard/issues](https://github.com/CorvusHold/guard/issues)
- **Deployment Help:** See [docs/sso/DEPLOYMENT.md](sso/DEPLOYMENT.md)
- **Performance Benchmarks:** Run `go test -bench=BenchmarkJWT ./internal/auth/keys/...`
- **Example Implementations:** See `examples/` directory for reference integrations
