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
