# OAuth2 Authorization Code + PKCE: Implementation Flow (Guard)

This document defines a **reusable integration flow** for OAuth2 with Guard.

It is written for:
- **LLMs** (deterministic contract + sequence)
- **Humans** (practical setup, validation, and troubleshooting)

> Scope: implementation architecture and flow contract.
> Not a UI guide for the POC app.

---

## 1) Integration goal

Implement a client application that can:
1. Start OAuth2 sign-in (Authorization Code + PKCE)
2. Handle callback and exchange code for tokens
3. Call protected APIs with access token
4. Revoke refresh token on logout

Optional:
- Pre-login signup flow (application-specific)

**SDK recommendation:** We highly recommend using the Guard SDK to run this OAuth2 workflow instead of hand-rolling HTTP calls. The SDK:
- Generates PKCE values and state/nonce safely
- Builds the authorize URL and normalizes callback handling
- Exchanges code → tokens with the correct redirect_uri and verifier
- Stores/refreshes tokens and adds Authorization headers for you

Use the SDK in these cases:
- Web or mobile apps that already depend on the Guard API (default choice)
- When you need refresh handling, storage, and retry policies out of the box
- When you want consistent telemetry and error shapes

Use raw HTTP only if:
- You are writing a backend-to-backend integration with a custom token cache, or
- You are implementing a new SDK/agent and need the canonical wire contract below.

---

## 2) Protocol profile (what to implement)

- **Grant**: `authorization_code`
- **PKCE**: required (`S256`)
- **Client type**: `public` (for SPA/native)
- **Scopes**: at least `openid profile email`; add `offline_access` for refresh token
- **Recommended response type**: `code`

Guard endpoints used by the flow:
- Authorize: `GET /oauth/authorize`
- Consent decision: `POST /oauth/authorize/decision` (Guard internal consent step)
- Token exchange: `POST /oauth/token`
- User profile: `GET /api/v1/auth/me`
- Revoke: `POST /oauth/revoke`
- Discovery (optional): `GET /.well-known/openid-configuration`

---

## 3) LLM-ready integration contract

Use this as the canonical machine-readable implementation contract.

```yaml
oauth2_flow:
  pattern: authorization_code_pkce
  required_inputs:
    - guard_base_url
    - client_id
    - redirect_uri
    - tenant_id
    - scopes
  authorize_request:
    method: GET
    path: /oauth/authorize
    query:
      client_id: string
      redirect_uri: absolute_uri
      response_type: code
      scope: space_delimited
      state: random_csrf_token
      nonce: random_oidc_nonce
      code_challenge: base64url_sha256(code_verifier)
      code_challenge_method: S256
  callback_requirements:
    validate_state: true
    expected_query:
      - code
      - state
  token_exchange:
    method: POST
    path: /oauth/token
    content_type: application/x-www-form-urlencoded
    body:
      grant_type: authorization_code
      code: callback_code
      client_id: public_client_id
      redirect_uri: exact_same_as_authorize
      code_verifier: original_random_verifier
  access_protected_resource:
    method: GET
    path: /api/v1/auth/me
    auth: Bearer access_token
  logout:
    method: POST
    path: /oauth/revoke
    body:
      token: refresh_token
      token_type_hint: refresh_token
  invariants:
    - never_skip_state_validation
    - never_reuse_authorization_code
    - never_change_redirect_uri_between_authorize_and_token
    - never_log_tokens_or_code_verifier
```

---

## 4) End-to-end sequence

1. **Generate crypto values**
   - `state` (CSRF)
   - `nonce` (OIDC replay defense)
   - `code_verifier` (high entropy)
   - `code_challenge = BASE64URL(SHA256(code_verifier))`

2. **Redirect user to authorize endpoint**
   - Build `/oauth/authorize?...` with all required query params.

3. **User authentication + consent at Guard**
   - If user is not authenticated, Guard login UI is shown.
   - After successful login/consent, Guard redirects to app callback with `code` and `state`.

4. **Handle callback in your app**
   - Verify `state` against stored pending value.
   - If mismatch: fail hard and clear pending auth state.

5. **Exchange code for tokens**
   - `POST /oauth/token` with `grant_type=authorization_code` and `code_verifier`.

6. **Persist session tokens appropriately**
   - SPA demo: local storage (acceptable for demo/test only).
   - Production: backend exchange + secure session cookie preferred.

7. **Call protected API**
   - `GET /api/v1/auth/me` with bearer token.

8. **Logout**
   - Revoke refresh token via `/oauth/revoke`.
   - Clear local session state.

---

## 5) Setup checklist (environment + client)

### Guard server prerequisites

- Guard API reachable (`guard_base_url`)
- Database and migrations applied
- OAuth routes enabled

### OAuth client registration

Create a **public** OAuth client with:
- Redirect URI(s): exact callback URL(s)
- Scopes: `openid profile email offline_access`
- Grant types: `authorization_code`, `refresh_token`

Required runtime config for integrating app:
- `GUARD_BASE_URL`
- `OAUTH_CLIENT_ID`
- `REDIRECT_URI`
- `OAUTH_SCOPE`
- `TENANT_ID` (for signup/login APIs that require tenant context)

---

## 6) Minimal endpoint payload reference

### 6.1 Authorize URL (query)

```text
GET {GUARD_BASE_URL}/oauth/authorize
  ?client_id={CLIENT_ID}
  &redirect_uri={URL_ENCODED_REDIRECT_URI}
  &response_type=code
  &scope={URL_ENCODED_SCOPE}
  &state={STATE}
  &nonce={NONCE}
  &code_challenge={CODE_CHALLENGE}
  &code_challenge_method=S256
```

### 6.2 Token exchange

```bash
curl -X POST "$GUARD_BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER"
```

### 6.3 Profile

```bash
curl "$GUARD_BASE_URL/api/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### 6.4 Revoke

```bash
curl -X POST "$GUARD_BASE_URL/oauth/revoke" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=$REFRESH_TOKEN&token_type_hint=refresh_token"
```

---

## 7) Common pitfalls (observed during implementation)

1. **Losing `return_to` during login redirect normalization**
   - Impact: user lands on dashboard after login instead of resuming OAuth authorize flow.
   - Fix: preserve and honor `return_to` in login UI/query-state handling.

2. **Auth mode mismatch (cookie vs json) in scripted tests**
   - In cookie mode, password login may return `{ "success": true }` without tokens.
   - For API smoke tests requiring bearer extraction, send `X-Auth-Mode: json`.

3. **Scope value with spaces in shell env files**
   - Quote scope values in `.env` files:
     - `OAUTH_SCOPE="openid profile email offline_access"`

4. **Wrong API port/base URL**
   - Ensure flow points to actual running Guard host/port.

5. **Redirect URI mismatch**
   - Must match exactly between authorize request, token request, and registered client.

---

## 8) Security rules (must-follow)

- Use PKCE `S256`; never plain challenge.
- Validate `state` on callback every time.
- Keep token/code verifier out of logs.
- Use HTTPS outside local development.
- Prefer backend token exchange for production web apps.
- Revoke refresh token on logout.
- Clear client-side session state after revoke/logout.

---

## 9) Test strategy (implementation validation)

### A. API-level smoke (deterministic)

Validate this chain in CI/local automation:
1. Signup test user
2. Login user (obtain bearer token)
3. Call `/oauth/authorize` and retrieve consent challenge
4. Approve consent (`/oauth/authorize/decision`) and capture redirect code
5. Exchange code at `/oauth/token`
6. Call `/api/v1/auth/me`
7. Revoke token at `/oauth/revoke`

Expected result: all steps succeed and `/me.email` equals created test user email.

### B. Browser flow (integration)

Validate these user journeys:
1. Already authenticated user starts OAuth -> callback completes.
2. Unauthenticated user logs in via Guard UI -> redirected back to app callback (not dashboard).
3. Logout revokes token and app session is cleared.

---

## 10) Productionization delta (from demo to real-world)

If starting from SPA demo logic, promote to production by:
1. Moving code exchange to backend (BFF) endpoint.
2. Storing session in secure, HTTP-only, same-site cookies.
3. Adding token refresh strategy server-side.
4. Hardening redirect allowlist and origin validation.
5. Adding structured auth telemetry (without secrets).

---

## 11) Quick implementation checklist

- [ ] OAuth public client created with correct redirect URI/scopes/grants
- [ ] PKCE generation + `state` + `nonce` implemented
- [ ] Authorize redirect constructed correctly
- [ ] Callback validates `state`
- [ ] Token exchange includes exact redirect URI + original verifier
- [ ] `/me` call succeeds with bearer token
- [ ] Logout revokes refresh token
- [ ] `return_to` preserved through login redirects
- [ ] Smoke test covers full chain

---

## 12) When an LLM should fail fast

An LLM implementing this flow should stop and request clarification if:
- `redirect_uri` is not absolute and trusted
- client is confidential but no secret handling path is provided
- requested scope is empty or invalid
- callback lacks `state` and no secure alternative is defined
- environment appears to be production but uses insecure storage assumptions

---

This is the canonical OAuth2 implementation flow extracted from practical Guard integration behavior and validated with end-to-end smoke testing.
