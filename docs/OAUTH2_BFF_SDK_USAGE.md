# OAuth2 BFF with Guard Go SDK: Integration Guide

This document provides a practical, production-oriented reference for implementing OAuth2 Authorization Code + PKCE in a **Backend For Frontend (BFF)** using the Guard Go SDK.

It complements:
- `docs/OAUTH2_IMPLEMENTATION_FLOW.md` (protocol contract)
- `examples/oauth2-bff-go/` (working front + backend example)

---

## 1) Why BFF for OAuth2

Use BFF when you want to:
- Keep OAuth tokens out of browser JavaScript
- Perform code exchange and refresh server-side
- Control session lifecycle with HTTP-only cookies

Compared to SPA-only exchange, BFF reduces token exposure risk and aligns better with production web security baselines.

---

## 2) New Go SDK primitives for BFF

The Go SDK now provides first-class OAuth2 helpers:

- `BuildOAuth2AuthorizeURL(...)`
- `ExchangeOAuth2Code(...)`
- `OAuth2Refresh(...)`

These are implemented in:
- `sdk/go/client.go`
- covered by tests in `sdk/go/client_test.go`

---

## 3) Recommended BFF architecture

1. Browser hits backend `/oauth/login`
2. Backend generates `state`, `nonce`, `code_verifier` + `code_challenge`
3. Backend stores pending flow in server session
4. Backend redirects to Guard `/oauth/authorize`
5. Guard callback returns to backend `/oauth/callback`
6. Backend validates `state`, calls `ExchangeOAuth2Code`
7. SDK persists access/refresh token to your `TokenStore`
8. Backend exposes app APIs (`/api/me`, etc.) using SDK `Me()`
9. On token expiry, backend calls `OAuth2Refresh` and retries

---

## 4) Minimal implementation pattern (Go)

```go
// Build client with session-scoped token store
client, err := guard.NewGuardClient(
    guardBaseURL,
    guard.WithAuthMode(guard.AuthModeBearer),
    guard.WithTokenStore(sessionStore),
)

// 1) Build authorize URL
authorizeURL, err := client.BuildOAuth2AuthorizeURL(guard.OAuth2AuthorizeParams{
    ClientID:      oauthClientID,
    RedirectURI:   redirectURI,
    Scope:         "openid profile email offline_access",
    State:         state,
    Nonce:         nonce,
    CodeChallenge: codeChallenge,
})

// 2) Exchange callback code server-side
_, err = client.ExchangeOAuth2Code(ctx, guard.OAuth2CodeExchangeRequest{
    Code:         code,
    CodeVerifier: codeVerifier,
    RedirectURI:  redirectURI,
    ClientID:     &oauthClientID,
})

// 3) Call protected API with stored bearer token
profile, err := client.Me(ctx)

// 4) Optional refresh on expired token
if err != nil {
    if _, rerr := client.OAuth2Refresh(ctx, guard.OAuth2RefreshRequest{ClientID: &oauthClientID}); rerr == nil {
        profile, err = client.Me(ctx)
    }
}
_ = profile
```

---

## 5) Session and token-store guidance

For production:
- Use Redis/DB-backed session storage
- Use HTTP-only, `SameSite=Lax|Strict`, secure cookies
- Keep pending auth state (`state`, `code_verifier`) short-lived
- Bind session to expected origin/CSRF model

`TokenStore` should be scoped per user session (not global process memory).

---

## 6) End-to-end example and smoke validation

Use the working example:
- `examples/oauth2-bff-go/backend/main.go`
- `examples/oauth2-bff-go/backend/static/index.html`

Bootstrap + smoke:

```bash
bash examples/oauth2-bff-go/scripts/bootstrap.sh
bash examples/oauth2-bff-go/scripts/oauth2-bff-smoke.sh
```

Smoke script validates:
1. BFF login redirect generation
2. Guard authorize + consent decision
3. Callback code exchange via SDK
4. BFF `/api/me` after login
5. Logout/session clear

---

## 7) Failure modes and debugging checklist

If callback exchange fails:
- Verify `redirect_uri` exact match across:
  - client registration
  - authorize request
  - token exchange request
- Verify callback `state` equals pending session state
- Verify `code_verifier` matches original challenge
- Verify backend uses correct `GUARD_BASE_URL`

If `/api/me` fails after exchange:
- Inspect session token store persistence
- Verify `Authorization: Bearer <access_token>` header on backend -> Guard requests
- Attempt `OAuth2Refresh(...)` and retry `/api/v1/auth/me`

---

## 8) Security rules (BFF)

- Always use PKCE `S256`
- Never log auth code, access token, refresh token, code verifier
- Use HTTPS in non-local environments
- Rotate/expire session cookies aggressively
- Revoke refresh token chain on logout

---

This is the canonical SDK-level guide for BFF OAuth2 integration with Guard Go SDK.
