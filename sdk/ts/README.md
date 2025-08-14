# TypeScript SDK (Reference)

This package will provide the reference Guard SDK for Node.js and browsers.

Planned features:
- Generated DTO types from `../../docs/swagger.json`
- Pluggable `fetch` transport
- Token provider abstraction
- Helpers for password + MFA, magic link, refresh/revoke, me/introspect, SSO start/callback
- Rate-limit error parsing (`Retry-After`)

Implementation will begin after endpoint mapping is verified against the OpenAPI spec.
