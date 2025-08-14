# Guard SDK Compatibility Matrix

This matrix relates API spec versions to SDK versions across languages.

- Source of truth API spec: `docs/swagger.json`
- Pinned SDK spec: `sdk/spec/openapi.json`

| API (docs/swagger) | TS (@corvushold/guard-sdk) | Go (planned) | Rust (planned) | Notes |
|--------------------|----------------------------|--------------|----------------|-------|
| 0.1.x              | 0.1.0-beta.0+              | -            | -              | Initial beta: password+MFA, refresh/revoke, me/introspect, magic link. Conformance runner available. Node LTS, Browser, RN supported. |

Guidelines:
- On breaking API changes, bump SDK major and update this matrix.
- CI contract-diff must block merges unless corresponding SDK major bump + matrix update is present.
- Each SDK reads the pinned `sdk/spec/openapi.json` for its generation and tests.

Additional TS SDK notes:
- `baseUrl` must be explicitly configured (no default).
- `X-Guard-Client` header is dynamic from package version (e.g., `ts-sdk/0.1.0-beta.0`).
 - Initial conformance scenarios: password login (200/202 + mfa/verify), me unauthorized (401), refresh/logout, magic send/verify.
