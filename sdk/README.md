# Guard SDKs

This directory contains the multi-language SDKs for Guard CAS.

- `sdk/spec/` — source-of-truth OpenAPI reference and usage notes
- `sdk/conventions/` — cross-language conventions: errors, headers, tokens, tenant, rate limits
- `sdk/conformance/` — language-agnostic conformance scenarios and schema
- `sdk/ts/` — TypeScript SDK (reference client)
- `sdk/go/` — Go SDK (planned)
- `sdk/rust/` — Rust SDK (planned)

Goals:
- Single spec-first approach driven by `docs/swagger.json`
- Consistent error and rate-limit handling across languages
- Shared, language-agnostic conformance scenarios

Release strategy:
- Each SDK is versioned independently (semver).
- A compatibility matrix will be maintained to relate API version ↔ SDK versions.
