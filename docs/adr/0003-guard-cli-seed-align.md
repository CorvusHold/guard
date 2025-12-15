# ADR-0003: Guard CLI Seed Alignment & Automation Strategy

**Status:** Proposed  
**Date:** 2025-11-19  
**Deciders:** Guard Platform Team  
**Technical Story:** Guard CLI parity with legacy `cmd/seed`

---

## Context and Problem Statement

`make conformance`, onboarding workflows, and documentation still depend on the retired `go run ./cmd/seed ...` helper. The new `guard-cli` already exposes API-driven `seed` commands, but automation fails because:

1. **Token bootstrap:** `guard-cli` requires a bearer token before any tenant exists, while the legacy seeder ran with DB access and no auth.
2. **Output contract:** scripts expect `KEY=value` pairs that can be sourced; the CLI defaults to human tables/JSON.
3. **Documentation drift:** guides and CI scripts reference the old binary/flags, creating confusion for community users.

We need a future-proof plan that keeps `guard-cli` as the single seeding surface, ensures CI/Conformance flows stay deterministic, and clarifies how tokens are issued and consumed.

---

## Decision Drivers

- **Deterministic automation:** `make conformance` and doc tests must succeed headlessly inside `docker-compose.test`.
- **Security:** even bootstrap tooling should authenticate against the public Guard API to mirror production behavior.
- **Single source of truth:** avoid maintaining two seed binaries.
- **Developer ergonomics:** scripting-friendly output and documented env contracts.
- **Documentation accuracy:** published workflows must reflect the supported toolchain.

---

## Considered Options

| Option | Description | Pros | Cons |
| --- | --- | --- | --- |
| 1. Keep legacy `cmd/seed` | Restore the deleted program for automation only | Minimal changes; works without tokens | Diverges from CLI, reintroduces direct DB writes, doubles maintenance |
| 2. Relax guard-cli auth | Allow seed commands to bypass auth in dev/test | Simplifies bootstrapping | Violates zero-trust assumptions; easy to misuse outside tests |
| 3. **Standardize on guard-cli with explicit token flow + env output** | Use guard-cli everywhere, teach automation how to acquire tokens, add `--output env` | Aligns with production API usage, single toolchain, secure | Requires Makefile/script updates and ADR (this work) |

**Chosen Option:** **3. Guard CLI everywhere with explicit token + env mode**

---

## Decision

We will:

1. **Adopt guard-cli as the only supported seeding surface.** `go run ./cmd/seed` will not return.
2. **Require authenticated flows.** `guard-cli seed` continues to demand `GUARD_API_TOKEN` / `--token`.
3. **Provide a bootstrap recipe for tokens inside automation:**
   - During `make conformance`, create the initial tenant+admin via guard-cli running inside `api_test` using a **bootstrap token** derived from the server’s `JWT_SIGNING_KEY`. (Implementation detail captured in PR.)
   - Persist the issued admin access token (or refresh token) into `.env.conformance` for subsequent CLI calls.
4. **Add a first-class `--output env` (or `-o env`) formatter.** Every seed command must support deterministic `KEY=value` output suitable for `set -a; source <(guard-cli ...)`.
5. **Update Makefile targets, scripts, and docs** to:
   - Export `GUARD_API_TOKEN` before invoking guard-cli inside containers.
   - Use `guard-cli seed default|tenant|user ... --output env` instead of piping/grepping.
   - Clearly document required environment variables and how to obtain tokens for self-hosters.
6. **Document this strategy in this ADR and reference it from README/docs.**

---

## Consequences

### Positive
- One code path for seeding → easier maintenance and testing.
- Automation mirrors production-grade API usage (auth + HTTP), catching regressions earlier.
- `env` output keeps shell tooling simple and POSIX-friendly.
- Documentation stays accurate for community adopters.

### Negative / Risks
- Bootstrap token plumbing adds steps to the Makefile and might confuse contributors; needs clear comments.
- If guard-cli output formats change without versioning, automation can break → mitigated via ADR + explicit flag.
- Requires CI to ensure `.env.conformance` always gets a fresh token (avoid stale creds).

### Mitigations
- Provide helper scripts/functions to fetch/store admin tokens (e.g., `scripts/issue-admin-token.sh`).
- Guard-cli should emit warnings when `--output env` is combined with unsupported subcommands, preventing silent format drift.
- Add regression tests in `scripts/test-documentation.sh` to exercise `--output env`.

---

## Implementation Plan (High-Level)

1. **guard-cli enhancements**
   - Introduce `--output env` flag recognized globally.
   - Refactor seed subcommands to funnel through shared env writer (order-stable, uppercase keys).
2. **Token bootstrap helper**
   - In `make conformance`, after migrations, call `guard-cli seed default --output env` inside the API container **with** a provisional token.
   - Acquire that provisional token by invoking a new helper (`scripts/bootstrap-token.sh`) that signs a short-lived admin JWT using `JWT_SIGNING_KEY` or logs in with known bootstrap credentials (documented).
3. **Automation changes**
   - Replace all `go run ./cmd/seed` occurrences (`Makefile`, `scripts/test-documentation.sh`, docs) with guard-cli equivalents.
   - Ensure `.env.conformance` is populated exclusively via guard-cli output.
4. **Docs & ADR references**
   - Update `docs/TENANT_ONBOARDING.md`, `docs/WORKFLOWS.md`, README snippets, and ADR index to reference guard-cli usage and token requirements.
5. **Verification**
   - Run `make conformance`, `scripts/test-documentation.sh`, and CI smoke jobs to validate the new flow.

---

## Future Work / TODOs

- Provide a `guard-cli auth token` helper that exchanges username/password for a token, simplifying bootstrap stories.
- Consider emitting machine-readable metadata (JSON) alongside env output for richer automation (e.g., structured secrets management).
- Version guard-cli output contracts (e.g., `guard-cli --compat 1`) to avoid breaking changes for downstream tooling.
- Explore generating short-lived service tokens from the server for CI via a dedicated `/api/v1/admin/bootstrap` endpoint with rate limits.

---

## References

- `docs/TENANT_ONBOARDING.md` (current workflows referencing legacy seeder)
- `docs/WORKFLOWS.md`
- `scripts/test-documentation.sh`
- `Makefile` `conformance` target
- Guard CLI source: `cmd/guard-cli/*.go`
