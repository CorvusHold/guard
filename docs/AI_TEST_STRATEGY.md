# Corvus Guard — AI-First Deterministic Test Strategy (Automation Contract)

Version: `v1.0`
Owner: `Quality Architecture`
Status: `Proposed for immediate rollout`
Scope: `Go backend + UI + SDK + conformance + k6 + security/compliance`

---

## 0) Deterministic policy (non-negotiable)

1. Every test artifact MUST be classifiable by path + filename only.
2. Every CI stage MUST emit machine-readable artifacts (JSON, JUnit XML, SARIF, or NDJSON).
3. No unbounded retries. All retries MUST be policy-driven and deterministic.
4. Integration/E2E tests MUST run in containerized, resettable environments.
5. Coverage and performance regression policies MUST block merges when thresholds are violated.
6. AI-generated tests MUST pass structural validators before execution.

---

## 1) AI-Compatible Testing Philosophy

### 1.1 Naming conventions (machine-parsable)

#### File naming (strict with transition support)

```regex
# Go unit tests (preferred) + transitional legacy files
^(?:.+_unit_test|.+_test)\.go$

# Go integration tests (requires //go:build integration)
^.+_integration_test\.go$

# Go contract tests (OpenAPI/DTO/API compatibility)
^.+_contract_test\.go$

# UI unit/component tests
^.+\.(unit|component)\.test\.tsx?$

# UI E2E tests
^.+\.e2e\.spec\.ts$

# SDK TS tests
^.+\.(unit|contract)\.test\.ts$

# k6 scenarios
^[0-9]{3}_[a-z0-9_]+\.(smoke|baseline|regression)\.js$

# Security tests
^.+_(sast|depsec|secret|fuzz)_test\.(go|ts)$
```

#### Test function naming

```regex
# Go (preferred GWT style + accepted transitional forms)
^(?:Test[A-Z][A-Za-z0-9]+__(Given|When|Then)_[A-Za-z0-9_]+|Test[A-Za-z0-9_]+)$

# TS (Vitest/Playwright)
^[A-Z][A-Za-z0-9 ]+ :: (Given|When|Then) .+$
```

Notes:
- Preferred naming remains `_unit_test.go` and `Test...__(Given|When|Then)_...`.
- During migration, legacy/transitional Go test files named `*_test.go` and standard `Test...` function names are accepted.

### 1.2 Directory structure rules (inferable)

- Test type MUST be inferable from path segment: `tests/{unit|integration|contract|e2e|performance|security|compliance}`.
- Execution tier MUST be inferable from path segment: `tiers/{pr|extended|nightly|release}`.
- Runtime dependency MUST be inferable from path segment: `deps/{none|docker|external-mock}`.

### 1.3 Standardized metadata annotation strategy

Every new test file MUST include a metadata header block.

#### Go header template

```go
// TEST_META:
// id: internal.auth.service.service_unit_test
// path: internal/auth/service/service_unit_test.go
// type: UNIT
// tier: PR
// deps: none
// owner: auth
// deterministic: true
// risk: R2
// timeout_sec: 60
// maps_to:
//   - internal/auth/service/service.go
```

#### TS header template

```ts
/**
 * TEST_META:
 * id=ui.components.auth.simple-progressive-login-form.component.test
 * path=ui/src/components/auth/SimpleProgressiveLoginForm.component.test.tsx
 * type=E2E
 * tier=EXTENDED
 * deps=docker
 * owner=ui-auth
 * deterministic=true
 * risk=R3
 * timeout_sec=600
 * maps_to=["ui/src/components/auth/SimpleProgressiveLoginForm.tsx"]
 */
```

### 1.4 Deterministic boundaries

- UNIT: no network, no wall clock dependency, no shared mutable global state.
- INTEGRATION: dockerized dependencies only, seeded deterministic fixtures, DB+Redis reset pre-run.
- CONTRACT: pinned schema/spec fixtures, strict DTO assertions.
- E2E: controlled browser env, fixed server startup contract, isolated test data namespace.

---

## 2) Canonical Test Taxonomy (Strict Schema)

### 2.1 Taxonomy model

```json
{
  "UNIT": {"tier": "PR", "deps": "none"},
  "INTEGRATION": {"tier": "EXTENDED", "deps": "docker"},
  "CONTRACT": {"tier": "PR", "deps": "none"},
  "E2E": {"tier": "EXTENDED", "deps": "docker"},
  "PERFORMANCE_BASELINE": {"tier": "NIGHTLY", "deps": "docker"},
  "PERFORMANCE_REGRESSION": {"tier": "RELEASE", "deps": "docker"},
  "SECURITY_STATIC": {"tier": "PR", "deps": "none"},
  "SECURITY_DYNAMIC": {"tier": "NIGHTLY", "deps": "docker"},
  "CHAOS": {"tier": "NIGHTLY", "deps": "docker"},
  "MIGRATION": {"tier": "EXTENDED", "deps": "docker"},
  "COMPLIANCE_VALIDATION": {"tier": "RELEASE", "deps": "docker"}
}
```

Note: prior drafts used pipe notation (for example, `none|docker`) informally. Manifest generators and AI agents MUST emit exactly one schema-valid `deps` value per entry: `none`, `docker`, or `external-mock`.

### 2.2 Category contract table

| Category | Purpose | Scope boundaries | Mocking rules | Tooling | Coverage target | Tier | Determinism requirement |
|---|---|---|---|---|---:|---|---|
| UNIT | Validate pure logic | Single package/module | Allow only in-memory fakes | `go test`, `vitest` | 85%+ branch | PR | Zero retries |
| INTEGRATION | Validate module collaboration with DB/Redis | API/service/repository with docker deps | External APIs mocked | `go test -tags=integration`, docker compose | 70%+ critical-path line | Extended | Fixed seed + reset |
| CONTRACT | Protect API/DTO/spec compatibility | OpenAPI, SDK DTOs, endpoint contracts | No behavior mocks for DTO assertions | `openapi-diff`, conformance runner | 100% endpoint-schema mapping | PR | Immutable pinned schema |
| E2E | Validate user workflows | UI + API + auth flows | Network mocks only where required by design | `playwright` | 100% P0 flows | Extended | deterministic selectors + fixtures |
| PERFORMANCE_BASELINE | Capture baseline latency/error | Key auth endpoints | No response mocking | `k6` | p95 baseline recorded | Nightly | Fixed profile + env |
| PERFORMANCE_REGRESSION | Detect release degradation | Baseline delta checks | No mocks | `k6` + comparator | <=10% p95 drift | Release | baseline ID pinning |
| SECURITY_STATIC | Prevent known code flaws | Source + deps + secrets | N/A | `gosec`, `govulncheck`, lint, secret scan | 0 high severity | PR | tool versions pinned |
| SECURITY_DYNAMIC | Exercise runtime security boundaries | AuthN/AuthZ/rate limit/session | No auth bypass mocks | integration + E2E security suites | 100% critical controls | Nightly | deterministic attack templates |
| CHAOS | Validate resilience | controlled failure injection | N/A | docker fault scripts + probes | defined SLO survival | Nightly | bounded chaos duration |
| MIGRATION | Validate DB schema evolution | migration up/down + compatibility | No schema mocks | goose + integration checks | 100% migration chain | Extended | reset database each run |
| COMPLIANCE_VALIDATION | Produce audit evidence | SDLC controls + test evidence | N/A | CI evidence pack job | 100% control checklist | Release | immutable artifact bundle |

### 2.3 Machine-enforceable schema for test registration

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "TestManifestEntry",
  "type": "object",
  "required": ["id", "path", "type", "tier", "deps", "owner", "risk", "maps_to", "timeout_sec"],
  "properties": {
    "id": {"type": "string", "pattern": "^[a-z0-9_.-]+$"},
    "path": {"type": "string"},
    "type": {"enum": ["UNIT", "INTEGRATION", "CONTRACT", "E2E", "PERFORMANCE_BASELINE", "PERFORMANCE_REGRESSION", "SECURITY_STATIC", "SECURITY_DYNAMIC", "CHAOS", "MIGRATION", "COMPLIANCE_VALIDATION"]},
    "tier": {"enum": ["PR", "EXTENDED", "NIGHTLY", "RELEASE"]},
    "deps": {"enum": ["none", "docker", "external-mock"]},
    "owner": {"type": "string"},
    "risk": {"enum": ["R1", "R2", "R3", "R4"]},
    "deterministic": {"type": "boolean"},
    "maps_to": {"type": "array", "items": {"type": "string"}},
    "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 3600}
  },
  "additionalProperties": false
}
```

Generation rules (required because `id` and `path` are required and `additionalProperties: false` is enabled):

- `path`: MUST be the repository-relative test file path.
- `id`: MUST be derived from `path` by replacing `/` with `.`, removing the file extension, and keeping only `a-z`, `0-9`, `_`, `-`, and `.`.
  - Example: `internal/auth/service/service_unit_test.go` -> `internal.auth.service.service_unit_test`.
- If headers omit `id`/`path`, manifest generators MUST auto-populate both fields before schema validation.

Default timeout policy (bounded execution, aligned to policy rule 3 "No unbounded retries"):

- Manifest generators MUST emit `timeout_sec` for every test entry.
- `UNIT`: 60s
- `INTEGRATION`: 300s
- `CONTRACT`: 60s
- `E2E`: 600s
- `PERFORMANCE_BASELINE`: 600s
- `PERFORMANCE_REGRESSION`: 600s
- `SECURITY_STATIC`: 120s
- `SECURITY_DYNAMIC`: 600s
- `CHAOS`: 600s
- `MIGRATION`: 300s
- `COMPLIANCE_VALIDATION`: 900s

CI MUST reject entries without `timeout_sec` and MUST reject values outside `1..3600`.

---

## 3) AI-Optimized Directory Structure

### 3.1 Top-level target layout

```text
/tests
  /manifest
    test-manifest.json
  /unit
    /backend
    /ui
    /sdk
  /integration
    /backend
    /sdk
  /contract
    /api
    /sdk
  /e2e
    /ui
    /api
  /performance
    /k6
      /scenarios
      /baselines
      /results
  /security
    /static
    /dynamic
    /fuzz
  /migration
  /compliance
    /evidence
/tier
  /pr
  /extended
  /nightly
  /release
```

### 3.2 Backend mapping rules

1. `internal/**/foo.go` MUST have `internal/**/foo_unit_test.go`.
2. Any handler/controller touching DB/Redis MUST also have `*_integration_test.go`.
3. Files with swagger DTO annotations MUST have `*_contract_test.go` validating response shape.
4. Integration tests MUST include `//go:build integration`.

Examples:

- `internal/auth/service/service.go` -> `internal/auth/service/service_unit_test.go`
- `internal/auth/controller/http.go` -> `internal/auth/controller/http_integration_test.go`
- `internal/auth/controller/http.go` -> `internal/auth/controller/http_contract_test.go`

### 3.3 SDK mapping rules

- `sdk/ts/src/client.ts` -> `sdk/ts/src/client.unit.test.ts` + `sdk/ts/src/client.contract.test.ts`
- Each conformance scenario in `sdk/conformance/scenarios/*.json` MUST map to SDK runner assertions.
- `sdk/spec/openapi.json` changes MUST trigger contract diff + SDK conformance.

### 3.4 UI mapping rules

- `ui/src/components/**/X.tsx` -> `ui/src/components/**/X.component.test.tsx`
- Every auth flow page/component must map to at least one E2E spec in `ui/e2e/*.e2e.spec.ts`.
- Use deterministic `data-testid` contract for all asserted elements.

### 3.5 Performance mapping rules

- Every critical endpoint (`/api/v1/auth/password/login`, `/api/v1/auth/mfa/verify`, `/oauth/token`, `/readyz`) MUST have:
  - baseline scenario
  - regression scenario
  - threshold profile

---

## 4) AI-Driven Coverage Strategy

### 4.1 Minimum coverage thresholds

| Layer | Global min | Critical modules (auth/session/token/rbac/sso) |
|---|---:|---:|
| Go backend line | 80% | 90% |
| Go backend branch | 70% | 85% |
| UI unit/component line | 75% | 85% |
| SDK TS line | 85% | 90% |
| Contract endpoint coverage | 95% | 100% for auth endpoints |
| E2E P0 journey coverage | 100% | 100% |

### 4.2 Risk-based coverage policy

- `R1` (critical auth/security): branch >= 85%, mutation score >= 65%
- `R2` (tenant/admin settings): branch >= 75%, mutation score >= 55%
- `R3` (auxiliary features): branch >= 65%
- `R4` (low risk): branch >= 50%

### 4.3 Gap detection algorithm for AI agents

1. Parse changed files in PR.
2. Build expected test mapping via naming/path rules.
3. Compare expected vs existing tests.
4. Check current coverage JSON per module.
5. Emit missing test tasks as structured JSON.

#### Gap report schema

```json
{
  "module": "internal/auth/service/service.go",
  "risk": "R1",
  "expected_tests": [
    "internal/auth/service/service_unit_test.go",
    "internal/auth/service/service_integration_test.go"
  ],
  "missing_tests": ["internal/auth/service/service_unit_test.go"],
  "coverage": {"line": 78.2, "branch": 61.4},
  "status": "fail"
}
```

### 4.4 CI fail logic

Fail the build if any of the following:

- coverage drops > 1.0% absolute in any R1 module
- module threshold is violated
- new/changed file has no mapped test (except approved exemptions)
- conformance or contract drift check fails

---

## 5) CI/CD Strategy Optimized for Agents

### 5.1 Stage model

### Stage A — Fast PR
- Inputs: source diff + manifests
- Runs: lint, unit, static security, contract diff lite
- Outputs: `reports/pr/*.json`, JUnit XML, SARIF
- Fail conditions: any lint/test/security high or contract break
- Retry: 1 bounded retry for infra-only failures

### Stage B — Extended validation
- Inputs: Stage A artifacts + docker stack
- Runs: integration, selective E2E, migration checks, full SDK verify
- Outputs: `reports/extended/*.json`, Playwright artifacts
- Fail conditions: any suite failure, non-deterministic retry exhaustion
- Retry: test-level retry policy only (no full stage rerun by default)

### Stage C — Nightly deep validation
- Inputs: default branch + baseline data
- Runs: full E2E matrix, conformance matrix, performance baseline, dynamic security, chaos-lite
- Outputs: trend JSON, flake index, perf baseline candidates
- Fail conditions: SLO/security/perf regressions
- Retry: isolated suite reruns only

### Stage D — Release hardening
- Inputs: tagged commit + frozen manifests
- Runs: full matrix, compliance validation, artifact signing/hash
- Outputs: immutable evidence bundle (`/compliance/evidence/release-<id>.tar.gz`)
- Fail conditions: any unresolved blocker from earlier stages
- Retry: manual, scoped, audited

### 5.2 Required artifact contract

```text
/reports
  /pr
    coverage-summary.json
    unit-junit.xml
    static-security.sarif
  /extended
    integration-junit.xml
    e2e-results.json
    migration-report.json
  /nightly
    perf-summary.json
    flake-report.json
    dynamic-security.json
  /release
    compliance-controls.json
    traceability-matrix.json
    checksums.txt
```

---

## 6) Local CI Parity (AI-Compatible)

### 6.1 Required Makefile target model

Introduce deterministic wrappers:

- `make ci-pr`
- `make ci-extended`
- `make ci-nightly-local`
- `make ci-release-dryrun`

Taxonomy selectors:

- `make test-by-type TYPE=UNIT`
- `make test-by-tier TIER=PR`
- `make test-by-risk RISK=R1`

### 6.2 Containerization rules

- Use `docker-compose.test.yml` as single parity source.
- No host-only dependency for integration/e2e/perf/security-dynamic.
- Seed scripts MUST be idempotent and versioned.

### 6.3 Isolation and reset guarantees

Before each non-unit stage:
1. Purge DB schema.
2. Reapply migrations.
3. Flush Redis/Valkey.
4. Seed deterministic fixtures.
5. Emit fixture hash in report.

### 6.4 AI-debug mode

`make ci-debug STAGE=extended TEST=internal/auth/controller/http_integration_test.go`

Outputs:
- container logs
- failed test JSON
- reproduction command
- fixture snapshot metadata

---

## 7) AI-Friendly Performance Strategy (k6)

### 7.1 Scenario template contract

```json
{
  "id": "perf.auth.login.baseline",
  "type": "PERFORMANCE_BASELINE",
  "script": "ops/k6/scenarios/001_auth_login.baseline.js",
  "endpoint": "/api/v1/auth/password/login",
  "profile": {"vus": 20, "duration": "5m"},
  "thresholds": {"p95_ms": 500, "error_rate": 0.01},
  "owner": "auth-platform"
}
```

### 7.2 Baseline storage format

`tests/performance/k6/baselines/<scenario-id>.json`

```json
{
  "scenario_id": "perf.auth.login.baseline",
  "commit": "<sha>",
  "captured_at": "<iso8601>",
  "metrics": {"p50_ms": 120, "p95_ms": 280, "p99_ms": 410, "error_rate": 0.002}
}
```

### 7.3 Regression detection logic

- Hard fail if `p95` > threshold.
- Hard fail if `error_rate` > threshold.
- Soft fail if degradation > 10% vs baseline in two consecutive nightlies.

### 7.4 Baseline update governance

- Only allowed in dedicated `perf-baseline-update` PR.
- Requires two approvals (`owner + quality`).
- Must include rationale JSON:

```json
{"reason":"expected cost of stronger hashing","evidence":"link-to-nightly-run"}
```

---

## 8) Security Testing for Automated Agents

### 8.1 Tooling by tier

| Tool | PR | Extended | Nightly | Release |
|---|---|---|---|---|
| golangci-lint/staticcheck | ✅ | ✅ | ✅ | ✅ |
| gosec (SAST) | ✅ | ✅ | ✅ | ✅ |
| govulncheck (dependencies) | ✅ | ✅ | ✅ | ✅ |
| secret scan (gitleaks/trufflehog) | ✅ | ✅ | ✅ | ✅ |
| fuzz tests (Go fuzz) | ❌ | ✅ targeted | ✅ full | ✅ targeted |
| dynamic auth boundary tests | ❌ | ✅ smoke | ✅ full | ✅ full |

### 8.2 AuthZ/AuthN boundary test templates

Must include deterministic templates for:
1. cross-tenant access denial
2. role escalation denial
3. expired/replayed token denial
4. rate limit enforcement
5. SSO callback state replay denial

### 8.3 Structured output and fail conditions

- SARIF for static security.
- JSON for dynamic security (`dynamic-security.json`).
- Auto-fail on high/critical findings or boundary bypass.

---

## 9) Test Maintenance Automation Model

### 9.1 Stale test detection

A test is stale if mapped source no longer exists, or if execution freshness is violated by tier:

- PR, EXTENDED, NIGHTLY tiers: stale when no execution in the last 30 days.
- RELEASE tier (`COMPLIANCE_VALIDATION`, `PERFORMANCE_REGRESSION`, and other release-gated tests): stale when not executed in the last release/tag cycle (or >90 days if release metadata is unavailable).

### 9.2 Redundant test detection

Redundant if two tests have:
- same type
- same mapped source
- equivalent assertion fingerprint > 90%

### 9.3 Flaky test detection

Flaky if same commit has pass/fail variance across retries or reruns.

Flake index:

```text
flake_index = (failed_then_passed_runs / total_runs_last_14_days)
```

Response policy (aligned to KPI in §12):

- Warn threshold: `flake_index >= 0.02` (CI emits warning + alert artifact, test remains runnable).
- Auto-quarantine threshold: `flake_index >= 0.05` (CI blocks normal tier execution for the test and requires quarantine workflow).

CI alerting logic:

- `flake_index < 0.02`: pass (no flake alert)
- `0.02 <= flake_index < 0.05`: warn (`flake-report.json` + CI warning annotation)
- `flake_index >= 0.05`: quarantine (`flake-report.json` + CI failure requiring quarantine routing)

### 9.4 Legacy refactoring rules

- Move non-conforming tests into canonical path.
- Rename to compliant suffix.
- Add metadata header.
- Preserve behavior using snapshot diff before/after.

### 9.5 AI-generated PR guardrails

- Max generated tests per PR: 15 files.
- Must include `ai-generation-report.json`:
  - mapping rationale
  - risk target
  - determinism checks
- Human approval required for:
  - R1 changes
  - baseline updates
  - migration/security test modifications

---

## 10) Migration Plan for Current Repository

### 10.1 Current fragmentation and risks

1. Test taxonomy is implicit, not path-enforced.
2. Coverage gates are not uniformly blocking.
3. Artifacts are partially structured; not fully normalized for agent ingestion.
4. k6 thresholds exist but governed baseline lifecycle is missing.
5. Security workflows exist but fail semantics vary by tool/job.

### 10.2 Phased rollout

### 30-day stabilization

- Add canonical naming/path validator job.
- Introduce test manifest generation.
- Standardize JSON/JUnit/SARIF artifacts.
- Enforce integration build tags + deterministic reset checks.

Exit criteria:
- 95% tests classified in manifest
- 0 untagged integration tests
- reproducible `make ci-pr` on dev machines

### 60-day standardization

- Refactor legacy test names/paths to canonical schema.
- Enable module-level coverage gates (R1 first).
- Wire conformance + contract gates into PR defaults.

Exit criteria:
- 100% R1 modules under coverage gates
- 90% repo tests metadata-compliant
- flake index < 3%

### 90-day automation maturity

- Enable AI gap detection + auto-PR generator with guardrails.
- Activate baseline governance for k6.
- Produce release compliance evidence bundle automatically.

Exit criteria:
- AI-generated tests accepted rate > 70%
- perf regression detection active on all critical endpoints
- compliance evidence bundle generated for every release candidate

---

## 11) Enforcement rules (machine-checkable)

Reject PR if any of the following:

1. file naming regex is invalid
2. changed source has no mapped tests
3. coverage threshold/risk gate is violated
4. contract diff is breaking
5. required artifacts are missing
6. deterministic reset steps are absent for dockerized tiers

---

## 12) KPI scorecard (test maturity)

| KPI | Target | Window |
|---|---:|---|
| Test determinism rate | >= 98% | rolling 14d |
| Flake index | <= 2% | rolling 14d |
| R1 coverage compliance | 100% | per PR |
| Mean failure isolation time | <= 15 min | rolling 30d |
| Test classification completeness | 100% | rolling 30d |
| AI test acceptance rate | >= 70% | rolling 30d |
| Perf regression false-positive rate | <= 5% | rolling 30d |

Enforced KPI mapping:

- `Flake index <= 2%` is actively enforced via §9.3 warning threshold (`flake_index >= 0.02`).
- Auto-quarantine remains at `flake_index >= 0.05` to isolate severe instability while preserving signal at KPI breach.

---

## 13) Immediate implementation checklist (repo-specific)

Implement the following immediate actions:

1. add `tests/manifest/test-manifest.json` generator + validator
2. add `make ci-pr`, `make ci-extended`, `make ci-nightly-local`, `make ci-release-dryrun`
3. add coverage export jobs for Go/UI/SDK in JSON
4. add security secret-scan workflow with SARIF output
5. add k6 baseline registry and baseline update workflow
6. add deterministic gate script verifying DB purge + Redis flush occurred before integration/perf runs
7. add AI maintenance bot job emitting stale/redundant/flaky reports

---

## 14) Compliance mapping (SOC2 / ISO 27001 evidence)

- **Change management:** test manifest + PR gates + approvals.
- **Secure SDLC:** static/dynamic security + fuzz + boundary tests.
- **Release integrity:** signed artifacts + checksums + immutable evidence bundles.
- **Operational resilience:** performance baselines + chaos validation.
- **Auditability:** machine-readable reports retained per pipeline tier.

This strategy is intentionally strict to prevent test entropy and to maximize safe AI automation in Corvus Guard.
