# ADR 0008: Go SDK Standardization and Feature Parity with TypeScript SDK

## Status
PROPOSED

## Context

Following the completion of ADR 0007 (API Versioning and /api/v1 Routing), the Go SDK wrapper layer (`sdk/go/client.go`) requires refactoring to:

1. **Match the TypeScript SDK quality standard** - The TypeScript SDK has a well-structured, ergonomic API with clear separation of concerns
2. **Achieve full feature parity** - Both SDKs should expose the same functionality with equivalent method signatures
3. **Enable maintenance and monitoring** - Establish clear patterns for tracking and preventing SDK divergence

## Problem Statement

Currently, the Go SDK has several limitations:

### 1. **Wrapper Layer Inconsistency**
- `client.go` contains manual, non-generated wrapper methods
- Method signatures don't align with the generated `api.gen.go` types
- Refactoring `api.gen.go` breaks `client.go` compatibility
- Example mismatch:
  ```go
  // Generated method signature
  func (c *ClientWithResponses) PostApiV1AuthMeWithResponse(
    ctx context.Context,
    *GetApiV1AuthMeParams,
    ...RequestEditorFn
  ) (*GetApiV1AuthMeResponse, error)

  // Current wrapper call
  resp, err := c.inner.GetApiV1AuthMeWithResponse(ctx)  // Missing params!
  ```

### 2. **No Feature Parity Tracking**
- No documented comparison between Go and TypeScript SDK features
- Method additions to one SDK don't automatically propagate to the other
- No CI/CD validation that both SDKs have equivalent endpoints

### 3. **Code Generation Pipeline Issues**
- `oapi-codegen` generates v1-based method names (e.g., `PostV1Auth*`)
- Manual refactoring required after each OpenAPI spec change
- No automation to keep method names synchronized with spec changes

### 4. **Testing & Validation Gaps**
- Go SDK wrapper methods not tested against generated API
- No conformance tests comparing Go and TypeScript SDK behavior
- Manual verification required for SDK compatibility

## Decision

We will standardize the Go SDK through a multi-phase approach:

### Phase 1: Refactor Client Wrapper Layer (Immediate)
**Goal:** Fix signature mismatches and align with generated API

**Approach:**
1. Analyze all 22 methods in `client.go` that call generated API
2. Update method signatures to match generated API requirements
3. Create explicit parameter structs for ergonomic API design
4. Add comprehensive documentation and examples

**Key Changes:**
- Replace manual parameter building with generated types
- Use generated parameter structs (e.g., `GetApiV1AuthMeParams`)
- Ensure all call sites match generated method signatures
- Maintain backward compatibility where possible (or document breaking changes)

**Example Refactor:**
```go
// Before (broken)
func (c *GuardClient) Me(ctx context.Context) (*DomainUserProfile, error) {
  resp, err := c.inner.GetApiV1AuthMeWithResponse(ctx)  // Wrong signature!
  ...
}

// After (correct)
func (c *GuardClient) Me(ctx context.Context) (*DomainUserProfile, error) {
  // GetApiV1AuthMeWithResponse expects *GetApiV1AuthMeParams
  resp, err := c.inner.GetApiV1AuthMeWithResponse(ctx, &GetApiV1AuthMeParams{})
  ...
}
```

### Phase 2: Create Feature Parity Matrix (1-2 weeks)
**Goal:** Establish and document feature equivalence

**Deliverables:**
1. **SDK Feature Parity Document** (`sdk/FEATURE_PARITY_MATRIX.md`)
   - Table mapping TypeScript methods → Go methods
   - Parameter and return type mappings
   - Notes on language-specific differences
   - Last updated timestamp and validation status

2. **Automated Parity Checker (CI/CD)**
   - Script that compares OpenAPI spec against both SDKs
   - Validates each endpoint has equivalent methods in both SDKs
   - Reports missing methods and parameter mismatches
   - Runs on every OpenAPI spec change

**Example Matrix Structure:**
```markdown
| Feature | TypeScript Method | Go Method | Params | Returns | Status |
|---------|------------------|-----------|--------|---------|--------|
| Password Login | `passwordLogin()` | `PasswordLogin()` | ✓ Match | ✓ Match | ✅ |
| User Profile | `me()` | `Me()` | ✓ Match | ✓ Match | ✅ |
| MFA TOTP Start | `mfaStartTotp()` | `MFATOTPStart()` | ✓ Match | ✓ Match | ✅ |
```

### Phase 3: Establish Conformance Testing (2-3 weeks)
**Goal:** Verify SDK behavior equivalence

**Implementation:**
1. **Shared Conformance Suite** (`sdk/conformance/`)
   - Language-agnostic test scenarios
   - Each scenario defined in YAML or JSON
   - Tests login flow, MFA, SSO, admin operations

2. **SDK-Specific Test Runners**
   - `sdk/go/conformance_test.go` - Runs shared suite against Go SDK
   - `sdk/ts/src/conformance.test.ts` - Runs shared suite against TS SDK
   - Both test against live API instance

3. **Diff Detection**
   - CI job that runs both test runners
   - Flags any behavior differences
   - Prevents merging if SDKs diverge

**Example Test Case (YAML):**
```yaml
testCase:
  name: "Password Login Success"
  steps:
    - action: "login"
      email: "{{ TEST_EMAIL }}"
      password: "{{ TEST_PASSWORD }}"
      tenantId: "{{ TEST_TENANT_ID }}"
    - action: "assert"
      condition: "response.status == 200"
    - action: "assert"
      condition: "response.access_token exists"
      condition: "response.refresh_token exists"
```

### Phase 4: Version Alignment & Release Strategy (Ongoing)
**Goal:** Keep SDKs in sync version-wise and feature-wise

**Policy:**
1. **Version Pinning:** Both SDKs must release with the same major.minor version
   - Go: `sdk/go/v2.1.0`
   - TypeScript: `@corvushold/guard-sdk@2.1.0`

2. **Release Checklist:**
   ```
   [ ] OpenAPI spec updated (docs/swagger.json)
   [ ] Go SDK: api.gen.go regenerated
   [ ] TypeScript SDK: types regenerated
   [ ] Feature parity matrix verified
   [ ] Conformance tests passing
   [ ] Both SDKs build without errors
   [ ] CHANGELOG entries for both SDKs
   [ ] Version bumped in both go.mod and package.json
   [ ] Tags created: sdk/go/v2.x.x and sdk/ts@v2.x.x
   ```

3. **Breaking Changes:**
   - Documented in migration guide
   - Both SDKs change together
   - Version number reflects change scope (major/minor/patch)

## Implementation Plan

### Immediate (This Sprint)
1. **Fix Go SDK Compilation** (2-4 hours)
   - Update `client.go` to match generated `api.gen.go` signatures
   - Ensure `go build ./sdk/go/...` succeeds
   - Document all changes in CHANGELOG

2. **Document Current State** (1-2 hours)
   - Create `sdk/go/MIGRATION_FROM_V1.md`
   - List all breaking changes from API refactoring
   - Provide upgrade examples

### Week 1
3. **Create Feature Parity Matrix** (4-6 hours)
   - Manual analysis of both SDKs
   - Build feature comparison spreadsheet
   - Identify gaps and inconsistencies

4. **Begin Conformance Test Framework** (6-8 hours)
   - Design shared test suite structure
   - Implement first 5 test cases
   - Set up CI integration

### Week 2-3
5. **Complete Conformance Suite** (8-10 hours)
   - Add remaining test scenarios
   - Test against staging/test environment
   - Document test execution

6. **Automated Parity Checker** (6-8 hours)
   - Build script to validate feature parity
   - Integrate into pre-commit hooks
   - Add to CI pipeline

### Ongoing
7. **Monitoring & Maintenance**
   - Weekly parity checks
   - Monthly review of feature matrix
   - Dashboard tracking SDK divergence metrics

## Monitoring & Maintenance Strategy

### Automated Checks (Every Commit)
```bash
# Pre-commit hook
./scripts/validate-sdk-parity.sh

# Output example
✅ OpenAPI spec found
✅ Go SDK: 48 endpoints detected
✅ TypeScript SDK: 48 endpoints detected
✅ Parity check: ALL PASS (100%)
```

### CI/CD Integration
```yaml
# .github/workflows/sdk-parity.yml
- name: Check SDK Feature Parity
  run: ./scripts/validate-sdk-parity.sh

- name: Run Go Conformance Tests
  run: cd sdk/go && go test -v ./conformance_test.go

- name: Run TypeScript Conformance Tests
  run: cd sdk/ts && npm run test:conformance

- name: Compare Results
  run: ./scripts/compare-conformance-results.sh
```

### Dashboard Metrics (Monthly)
Track and report on:
- **Endpoint Coverage:** % of OpenAPI endpoints with matching methods in both SDKs
- **Test Coverage:** % of endpoints covered by conformance tests
- **Build Status:** Both SDKs compile without warnings
- **Parity Score:** Overall feature parity percentage
- **Divergence Index:** Lines of code difference between SDKs

Example dashboard:
```
┌─ SDK Parity Metrics ─────────────────────────────┐
│ Endpoint Parity:    48/48 ✅ (100%)             │
│ Test Coverage:      42/48 ⚠️  (87.5%)           │
│ Go SDK Build:       ✅ Clean                    │
│ TypeScript Build:   ✅ Clean                    │
│ Last Parity Check:  2025-12-12 08:30 UTC       │
│ Last Update:        1 day ago                    │
└──────────────────────────────────────────────────┘
```

## Documentation

### Files to Create/Update

1. **`sdk/FEATURE_PARITY_MATRIX.md`**
   - Comprehensive comparison of all SDK methods
   - Updated with each SDK release
   - Automated validation notes

2. **`sdk/go/STANDARDIZATION_PLAN.md`**
   - Detailed refactoring plan
   - Timeline and milestones
   - Known issues and workarounds

3. **`sdk/ts/FEATURE_PARITY_PLAN.md`** (Update)
   - Link to shared parity matrix
   - TypeScript-specific migration notes

4. **`scripts/validate-sdk-parity.sh`** (New)
   - Automated parity validation
   - Runnable locally and in CI
   - Clear success/failure reporting

5. **`sdk/conformance/test-suite.yaml`** (New)
   - Shared test cases
   - Language-agnostic scenario definitions
   - Easy to add new test cases

## Success Criteria

### Short-term (This Sprint)
- ✅ Go SDK compiles without errors
- ✅ All 22 wrapper methods have correct signatures
- ✅ Feature parity matrix created and published
- ✅ First 10 conformance tests passing in both SDKs

### Medium-term (1 Month)
- ✅ Complete conformance test suite (40+ tests)
- ✅ Automated parity checker integrated in CI
- ✅ 100% endpoint parity between SDKs
- ✅ Both SDKs pass all conformance tests
- ✅ Dashboard tracking metrics

### Long-term (Ongoing)
- ✅ Zero parity divergence
- ✅ Monthly SDK alignment reviews
- ✅ SDK updates always include both Go and TypeScript
- ✅ New features tested in both SDKs before release

## Risks & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Breaking changes** for Go SDK users | High | Document clearly in CHANGELOG; provide migration guide; consider v2 major version |
| **Conformance tests are flaky** | Medium | Run against stable test environment; add retry logic; monitor false positives |
| **oapi-codegen generates breaking changes** | Medium | Pin version; review spec changes before regeneration; test thoroughly |
| **Team unfamiliar with Go SDK** | Medium | Document patterns; pair programming on refactoring; code review checklist |
| **Time to implement** | Medium | Prioritize Phase 1 (critical); defer Phases 2-4 if needed; can be incremental |

## Alternatives Considered

### 1. **Rewrite Go SDK from Scratch**
- ❌ Too time-consuming (4-6 weeks)
- ❌ High risk of missing features
- ✅ Would achieve perfect consistency

### 2. **Auto-generate Both SDKs (openapi-generator)**
- ✅ Guarantees parity
- ❌ Generated code less ergonomic
- ❌ Less customization for language-specific patterns
- ❌ Complex setup and configuration

### 3. **TypeScript SDK Only, Go SDK Deprecated**
- ❌ Breaks existing Go users
- ❌ Loses Go adoption
- ✅ Reduces maintenance burden

### 4. **Incremental Parity (Chosen)**
- ✅ Fixes immediate issues
- ✅ Allows phased approach
- ✅ Maintains backward compatibility where possible
- ✅ Establishes monitoring for future

## References

- ADR 0007: API Versioning and /api/v1 Routing
- SDK Comparison: `sdk/FEATURE_PARITY_MATRIX.md` (to be created)
- Go SDK Current Issues: `sdk/go/STANDARDIZATION_PLAN.md` (to be created)
- TypeScript SDK: `sdk/ts/README.md` (reference implementation)

## Follow-up ADRs

- **ADR 0009:** SDK Code Generation Strategy (if moving to full auto-generation)
- **ADR 0010:** Multi-language SDK Testing Framework (for conformance expansion)
- **ADR 0011:** SDK Release and Versioning Policy (formalize version alignment)
