# SDK Upgrade & Standardization Agent

## Mission

Complete the Go SDK standardization to achieve feature parity with TypeScript SDK v2.0.0. Execute ADR 0008 phases in sequence with clear success criteria and automated validation.

## Current Context

### What's Done ✅
- ADR 0007 (API versioning) fully implemented across all phases
- TypeScript SDK v2.0.0: Complete and ready for release (59 paths updated)
- Backend API: Serving at `/api/v1/...` with backward compatibility
- Infrastructure: K6 tests, shell scripts, UI all updated
- Documentation: Comprehensive migration guides and ADRs published

### What's Needed 🔧
- Go SDK wrapper layer fix (22 method signature mismatches)
- Feature parity expansion (56 missing ergonomic wrapper methods)
- Conformance test suite (test both SDKs against same scenarios)
- CI/CD integration (automated parity monitoring)

### Key Constraints
- TypeScript SDK is the reference implementation (100% feature coverage)
- Go SDK `api.gen.go` is correct (62 endpoints, all paths use `/api/v1/`)
- Only wrapper layer (`client.go`) needs refactoring
- Backward compatibility required where possible
- Must follow existing code patterns and conventions

## Execution Plan (ADR 0008 Phases)

### Phase 1: Fix Go SDK Compilation (IMMEDIATE - 2-4 hours)

**Goal:** Make `go build ./sdk/go/...` succeed

**Steps:**
1. Read `sdk/go/client.go` completely to understand current state
2. Check generated `sdk/go/api.gen.go` to understand new method signatures
3. Identify all 22 method call mismatches (search for errors in `go build` output)
4. Update each method call to match generated API signature
5. Run validation: `./scripts/validate-sdk-parity.sh`
6. Ensure all tests pass

**Key Pattern to Fix:**
```go
// BEFORE (broken)
resp, err := c.inner.GetApiV1AuthMeWithResponse(ctx)

// AFTER (correct - matches generated signature)
resp, err := c.inner.GetApiV1AuthMeWithResponse(ctx, &GetApiV1AuthMeParams{})
```

**Success Criteria:**
- ✅ `go build ./sdk/go/...` completes without errors
- ✅ `./scripts/validate-sdk-parity.sh` shows 0 compilation errors
- ✅ All wrapper methods maintain their user-facing signatures

**Files to Modify:**
- `sdk/go/client.go` - Main wrapper file (22 call sites)
- `sdk/go/client_*.go` - Additional wrapper files if needed

---

### Phase 2: Feature Parity Matrix Validation (1-2 weeks)

**Goal:** Complete and verify feature parity matrix with 78 endpoints

**Steps:**
1. Review `sdk/FEATURE_PARITY_MATRIX.md` (already created)
2. Verify each entry is accurate:
   - TypeScript SDK method exists and has correct signature
   - Go SDK method exists (or explicitly mark missing)
   - Parameter/return type compatibility noted
3. Identify priority order for missing wrappers:
   - **Priority 1 (Critical):** Core auth methods (password, magic, MFA)
   - **Priority 2 (High):** User management, SSO providers
   - **Priority 3 (Medium):** RBAC, FGA admin operations
4. Create implementation roadmap for adding wrappers
5. Run validation script with full report

**Success Criteria:**
- ✅ Matrix shows 100% of 78 endpoints with status
- ✅ Priority classification clear for each missing method
- ✅ Implementation plan documented with effort estimates
- ✅ `./scripts/validate-sdk-parity.sh` runs cleanly

**Reference Files:**
- `sdk/FEATURE_PARITY_MATRIX.md` - Current matrix
- `sdk/ts/src/client.ts` - Reference implementation
- `sdk/go/client.go` - Go implementation

---

### Phase 3: Conformance Test Suite (2-3 weeks)

**Goal:** Build shared test framework that validates both SDKs equivalently

**Steps:**
1. Design test suite structure:
   - YAML/JSON scenario definitions (language-agnostic)
   - Go test runner (`sdk/go/conformance_test.go`)
   - TypeScript test runner (`sdk/ts/src/conformance.test.ts`)
2. Implement first 10 test scenarios covering:
   - Password login (success, failure, MFA)
   - Magic link flow
   - Session management
   - Basic auth operations
3. Run both SDKs against shared scenarios
4. Compare results (should be identical)
5. Document any language-specific differences
6. Create CI job to run on every commit

**Success Criteria:**
- ✅ 40+ shared test scenarios defined
- ✅ Both Go and TypeScript runners pass all tests
- ✅ Identical behavior verified (no divergence)
- ✅ CI integration working

**Reference:**
- `sdk/FEATURE_PARITY_MATRIX.md` - Endpoints to test
- `docs/MIGRATION_GUIDE_ADR0007.md` - Test scenarios and flows

---

### Phase 4: Monitoring & Automation (Ongoing)

**Goal:** Establish continuous parity checks

**Steps:**
1. Integrate validation script into CI/CD:
   - GitHub Actions workflow: `validate-sdk-parity.sh`
   - Block merges if SDKs diverge
   - Email alerts on failures
2. Create dashboard with metrics:
   - Feature coverage % (Go vs TypeScript)
   - Build status for both SDKs
   - Version alignment
   - Test coverage %
3. Document maintenance playbook:
   - When releasing SDKs
   - When changing API
   - When adding features
4. Schedule monthly reviews

**Success Criteria:**
- ✅ CI job running on every commit
- ✅ Dashboard shows real-time metrics
- ✅ Zero divergence in main branch
- ✅ Maintenance runbook documented

**Reference:**
- `scripts/validate-sdk-parity.sh` - Validation script
- `docs/adr/0008-go-sdk-standardization-and-parity.md` - Full ADR

---

## Key Resources

### Documentation
- **ADR 0008:** `docs/adr/0008-go-sdk-standardization-and-parity.md` - Complete strategy
- **Feature Matrix:** `sdk/FEATURE_PARITY_MATRIX.md` - 78 endpoints tracked
- **Quick Start:** `sdk/GO_SDK_STANDARDIZATION_QUICK_START.md` - Developer reference
- **Status:** `STATUS_2025_12_12.md` - Current snapshot
- **Summary:** `ADR0007_AND_SDK_STANDARDIZATION_SUMMARY.md` - High-level overview

### Implementation References
- **TypeScript SDK:** `sdk/ts/src/client.ts` - Reference for method patterns
- **Go SDK Wrapper:** `sdk/go/client.go` - Current implementation
- **Generated API:** `sdk/go/api.gen.go` - Auto-generated types and methods
- **Validation Script:** `scripts/validate-sdk-parity.sh` - Automated checks

### Testing & Validation
- OpenAPI Spec: `sdk/spec/openapi.json` - Source of truth
- Makefile: `Makefile` - Build and test commands
  - `make sdk-gen` - Regenerate SDKs
  - `make sdk-check` - Check SDK builds
  - `make test` - Run tests

---

## Success Metrics

### Phase 1 Completion
- Go SDK compiles without errors
- Validation script passes all checks
- 0 method signature errors
- All tests pass

### Phase 2 Completion
- Feature matrix 100% complete
- Clear roadmap for remaining wrappers
- Priority classification documented
- Implementation estimates provided

### Phase 3 Completion
- 40+ conformance tests written
- Both SDKs pass all tests identically
- CI integration working
- Zero divergence detected

### Phase 4 Completion
- Continuous monitoring in place
- Dashboard tracking metrics
- Monthly reviews scheduled
- Maintenance playbook published

---

## Common Patterns & Code Examples

### Pattern 1: Simple Wrapper (No Parameters)
```go
// TypeScript Reference
async mfaDisableTotp(): Promise<ResponseWrapper<unknown>> {
  return this.request<unknown>('/api/v1/auth/mfa/totp/disable', { method: 'POST' });
}

// Go Implementation
func (c *GuardClient) MFATOTPDisable(ctx context.Context) error {
  resp, err := c.inner.PostApiV1AuthMfaTotpDisableWithResponse(ctx)
  if err != nil {
    return err
  }
  if resp.HTTPResponse == nil || (resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusNoContent) {
    return errors.New(resp.Status())
  }
  return nil
}
```

### Pattern 2: With Required Parameters
```go
// TypeScript Reference
async me(): Promise<ResponseWrapper<UserProfile>> {
  return this.request<UserProfile>('/api/v1/auth/me', { method: 'GET' });
}

// Go Implementation
func (c *GuardClient) Me(ctx context.Context) (*DomainUserProfile, error) {
  resp, err := c.inner.GetApiV1AuthMeWithResponse(ctx, &GetApiV1AuthMeParams{})
  // Handle response...
}
```

### Pattern 3: With Request Body
```go
// TypeScript Reference
async introspect(body?: { token?: string }): Promise<ResponseWrapper<Introspection>> {
  return this.request<Introspection>('/api/v1/auth/introspect', {
    method: 'POST',
    body: JSON.stringify(body ?? {}),
  });
}

// Go Implementation
func (c *GuardClient) Introspect(ctx context.Context, token *string) (*DomainIntrospection, error) {
  body := PostApiV1AuthIntrospectJSONRequestBody{Token: token}
  resp, err := c.inner.PostApiV1AuthIntrospectWithResponse(ctx, body)
  // Handle response...
}
```

---

## Debugging & Troubleshooting

### Build Errors
```bash
# See full error output
cd sdk/go && go build ./... 2>&1

# Check specific method signature
grep -A 3 "PostApiV1AuthLogoutWithResponse" sdk/go/api.gen.go

# Check current call site
grep -n "PostApiV1AuthLogoutWithResponse" sdk/go/client.go
```

### Validation Checks
```bash
# Run full validation with details
./scripts/validate-sdk-parity.sh --verbose

# Check SDK compilation status only
cd sdk/go && go build ./... && echo "✅ Go SDK OK"
cd sdk/ts && npm run build && echo "✅ TypeScript SDK OK"

# Verify path consistency
grep -c "/api/v1/" sdk/go/client.go
grep -c "/api/v1/" sdk/ts/src/client.ts
```

### Method Name References
```bash
# Find all generated methods
grep "^func (c \*ClientWithResponses)" sdk/go/api.gen.go | wc -l

# Check if method exists
grep "PostApiV1AuthMagicSendWithResponse" sdk/go/api.gen.go

# See all wrapper methods
grep "^func (c \*GuardClient)" sdk/go/client.go
```

---

## Daily Standup Template

When reporting progress, include:

### What Was Completed
- [ ] Specific methods fixed / features added
- [ ] Tests passing: yes/no
- [ ] Blockers resolved

### What's Next
- [ ] Next method or feature
- [ ] Expected completion time
- [ ] Any blockers or questions

### Metrics
- Current: X/Y methods working (X%)
- Target: 100% feature parity
- Status: On track / At risk / Blocked

---

## Emergency Contacts & Escalations

### If Stuck
1. Review `sdk/GO_SDK_STANDARDIZATION_QUICK_START.md` for patterns
2. Check TypeScript SDK (`sdk/ts/src/client.ts`) for reference
3. Compare with generated API signatures in `sdk/go/api.gen.go`
4. Run validation script to identify exact failures

### If Compilation Fails
1. Get full error: `cd sdk/go && go build ./...`
2. Find the failing method call site
3. Check generated method signature
4. Update call to match signature exactly

### If Unsure About Pattern
1. Find similar method in TypeScript SDK
2. Copy pattern to Go SDK
3. Adjust for Go syntax and types
4. Test: `go build ./...`

---

## Version & Release Guidelines

### SDK Release Checklist
- [ ] Compilation: Both SDKs build without errors
- [ ] Tests: All tests passing
- [ ] Parity: Feature matrix 100% complete
- [ ] Conformance: All shared tests pass
- [ ] Documentation: Updated with changes
- [ ] Version: Both SDKs at same major.minor
- [ ] Changelog: Entries for both SDKs
- [ ] Tags: Created (sdk/go/vX.Y.Z and @sdk/ts@vX.Y.Z)

### Breaking Changes
- Document in migration guide
- Include in CHANGELOG
- Communicate to users
- Update examples in docs

---

## Final Notes

**Remember:** The goal is not perfection in Phase 1-2, but establishing a sustainable pattern that can be maintained long-term. The validation script and parity matrix are more important than any single feature.

**Phase 1 is blocking:** Fix compilation first before moving to other phases. This unblocks v2.0.0 release.

**Celebrate small wins:** Each method fixed, each test passing, each phase completed brings the SDKs closer to parity.

Good luck! 🚀
