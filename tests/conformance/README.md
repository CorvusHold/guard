# Conformance Testing Framework

## Overview

This directory contains the conformance test framework for Go SDK v2.0.0. The framework validates that the Go and TypeScript SDKs behave identically across all major API operations.

## Structure

```
tests/conformance/
├── scenarios/              # YAML-based test scenario definitions
│   ├── auth/              # Authentication test scenarios
│   ├── tenant/            # Tenant management test scenarios
│   ├── rbac/              # RBAC role management test scenarios
│   ├── mfa/               # MFA enrollment test scenarios
│   └── admin/             # Admin user management test scenarios
├── README.md              # This file
└── SCENARIOS.md           # Detailed scenario documentation
```

## Scenario Files

### Authentication (`auth/`)
- **login.yaml**: Password login flows (valid/invalid credentials)
- **signup.yaml**: User registration and password signup
- Other authentication scenarios (magic link, email discovery, etc.)

### RBAC (`rbac/`)
- **roles.yaml**: Role CRUD operations
- **permissions.yaml**: Permission management and assignment
- **user_roles.yaml**: User role assignments

### Tenant (`tenant/`)
- **crud.yaml**: Tenant creation, retrieval, update, deletion
- **settings.yaml**: Tenant settings management

### MFA (`mfa/`)
- **totp.yaml**: Time-based One-Time Password enrollment
- **backup_codes.yaml**: Backup code generation and usage

## Test Scenario Format

Each YAML file contains a test suite with multiple scenarios:

```yaml
name: "Test Suite Name"
description: "Suite description"
scenarios:
  - id: "unique_scenario_id"
    name: "Scenario Name"
    description: "What this scenario tests"
    method: "POST|GET|PUT|PATCH|DELETE"
    endpoint: "/api/v1/path"
    headers:
      authorization: "Bearer {access_token}"
    request:
      field1: "value1"
      field2: 123
    expected_response:
      status: 200
      fields:
        - name: "response_field"
          type: "string"
          required: true
    sdk_method: "SDKMethodName"
    expected_error: false
```

## Running Conformance Tests

### Go SDK Tests

```bash
# Run all conformance tests
cd sdk/go
go test -v ./conformance_test.go

# Run specific test category
go test -v -run TestConformanceAuth ./conformance_test.go

# Run with short timeout
go test -short -v ./conformance_test.go
```

### TypeScript SDK Tests

```bash
# Run all conformance tests
cd sdk/ts
npm test -- conformance.test.ts

# Run specific test suite
npm test -- conformance.test.ts -t "Authentication"

# Run with coverage
npm test -- conformance.test.ts --coverage
```

## Test Categories

### 1. Authentication (12 scenarios)
Tests login, signup, password reset, and SSO flows:
- Valid credential login ✓
- Invalid email login ✗
- Invalid password login ✗
- Missing tenant ID ✗
- Valid user registration ✓
- Duplicate email registration ✗
- Weak password registration ✗
- Invalid email format ✗
- Request password reset ✓
- Confirm password reset ✓
- Reset with invalid token ✗
- OIDC/SAML flows (4 scenarios)

### 2. RBAC (6 scenarios)
Tests role and permission management:
- List all roles ✓
- Create new role ✓
- Create duplicate role ✗
- Update role ✓
- Delete role ✓
- Delete system role ✗

### 3. Tenant (7 scenarios)
Tests tenant CRUD operations:
- Create tenant ✓
- Create duplicate slug ✗
- Get tenant by ID ✓
- Get non-existent tenant ✗
- List all tenants ✓
- Update tenant ✓
- Deactivate tenant ✓

### 4. MFA (6 scenarios)
Tests TOTP and backup code management:
- Start TOTP enrollment ✓
- Activate TOTP ✓
- Activate with invalid code ✗
- Disable TOTP ✓
- Disable when not enabled ✗
- View backup codes ✓

### 5. Admin (6 scenarios)
Tests user administration and management:
- List all users ✓
- Get user by ID ✓
- Update user information ✓
- Block user account ✓
- Unblock user account ✓
- Search users by email ✓

### 6. Sessions (4 scenarios)
Tests session lifecycle and management:
- List user sessions ✓
- Revoke session ✓
- Revoke all sessions ✓
- Get current session ✓

## Test Results Interpretation

### Passing Test
- ✓ SDK method executed successfully
- Response status matched expected status code
- Required response fields present
- No unexpected errors

### Failing Test
- ✗ SDK method failed to execute
- Response status didn't match expected
- Required response fields missing
- Unexpected errors occurred

## Expected Error Scenarios

Some scenarios are marked with `expected_error: true`. These test error handling:

```yaml
expected_error: true
expected_response:
  status: 401  # or 400, 409, etc.
  fields:
    - name: "error"
      type: "string"
```

These scenarios verify that the SDK properly handles errors and returns the expected error status.

## Adding New Scenarios

To add a new test scenario:

1. **Create/Edit YAML file** in appropriate category directory
2. **Add scenario definition** with unique ID
3. **Specify SDK method** to test
4. **Define expected response** status and fields
5. **Run tests** to validate

Example:
```yaml
  - id: "auth_magic_link_send"
    name: "Magic Link Send"
    description: "Send magic link to user email"
    method: "POST"
    endpoint: "/api/v1/auth/magic-link/send"
    request:
      email: "user@example.com"
    expected_response:
      status: 200
    sdk_method: "SendMagicLink"
```

## Parity Validation

The conformance framework validates:

✓ **Method Count**: Both SDKs implement same number of methods
✓ **Response Schemas**: Identical response structure across SDKs
✓ **Error Handling**: Same error codes and messages
✓ **Type Conversions**: Proper type handling in both languages
✓ **Business Logic**: Identical behavior for same operations

## CI/CD Integration

### GitHub Actions Example
```yaml
- name: Run Conformance Tests (Go)
  run: |
    cd sdk/go
    go test -v ./conformance_test.go

- name: Run Conformance Tests (TypeScript)
  run: |
    cd sdk/ts
    npm test -- conformance.test.ts
```

### Success Criteria
- ✓ All scenario YAML files parse without errors
- ✓ All SDK methods execute successfully
- ✓ Response structures match expected schema
- ✓ Error handling behaves identically
- ✓ 100% scenario pass rate

## Metrics Tracked

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Total Scenarios | 40+ | 44 | ✅ Complete |
| Auth Scenarios | 8+ | 12 | ✅ Complete |
| RBAC Scenarios | 6+ | 6 | ✅ Complete |
| Tenant Scenarios | 6+ | 7 | ✅ Complete |
| MFA Scenarios | 6+ | 6 | ✅ Complete |
| Admin Scenarios | 6+ | 6 | ✅ Complete |
| Session Scenarios | 4+ | 4 | ✅ Complete |
| Password Reset Scenarios | 3+ | 3 | ✅ Complete |
| SSO Scenarios | 4+ | 4 | ✅ Complete |
| Pass Rate | 100% | Pending | 🔄 Test Execution |
| Go SDK Coverage | 80%+ | Pending | 🔄 Test Execution |
| TS SDK Coverage | 80%+ | Pending | 🔄 Test Execution |

## Troubleshooting

### Scenarios Not Loading
- Verify YAML syntax is valid
- Check file is in correct directory
- Ensure file ends with `.yaml`

### Test Failures
- Check API endpoint is accessible
- Verify request/response format matches
- Review error messages in test output
- Compare with TypeScript SDK test results

### Missing Methods
- Verify SDK method name matches `sdk_method` field
- Check method is exported in SDK
- Ensure method signature matches expected

## Future Enhancements

- [ ] Automatic scenario generation from OpenAPI spec
- [ ] Performance benchmarking
- [ ] Load testing scenarios
- [ ] E2E workflow scenarios
- [ ] Multi-tenant scenarios
- [ ] Concurrent request testing
- [ ] Response time assertions
- [ ] Automatic parity report generation

## References

- [SDK Feature Parity Matrix](../../sdk/FEATURE_PARITY_MATRIX.md)
- [Phase 3 Execution Checklist](../../docs/PHASE_3_EXECUTION_CHECKLIST.md)
- [Go SDK Implementation](../../sdk/go/)
- [TypeScript SDK Implementation](../../sdk/ts/src/)
