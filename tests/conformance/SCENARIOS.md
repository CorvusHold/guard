# Conformance Test Scenarios - Detailed Documentation

## Scenario Index

### Authentication (12 scenarios)
- Login with Valid Credentials
- Login with Invalid Email
- Login with Invalid Password
- Login with Missing Tenant
- New User Signup
- Duplicate Email Registration
- Weak Password Registration
- Invalid Email Format
- Request Password Reset
- Confirm Password Reset
- Reset with Invalid Token
- OIDC/SAML SSO Flows (4 scenarios)

### RBAC (6 scenarios)
- List All Roles
- Create New Role
- Create Duplicate Role
- Update Role
- Delete Role
- Delete System Role

### Tenant (7 scenarios)
- Create Tenant
- Create Duplicate Slug
- Get Tenant by ID
- Get Non-existent Tenant
- List All Tenants
- Update Tenant
- Deactivate Tenant

### MFA (6 scenarios)
- TOTP Enrollment Start
- TOTP Activation
- TOTP Activation with Invalid Code
- TOTP Disable
- Disable TOTP When Not Enabled
- View Backup Codes

### Admin (6 scenarios)
- List All Users
- Get User by ID
- Update User Information
- Block User Account
- Unblock User Account
- Search Users by Email

### Sessions (4 scenarios)
- List User Sessions
- Revoke Session
- Revoke All Sessions
- Get Current Session

### Password Reset (3 scenarios)
- Request Password Reset
- Confirm Password Reset
- Reset with Invalid Token

### SSO (4 scenarios)
- Initiate OIDC Flow
- OIDC Callback Handler
- Initiate SAML Flow
- List SSO Providers

---

## Total Scenarios: 44 ✅

---

## Authentication Scenarios

### auth_login_valid
**Purpose**: Validate successful login with correct credentials

**Endpoint**: `POST /api/v1/auth/login`

**SDK Method**: `PasswordLogin(email, password, tenantID)`

**Input**:
```json
{
  "email": "test@example.com",
  "password": "ValidPassword123!",
  "tenant_id": "tenant-1"
}
```

**Expected Response**:
- Status: 200
- Fields: access_token, refresh_token, user

**Assertions**:
- Access token is valid JWT
- Refresh token is non-empty string
- User object contains id and email
- Both tokens are usable for subsequent requests

---

### auth_login_invalid_email
**Purpose**: Validate error handling for non-existent email

**Endpoint**: `POST /api/v1/auth/login`

**SDK Method**: `PasswordLogin(email, password, tenantID)`

**Input**:
```json
{
  "email": "nonexistent@example.com",
  "password": "AnyPassword123!",
  "tenant_id": "tenant-1"
}
```

**Expected Response**:
- Status: 401
- Fields: error message

**Assertions**:
- Returns 401 Unauthorized
- Error message is user-friendly
- No partial authentication data returned

---

### auth_login_invalid_password
**Purpose**: Validate error handling for incorrect password

**Endpoint**: `POST /api/v1/auth/login`

**SDK Method**: `PasswordLogin(email, password, tenantID)`

**Input**:
```json
{
  "email": "test@example.com",
  "password": "WrongPassword123!",
  "tenant_id": "tenant-1"
}
```

**Expected Response**:
- Status: 401
- Fields: error message

**Assertions**:
- Returns 401 Unauthorized
- Error doesn't reveal account existence
- No authentication tokens returned

---

### auth_login_missing_tenant
**Purpose**: Validate error handling for missing tenant ID

**Endpoint**: `POST /api/v1/auth/login`

**SDK Method**: `PasswordLogin(email, password, tenantID)`

**Input**:
```json
{
  "email": "test@example.com",
  "password": "ValidPassword123!"
}
```

**Expected Response**:
- Status: 400
- Fields: error message

**Assertions**:
- Returns 400 Bad Request
- Error indicates missing tenant_id
- Request is rejected before authentication attempt

---

### auth_signup_new_user
**Purpose**: Validate successful new user registration

**Endpoint**: `POST /api/v1/auth/signup`

**SDK Method**: `PasswordSignup(email, password, firstName, lastName, tenantID)`

**Input**:
```json
{
  "email": "newuser@example.com",
  "password": "NewPassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "tenant_id": "tenant-1"
}
```

**Expected Response**:
- Status: 201
- Fields: user (with id, email, first_name, last_name)

**Assertions**:
- User ID is generated
- Email matches request
- Names are stored correctly
- User can immediately log in

---

### auth_signup_duplicate_email
**Purpose**: Validate error handling for duplicate email registration

**Endpoint**: `POST /api/v1/auth/signup`

**SDK Method**: `PasswordSignup(email, password, firstName, lastName, tenantID)`

**Input**:
```json
{
  "email": "test@example.com",
  "password": "Password123!",
  "first_name": "Jane",
  "last_name": "Doe",
  "tenant_id": "tenant-1"
}
```

**Expected Response**:
- Status: 409
- Fields: error message

**Assertions**:
- Returns 409 Conflict
- Error indicates email already exists
- No duplicate account created

---

### auth_signup_weak_password
**Purpose**: Validate password strength requirements

**Endpoint**: `POST /api/v1/auth/signup`

**SDK Method**: `PasswordSignup(email, password, firstName, lastName, tenantID)`

**Input**:
```json
{
  "email": "weakpass@example.com",
  "password": "weak",
  "first_name": "Bob",
  "last_name": "Smith",
  "tenant_id": "tenant-1"
}
```

**Expected Response**:
- Status: 400
- Fields: error message with password requirements

**Assertions**:
- Returns 400 Bad Request
- Error message describes password requirements
- No account created
- User can retry with stronger password

---

### auth_signup_invalid_email
**Purpose**: Validate email format validation

**Endpoint**: `POST /api/v1/auth/signup`

**SDK Method**: `PasswordSignup(email, password, firstName, lastName, tenantID)`

**Input**:
```json
{
  "email": "not-an-email",
  "password": "ValidPassword123!",
  "first_name": "Alice",
  "last_name": "Johnson",
  "tenant_id": "tenant-1"
}
```

**Expected Response**:
- Status: 400
- Fields: error message

**Assertions**:
- Returns 400 Bad Request
- Error indicates invalid email format
- No account created

---

## RBAC Scenarios

### rbac_list_roles
**Purpose**: Retrieve all roles for a tenant

**Endpoint**: `GET /api/v1/auth/admin/rbac/roles?tenant_id=tenant-1`

**SDK Method**: `ListRoles(tenantID)`

**Headers**:
```
Authorization: Bearer {access_token}
```

**Expected Response**:
- Status: 200
- Fields: roles array with id, name, description

**Assertions**:
- Returns array of role objects
- Each role has required fields
- System roles are included

---

### rbac_create_role
**Purpose**: Create a new custom role

**Endpoint**: `POST /api/v1/auth/admin/rbac/roles`

**SDK Method**: `CreateRole(tenantID, name, description)`

**Input**:
```json
{
  "tenant_id": "tenant-1",
  "name": "Editor",
  "description": "Can edit content and manage permissions"
}
```

**Expected Response**:
- Status: 201
- Fields: id, name, description, created_at

**Assertions**:
- Role ID is generated
- Role appears in ListRoles
- Role can be assigned to users

---

### rbac_create_duplicate_role
**Purpose**: Validate duplicate role prevention

**Endpoint**: `POST /api/v1/auth/admin/rbac/roles`

**SDK Method**: `CreateRole(tenantID, name, description)`

**Input**:
```json
{
  "tenant_id": "tenant-1",
  "name": "Admin",
  "description": "Another admin role"
}
```

**Expected Response**:
- Status: 409
- Fields: error message

**Assertions**:
- Returns 409 Conflict
- Error indicates role exists
- No duplicate role created

---

### rbac_update_role
**Purpose**: Update role name and description

**Endpoint**: `PATCH /api/v1/auth/admin/rbac/roles/{role_id}`

**SDK Method**: `UpdateRole(roleID, name, description)`

**Input**:
```json
{
  "name": "Senior Editor",
  "description": "Can edit and approve content"
}
```

**Expected Response**:
- Status: 200
- Fields: id, name, description, updated_at

**Assertions**:
- Fields are updated
- Timestamp is current
- Changes appear in ListRoles

---

### rbac_delete_role
**Purpose**: Delete a custom role

**Endpoint**: `DELETE /api/v1/auth/admin/rbac/roles/{role_id}`

**SDK Method**: `DeleteRole(roleID)`

**Expected Response**:
- Status: 204 No Content

**Assertions**:
- Role is removed
- Role no longer appears in ListRoles
- Users assigned to role are updated

---

### rbac_delete_system_role
**Purpose**: Validate system role deletion prevention

**Endpoint**: `DELETE /api/v1/auth/admin/rbac/roles/{system_role_id}`

**SDK Method**: `DeleteRole(roleID)`

**Expected Response**:
- Status: 400
- Fields: error message

**Assertions**:
- Returns 400 Bad Request
- Error indicates system role protection
- System role remains in system

---

## Tenant Scenarios

### tenant_create
**Purpose**: Create a new tenant

**Endpoint**: `POST /api/v1/tenants`

**SDK Method**: `CreateTenant(name, slug)`

**Input**:
```json
{
  "name": "Test Organization",
  "slug": "test-org"
}
```

**Expected Response**:
- Status: 201
- Fields: id, name, slug, created_at

**Assertions**:
- Tenant ID is generated
- Slug is unique identifier
- Tenant can immediately use services

---

### tenant_create_duplicate_slug
**Purpose**: Validate slug uniqueness

**Endpoint**: `POST /api/v1/tenants`

**SDK Method**: `CreateTenant(name, slug)`

**Input**:
```json
{
  "name": "Another Org",
  "slug": "test-org"
}
```

**Expected Response**:
- Status: 409
- Fields: error message

**Assertions**:
- Returns 409 Conflict
- Error indicates slug exists
- No duplicate tenant created

---

### tenant_get
**Purpose**: Retrieve tenant details by ID

**Endpoint**: `GET /api/v1/tenants/{tenant_id}`

**SDK Method**: `GetTenant(tenantID)`

**Expected Response**:
- Status: 200
- Fields: id, name, slug, created_at

**Assertions**:
- Returns correct tenant
- All fields populated
- Data matches creation input

---

### tenant_get_not_found
**Purpose**: Validate error for non-existent tenant

**Endpoint**: `GET /api/v1/tenants/non-existent-id`

**SDK Method**: `GetTenant(tenantID)`

**Expected Response**:
- Status: 404
- Fields: error message

**Assertions**:
- Returns 404 Not Found
- Error is user-friendly
- No partial data returned

---

### tenant_list
**Purpose**: Retrieve list of accessible tenants

**Endpoint**: `GET /api/v1/tenants`

**SDK Method**: `ListTenants()`

**Expected Response**:
- Status: 200
- Fields: tenants array

**Assertions**:
- Returns array of tenant objects
- Each tenant has required fields
- Only accessible tenants included

---

### tenant_update
**Purpose**: Update tenant details

**Endpoint**: `PATCH /api/v1/tenants/{tenant_id}`

**SDK Method**: `UpdateTenant(tenantID, name)`

**Input**:
```json
{
  "name": "Updated Organization Name"
}
```

**Expected Response**:
- Status: 200
- Fields: id, name, updated_at

**Assertions**:
- Name is updated
- Timestamp is current
- Changes appear in GetTenant

---

### tenant_deactivate
**Purpose**: Deactivate a tenant

**Endpoint**: `DELETE /api/v1/tenants/{tenant_id}`

**SDK Method**: `DeactivateTenant(tenantID)`

**Expected Response**:
- Status: 204 No Content

**Assertions**:
- Tenant is deactivated
- Users cannot log in
- Data is preserved
- Tenant can be reactivated if needed

---

## MFA Scenarios

### mfa_totp_start
**Purpose**: Initiate TOTP enrollment

**Endpoint**: `POST /api/v1/auth/mfa/totp/start`

**SDK Method**: `MFATOTPStart()`

**Headers**:
```
Authorization: Bearer {access_token}
```

**Expected Response**:
- Status: 200
- Fields: secret, qr_code_url

**Assertions**:
- Secret is base32 encoded
- QR code URL is valid
- Enrollment is pending activation

---

### mfa_totp_activate
**Purpose**: Activate TOTP with valid code

**Endpoint**: `POST /api/v1/auth/mfa/totp/activate`

**SDK Method**: `MFATOTPActivate(code)`

**Input**:
```json
{
  "code": "123456"
}
```

**Expected Response**:
- Status: 200
- Fields: backup_codes array

**Assertions**:
- TOTP is activated
- Backup codes are provided
- User can log in with TOTP codes

---

### mfa_totp_activate_invalid_code
**Purpose**: Validate TOTP code verification

**Endpoint**: `POST /api/v1/auth/mfa/totp/activate`

**SDK Method**: `MFATOTPActivate(code)`

**Input**:
```json
{
  "code": "000000"
}
```

**Expected Response**:
- Status: 400
- Fields: error message

**Assertions**:
- Returns 400 Bad Request
- Error indicates invalid code
- Enrollment remains pending

---

### mfa_totp_disable
**Purpose**: Disable TOTP for user

**Endpoint**: `POST /api/v1/auth/mfa/totp/disable`

**SDK Method**: `MFATOTPDisable()`

**Headers**:
```
Authorization: Bearer {access_token}
```

**Expected Response**:
- Status: 200

**Assertions**:
- TOTP is disabled
- User can log in without TOTP
- Backup codes are invalidated

---

### mfa_totp_disable_not_enabled
**Purpose**: Validate error when disabling inactive TOTP

**Endpoint**: `POST /api/v1/auth/mfa/totp/disable`

**SDK Method**: `MFATOTPDisable()`

**Headers**:
```
Authorization: Bearer {access_token}
```

**Expected Response**:
- Status: 400
- Fields: error message

**Assertions**:
- Returns 400 Bad Request
- Error indicates TOTP not enabled
- No state changes

---

## Test Execution

### Running Individual Scenarios
```bash
# Go
go test -v -run TestConformanceAuth

# TypeScript
npm test -- conformance.test.ts -t "Login"
```

### Running All Scenarios
```bash
# Go
go test -v ./conformance_test.go

# TypeScript
npm test -- conformance.test.ts
```

## Validation Checklist

- [ ] All scenario IDs are unique
- [ ] All SDK method names match actual SDK methods
- [ ] All endpoints are documented in OpenAPI spec
- [ ] All expected response fields are correct
- [ ] Error scenarios test proper error handling
- [ ] Scenarios cover happy path and error cases
- [ ] Tests pass on both Go and TypeScript SDKs
- [ ] All required fields are marked as required
- [ ] Status codes match HTTP standards
- [ ] Documentation is accurate and complete
