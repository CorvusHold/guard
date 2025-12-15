# Tenant Onboarding Guide - Corvus Guard

## Overview

This guide provides comprehensive instructions for onboarding new tenants in the Corvus Guard Central Authentication Service. Corvus Guard uses a multi-tenant architecture where each tenant represents an organization with isolated users, settings, and configurations.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Step-by-Step Onboarding](#step-by-step-onboarding)
- [API Reference](#api-reference)
- [Configuration Options](#configuration-options)
- [User Management](#user-management)
- [SSO Configuration](#sso-configuration)
- [Security Settings](#security-settings)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Prerequisites

Before onboarding a new tenant, ensure you have:

1. **Running Corvus Guard Instance**
   ```bash
   # Start the services
   make compose-up
   
   # Run migrations
   make migrate-up
   
   # Start the API
   make dev
   ```

2. **API Access**
   - Base URL: `http://localhost:8080` (development)
   - Admin credentials or API access
   - HTTP client (curl, Postman, etc.)

3. **Database Access** (optional)
   - PostgreSQL connection for direct verification
   - Connection: `postgres://guard:guard@localhost:5433/guard`

## Quick Start

### Option 1: Using the Seed Command (Recommended)

The fastest way to create a complete tenant setup:

```bash
# Create tenant with admin user
go run ./cmd/seed default \
  --tenant-name "acme-corp" \
  --email "admin@acme-corp.com" \
  --password "SecurePassword123!" \
  --enable-mfa

# Output will include:
# TENANT_ID=550e8400-e29b-41d4-a716-446655440000
# EMAIL=admin@acme-corp.com
# PASSWORD=SecurePassword123!
# USER_ID=660f9500-f39c-52e5-b827-556766550111
# TOTP_SECRET=JBSWY3DPEHPK3PXP
# BACKUP_CODES=abc123,def456,ghi789
```

### Option 2: Using API Calls

```bash
# 1. Create tenant
TENANT_RESPONSE=$(curl -X POST http://localhost:8080/tenants \
  -H "Content-Type: application/json" \
  -d '{"name": "acme-corp"}')

TENANT_ID=$(echo $TENANT_RESPONSE | jq -r '.id')

# 2. Create admin user
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"email\": \"admin@acme-corp.com\",
    \"password\": \"SecurePassword123!\",
    \"first_name\": \"Admin\",
    \"last_name\": \"User\"
  }"
```

## Step-by-Step Onboarding

### Step 1: Create the Tenant

**Using API:**
```bash
curl -X POST http://localhost:8080/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "name": "acme-corp"
  }'
```

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "acme-corp",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

**Using Seed Command:**
```bash
go run ./cmd/seed tenant --name "acme-corp"
```

### Step 2: Create Initial Admin User

```bash
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@acme-corp.com",
    "password": "SecurePassword123!",
    "first_name": "Admin",
    "last_name": "User"
  }'
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_abc123..."
}
```

### Step 3: Grant Admin Role

```bash
# Login to get admin token
ADMIN_TOKEN=$(curl -X POST http://localhost:8080/api/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@acme-corp.com",
    "password": "SecurePassword123!"
  }' | jq -r '.access_token')

# Get user ID from introspection
USER_ID=$(curl -X POST http://localhost:8080/api/v1/auth/introspect \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"token": "'$ADMIN_TOKEN'"}' | jq -r '.user_id')

# Grant admin role
curl -X POST http://localhost:8080/api/v1/auth/admin/rbac/users/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "'$USER_ID'",
    "role_name": "admin"
  }'
```

### Step 4: Configure Tenant Settings

#### Basic Configuration
```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "https://app.acme-corp.com,https://staging.acme-corp.com",
    "auth_access_token_ttl": "15m",
    "auth_refresh_token_ttl": "720h"
  }'
```

#### Email Configuration
```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email_provider": "smtp",
    "email_smtp_host": "smtp.acme-corp.com",
    "email_smtp_port": "587",
    "email_smtp_username": "noreply@acme-corp.com",
    "email_smtp_password": "smtp_password_here",
    "email_smtp_from": "Acme Corp <noreply@acme-corp.com>"
  }'
```

### Step 5: Set Up SSO (Optional)

#### WorkOS SSO Configuration
```bash
# Configure WorkOS SSO
go run ./cmd/seed sso-workos \
  --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
  --client-id "client_01234567890" \
  --client-secret "wk_live_abc123..." \
  --state-ttl "10m" \
  --redirect-allowlist "https://app.acme-corp.com/callback"
```

#### Dev SSO Configuration
```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sso_provider": "dev",
    "sso_redirect_allowlist": "https://app.acme-corp.com/callback,http://localhost:3000/callback"
  }'
```

## Seeding Utilities Reference

Corvus Guard provides powerful seeding utilities for development, testing, and initial setup. All commands are available via `go run ./cmd/seed <command>`.

### Available Commands

#### 1. `default` - Complete Tenant Setup

Creates or reuses a tenant and ensures an admin user exists with optional MFA.

```bash
go run ./cmd/seed default [options]
```

**Options:**
- `--tenant-name` - Tenant name (env: `TENANT_NAME`, default: `test`)
- `--email` - User email (env: `EMAIL`, default: `test@example.com`)
- `--password` - User password (env: `PASSWORD`, default: `Password123!`)
- `--first` - First name (env: `FIRST_NAME`, default: `Test`)
- `--last` - Last name (env: `LAST_NAME`, default: `User`)
- `--enable-mfa` - Enable TOTP MFA (env: `ENABLE_MFA`, default: `false`)

**Examples:**
```bash
# Basic setup
go run ./cmd/seed default --tenant-name "my-company" --email "admin@my-company.com"

# With MFA enabled
go run ./cmd/seed default \
  --tenant-name "secure-corp" \
  --email "admin@secure-corp.com" \
  --password "VerySecure123!" \
  --enable-mfa

# Using environment variables
export TENANT_NAME="env-corp"
export EMAIL="admin@env-corp.com"
export ENABLE_MFA="true"
go run ./cmd/seed default
```

**Output:**
```
TENANT_ID=550e8400-e29b-41d4-a716-446655440000
EMAIL=admin@my-company.com
PASSWORD=Password123!
USER_ID=660f9500-f39c-52e5-b827-556766550111
TOTP_SECRET=JBSWY3DPEHPK3PXP
BACKUP_CODES=abc123,def456,ghi789,jkl012,mno345
```

#### 2. `tenant` - Create Tenant Only

Creates a new tenant without users.

```bash
go run ./cmd/seed tenant [options]
```

**Options:**
- `--name` - Tenant name (env: `TENANT_NAME`, default: `test`)

**Examples:**
```bash
# Create tenant
go run ./cmd/seed tenant --name "new-tenant"

# Using environment variable
export TENANT_NAME="env-tenant"
go run ./cmd/seed tenant
```

**Output:**
```
TENANT_ID=770f9600-g49d-53f6-c938-667877661222
```

#### 3. `user` - Create User Only

Creates a user in an existing tenant with optional MFA and role assignment.

```bash
go run ./cmd/seed user [options]
```

**Options:**
- `--tenant-id` - Target tenant UUID (env: `TENANT_ID`, required)
- `--email` - User email (env: `EMAIL`, required)
- `--password` - User password (env: `PASSWORD`, required)
- `--first` - First name (env: `FIRST_NAME`, default: `Test`)
- `--last` - Last name (env: `LAST_NAME`, default: `User`)
- `--enable-mfa` - Enable TOTP MFA (env: `ENABLE_MFA`, default: `false`)
- `--roles` - Comma-separated role names (env: `ROLES`)

**Examples:**
```bash
# Basic user
go run ./cmd/seed user \
  --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
  --email "user@example.com" \
  --password "UserPass123!"

# User with MFA and roles
go run ./cmd/seed user \
  --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
  --email "admin@example.com" \
  --password "AdminPass123!" \
  --enable-mfa \
  --roles "admin,manager"

# Using environment variables
export TENANT_ID="550e8400-e29b-41d4-a716-446655440000"
export EMAIL="manager@example.com"
export PASSWORD="ManagerPass123!"
export ROLES="manager,editor"
go run ./cmd/seed user
```

**Output:**
```
TENANT_ID=550e8400-e29b-41d4-a716-446655440000
EMAIL=user@example.com
PASSWORD=UserPass123!
USER_ID=880g0700-h5ae-64g7-d049-778988772333
TOTP_SECRET=KBSWY3DPEHPK3PXQ
BACKUP_CODES=xyz789,uvw456,rst123,opq890,lmn567
ROLES_ASSIGNED=admin,manager
```

#### 4. `sso-workos` - Configure WorkOS SSO

Configures WorkOS SSO settings for a tenant.

```bash
go run ./cmd/seed sso-workos [options]
```

**Options:**
- `--tenant-id` - Target tenant UUID (env: `TENANT_ID`, required)
- `--client-id` - WorkOS client ID (env: `WORKOS_CLIENT_ID`, required)
- `--client-secret` - WorkOS client secret (env: `WORKOS_CLIENT_SECRET`, required)
- `--api-key` - WorkOS API key (env: `WORKOS_API_KEY`, optional)
- `--api-base-url` - WorkOS API base URL (env: `WORKOS_API_BASE_URL`, default: `https://api.workos.com`)
- `--state-ttl` - OAuth state TTL (env: `SSO_STATE_TTL`, default: `10m`)
- `--redirect-allowlist` - Allowed redirect URLs (env: `SSO_REDIRECT_ALLOWLIST`, required)
- `--default-connection-id` - Default WorkOS connection (env: `WORKOS_DEFAULT_CONNECTION_ID`)
- `--default-organization-id` - Default WorkOS organization (env: `WORKOS_DEFAULT_ORGANIZATION_ID`)

**Examples:**
```bash
# Basic WorkOS setup
go run ./cmd/seed sso-workos \
  --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
  --client-id "client_01234567890" \
  --client-secret "wk_live_abc123def456" \
  --redirect-allowlist "https://app.example.com/callback"

# Advanced WorkOS setup
go run ./cmd/seed sso-workos \
  --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
  --client-id "client_01234567890" \
  --client-secret "wk_live_abc123def456" \
  --api-key "sk_live_xyz789uvw012" \
  --state-ttl "15m" \
  --redirect-allowlist "https://app.example.com/callback,https://staging.example.com/callback" \
  --default-connection-id "conn_01234567890"

# Using environment variables
export TENANT_ID="550e8400-e29b-41d4-a716-446655440000"
export WORKOS_CLIENT_ID="client_01234567890"
export WORKOS_CLIENT_SECRET="wk_live_abc123def456"
export SSO_REDIRECT_ALLOWLIST="https://app.example.com/callback"
go run ./cmd/seed sso-workos
```

**Output:**
```
TENANT_ID=550e8400-e29b-41d4-a716-446655440000
WORKOS_CLIENT_ID=client_01234567890
WORKOS_CLIENT_SECRET=wk_live_abc123def456
WORKOS_API_KEY=sk_live_xyz789uvw012
WORKOS_CLIENT_ID_SET=true
SSO_PROVIDER=workos
SSO_STATE_TTL=15m
SSO_REDIRECT_ALLOWLIST=https://app.example.com/callback,https://staging.example.com/callback
```

### Batch Operations

#### Create Multiple Tenants
```bash
#!/bin/bash
# create-tenants.sh

TENANTS=("tenant-a" "tenant-b" "tenant-c")

for tenant in "${TENANTS[@]}"; do
  echo "Creating tenant: $tenant"
  go run ./cmd/seed tenant --name "$tenant"
done
```

#### Create Test Environment
```bash
#!/bin/bash
# setup-test-env.sh

# Create main tenant with admin
echo "Setting up main tenant..."
go run ./cmd/seed default \
  --tenant-name "test-main" \
  --email "admin@test-main.com" \
  --password "Admin123!" \
  --enable-mfa > main-tenant.env

source main-tenant.env

# Create additional users
echo "Creating additional users..."
go run ./cmd/seed user \
  --tenant-id "$TENANT_ID" \
  --email "manager@test-main.com" \
  --password "Manager123!" \
  --roles "manager"

go run ./cmd/seed user \
  --tenant-id "$TENANT_ID" \
  --email "user@test-main.com" \
  --password "User123!"

# Configure SSO
echo "Configuring SSO..."
go run ./cmd/seed sso-workos \
  --tenant-id "$TENANT_ID" \
  --client-id "client_test123" \
  --client-secret "wk_test_secret" \
  --redirect-allowlist "http://localhost:3000/callback"

echo "Test environment ready!"
echo "Admin: admin@test-main.com / Admin123!"
echo "Manager: manager@test-main.com / Manager123!"
echo "User: user@test-main.com / User123!"
```

## API Reference

### Tenant Management Endpoints

#### Create Tenant
```http
POST /tenants
Content-Type: application/json

{
  "name": "tenant-name"
}
```

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "tenant-name",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

**Error Responses:**
```json
// 400 Bad Request - Name already exists
{
  "error": "tenant name already exists",
  "code": "TENANT_NAME_EXISTS"
}

// 400 Bad Request - Invalid name
{
  "error": "tenant name is required",
  "code": "VALIDATION_ERROR"
}
```

#### Get Tenant by ID
```http
GET /tenants/{id}
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "tenant-name",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

**Error Response (404 Not Found):**
```json
{
  "error": "tenant not found",
  "code": "TENANT_NOT_FOUND"
}
```

#### Get Tenant by Name
```http
GET /tenants/by-name/{name}
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "tenant-name",
  "is_active": true,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

#### List Tenants
```http
GET /tenants?q=search&active=1&page=1&page_size=20
```

**Query Parameters:**
- `q` - Search query (matches tenant name)
- `active` - Filter by active status (1=active, 0=inactive)
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 20, max: 100)

**Response (200 OK):**
```json
{
  "tenants": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "tenant-a",
      "is_active": true,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    },
    {
      "id": "660f9500-f39c-52e5-b827-556766550111",
      "name": "tenant-b",
      "is_active": true,
      "created_at": "2024-01-15T11:00:00Z",
      "updated_at": "2024-01-15T11:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_count": 2,
    "total_pages": 1
  }
}
```

#### Deactivate Tenant
```http
PATCH /tenants/{id}/deactivate
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "tenant-name",
  "is_active": false,
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T12:00:00Z"
}
```

### Settings Management Endpoints

#### Get Tenant Settings
```http
GET /api/v1/tenants/{id}/settings
Authorization: Bearer {admin_token}
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "settings": {
    "app_cors_allowed_origins": "https://app.example.com,https://admin.example.com",
    "auth_access_token_ttl": "15m",
    "auth_refresh_token_ttl": "720h",
    "sso_provider": "workos",
    "sso_state_ttl": "10m",
    "sso_redirect_allowlist": "https://app.example.com/callback",
    "auth_ratelimit_login_limit": "10",
    "auth_ratelimit_login_window": "1m"
  }
}
```

#### Update Tenant Settings
```http
PUT /api/v1/tenants/{id}/settings
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "app_cors_allowed_origins": "https://app.example.com,https://staging.example.com",
  "auth_access_token_ttl": "30m",
  "sso_provider": "workos",
  "sso_workos_client_id": "client_01234567890",
  "sso_workos_client_secret": "wk_live_secret123"
}
```

**Response (200 OK):**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "updated_settings": [
    "app_cors_allowed_origins",
    "auth_access_token_ttl",
    "sso_provider",
    "sso_workos_client_id",
    "sso_workos_client_secret"
  ]
}
```

**Error Responses:**
```json
// 400 Bad Request - Invalid setting value
{
  "error": "invalid duration format for auth_access_token_ttl",
  "code": "VALIDATION_ERROR",
  "field": "auth_access_token_ttl"
}

// 403 Forbidden - Insufficient permissions
{
  "error": "admin role required",
  "code": "INSUFFICIENT_PERMISSIONS"
}

// 429 Too Many Requests - Rate limited
{
  "error": "rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "retry_after": 60
}
```

### Authentication Endpoints

#### User Signup
```http
POST /api/v1/auth/signup
Content-Type: application/json

{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_abc123def456...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "660f9500-f39c-52e5-b827-556766550111",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "email_verified": false,
    "mfa_enabled": false
  }
}
```

**Error Responses:**
```json
// 400 Bad Request - Email already exists
{
  "error": "email already exists",
  "code": "EMAIL_EXISTS"
}

// 400 Bad Request - Weak password
{
  "error": "password does not meet requirements",
  "code": "WEAK_PASSWORD",
  "requirements": [
    "minimum 8 characters",
    "at least one uppercase letter",
    "at least one number",
    "at least one special character"
  ]
}
```

#### Password Login
```http
POST /api/v1/auth/password/login
Content-Type: application/json

{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200 OK - No MFA):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_abc123def456...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Response (202 Accepted - MFA Required):**
```json
{
  "mfa_token": "mfa_temp_token_abc123",
  "mfa_required": true,
  "available_methods": ["totp"]
}
```

#### MFA Verification
```http
POST /api/v1/auth/mfa/verify
Content-Type: application/json

{
  "mfa_token": "mfa_temp_token_abc123",
  "code": "123456",
  "method": "totp"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "rt_abc123def456...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Admin Endpoints

#### List Users (Admin)
```http
GET /api/v1/auth/admin/users?tenant_id={uuid}&page=1&page_size=20
Authorization: Bearer {admin_token}
```

**Response (200 OK):**
```json
{
  "users": [
    {
      "id": "660f9500-f39c-52e5-b827-556766550111",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "email_verified": true,
      "mfa_enabled": false,
      "is_active": true,
      "created_at": "2024-01-15T10:30:00Z",
      "last_login_at": "2024-01-15T14:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total_count": 1,
    "total_pages": 1
  }
}
```

#### Assign User Role
```http
POST /api/v1/auth/admin/rbac/users/roles
Authorization: Bearer {admin_token}
Content-Type: application/json

{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "660f9500-f39c-52e5-b827-556766550111",
  "role_name": "admin"
}
```

**Response (200 OK):**
```json
{
  "user_id": "660f9500-f39c-52e5-b827-556766550111",
  "role_name": "admin",
  "assigned_at": "2024-01-15T15:00:00Z"
}
```

## Configuration Options

### Authentication Settings

| Setting Key | Description | Default | Example |
|-------------|-------------|---------|---------|
| `auth.access_token_ttl` | Access token lifetime | `15m` | `30m`, `1h` |
| `auth.refresh_token_ttl` | Refresh token lifetime | `720h` | `168h`, `2160h` |
| `auth.magic_link_ttl` | Magic link lifetime | `15m` | `10m`, `30m` |
| `auth.jwt_issuer` | JWT issuer claim | `guard` | `acme-corp` |
| `auth.jwt_audience` | JWT audience claim | `guard` | `acme-app` |

### Rate Limiting Settings

| Setting Key | Description | Default | Example |
|-------------|-------------|---------|---------|
| `auth.ratelimit.login.limit` | Login attempts per window | `10` | `5`, `20` |
| `auth.ratelimit.login.window` | Login rate limit window | `1m` | `30s`, `5m` |
| `auth.ratelimit.signup.limit` | Signup attempts per window | `5` | `3`, `10` |
| `auth.ratelimit.mfa.limit` | MFA attempts per window | `10` | `5`, `15` |

### SSO Settings

| Setting Key | Description | Required | Example |
|-------------|-------------|----------|---------|
| `sso.provider` | SSO provider type | Yes | `dev`, `workos` |
| `sso.state_ttl` | OAuth state TTL | No | `10m`, `5m` |
| `sso.redirect_allowlist` | Allowed redirect URLs | Yes | `https://app.com/callback` |
| `sso.workos.client_id` | WorkOS client ID | WorkOS only | `client_123` |
| `sso.workos.client_secret` | WorkOS client secret | WorkOS only | `wk_live_abc` |
| `sso.workos.api_key` | WorkOS API key | Alternative | `sk_live_xyz` |

### Email Settings

| Setting Key | Description | Example |
|-------------|-------------|---------|
| `email.provider` | Email provider | `smtp`, `brevo` |
| `email.smtp.host` | SMTP server host | `smtp.gmail.com` |
| `email.smtp.port` | SMTP server port | `587`, `465` |
| `email.smtp.username` | SMTP username | `user@gmail.com` |
| `email.smtp.password` | SMTP password | `app_password` |
| `email.smtp.from` | From address | `App <noreply@app.com>` |

### Application Settings

| Setting Key | Description | Example |
|-------------|-------------|---------|
| `app.public_base_url` | Public API base URL | `https://api.acme.com` |
| `app.cors_allowed_origins` | CORS allowed origins | `https://app.com,https://admin.com` |

## User Management

### Creating Users

#### Method 1: Self-Registration (Signup)
```bash
curl -X POST http://localhost:8080/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@acme-corp.com",
    "password": "UserPassword123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

#### Method 2: Admin Creation
```bash
# Use the seed command for admin creation
go run ./cmd/seed user \
  --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
  --email "manager@acme-corp.com" \
  --password "ManagerPassword123!" \
  --first "Jane" \
  --last "Smith" \
  --roles "admin,manager"
```

### Assigning Roles

#### Built-in Roles
- `admin` - Full administrative access
- `member` - Basic user access
- `owner` - Tenant owner (highest privileges)

#### Custom Roles
```bash
# Create custom role
curl -X POST http://localhost:8080/api/v1/auth/admin/rbac/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "editor",
    "description": "Content editor role"
  }'

# Assign role to user
curl -X POST http://localhost:8080/api/v1/auth/admin/rbac/users/roles \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "660f9500-f39c-52e5-b827-556766550111",
    "role_name": "editor"
  }'
```

### Enabling MFA

```bash
# Enable MFA for user during creation
go run ./cmd/seed user \
  --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
  --email "secure-user@acme-corp.com" \
  --password "SecurePassword123!" \
  --enable-mfa

# Output includes TOTP secret for authenticator app setup
# TOTP_SECRET=JBSWY3DPEHPK3PXP
```

## SSO Configuration

### WorkOS Integration

1. **Set up WorkOS Account**
   - Create account at [WorkOS Dashboard](https://dashboard.workos.com)
   - Create a new application
   - Note the Client ID and Client Secret

2. **Configure in Corvus Guard**
   ```bash
   go run ./cmd/seed sso-workos \
     --tenant-id "550e8400-e29b-41d4-a716-446655440000" \
     --client-id "client_01234567890" \
     --client-secret "wk_live_abc123..." \
     --state-ttl "10m" \
     --redirect-allowlist "https://app.acme-corp.com/callback" \
     --default-connection-id "conn_01234567890"
   ```

3. **Test SSO Flow**
   ```bash
   # Start SSO flow
   curl -i "http://localhost:8080/api/v1/auth/sso/google/start?tenant_id=550e8400-e29b-41d4-a716-446655440000"
   
   # Follow redirect to WorkOS, complete authentication
   # User will be redirected back to callback URL with tokens
   ```

### Development SSO

For development and testing:

```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sso_provider": "dev",
    "sso_redirect_allowlist": "http://localhost:3000/callback,http://localhost:5173/callback"
  }'
```

## Security Settings

### Password Policy

Corvus Guard enforces strong password requirements by default:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one number
- At least one special character

### Rate Limiting

Configure rate limits per tenant:

```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_ratelimit_login_limit": "5",
    "auth_ratelimit_login_window": "5m",
    "auth_ratelimit_signup_limit": "3",
    "auth_ratelimit_signup_window": "1h"
  }'
```

### CORS Configuration

```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "https://app.acme-corp.com,https://admin.acme-corp.com"
  }'
```

## Troubleshooting

### Common Issues

#### 1. Tenant Creation Fails
**Error:** `tenant name already exists`
**Solution:** Choose a unique tenant name or check existing tenants:
```bash
curl http://localhost:8080/tenants/by-name/acme-corp
```

#### 2. User Signup Fails
**Error:** `email already exists`
**Solution:** Email addresses must be unique within a tenant. Use a different email or check existing users:
```bash
curl http://localhost:8080/api/v1/auth/admin/users?tenant_id=550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### 3. SSO Configuration Issues
**Error:** `redirect URL not allowed`
**Solution:** Ensure the redirect URL is in the allowlist:
```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sso_redirect_allowlist": "https://your-app.com/callback"
  }'
```

#### 4. Rate Limiting Issues
**Error:** `429 Too Many Requests`
**Solution:** Wait for the rate limit window to reset or adjust limits:
```bash
curl -X PUT http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_ratelimit_login_limit": "20",
    "auth_ratelimit_login_window": "1m"
  }'
```

### Debugging Tools

#### Check Tenant Status
```bash
curl http://localhost:8080/tenants/550e8400-e29b-41d4-a716-446655440000
```

#### Verify Settings
```bash
curl http://localhost:8080/api/v1/tenants/550e8400-e29b-41d4-a716-446655440000/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### Test Authentication
```bash
curl -X POST http://localhost:8080/api/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@acme-corp.com",
    "password": "SecurePassword123!"
  }'
```

#### Check API Health
```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

## Best Practices

### Security Best Practices

1. **Use Strong Passwords**
   - Enforce password complexity requirements
   - Consider implementing password rotation policies
   - Enable MFA for admin users

2. **Configure Rate Limiting**
   - Set appropriate rate limits for your use case
   - Monitor for abuse patterns
   - Use tenant-specific overrides when needed

3. **Secure SSO Configuration**
   - Use HTTPS for all redirect URLs
   - Implement proper state validation
   - Regularly rotate SSO credentials

4. **Network Security**
   - Configure CORS properly for your domains
   - Use HTTPS in production
   - Implement IP allowlisting for admin operations

### Operational Best Practices

1. **Monitoring and Logging**
   - Monitor authentication metrics
   - Set up alerts for failed login attempts
   - Review audit logs regularly

2. **Backup and Recovery**
   - Implement regular database backups
   - Test recovery procedures
   - Document disaster recovery plans

3. **Performance Optimization**
   - Monitor database performance
   - Implement connection pooling
   - Use Redis for session caching

4. **Tenant Management**
   - Use descriptive tenant names
   - Implement tenant lifecycle management
   - Plan for tenant data isolation

### Development Best Practices

1. **Environment Separation**
   - Use separate tenants for development/staging/production
   - Implement proper configuration management
   - Use environment-specific settings

2. **Testing**
   - Test authentication flows thoroughly
   - Validate SSO integrations
   - Implement automated testing for critical paths

3. **Documentation**
   - Document tenant-specific configurations
   - Maintain API integration guides
   - Keep security procedures updated

## Next Steps

After completing tenant onboarding:

1. **Integrate with Your Application**
   - Use the provided SDKs (TypeScript, Go, Rust)
   - Implement authentication flows
   - Set up session management

2. **Configure Monitoring**
   - Set up Prometheus metrics collection
   - Configure Grafana dashboards
   - Implement alerting rules

3. **Production Readiness**
   - Review security configurations
   - Implement backup procedures
   - Set up monitoring and alerting

4. **User Training**
   - Train administrators on user management
   - Document SSO setup for end users
   - Provide troubleshooting guides

For additional support, refer to:
- [API Documentation](http://localhost:8080/swagger/index.html)
- [Rate Limiting Guide](docs/rate-limiting.md)
- [Backend Architecture Review](BACKEND_REVIEW.md)
