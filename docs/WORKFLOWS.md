# Tenant Onboarding Workflows

This document provides detailed step-by-step workflows for common tenant onboarding scenarios.

## Workflow 1: Enterprise Customer Onboarding

### Scenario
Large enterprise customer with:
- Custom domain requirements
- WorkOS SSO integration
- Multiple user roles
- Strict security requirements

### Steps

#### Phase 1: Initial Setup
```bash
# 1. Create tenant
go run ./cmd/seed tenant --name "enterprise-corp"

# Capture tenant ID
export TENANT_ID="<output-tenant-id>"

# 2. Create admin user with MFA
go run ./cmd/seed user \
  --tenant-id "$TENANT_ID" \
  --email "admin@enterprise-corp.com" \
  --password "EnterpriseAdmin123!" \
  --first "Enterprise" \
  --last "Admin" \
  --enable-mfa \
  --roles "admin,owner"

# 3. Login and get admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"email\": \"admin@enterprise-corp.com\",
    \"password\": \"EnterpriseAdmin123!\"
  }" | jq -r '.access_token')
```

#### Phase 2: Security Configuration
```bash
# 4. Configure strict rate limits
curl -X PUT http://localhost:8080/v1/tenants/$TENANT_ID/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_ratelimit_login_limit": "3",
    "auth_ratelimit_login_window": "5m",
    "auth_ratelimit_signup_limit": "1",
    "auth_ratelimit_signup_window": "1h",
    "auth_access_token_ttl": "10m",
    "auth_refresh_token_ttl": "24h"
  }'

# 5. Configure CORS for enterprise domains
curl -X PUT http://localhost:8080/v1/tenants/$TENANT_ID/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "https://app.enterprise-corp.com,https://admin.enterprise-corp.com"
  }'
```

#### Phase 3: WorkOS SSO Setup
```bash
# 6. Configure WorkOS SSO (requires WorkOS credentials)
go run ./cmd/seed sso-workos \
  --tenant-id "$TENANT_ID" \
  --client-id "$WORKOS_CLIENT_ID" \
  --client-secret "$WORKOS_CLIENT_SECRET" \
  --api-key "$WORKOS_API_KEY" \
  --state-ttl "5m" \
  --redirect-allowlist "https://app.enterprise-corp.com/auth/callback" \
  --default-connection-id "$WORKOS_CONNECTION_ID"

# 7. Test SSO flow
curl -i "http://localhost:8080/v1/auth/sso/google/start?tenant_id=$TENANT_ID&redirect_uri=https://app.enterprise-corp.com/auth/callback"
```

#### Phase 4: User Management Setup
```bash
# 8. Create department managers
go run ./cmd/seed user \
  --tenant-id "$TENANT_ID" \
  --email "hr-manager@enterprise-corp.com" \
  --password "HRManager123!" \
  --roles "manager"

go run ./cmd/seed user \
  --tenant-id "$TENANT_ID" \
  --email "it-manager@enterprise-corp.com" \
  --password "ITManager123!" \
  --roles "manager,admin"

# 9. Create regular users
go run ./cmd/seed user \
  --tenant-id "$TENANT_ID" \
  --email "employee1@enterprise-corp.com" \
  --password "Employee123!"

go run ./cmd/seed user \
  --tenant-id "$TENANT_ID" \
  --email "employee2@enterprise-corp.com" \
  --password "Employee123!"
```

## Workflow 2: SaaS Startup Onboarding

### Scenario
Fast-growing SaaS startup with:
- Development/staging/production environments
- Simple email/password auth initially
- Plans to add SSO later

### Steps

#### Development Environment
```bash
# 1. Create dev tenant with relaxed settings
go run ./cmd/seed default \
  --tenant-name "startup-dev" \
  --email "dev@startup.com" \
  --password "DevPassword123!"

export DEV_TENANT_ID="<output-tenant-id>"

# 2. Configure dev-friendly settings
DEV_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$DEV_TENANT_ID\",
    \"email\": \"dev@startup.com\",
    \"password\": \"DevPassword123!\"
  }" | jq -r '.access_token')

curl -X PUT http://localhost:8080/v1/tenants/$DEV_TENANT_ID/settings \
  -H "Authorization: Bearer $DEV_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "http://localhost:3000,http://localhost:5173",
    "auth_access_token_ttl": "1h",
    "auth_ratelimit_login_limit": "50",
    "sso_provider": "dev",
    "sso_redirect_allowlist": "http://localhost:3000/callback"
  }'
```

#### Staging Environment
```bash
# 3. Create staging tenant
go run ./cmd/seed default \
  --tenant-name "startup-staging" \
  --email "staging@startup.com" \
  --password "StagingPassword123!"

export STAGING_TENANT_ID="<output-tenant-id>"

# 4. Configure staging settings
STAGING_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$STAGING_TENANT_ID\",
    \"email\": \"staging@startup.com\",
    \"password\": \"StagingPassword123!\"
  }" | jq -r '.access_token')

curl -X PUT http://localhost:8080/v1/tenants/$STAGING_TENANT_ID/settings \
  -H "Authorization: Bearer $STAGING_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "https://staging.startup.com",
    "auth_access_token_ttl": "30m"
  }'
```

#### Production Environment
```bash
# 5. Create production tenant with security
go run ./cmd/seed default \
  --tenant-name "startup-prod" \
  --email "admin@startup.com" \
  --password "ProductionAdmin123!" \
  --enable-mfa

export PROD_TENANT_ID="<output-tenant-id>"

# 6. Configure production security
PROD_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$PROD_TENANT_ID\",
    \"email\": \"admin@startup.com\",
    \"password\": \"ProductionAdmin123!\"
  }" | jq -r '.access_token')

curl -X PUT http://localhost:8080/v1/tenants/$PROD_TENANT_ID/settings \
  -H "Authorization: Bearer $PROD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "https://app.startup.com",
    "auth_access_token_ttl": "15m",
    "auth_refresh_token_ttl": "168h",
    "auth_ratelimit_login_limit": "5",
    "auth_ratelimit_login_window": "5m"
  }'
```

## Workflow 3: Multi-Tenant SaaS Platform

### Scenario
Platform serving multiple customers, each needing isolated tenants with custom branding and settings.

### Automation Script
```bash
#!/bin/bash
# multi-tenant-setup.sh

CUSTOMERS=("customer-a" "customer-b" "customer-c")
BASE_DOMAIN="platform.com"

for customer in "${CUSTOMERS[@]}"; do
  echo "Setting up tenant for $customer..."
  
  # 1. Create tenant
  TENANT_OUTPUT=$(go run ./cmd/seed default \
    --tenant-name "$customer" \
    --email "admin@$customer.com" \
    --password "Admin123!" \
    --enable-mfa)
  
  TENANT_ID=$(echo "$TENANT_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)
  
  # 2. Get admin token
  ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
    -H "Content-Type: application/json" \
    -d "{
      \"tenant_id\": \"$TENANT_ID\",
      \"email\": \"admin@$customer.com\",
      \"password\": \"Admin123!\"
    }" | jq -r '.access_token')
  
  # 3. Configure customer-specific settings
  curl -X PUT http://localhost:8080/v1/tenants/$TENANT_ID/settings \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"app_cors_allowed_origins\": \"https://$customer.$BASE_DOMAIN\",
      \"app_public_base_url\": \"https://api.$BASE_DOMAIN\",
      \"auth_jwt_issuer\": \"$customer-platform\",
      \"auth_jwt_audience\": \"$customer-app\"
    }"
  
  # 4. Create sample users
  go run ./cmd/seed user \
    --tenant-id "$TENANT_ID" \
    --email "manager@$customer.com" \
    --password "Manager123!" \
    --roles "manager"
  
  go run ./cmd/seed user \
    --tenant-id "$TENANT_ID" \
    --email "user@$customer.com" \
    --password "User123!"
  
  echo "✓ Tenant $customer setup complete"
  echo "  Tenant ID: $TENANT_ID"
  echo "  Admin: admin@$customer.com / Admin123!"
  echo "  App URL: https://$customer.$BASE_DOMAIN"
  echo ""
done

echo "All tenants configured successfully!"
```

## Workflow 4: Testing Environment Setup

### Scenario
Comprehensive testing environment with multiple scenarios for QA and integration testing.

### Setup Script
```bash
#!/bin/bash
# testing-environment-setup.sh

echo "Setting up comprehensive testing environment..."

# 1. Main test tenant with all features
echo "Creating main test tenant..."
MAIN_OUTPUT=$(go run ./cmd/seed default \
  --tenant-name "test-main" \
  --email "admin@test.com" \
  --password "TestAdmin123!" \
  --enable-mfa)

MAIN_TENANT_ID=$(echo "$MAIN_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)
TOTP_SECRET=$(echo "$MAIN_OUTPUT" | grep TOTP_SECRET | cut -d'=' -f2)

# 2. Get admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$MAIN_TENANT_ID\",
    \"email\": \"admin@test.com\",
    \"password\": \"TestAdmin123!\"
  }" | jq -r '.access_token')

# 3. Configure for testing
curl -X PUT http://localhost:8080/v1/tenants/$MAIN_TENANT_ID/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "app_cors_allowed_origins": "http://localhost:3000,http://localhost:5173",
    "sso_provider": "dev",
    "sso_redirect_allowlist": "http://localhost:3000/callback,http://localhost:5173/callback",
    "auth_ratelimit_login_limit": "100",
    "auth_ratelimit_signup_limit": "50"
  }'

# 4. Create test users with different roles
echo "Creating test users..."

# Admin user (already created)
# Manager user
go run ./cmd/seed user \
  --tenant-id "$MAIN_TENANT_ID" \
  --email "manager@test.com" \
  --password "TestManager123!" \
  --roles "manager"

# Regular user
go run ./cmd/seed user \
  --tenant-id "$MAIN_TENANT_ID" \
  --email "user@test.com" \
  --password "TestUser123!"

# MFA user
go run ./cmd/seed user \
  --tenant-id "$MAIN_TENANT_ID" \
  --email "mfa-user@test.com" \
  --password "TestMFA123!" \
  --enable-mfa

# 5. Create rate-limiting test tenant
echo "Creating rate-limiting test tenant..."
RATE_OUTPUT=$(go run ./cmd/seed default \
  --tenant-name "test-ratelimit" \
  --email "admin@ratelimit.com" \
  --password "RateAdmin123!")

RATE_TENANT_ID=$(echo "$RATE_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)

RATE_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$RATE_TENANT_ID\",
    \"email\": \"admin@ratelimit.com\",
    \"password\": \"RateAdmin123!\"
  }" | jq -r '.access_token')

curl -X PUT http://localhost:8080/v1/tenants/$RATE_TENANT_ID/settings \
  -H "Authorization: Bearer $RATE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_ratelimit_login_limit": "2",
    "auth_ratelimit_login_window": "1m",
    "auth_ratelimit_signup_limit": "1",
    "auth_ratelimit_signup_window": "5m"
  }'

# 6. Create SSO test tenant
echo "Creating SSO test tenant..."
SSO_OUTPUT=$(go run ./cmd/seed default \
  --tenant-name "test-sso" \
  --email "admin@sso.com" \
  --password "SSOAdmin123!")

SSO_TENANT_ID=$(echo "$SSO_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)

# Configure dev SSO
SSO_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$SSO_TENANT_ID\",
    \"email\": \"admin@sso.com\",
    \"password\": \"SSOAdmin123!\"
  }" | jq -r '.access_token')

curl -X PUT http://localhost:8080/v1/tenants/$SSO_TENANT_ID/settings \
  -H "Authorization: Bearer $SSO_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "sso_provider": "dev",
    "sso_redirect_allowlist": "http://localhost:3000/callback"
  }'

# 7. Output test environment summary
echo ""
echo "🎉 Testing environment setup complete!"
echo ""
echo "=== MAIN TEST TENANT ==="
echo "Tenant ID: $MAIN_TENANT_ID"
echo "Admin: admin@test.com / TestAdmin123!"
echo "TOTP Secret: $TOTP_SECRET"
echo "Manager: manager@test.com / TestManager123!"
echo "User: user@test.com / TestUser123!"
echo "MFA User: mfa-user@test.com / TestMFA123!"
echo ""
echo "=== RATE LIMITING TEST TENANT ==="
echo "Tenant ID: $RATE_TENANT_ID"
echo "Admin: admin@ratelimit.com / RateAdmin123!"
echo "Login limit: 2 attempts per minute"
echo ""
echo "=== SSO TEST TENANT ==="
echo "Tenant ID: $SSO_TENANT_ID"
echo "Admin: admin@sso.com / SSOAdmin123!"
echo "SSO Provider: dev"
echo ""
echo "Environment variables for testing:"
echo "export MAIN_TENANT_ID=\"$MAIN_TENANT_ID\""
echo "export RATE_TENANT_ID=\"$RATE_TENANT_ID\""
echo "export SSO_TENANT_ID=\"$SSO_TENANT_ID\""
echo "export TOTP_SECRET=\"$TOTP_SECRET\""
```

## Workflow 5: Migration from Legacy System

### Scenario
Migrating users from an existing authentication system to Corvus Guard.

### Migration Script
```bash
#!/bin/bash
# legacy-migration.sh

# Configuration
LEGACY_TENANT_NAME="legacy-migration"
LEGACY_ADMIN_EMAIL="admin@legacy.com"
LEGACY_ADMIN_PASSWORD="LegacyAdmin123!"

echo "Starting legacy system migration..."

# 1. Create migration tenant
echo "Creating migration tenant..."
TENANT_OUTPUT=$(go run ./cmd/seed default \
  --tenant-name "$LEGACY_TENANT_NAME" \
  --email "$LEGACY_ADMIN_EMAIL" \
  --password "$LEGACY_ADMIN_PASSWORD")

TENANT_ID=$(echo "$TENANT_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)

# 2. Get admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"email\": \"$LEGACY_ADMIN_EMAIL\",
    \"password\": \"$LEGACY_ADMIN_PASSWORD\"
  }" | jq -r '.access_token')

# 3. Configure migration-friendly settings
curl -X PUT http://localhost:8080/v1/tenants/$TENANT_ID/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "auth_ratelimit_signup_limit": "1000",
    "auth_ratelimit_signup_window": "1h",
    "auth_access_token_ttl": "1h"
  }'

# 4. Simulate user migration (in practice, read from CSV/database)
echo "Migrating users..."

# Sample legacy users
declare -a LEGACY_USERS=(
  "john.doe@legacy.com:John:Doe:manager"
  "jane.smith@legacy.com:Jane:Smith:user"
  "bob.wilson@legacy.com:Bob:Wilson:admin"
  "alice.brown@legacy.com:Alice:Brown:user"
)

for user_data in "${LEGACY_USERS[@]}"; do
  IFS=':' read -r email first last role <<< "$user_data"
  
  echo "Migrating user: $email"
  
  # Create user with temporary password
  TEMP_PASSWORD="TempPassword123!"
  
  go run ./cmd/seed user \
    --tenant-id "$TENANT_ID" \
    --email "$email" \
    --password "$TEMP_PASSWORD" \
    --first "$first" \
    --last "$last" \
    --roles "$role"
  
  echo "✓ Migrated $email with role $role"
done

echo ""
echo "🎉 Migration complete!"
echo "Tenant ID: $TENANT_ID"
echo "Admin: $LEGACY_ADMIN_EMAIL / $LEGACY_ADMIN_PASSWORD"
echo ""
echo "Next steps:"
echo "1. Send password reset emails to all migrated users"
echo "2. Update application configuration to use new tenant"
echo "3. Test authentication flows"
echo "4. Decommission legacy system"
```

## Common Validation Steps

### Post-Setup Validation
```bash
#!/bin/bash
# validate-tenant.sh

TENANT_ID="$1"
ADMIN_EMAIL="$2"
ADMIN_PASSWORD="$3"

if [ -z "$TENANT_ID" ] || [ -z "$ADMIN_EMAIL" ] || [ -z "$ADMIN_PASSWORD" ]; then
  echo "Usage: $0 <tenant_id> <admin_email> <admin_password>"
  exit 1
fi

echo "Validating tenant setup: $TENANT_ID"

# 1. Test tenant exists
echo "1. Checking tenant exists..."
TENANT_RESPONSE=$(curl -s http://localhost:8080/tenants/$TENANT_ID)
if echo "$TENANT_RESPONSE" | jq -e '.id' > /dev/null; then
  echo "✓ Tenant exists and is accessible"
else
  echo "✗ Tenant not found or inaccessible"
  exit 1
fi

# 2. Test admin login
echo "2. Testing admin login..."
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/auth/password/login \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"email\": \"$ADMIN_EMAIL\",
    \"password\": \"$ADMIN_PASSWORD\"
  }")

if echo "$LOGIN_RESPONSE" | jq -e '.access_token' > /dev/null; then
  echo "✓ Admin login successful"
  ADMIN_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
else
  echo "✗ Admin login failed"
  echo "$LOGIN_RESPONSE"
  exit 1
fi

# 3. Test settings access
echo "3. Testing settings access..."
SETTINGS_RESPONSE=$(curl -s http://localhost:8080/v1/tenants/$TENANT_ID/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN")

if echo "$SETTINGS_RESPONSE" | jq -e '.tenant_id' > /dev/null; then
  echo "✓ Settings accessible"
else
  echo "✗ Settings not accessible"
  exit 1
fi

# 4. Test user creation
echo "4. Testing user creation..."
TEST_EMAIL="test-$(date +%s)@example.com"
SIGNUP_RESPONSE=$(curl -s -X POST http://localhost:8080/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"$TENANT_ID\",
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"TestPassword123!\",
    \"first_name\": \"Test\",
    \"last_name\": \"User\"
  }")

if echo "$SIGNUP_RESPONSE" | jq -e '.access_token' > /dev/null; then
  echo "✓ User signup successful"
else
  echo "✗ User signup failed"
  echo "$SIGNUP_RESPONSE"
fi

echo ""
echo "🎉 Tenant validation complete!"
echo "Tenant $TENANT_ID is ready for use."
```

These workflows provide comprehensive step-by-step processes for different tenant onboarding scenarios, from simple setups to complex enterprise deployments with automation and validation.
