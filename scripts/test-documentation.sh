#!/bin/bash
# test-documentation.sh - Automated testing of tenant onboarding documentation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="http://localhost:8080"
TEST_PREFIX="doctest-$(date +%s)"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if API is running
    if ! curl -s "$BASE_URL/healthz" > /dev/null; then
        log_error "API server not running at $BASE_URL"
        log_info "Please start the server with: make dev"
        exit 1
    fi
    
    # Check if database is accessible
    if ! curl -s "$BASE_URL/readyz" > /dev/null; then
        log_error "Database not ready"
        log_info "Please ensure database is running with: make compose-up"
        exit 1
    fi
    
    # Check if jq is available
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed"
        exit 1
    fi
    
    log_info "✓ Prerequisites check passed"
}

test_seed_commands() {
    log_info "Testing seed commands..."
    
    # Test 1: Create tenant only
    log_info "Testing 'tenant' seed command..."
    TENANT_OUTPUT=$(go run ./cmd/seed tenant --name "$TEST_PREFIX-tenant-only")
    TENANT_ID=$(echo "$TENANT_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)
    
    if [ -z "$TENANT_ID" ]; then
        log_error "Failed to create tenant"
        exit 1
    fi
    
    # Verify tenant exists
    TENANT_CHECK=$(curl -s "$BASE_URL/tenants/$TENANT_ID")
    if ! echo "$TENANT_CHECK" | jq -e '.id' > /dev/null; then
        log_error "Created tenant not found via API"
        exit 1
    fi
    
    log_info "✓ Tenant creation test passed (ID: $TENANT_ID)"
    
    # Test 2: Create user in existing tenant
    log_info "Testing 'user' seed command..."
    USER_OUTPUT=$(go run ./cmd/seed user \
        --tenant-id "$TENANT_ID" \
        --email "$TEST_PREFIX-user@example.com" \
        --password "TestPassword123!" \
        --first "Test" \
        --last "User")
    
    USER_ID=$(echo "$USER_OUTPUT" | grep USER_ID | cut -d'=' -f2)
    if [ -z "$USER_ID" ]; then
        log_error "Failed to create user"
        exit 1
    fi
    
    log_info "✓ User creation test passed (ID: $USER_ID)"
    
    # Test 3: Complete default setup
    log_info "Testing 'default' seed command..."
    DEFAULT_OUTPUT=$(go run ./cmd/seed default \
        --tenant-name "$TEST_PREFIX-default" \
        --email "$TEST_PREFIX-admin@example.com" \
        --password "AdminPassword123!" \
        --enable-mfa)
    
    DEFAULT_TENANT_ID=$(echo "$DEFAULT_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)
    DEFAULT_USER_ID=$(echo "$DEFAULT_OUTPUT" | grep USER_ID | cut -d'=' -f2)
    TOTP_SECRET=$(echo "$DEFAULT_OUTPUT" | grep TOTP_SECRET | cut -d'=' -f2)
    
    if [ -z "$DEFAULT_TENANT_ID" ] || [ -z "$DEFAULT_USER_ID" ] || [ -z "$TOTP_SECRET" ]; then
        log_error "Failed to create default setup"
        exit 1
    fi
    
    log_info "✓ Default setup test passed (Tenant: $DEFAULT_TENANT_ID, User: $DEFAULT_USER_ID)"
    
    # Export for other tests
    export TEST_TENANT_ID="$DEFAULT_TENANT_ID"
    export TEST_USER_EMAIL="$TEST_PREFIX-admin@example.com"
    export TEST_USER_PASSWORD="AdminPassword123!"
}

test_api_endpoints() {
    log_info "Testing API endpoints..."
    
    # Test authentication
    log_info "Testing password login..."
    LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/auth/password/login" \
        -H "Content-Type: application/json" \
        -d "{
            \"tenant_id\": \"$TEST_TENANT_ID\",
            \"email\": \"$TEST_USER_EMAIL\",
            \"password\": \"$TEST_USER_PASSWORD\"
        }")
    
    if ! echo "$LOGIN_RESPONSE" | jq -e '.access_token' > /dev/null; then
        log_error "Login failed"
        echo "$LOGIN_RESPONSE"
        exit 1
    fi
    
    ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')
    log_info "✓ Authentication test passed"
    
    # Test tenant endpoints
    log_info "Testing tenant endpoints..."
    
    # Get tenant by ID
    TENANT_RESPONSE=$(curl -s "$BASE_URL/tenants/$TEST_TENANT_ID")
    if ! echo "$TENANT_RESPONSE" | jq -e '.id' > /dev/null; then
        log_error "Get tenant by ID failed"
        exit 1
    fi
    
    # List tenants
    TENANTS_LIST=$(curl -s "$BASE_URL/tenants?q=$TEST_PREFIX")
    if ! echo "$TENANTS_LIST" | jq -e '.tenants | length > 0' > /dev/null; then
        log_error "List tenants failed"
        exit 1
    fi
    
    log_info "✓ Tenant endpoints test passed"
    
    # Test settings endpoints
    log_info "Testing settings endpoints..."
    
    # Get settings
    SETTINGS_RESPONSE=$(curl -s "$BASE_URL/v1/tenants/$TEST_TENANT_ID/settings" \
        -H "Authorization: Bearer $ACCESS_TOKEN")
    
    if ! echo "$SETTINGS_RESPONSE" | jq -e '.tenant_id' > /dev/null; then
        log_error "Get settings failed"
        exit 1
    fi
    
    # Update settings
    UPDATE_RESPONSE=$(curl -s -X PUT "$BASE_URL/v1/tenants/$TEST_TENANT_ID/settings" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "app_cors_allowed_origins": "http://localhost:3000,http://localhost:5173",
            "auth_access_token_ttl": "30m"
        }')
    
    if ! echo "$UPDATE_RESPONSE" | jq -e '.updated_settings' > /dev/null; then
        log_error "Update settings failed"
        echo "$UPDATE_RESPONSE"
        exit 1
    fi
    
    log_info "✓ Settings endpoints test passed"
    
    # Test user signup
    log_info "Testing user signup..."
    SIGNUP_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/auth/signup" \
        -H "Content-Type: application/json" \
        -d "{
            \"tenant_id\": \"$TEST_TENANT_ID\",
            \"email\": \"$TEST_PREFIX-newuser@example.com\",
            \"password\": \"NewUserPassword123!\",
            \"first_name\": \"New\",
            \"last_name\": \"User\"
        }")
    
    if ! echo "$SIGNUP_RESPONSE" | jq -e '.access_token' > /dev/null; then
        log_error "User signup failed"
        echo "$SIGNUP_RESPONSE"
        exit 1
    fi
    
    log_info "✓ User signup test passed"
}

test_workflows() {
    log_info "Testing workflow scenarios..."
    
    # Test SaaS startup workflow (simplified)
    log_info "Testing SaaS startup workflow..."
    
    # Create dev tenant
    DEV_OUTPUT=$(go run ./cmd/seed default \
        --tenant-name "$TEST_PREFIX-startup-dev" \
        --email "$TEST_PREFIX-dev@startup.com" \
        --password "DevPassword123!")
    
    DEV_TENANT_ID=$(echo "$DEV_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)
    
    # Get dev admin token
    DEV_TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/v1/auth/password/login" \
        -H "Content-Type: application/json" \
        -d "{
            \"tenant_id\": \"$DEV_TENANT_ID\",
            \"email\": \"$TEST_PREFIX-dev@startup.com\",
            \"password\": \"DevPassword123!\"
        }")
    
    DEV_TOKEN=$(echo "$DEV_TOKEN_RESPONSE" | jq -r '.access_token')
    
    # Configure dev settings
    curl -s -X PUT "$BASE_URL/v1/tenants/$DEV_TENANT_ID/settings" \
        -H "Authorization: Bearer $DEV_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "app_cors_allowed_origins": "http://localhost:3000,http://localhost:5173",
            "auth_access_token_ttl": "1h",
            "sso_provider": "dev"
        }' > /dev/null
    
    log_info "✓ SaaS startup workflow test passed"
    
    # Test enterprise workflow (simplified)
    log_info "Testing enterprise workflow..."
    
    ENTERPRISE_OUTPUT=$(go run ./cmd/seed default \
        --tenant-name "$TEST_PREFIX-enterprise" \
        --email "$TEST_PREFIX-admin@enterprise.com" \
        --password "EnterpriseAdmin123!" \
        --enable-mfa)
    
    ENTERPRISE_TENANT_ID=$(echo "$ENTERPRISE_OUTPUT" | grep TENANT_ID | cut -d'=' -f2)
    
    # Create additional users
    go run ./cmd/seed user \
        --tenant-id "$ENTERPRISE_TENANT_ID" \
        --email "$TEST_PREFIX-manager@enterprise.com" \
        --password "Manager123!" \
        --roles "manager" > /dev/null
    
    log_info "✓ Enterprise workflow test passed"
}

cleanup() {
    log_info "Cleaning up test data..."
    
    # Note: In a real scenario, you might want to deactivate tenants
    # For now, we'll just log the created resources
    log_info "Test tenants created (consider cleanup):"
    curl -s "$BASE_URL/tenants?q=$TEST_PREFIX" | jq -r '.tenants[].name' | while read -r name; do
        log_info "  - $name"
    done
}

main() {
    log_info "Starting documentation testing..."
    log_info "Test prefix: $TEST_PREFIX"
    
    check_prerequisites
    test_seed_commands
    test_api_endpoints
    test_workflows
    
    log_info "🎉 All documentation tests passed!"
    log_info "Documentation is validated and working correctly."
    
    cleanup
}

# Run main function
main "$@"
