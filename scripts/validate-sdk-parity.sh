#!/bin/bash

################################################################################
# SDK Feature Parity Validation Script
#
# Purpose: Validate that Go and TypeScript SDKs have equivalent features
# Usage: ./scripts/validate-sdk-parity.sh [--fix] [--verbose]
#
# Options:
#   --fix      Attempt to auto-fix issues (where possible)
#   --verbose  Show detailed analysis
#   --json     Output results as JSON
#
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
GO_SDK_DIR="$REPO_ROOT/sdk/go"
TS_SDK_DIR="$REPO_ROOT/sdk/ts"
OPENAPI_SPEC="$REPO_ROOT/sdk/spec/openapi.json"

# Options
FIX_MODE=false
VERBOSE=false
JSON_OUTPUT=false

# Counters
ENDPOINTS_TOTAL=0
ENDPOINTS_IN_GO=0
ENDPOINTS_IN_TS=0
ENDPOINTS_MISSING_GO=0
ENDPOINTS_MISSING_TS=0
ERRORS=0

################################################################################
# Helper Functions
################################################################################

print_header() {
  echo -e "\n${BLUE}========== $1 ==========${NC}"
}

print_success() {
  echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
  echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
  echo -e "${RED}❌ $1${NC}"
  ((ERRORS++))
}

print_info() {
  echo -e "${BLUE}ℹ️  $1${NC}"
}

################################################################################
# Argument Parsing
################################################################################

while [[ $# -gt 0 ]]; do
  case $1 in
    --fix)
      FIX_MODE=true
      shift
      ;;
    --verbose)
      VERBOSE=true
      shift
      ;;
    --json)
      JSON_OUTPUT=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

################################################################################
# Validation Functions
################################################################################

check_openapi_spec() {
  if [ ! -f "$OPENAPI_SPEC" ]; then
    print_error "OpenAPI spec not found at $OPENAPI_SPEC"
    return 1
  fi
  print_success "OpenAPI spec found"
  return 0
}

check_go_sdk() {
  if [ ! -d "$GO_SDK_DIR" ]; then
    print_error "Go SDK directory not found at $GO_SDK_DIR"
    return 1
  fi

  if [ ! -f "$GO_SDK_DIR/go.mod" ]; then
    print_error "Go SDK go.mod not found"
    return 1
  fi

  if [ ! -f "$GO_SDK_DIR/api.gen.go" ]; then
    print_error "Go SDK api.gen.go not found"
    return 1
  fi

  print_success "Go SDK structure valid"
  return 0
}

check_ts_sdk() {
  if [ ! -d "$TS_SDK_DIR" ]; then
    print_error "TypeScript SDK directory not found at $TS_SDK_DIR"
    return 1
  fi

  if [ ! -f "$TS_SDK_DIR/package.json" ]; then
    print_error "TypeScript SDK package.json not found"
    return 1
  fi

  if [ ! -f "$TS_SDK_DIR/src/client.ts" ]; then
    print_error "TypeScript SDK src/client.ts not found"
    return 1
  fi

  print_success "TypeScript SDK structure valid"
  return 0
}

count_openapi_endpoints() {
  # Extract all path definitions from OpenAPI spec
  if ! command -v jq &> /dev/null; then
    print_warning "jq not installed, skipping endpoint count"
    return 1
  fi

  ENDPOINTS_TOTAL=$(jq '.paths | keys | length' "$OPENAPI_SPEC" 2>/dev/null || echo "0")
  print_info "Found $ENDPOINTS_TOTAL endpoints in OpenAPI spec"
  return 0
}

check_go_sdk_compilation() {
  print_info "Checking Go SDK compilation..."

  if ! (cd "$GO_SDK_DIR" && go build ./... 2>&1); then
    print_error "Go SDK compilation failed"
    if [ "$VERBOSE" = true ]; then
      (cd "$GO_SDK_DIR" && go build ./... 2>&1 | head -20)
    fi
    return 1
  fi

  print_success "Go SDK compiles successfully"
  return 0
}

check_ts_sdk_compilation() {
  print_info "Checking TypeScript SDK compilation..."

  if ! (cd "$TS_SDK_DIR" && npm run build 2>&1); then
    print_error "TypeScript SDK compilation failed"
    if [ "$VERBOSE" = true ]; then
      (cd "$TS_SDK_DIR" && npm run build 2>&1 | head -20)
    fi
    return 1
  fi

  print_success "TypeScript SDK builds successfully"
  return 0
}

check_go_methods() {
  # Count methods in Go SDK client.go
  if ! command -v grep &> /dev/null; then
    print_warning "grep not available, skipping Go method analysis"
    return 1
  fi

  ENDPOINTS_IN_GO=$(grep -c "^func (c \*GuardClient)" "$GO_SDK_DIR/client.go" 2>/dev/null || echo "0")
  print_info "Go SDK has $ENDPOINTS_IN_GO ergonomic wrapper methods"
  return 0
}

check_ts_methods() {
  # Count methods in TypeScript SDK client.ts
  if ! command -v grep &> /dev/null; then
    print_warning "grep not available, skipping TypeScript method analysis"
    return 1
  fi

  ENDPOINTS_IN_TS=$(grep -c "async [a-zA-Z].*() {" "$TS_SDK_DIR/src/client.ts" 2>/dev/null || echo "0")
  print_info "TypeScript SDK has $ENDPOINTS_IN_TS methods"
  return 0
}

check_version_alignment() {
  # Check if both SDKs have matching versions
  GO_VERSION=$(grep -oP 'const Version = "\K[^"]+' "$GO_SDK_DIR/version.go" 2>/dev/null || echo "unknown")
  TS_VERSION=$(grep -oP '"version": "\K[^"]+' "$TS_SDK_DIR/package.json" 2>/dev/null || echo "unknown")

  print_info "Go SDK version: $GO_VERSION"
  print_info "TypeScript SDK version: $TS_VERSION"

  # Extract major.minor version
  GO_MAJOR_MINOR=$(echo "$GO_VERSION" | cut -d. -f1-2)
  TS_MAJOR_MINOR=$(echo "$TS_VERSION" | cut -d. -f1-2)

  if [ "$GO_MAJOR_MINOR" != "$TS_MAJOR_MINOR" ]; then
    print_error "SDK versions not aligned: Go=$GO_MAJOR_MINOR, TS=$TS_MAJOR_MINOR"
    return 1
  fi

  print_success "SDK versions aligned: $GO_MAJOR_MINOR"
  return 0
}

check_api_paths() {
  # Verify both SDKs use /api/v1/ paths
  print_info "Checking API path consistency..."

  GO_API_PATHS=$(grep -o "/api/v1/" "$GO_SDK_DIR/client.go" 2>/dev/null | wc -l || echo "0")
  TS_API_PATHS=$(grep -o "/api/v1/" "$TS_SDK_DIR/src/client.ts" 2>/dev/null | wc -l || echo "0")

  # Detect legacy /v1/ paths but do not count canonical /api/v1/
  GO_OLD_PATHS=$(grep -o "[^a]\/v1/" "$GO_SDK_DIR/client.go" 2>/dev/null | wc -l || echo "0")
  TS_OLD_PATHS=$(grep -o "[^a]\/v1/" "$TS_SDK_DIR/src/client.ts" 2>/dev/null | wc -l || echo "0")

  print_info "Go SDK: $GO_API_PATHS /api/v1/ paths"
  print_info "TypeScript SDK: $TS_API_PATHS /api/v1/ paths"

  if [ "$GO_OLD_PATHS" -gt 0 ]; then
    print_error "Go SDK has $GO_OLD_PATHS old /v1/ paths (should use /api/v1/)"
    return 1
  fi

  if [ "$TS_OLD_PATHS" -gt 0 ]; then
    print_error "TypeScript SDK has $TS_OLD_PATHS old /v1/ paths (should use /api/v1/)"
    return 1
  fi

  print_success "Both SDKs use /api/v1/ paths consistently"
  return 0
}

################################################################################
# Main Execution
################################################################################

main() {
  if [ "$JSON_OUTPUT" = true ]; then
    # Will output JSON at the end
    echo "{"
  else
    print_header "SDK Feature Parity Validation"
    echo "Repository: $REPO_ROOT"
    echo "Timestamp: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  fi

  # Run all checks
  print_header "Prerequisites"
  check_openapi_spec || true
  check_go_sdk || true
  check_ts_sdk || true

  print_header "SDK Structure"
  check_go_sdk_compilation || true
  check_ts_sdk_compilation || true

  print_header "Endpoint Analysis"
  count_openapi_endpoints || true
  check_go_methods || true
  check_ts_methods || true

  print_header "Version Alignment"
  check_version_alignment || true

  print_header "API Path Consistency"
  check_api_paths || true

  print_header "Summary"
  if [ "$ENDPOINTS_TOTAL" -gt 0 ]; then
    PARITY_PERCENTAGE=$(( ENDPOINTS_IN_GO * 100 / ENDPOINTS_TOTAL ))
    if [ "$PARITY_PERCENTAGE" -ge 100 ]; then
      print_success "Parity: $PARITY_PERCENTAGE% ($ENDPOINTS_IN_GO/$ENDPOINTS_TOTAL endpoints)"
    elif [ "$PARITY_PERCENTAGE" -ge 80 ]; then
      print_warning "Parity: $PARITY_PERCENTAGE% ($ENDPOINTS_IN_GO/$ENDPOINTS_TOTAL endpoints)"
    else
      print_error "Parity: $PARITY_PERCENTAGE% ($ENDPOINTS_IN_GO/$ENDPOINTS_TOTAL endpoints)"
    fi
  fi

  if [ $ERRORS -eq 0 ]; then
    print_success "All validation checks passed!"
    if [ "$JSON_OUTPUT" = true ]; then
      echo '  "status": "PASS",'
      echo '  "errors": 0'
      echo "}"
    fi
    return 0
  else
    print_error "Validation failed with $ERRORS error(s)"
    if [ "$JSON_OUTPUT" = true ]; then
      echo '  "status": "FAIL",'
      echo '  "errors": '"$ERRORS"
      echo "}"
    fi
    return 1
  fi
}

# Run main
main
exit $?
