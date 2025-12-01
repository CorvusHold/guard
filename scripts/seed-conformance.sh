#!/usr/bin/env bash
set -euo pipefail

# seed-conformance.sh
# Helper to seed tenants/users for Makefile `conformance` using guard-cli + bootstrap token.
# Produces .env.conformance with TENANT_ID/EMAIL/PASSWORD/TOTP_SECRET and NONMFA* aliases.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_ID=${RUN_ID:-$(date +%s)}
DEFAULT_TENANT_NAME=${DEFAULT_TENANT_NAME:-"conformance-main-$RUN_ID"}

OUT_FILE=".env.conformance"
: >"$OUT_FILE"

compose="docker compose -f docker-compose.test.yml"

seed_default_mfa() {
  $compose exec -T -e DEFAULT_TENANT_NAME="$DEFAULT_TENANT_NAME" api_test sh -lc '
    set -e
    export PATH=/usr/local/go/bin:/go/bin:$PATH
    eval "$(scripts/bootstrap-token.sh --prefix conformance-main)"
    cd cmd/guard-cli
    GUARD_API_TOKEN=$GUARD_API_TOKEN go run . --api-url http://localhost:8080 seed default \
      --tenant-name "$DEFAULT_TENANT_NAME" --enable-mfa --output env
  '
}

seed_nonmfa() {
  local name="$1" email="$2" password="$3" prefix="$4"
  $compose exec -T \
    -e NONMFA_TENANT_NAME="$name" \
    -e NONMFA_EMAIL="$email" \
    -e NONMFA_PASSWORD="$password" \
    api_test sh -lc '
      set -e
      export PATH=/usr/local/go/bin:/go/bin:$PATH
      eval "$(scripts/bootstrap-token.sh --prefix '"$prefix"')"
      cd cmd/guard-cli
      GUARD_API_TOKEN=$GUARD_API_TOKEN go run . --api-url http://localhost:8080 seed default \
        --tenant-name "$NONMFA_TENANT_NAME" \
        --email "$NONMFA_EMAIL" \
        --password "$NONMFA_PASSWORD" \
        --output env
    '
}

# 1) Default tenant/user with MFA
DEFAULT_ENV="$(seed_default_mfa)"
printf '%s
' "$DEFAULT_ENV" >>"$OUT_FILE"

# 2) First non-MFA tenant/user
NONMFA_TENANT_NAME=${NONMFA_TENANT_NAME:-test-nomfa-$RUN_ID}
NONMFA_EMAIL=${NONMFA_EMAIL:-nomfa@example.com}
NONMFA_PASSWORD=${NONMFA_PASSWORD:-Password123!}
NONMFA_ENV="$(seed_nonmfa "$NONMFA_TENANT_NAME" "$NONMFA_EMAIL" "$NONMFA_PASSWORD" "conformance-nomfa1")"
NONMFA_TENANT_ID="$(printf '%s
' "$NONMFA_ENV" | awk -F= '$1=="TENANT_ID"{print $2; exit}')"
{
  printf '%s
' "$NONMFA_ENV"
  printf 'NONMFA_TENANT_ID=%s
' "$NONMFA_TENANT_ID"
  printf 'NONMFA_EMAIL=%s
' "$NONMFA_EMAIL"
  printf 'NONMFA_PASSWORD=%s
' "$NONMFA_PASSWORD"
} >>"$OUT_FILE"

# 3) Second non-MFA tenant/user (for rate-limit scenarios)
NONMFA2_TENANT_NAME=${NONMFA2_TENANT_NAME:-test-nomfa-2-$RUN_ID}
NONMFA2_EMAIL=${NONMFA2_EMAIL:-nomfa2@example.com}
NONMFA2_PASSWORD=${NONMFA2_PASSWORD:-Password123!}
NONMFA2_ENV="$(seed_nonmfa "$NONMFA2_TENANT_NAME" "$NONMFA2_EMAIL" "$NONMFA2_PASSWORD" "conformance-nomfa2")"
NONMFA2_TENANT_ID="$(printf '%s
' "$NONMFA2_ENV" | awk -F= '$1=="TENANT_ID"{print $2; exit}')"
{
  printf '%s
' "$NONMFA2_ENV"
  printf 'NONMFA2_TENANT_ID=%s
' "$NONMFA2_TENANT_ID"
  printf 'NONMFA2_EMAIL=%s
' "$NONMFA2_EMAIL"
  printf 'NONMFA2_PASSWORD=%s
' "$NONMFA2_PASSWORD"
} >>"$OUT_FILE"
