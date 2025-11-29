#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_FILE=".env.k6"
OLD_K6_ORG_ID=""
OLD_K6_ADMIN_TOKEN=""
if [ -f "$OUT_FILE" ]; then
  OLD_K6_ORG_ID="$(grep -m 1 '^K6_ORG_ID=' "$OUT_FILE" || true)"
  OLD_K6_ADMIN_TOKEN="$(grep -m 1 '^K6_ADMIN_TOKEN=' "$OUT_FILE" || true)"
fi
: >"$OUT_FILE"

compose="docker compose -f docker-compose.test.yml"

TENANT_NAME="${K6_TENANT_NAME:-k6-default}"
EMAIL="${K6_EMAIL:-test@example.com}"
PASSWORD="${K6_PASSWORD:-Password123!}"
ENABLE_MFA="${K6_ENABLE_MFA:-}"

ENV_OUT="$(
  $compose exec -T \
    -e K6_TENANT_NAME="$TENANT_NAME" \
    -e K6_EMAIL="$EMAIL" \
    -e K6_PASSWORD="$PASSWORD" \
    -e K6_ENABLE_MFA="$ENABLE_MFA" \
    api_test sh -lc '
      set -e
      export PATH=/usr/local/go/bin:/go/bin:$PATH
      eval "$(scripts/bootstrap-token.sh --prefix k6)"
      cd cmd/guard-cli
      FLAGS=""
      if [ "${K6_ENABLE_MFA:-}" = "1" ]; then
        FLAGS="--enable-mfa"
      fi
      ENV_OUT="$(GUARD_API_TOKEN="$GUARD_API_TOKEN" go run . --api-url http://localhost:8080 seed default \
        --tenant-name "$K6_TENANT_NAME" \
        --email "$K6_EMAIL" \
        --password "$K6_PASSWORD" \
        $FLAGS \
        --output env)"
      TENANT_ID="$(printf "%s\n" "$ENV_OUT" | grep -m 1 "^TENANT_ID=" | cut -d= -f2-)"
      if [ -n "$TENANT_ID" ]; then
        curl -sS -o /dev/null -X PUT "http://localhost:8080/v1/tenants/$TENANT_ID/settings" \
          -H "Authorization: Bearer $GUARD_API_TOKEN" \
          -H "Content-Type: application/json" \
          --data-binary @- <<JSON
{"auth_ratelimit_login_limit":"100000","auth_ratelimit_login_window":"1m"}
JSON
      fi
      printf "%s\n" "$ENV_OUT"
    '
)"

printf '%s
' "$ENV_OUT" >>"$OUT_FILE"

if [ -n "$OLD_K6_ORG_ID" ] && ! grep -q '^K6_ORG_ID=' "$OUT_FILE"; then
  printf '%s
' "$OLD_K6_ORG_ID" >>"$OUT_FILE"
fi
if [ -n "$OLD_K6_ADMIN_TOKEN" ] && ! grep -q '^K6_ADMIN_TOKEN=' "$OUT_FILE"; then
  printf '%s
' "$OLD_K6_ADMIN_TOKEN" >>"$OUT_FILE"
fi

echo "Wrote k6 env to $OUT_FILE"
