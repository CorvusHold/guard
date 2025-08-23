#!/usr/bin/env bash
set -euo pipefail

# FGA end-to-end smoke test
# - Seeds tenant/admin, logs in, ensures group+membership, creates ACL tuple
# - Verifies authorize allow, optionally deletes tuple, then verifies deny
# - Idempotent where possible
#
# Usage:
#   scripts/fga_smoke.sh [--help|-h]
#
# Environment variables:
#   BASE              API base URL (default: http://localhost:8080)
#   TENANT_NAME       Tenant name to seed (default: test)
#   EMAIL             Admin email to seed/login (default: admin@example.com)
#   PASSWORD          Admin password (default: Password123!)
#   SMOKE_WRITE_ENV   Controls writes (default: 0)
#                     0 => read-only: only calls /v1/auth/authorize and exits
#                     1 => write-enabled: performs group/membership/ACL writes
#   KEEP_TUPLE        When SMOKE_WRITE_ENV=1, keep the created ACL tuple (default: unset)
#                     1 => skip deletion and final deny check
#                     empty/unset => delete tuple and verify deny
#
# Examples:
#   # Read-only smoke (no writes):
#   SMOKE_WRITE_ENV=0 scripts/fga_smoke.sh
#
#   # Write-enabled smoke and keep ACL tuple for inspection:
#   SMOKE_WRITE_ENV=1 KEEP_TUPLE=1 scripts/fga_smoke.sh
#
# Requirements: docker-compose stack up, Go toolchain, curl, jq (recommended; falls back to python3 for read parsing)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE="http://localhost:8080"
TENANT_NAME=${TENANT_NAME:-test}
ADMIN_EMAIL=${EMAIL:-admin@example.com}
ADMIN_PASSWORD=${PASSWORD:-Password123!}

# Help/usage
usage() {
  cat <<'USAGE'
FGA smoke test

Flags:
  -h, --help    Show this help and exit

Environment variables:
  BASE              API base URL (default: http://localhost:8080)
  TENANT_NAME       Tenant name to seed (default: test)
  EMAIL             Admin email to seed/login (default: admin@example.com)
  PASSWORD          Admin password (default: Password123!)
  SMOKE_WRITE_ENV   0 = read-only, 1 = write-enabled (default: 0)
  KEEP_TUPLE        When write-enabled, 1 = keep ACL tuple (skip delete/deny)

Examples:
  SMOKE_WRITE_ENV=0 scripts/fga_smoke.sh
  SMOKE_WRITE_ENV=1 KEEP_TUPLE=1 scripts/fga_smoke.sh
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

# Ensure API is ready
for i in {1..60}; do
  if curl -fsS "$BASE/readyz" >/dev/null 2>&1; then
    echo "API ready"; break
  fi
  echo "Waiting for API ($i)..."; sleep 1
  if (( i == 60 )); then echo "API not ready after timeout" >&2; exit 1; fi
done

parse_json_key() {
  local key="$1"; shift
  if command -v jq >/dev/null 2>&1; then
    echo "$1" | jq -r ".$key" 2>/dev/null
  else
    python3 - "$key" <<'PY' "$1"
import sys, json
key = sys.argv[1]
print(json.load(sys.stdin).get(key, ''))
PY
  fi
}

# Write control flag: set SMOKE_WRITE_ENV=1 to enable write operations (default: disabled)
SMOKE_WRITE_ENV="${SMOKE_WRITE_ENV:-0}"
is_true() { case "$1" in 1|true|TRUE|yes|y) return 0 ;; *) return 1 ;; esac; }

# POST /password/login helper that retries once on 429 using Retry-After
login_json() {
  local email="$1" password="$2"
  local body headers_file body_file code retry_after
  if ! command -v jq >/dev/null 2>&1; then
    echo "login_json() requires jq; please install jq" >&2
    return 1
  fi
  body=$(jq -n --arg tenant_id "$TENANT_ID" --arg email "$email" --arg password "$password" '{tenant_id:$tenant_id, email:$email, password:$password}')
  headers_file=$(mktemp)
  body_file=$(mktemp)
  code=$(curl -sS -D "$headers_file" -o "$body_file" -w '%{http_code}' \
    -X POST "$BASE/v1/auth/password/login" -H 'Content-Type: application/json' --data-raw "$body")
  if [[ "$code" == "429" ]]; then
    retry_after=$(awk 'BEGIN{IGNORECASE=1} /^Retry-After:/ {gsub(/\r/,""); print $2; exit}' "$headers_file")
    echo "Login rate-limited (429). Waiting ${retry_after:-60}s then retrying..." >&2
    sleep "${retry_after:-60}"
    : > "$headers_file"; : > "$body_file"
    code=$(curl -sS -D "$headers_file" -o "$body_file" -w '%{http_code}' \
      -X POST "$BASE/v1/auth/password/login" -H 'Content-Type: application/json' --data-raw "$body")
  fi
  cat "$body_file"
  rm -f "$headers_file" "$body_file"
}

# Seed tenant and admin user
TENANT_LINE=$(go run ./cmd/seed tenant --name "$TENANT_NAME" | grep -m1 '^TENANT_ID=')
TENANT_ID=${TENANT_LINE#TENANT_ID=}
echo "TENANT_ID=$TENANT_ID" > .env.fga

go run ./cmd/seed user --tenant-id "$TENANT_ID" \
  --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" --roles admin >/dev/null || true

echo "Seeded tenant $TENANT_ID and ensured admin user $ADMIN_EMAIL"

# Login admin
LOGIN_JSON=$(login_json "$ADMIN_EMAIL" "$ADMIN_PASSWORD")
ACCESS_TOKEN=$(parse_json_key access_token "$LOGIN_JSON")
if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == null ]]; then
  echo "Login failed: $LOGIN_JSON" >&2; exit 1
fi

# /me
ME_JSON=$(curl -sS "$BASE/v1/auth/me" -H "Authorization: Bearer $ACCESS_TOKEN")
USER_ID=$(parse_json_key id "$ME_JSON")
if [[ -z "$USER_ID" || "$USER_ID" == null ]]; then
  echo "Failed to read user id: $ME_JSON" >&2; exit 1
fi

echo "User ID: $USER_ID"

# If writes are disabled, perform a read-only authorize call and exit
if ! is_true "$SMOKE_WRITE_ENV"; then
  echo "SMOKE_WRITE_ENV disabled; skipping writes. Performing read-only authorization check."
  AUTH_RO=$(curl -sS -X POST "$BASE/v1/auth/authorize" \
    -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"subject_type\":\"self\",\"permission_key\":\"settings:read\",\"object_type\":\"tenant\"}")
  echo "Authorize (read-only) result: $AUTH_RO"
  echo "FGA smoke (read-only) completed for TENANT_ID=$TENANT_ID USER_ID=$USER_ID"
  exit 0
fi

# Ensure group (idempotent)
# Try to find existing group by name first
LIST_JSON=$(curl -sS "$BASE/v1/auth/admin/fga/groups?tenant_id=$TENANT_ID" -H "Authorization: Bearer $ACCESS_TOKEN")
if command -v jq >/dev/null 2>&1; then
  GROUP_ID=$(echo "$LIST_JSON" | jq -r '.groups[] | select(.name=="engineering") | .id' | head -n1)
else
  GROUP_ID=$(python3 - "engineering" <<'PY' "$LIST_JSON"
import sys, json
name = sys.argv[1]
try:
    data = json.load(sys.stdin)
    print(next((g.get('id','') for g in data.get('groups', []) if g.get('name') == name), ""))
except Exception:
    print("")
PY
  )
fi
if [[ -z "$GROUP_ID" || "$GROUP_ID" == null ]]; then
  GRP_JSON=$(curl -sS -X POST "$BASE/v1/auth/admin/fga/groups" \
    -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"name\":\"engineering\",\"description\":\"Eng group\"}")
  GROUP_ID=$(parse_json_key id "$GRP_JSON")
  if [[ -z "$GROUP_ID" || "$GROUP_ID" == null ]]; then
    echo "Failed to create group: $GRP_JSON" >&2; exit 1
  fi
fi

echo "Group ID: $GROUP_ID"

# Add member
ADD_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/admin/fga/groups/$GROUP_ID/members" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"user_id\":\"$USER_ID\"}")
[[ "$ADD_CODE" == "204" ]] || { echo "Add member failed: $ADD_CODE" >&2; exit 1; }

echo "Added member ($USER_ID) -> 204"

# Create ACL tuple
TUP_CREATE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/admin/fga/acl/tuples" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"subject_type\":\"group\",\"subject_id\":\"$GROUP_ID\",\"permission_key\":\"settings:read\",\"object_type\":\"tenant\"}")
[[ "$TUP_CREATE_CODE" == "201" ]] || { echo "ACL create failed: $TUP_CREATE_CODE" >&2; exit 1; }

echo "ACL tuple created -> 201"

# Authorize should allow
AUTH_ALLOW=$(curl -sS -X POST "$BASE/v1/auth/authorize" \
  -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"subject_type\":\"self\",\"permission_key\":\"settings:read\",\"object_type\":\"tenant\"}")
if ! echo "$AUTH_ALLOW" | grep -q '"allowed":true'; then
  echo "Authorize expected allowed=true, got: $AUTH_ALLOW" >&2; exit 1
fi

echo "Authorize allowed ✅: $AUTH_ALLOW"

if [[ "${KEEP_TUPLE:-}" == "1" ]]; then
  echo "KEEP_TUPLE=1 set; skipping tuple deletion and deny check"
else
  # Delete ACL tuple
  TUP_DELETE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE/v1/auth/admin/fga/acl/tuples" \
    -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"subject_type\":\"group\",\"subject_id\":\"$GROUP_ID\",\"permission_key\":\"settings:read\",\"object_type\":\"tenant\"}")
  [[ "$TUP_DELETE_CODE" == "204" ]] || { echo "ACL delete failed: $TUP_DELETE_CODE" >&2; exit 1; }

  echo "ACL tuple deleted -> 204"

  # Authorize should deny now
  AUTH_DENY=$(curl -sS -X POST "$BASE/v1/auth/authorize" \
    -H "Authorization: Bearer $ACCESS_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"tenant_id\":\"$TENANT_ID\",\"subject_type\":\"self\",\"permission_key\":\"settings:read\",\"object_type\":\"tenant\"}")
  if ! echo "$AUTH_DENY" | grep -q '"allowed":false'; then
    echo "Authorize expected allowed=false, got: $AUTH_DENY" >&2; exit 1
  fi

  echo "Authorize denied ✅: $AUTH_DENY"
fi

echo "FGA smoke completed for TENANT_ID=$TENANT_ID USER_ID=$USER_ID GROUP_ID=$GROUP_ID"
