#!/usr/bin/env bash
set -euo pipefail

# Non-admin authorization flow helper:
# - ensures a non-admin user exists
# - logs in as non-admin and verifies deny (before ACL)
# - logs in as admin, adds non-admin to "engineering" group
# - creates ACL tuple (group -> settings:read on tenant)
# - re-authorizes as non-admin and verifies allow
# - optional cleanup: delete tuple unless KEEP_TUPLE=1
#
# Env (overrides):
#   BASE               (default: http://localhost:8080)
#   TENANT_ID          (required; if missing, sourced from .env.fga)
#   ADMIN_EMAIL        (default: admin@example.com)
#   ADMIN_PASSWORD     (default: Password123!)
#   NONADMIN_EMAIL     (default: user1@example.com)
#   NONADMIN_PASSWORD  (default: Password123!)
#   KEEP_TUPLE=1       (skip cleanup)
#   PRE_CLEAN=1        (delete residual ACL tuples before the initial deny check)
#   PRE_CLEAN_MEMBERSHIP=1 (also remove 'engineering' membership during pre-clean)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE=${BASE:-http://localhost:8081}

if ! command -v jq >/dev/null 2>&1; then
  echo "This script requires jq. Install jq and re-run." >&2
  exit 1
fi

# POST /password/login helper that retries once on 429 using Retry-After
login_json() {
  local email="$1" password="$2"
  local body headers_file body_file code retry_after
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

# Wait for API readiness
for i in {1..60}; do
  if curl -fsS "$BASE/readyz" >/dev/null 2>&1; then
    echo "API ready"; break
  fi
  echo "Waiting for API ($i)..."; sleep 1
  if (( i == 60 )); then echo "API not ready after timeout" >&2; exit 1; fi
done

# Always create fresh tenant and admin for isolated test
echo "Creating fresh tenant and admin for test..."
TENANT_NAME=${TENANT_NAME:-test}
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-Password123!}

TENANT_LINE=$(go run ./cmd/seed tenant --name "$TENANT_NAME" | grep -m1 '^TENANT_ID=')
TENANT_ID=${TENANT_LINE#TENANT_ID=}
echo "TENANT_ID=$TENANT_ID" > .env.fga

go run ./cmd/seed user --tenant-id "$TENANT_ID" \
  --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD" --roles admin >/dev/null || true

echo "Created tenant $TENANT_ID and admin $ADMIN_EMAIL"

NONADMIN_EMAIL=${NONADMIN_EMAIL:-user1@example.com}
NONADMIN_PASSWORD=${NONADMIN_PASSWORD:-Password123!}

# 1) Ensure non-admin user exists (idempotent)
GOFLAGS=${GOFLAGS:-}
if go run $GOFLAGS ./cmd/seed user --tenant-id "$TENANT_ID" \
  --email "$NONADMIN_EMAIL" --password "$NONADMIN_PASSWORD" 2>&1 | grep -q 'created user\|existing user'; then
  echo "Created non-admin: $NONADMIN_EMAIL"
else
  echo "Failed to create non-admin user" >&2
  exit 1
fi

# 2) Login non-admin and get id (with 429-aware retry)
USER_TOKEN=$(login_json "$NONADMIN_EMAIL" "$NONADMIN_PASSWORD" | jq -r '.access_token')
if [[ -z "$USER_TOKEN" || "$USER_TOKEN" == null ]]; then
  echo "Non-admin login failed" >&2; exit 1
fi
NONADMIN_ID=$(curl -sS "$BASE/v1/auth/me" -H "Authorization: Bearer $USER_TOKEN" | jq -r '.id')
if [[ -z "$NONADMIN_ID" || "$NONADMIN_ID" == null ]]; then
  echo "Failed to resolve non-admin user id" >&2; exit 1
fi

echo "Non-admin user id: $NONADMIN_ID"

# Optional pre-clean to guarantee deny-before-ACL
if [[ "${PRE_CLEAN:-}" == "1" ]]; then
  echo "Pre-clean: removing residual ACL tuples (and optional membership)"
  # Admin login for pre-clean
  PRE_ADMIN_TOKEN=$(login_json "$ADMIN_EMAIL" "$ADMIN_PASSWORD" | jq -r '.access_token')
  if [[ -z "$PRE_ADMIN_TOKEN" || "$PRE_ADMIN_TOKEN" == null ]]; then
    echo "Pre-clean admin login failed" >&2; exit 1
  fi

  # Resolve engineering group id if it exists
  PRE_GROUP_ID=$(curl -sS "$BASE/v1/auth/admin/fga/groups?tenant_id=$TENANT_ID" -H "Authorization: Bearer $PRE_ADMIN_TOKEN" \
    | jq -r '.groups[] | select(.name=="engineering") | .id' | head -n1)
  if [[ -n "${PRE_GROUP_ID:-}" && "$PRE_GROUP_ID" != null ]]; then
    # Delete group-based ACL tuple (idempotent)
    PRE_DEL_GROUP_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE/v1/auth/admin/fga/acl/tuples" \
      -H "Authorization: Bearer $PRE_ADMIN_TOKEN" -H 'Content-Type: application/json' \
      --data-raw "$(jq -n --arg tenant_id "$TENANT_ID" --arg group_id "$PRE_GROUP_ID" '{tenant_id:$tenant_id, subject_type:"group", subject_id:$group_id, permission_key:"settings:read", object_type:"tenant"}')")
    echo "Pre-clean: delete group ACL tuple -> $PRE_DEL_GROUP_CODE"

    if [[ "${PRE_CLEAN_MEMBERSHIP:-}" == "1" ]]; then
      # Try to remove membership (ignore non-204 codes)
      PRE_MEM_DEL_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE/v1/auth/admin/fga/groups/$PRE_GROUP_ID/members" \
        -H "Authorization: Bearer $PRE_ADMIN_TOKEN" -H 'Content-Type: application/json' \
        --data-raw "$(jq -n --arg user_id "$NONADMIN_ID" '{user_id:$user_id}')")
      echo "Pre-clean: remove membership -> $PRE_MEM_DEL_CODE"
    fi
  fi

  # Delete any direct user-based ACL tuple (idempotent)
  PRE_DEL_USER_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE/v1/auth/admin/fga/acl/tuples" \
    -H "Authorization: Bearer $PRE_ADMIN_TOKEN" -H 'Content-Type: application/json' \
    --data-raw "$(jq -n --arg tenant_id "$TENANT_ID" --arg user_id "$NONADMIN_ID" '{tenant_id:$tenant_id, subject_type:"user", subject_id:$user_id, permission_key:"settings:read", object_type:"tenant"}')")
  echo "Pre-clean: delete user ACL tuple -> $PRE_DEL_USER_CODE"
fi

# 3) Authorize before (expect deny)
AUTH_DENY=$(curl -sS -X POST "$BASE/v1/auth/authorize" \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  --data-raw "$(jq -n --arg tenant_id "$TENANT_ID" '{tenant_id:$tenant_id, subject_type:"self", permission_key:"settings:read", object_type:"tenant"}')")
if ! echo "$AUTH_DENY" | grep -q '"allowed":false'; then
  echo "Expected deny before ACL, got: $AUTH_DENY" >&2; exit 1
fi

echo "Authorize denied as expected: $AUTH_DENY"

# 4) Admin login (reuse pre-clean token when PRE_CLEAN=1)
if [[ "${PRE_CLEAN:-}" == "1" ]]; then
  ADMIN_TOKEN="$PRE_ADMIN_TOKEN"
  echo "Reusing pre-clean admin token"
else
  ADMIN_TOKEN=$(login_json "$ADMIN_EMAIL" "$ADMIN_PASSWORD" | jq -r '.access_token')
fi
if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == null ]]; then
  echo "Admin login failed" >&2; exit 1
fi

# 5) Ensure engineering group exists
GROUP_ID=$(curl -sS "$BASE/v1/auth/admin/fga/groups?tenant_id=$TENANT_ID" -H "Authorization: Bearer $ADMIN_TOKEN" \
  | jq -r '.groups[] | select(.name=="engineering") | .id' | head -n1)
if [[ -z "$GROUP_ID" || "$GROUP_ID" == null ]]; then
  GROUP_ID=$(curl -sS -X POST "$BASE/v1/auth/admin/fga/groups" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    --data-raw "$(jq -n --arg tenant_id "$TENANT_ID" '{tenant_id:$tenant_id, name:"engineering", description:"Eng group"}')" \
    | jq -r '.id')
fi
[[ -n "$GROUP_ID" && "$GROUP_ID" != null ]] || { echo "Failed to ensure engineering group" >&2; exit 1; }

echo "Group ID: $GROUP_ID"

# 6) Add membership (idempotent)
ADD_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/admin/fga/groups/$GROUP_ID/members" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  --data-raw "$(jq -n --arg user_id "$NONADMIN_ID" '{user_id:$user_id}')")
if [[ "$ADD_CODE" != "204" ]]; then
  echo "Add membership failed: $ADD_CODE" >&2; exit 1
fi

echo "Added non-admin to engineering: $ADD_CODE"

# 7) Create ACL tuple
CREATE_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/auth/admin/fga/acl/tuples" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  --data-raw "$(jq -n --arg tenant_id "$TENANT_ID" --arg group_id "$GROUP_ID" '{tenant_id:$tenant_id, subject_type:"group", subject_id:$group_id, permission_key:"settings:read", object_type:"tenant"}')")
if [[ "$CREATE_CODE" != "201" ]]; then
  echo "ACL tuple create failed: $CREATE_CODE" >&2; exit 1
fi

echo "ACL tuple create -> $CREATE_CODE"

# 8) Re-authorize (expect allow)
AUTH_ALLOW=$(curl -sS -X POST "$BASE/v1/auth/authorize" \
  -H "Authorization: Bearer $USER_TOKEN" -H 'Content-Type: application/json' \
  --data-raw "$(jq -n --arg tenant_id "$TENANT_ID" '{tenant_id:$tenant_id, subject_type:"self", permission_key:"settings:read", object_type:"tenant"}')")
if ! echo "$AUTH_ALLOW" | grep -q '"allowed":true'; then
  echo "Expected allow after ACL, got: $AUTH_ALLOW" >&2; exit 1
fi

echo "Authorize allowed as expected: $AUTH_ALLOW"

# 9) Optional cleanup (delete tuple)
if [[ "${KEEP_TUPLE:-}" == "1" ]]; then
  echo "KEEP_TUPLE=1 set; preserving ACL tuple"
else
  DEL_CODE=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$BASE/v1/auth/admin/fga/acl/tuples" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
    --data-raw "$(jq -n --arg tenant_id "$TENANT_ID" --arg group_id "$GROUP_ID" '{tenant_id:$tenant_id, subject_type:"group", subject_id:$group_id, permission_key:"settings:read", object_type:"tenant"}')")
  if [[ "$DEL_CODE" != "204" ]]; then
    echo "ACL tuple delete failed: $DEL_CODE" >&2; exit 1
  fi
  echo "ACL tuple deleted -> $DEL_CODE"
fi

echo "Non-admin check completed for TENANT_ID=$TENANT_ID USER_ID=$NONADMIN_ID GROUP_ID=$GROUP_ID"
