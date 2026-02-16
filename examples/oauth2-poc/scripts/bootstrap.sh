#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
POC_DIR="$ROOT_DIR/examples/oauth2-poc"

if [[ -f "$ROOT_DIR/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT_DIR/.env"
  set +a
fi

default_guard_base_url="http://localhost:8080"
if [[ -n "${APP_ADDR:-}" ]]; then
  app_port="${APP_ADDR#:}"
  default_guard_base_url="http://localhost:${app_port}"
fi

GUARD_BASE_URL="${GUARD_BASE_URL:-$default_guard_base_url}"
POC_REDIRECT_URI="${POC_REDIRECT_URI:-http://localhost:3003/callback}"
POC_CLIENT_NAME="${POC_CLIENT_NAME:-OAuth2 POC SPA}"

# 1) Create a fresh bootstrap tenant + admin user + admin token
bootstrap_env="$(cd "$ROOT_DIR" && scripts/bootstrap-token.sh --prefix oauth2-poc --output env)"
# shellcheck disable=SC1090
source /dev/stdin <<<"$bootstrap_env"

: "${GUARD_API_TOKEN:?bootstrap-token did not return GUARD_API_TOKEN}"
: "${BOOTSTRAP_TENANT_ID:?bootstrap-token did not return BOOTSTRAP_TENANT_ID}"
: "${BOOTSTRAP_USER_EMAIL:?bootstrap-token did not return BOOTSTRAP_USER_EMAIL}"
: "${BOOTSTRAP_USER_PASSWORD:?bootstrap-token did not return BOOTSTRAP_USER_PASSWORD}"

# 2) Create an OAuth public client in that tenant via admin token
create_payload="$(jq -n \
  --arg name "$POC_CLIENT_NAME" \
  --arg redirect "$POC_REDIRECT_URI" \
  '{
    name: $name,
    client_type: "public",
    redirect_uris: [$redirect],
    scopes: ["openid", "profile", "email", "offline_access"],
    grant_types: ["authorization_code", "refresh_token"]
  }')"

create_resp="$(curl -sS --connect-timeout 5 --max-time 10 -X POST "$GUARD_BASE_URL/api/v1/auth/admin/oauth-clients" \
  -H "Authorization: Bearer $GUARD_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$create_payload")"

client_id="$(printf '%s' "$create_resp" | jq -r '.client.client_id // empty')"
if [[ -z "$client_id" ]]; then
  echo "Failed to create OAuth client. Response:" >&2
  echo "$create_resp" >&2
  exit 1
fi

mkdir -p "$POC_DIR"
cat > "$POC_DIR/.env.local" <<EOF
VITE_GUARD_BASE_URL=$GUARD_BASE_URL
VITE_OAUTH_CLIENT_ID=$client_id
VITE_REDIRECT_URI=$POC_REDIRECT_URI
VITE_OAUTH_SCOPE="openid profile email offline_access"
VITE_TENANT_ID=$BOOTSTRAP_TENANT_ID
EOF

cat <<EOF
Bootstrap complete.

POC config written to: examples/oauth2-poc/.env.local

Use these credentials for SIGN-IN in the POC:
  tenant_id: $BOOTSTRAP_TENANT_ID
  email:     $BOOTSTRAP_USER_EMAIL
  password:  $BOOTSTRAP_USER_PASSWORD

OAuth client:
  client_id: $client_id
  redirect:  $POC_REDIRECT_URI

Run the app:
  cd examples/oauth2-poc
  pnpm install
  pnpm dev
EOF
