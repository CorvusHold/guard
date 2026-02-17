#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/examples/oauth2-bff-go"
BACKEND_DIR="$EXAMPLE_DIR/backend"

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
BFF_REDIRECT_URI="${BFF_REDIRECT_URI:-http://localhost:3004/oauth/callback}"
BFF_CLIENT_NAME="${BFF_CLIENT_NAME:-OAuth2 BFF Go Example}"
BFF_SCOPE="${BFF_SCOPE:-openid profile email offline_access}"

bootstrap_env="$(cd "$ROOT_DIR" && scripts/bootstrap-token.sh --prefix oauth2-bff-go --output env)"
# shellcheck disable=SC1090
source /dev/stdin <<<"$bootstrap_env"

: "${GUARD_API_TOKEN:?bootstrap-token did not return GUARD_API_TOKEN}"
: "${BOOTSTRAP_TENANT_ID:?bootstrap-token did not return BOOTSTRAP_TENANT_ID}"
: "${BOOTSTRAP_USER_EMAIL:?bootstrap-token did not return BOOTSTRAP_USER_EMAIL}"
: "${BOOTSTRAP_USER_PASSWORD:?bootstrap-token did not return BOOTSTRAP_USER_PASSWORD}"

create_payload="$(jq -n \
  --arg name "$BFF_CLIENT_NAME" \
  --arg redirect "$BFF_REDIRECT_URI" \
  '{
    name: $name,
    client_type: "public",
    redirect_uris: [$redirect],
    scopes: ["openid", "profile", "email", "offline_access"],
    grant_types: ["authorization_code", "refresh_token"]
  }')"

create_resp="$(curl -sS --connect-timeout 5 --max-time 15 -X POST "$GUARD_BASE_URL/api/v1/auth/admin/oauth-clients" \
  -H "Authorization: Bearer $GUARD_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$create_payload")"

client_id="$(printf '%s' "$create_resp" | jq -r '.client.client_id // empty')"
if [[ -z "$client_id" ]]; then
  echo "Failed to create OAuth client. Response:" >&2
  echo "$create_resp" >&2
  exit 1
fi

# Pre-grant consent for the bootstrap user so first browser login can redirect
# directly back to the BFF callback (no manual consent decision step in browser).
login_json="$(curl -sS --connect-timeout 5 --max-time 15 -X POST "$GUARD_BASE_URL/api/v1/auth/password/login" \
  -H 'X-Auth-Mode: json' \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$BOOTSTRAP_TENANT_ID\",\"email\":\"$BOOTSTRAP_USER_EMAIL\",\"password\":\"$BOOTSTRAP_USER_PASSWORD\"}")"
bootstrap_access="$(printf '%s' "$login_json" | jq -r '.access_token // empty')"
if [[ -z "$bootstrap_access" ]]; then
  echo "Warning: failed to login bootstrap user for consent pre-grant" >&2
else
  state="bff-bootstrap-$(openssl rand -hex 8)"
  nonce="bff-bootstrap-$(openssl rand -hex 8)"
  verifier="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n' | cut -c1-64)"
  challenge="$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  encoded_redirect="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=""))' "$BFF_REDIRECT_URI")"
  encoded_scope="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=""))' "$BFF_SCOPE")"
  authorize_url="$GUARD_BASE_URL/oauth/authorize?client_id=$client_id&redirect_uri=$encoded_redirect&response_type=code&scope=$encoded_scope&state=$state&nonce=$nonce&code_challenge=$challenge&code_challenge_method=S256"
  consent_json="$(curl -sS --connect-timeout 5 --max-time 15 -H "Authorization: Bearer $bootstrap_access" "$authorize_url")"
  consent_challenge="$(printf '%s' "$consent_json" | jq -r '.consent_challenge // empty')"
  if [[ -n "$consent_challenge" ]]; then
    curl -sS --connect-timeout 5 --max-time 15 -o /dev/null -X POST "$GUARD_BASE_URL/oauth/authorize/decision" \
      -H "Authorization: Bearer $bootstrap_access" \
      -H 'Content-Type: application/json' \
      -d "{\"approved\":true,\"consent_challenge\":\"$consent_challenge\",\"client_id\":\"$client_id\",\"redirect_uri\":\"$BFF_REDIRECT_URI\",\"response_type\":\"code\",\"scope\":\"$BFF_SCOPE\",\"state\":\"$state\",\"nonce\":\"$nonce\",\"code_challenge\":\"$challenge\",\"code_challenge_method\":\"S256\"}" || true
  fi
fi

mkdir -p "$BACKEND_DIR"
cat > "$BACKEND_DIR/.env" <<EOF
PORT=3004
GUARD_BASE_URL=$GUARD_BASE_URL
OAUTH_CLIENT_ID=$client_id
OAUTH_REDIRECT_URI=$BFF_REDIRECT_URI
OAUTH_SCOPE="$BFF_SCOPE"
TENANT_ID=$BOOTSTRAP_TENANT_ID
BOOTSTRAP_USER_EMAIL=$BOOTSTRAP_USER_EMAIL
BOOTSTRAP_USER_PASSWORD=$BOOTSTRAP_USER_PASSWORD
EOF

cat <<EOF
Bootstrap complete.

Backend env written to: examples/oauth2-bff-go/backend/.env

Guard:
  base_url: $GUARD_BASE_URL
  tenant_id: $BOOTSTRAP_TENANT_ID

OAuth client:
  client_id: $client_id
  redirect:  $BFF_REDIRECT_URI

Bootstrap user (can login directly in Guard UI):
  email:    $BOOTSTRAP_USER_EMAIL
  password: $BOOTSTRAP_USER_PASSWORD
EOF
