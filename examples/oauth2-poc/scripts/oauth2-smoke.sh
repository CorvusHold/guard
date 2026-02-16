#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
POC_DIR="$ROOT_DIR/examples/oauth2-poc"

if [[ ! -f "$POC_DIR/.env.local" ]]; then
  echo "Missing $POC_DIR/.env.local. Run scripts/bootstrap.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$POC_DIR/.env.local"

GUARD_BASE_URL="${VITE_GUARD_BASE_URL:-http://localhost:8080}"
TENANT_ID="${VITE_TENANT_ID:-}"
CLIENT_ID="${VITE_OAUTH_CLIENT_ID:-}"
REDIRECT_URI="${VITE_REDIRECT_URI:-http://localhost:3003/callback}"
SCOPE="${VITE_OAUTH_SCOPE:-openid profile email offline_access}"

if [[ -z "$TENANT_ID" || -z "$CLIENT_ID" ]]; then
  echo "VITE_TENANT_ID and VITE_OAUTH_CLIENT_ID are required in .env.local" >&2
  exit 1
fi

new_email="oauth-smoke-$(date +%s)@example.com"
new_password="Password123!"

echo "[1/8] Signup new user: $new_email"
curl -sS -X POST "$GUARD_BASE_URL/api/v1/auth/password/signup" \
  -H 'X-Auth-Mode: json' \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"email\":\"$new_email\",\"password\":\"$new_password\",\"first_name\":\"OAuth\",\"last_name\":\"Smoke\"}" >/dev/null

echo "[2/8] Password login to get user bearer token"
login_json="$(curl -sS -X POST "$GUARD_BASE_URL/api/v1/auth/password/login" \
  -H 'X-Auth-Mode: json' \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"email\":\"$new_email\",\"password\":\"$new_password\"}")"
user_access="$(printf '%s' "$login_json" | jq -r '.access_token // empty')"
if [[ -z "$user_access" ]]; then
  echo "Password login failed: $login_json" >&2
  exit 1
fi

code_verifier="$(openssl rand -base64 64 | tr '+/' '-_' | tr -d '=\n' | cut -c1-96)"
code_challenge="$(printf '%s' "$code_verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
state="st$(date +%s)"
nonce="nc$(date +%s)"

authorize_url="$GUARD_BASE_URL/oauth/authorize?client_id=$CLIENT_ID&redirect_uri=$(python3 - <<PY
import urllib.parse
print(urllib.parse.quote('''$REDIRECT_URI''', safe=''))
PY
)&response_type=code&scope=$(python3 - <<PY
import urllib.parse
print(urllib.parse.quote('''$SCOPE''', safe=''))
PY
)&state=$state&nonce=$nonce&code_challenge=$code_challenge&code_challenge_method=S256"

echo "[3/8] GET /oauth/authorize (expect consent payload)"
consent_json="$(curl -sS -H "Authorization: Bearer $user_access" "$authorize_url")"
consent_challenge="$(printf '%s' "$consent_json" | jq -r '.consent_challenge // empty')"
if [[ -z "$consent_challenge" ]]; then
  echo "Authorize did not return consent challenge: $consent_json" >&2
  exit 1
fi

echo "[4/8] POST /oauth/authorize/decision (approve)"
decision_headers="$(mktemp)"
curl -sS -o /dev/null -D "$decision_headers" -X POST "$GUARD_BASE_URL/oauth/authorize/decision" \
  -H "Authorization: Bearer $user_access" \
  -H 'Content-Type: application/json' \
  -d "{\"approved\":true,\"consent_challenge\":\"$consent_challenge\",\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"response_type\":\"code\",\"scope\":\"$SCOPE\",\"state\":\"$state\",\"nonce\":\"$nonce\",\"code_challenge\":\"$code_challenge\",\"code_challenge_method\":\"S256\"}" || true

location="$(grep -i '^Location:' "$decision_headers" | awk '{print $2}' | tr -d '\r')"
rm -f "$decision_headers"
if [[ -z "$location" ]]; then
  echo "Missing Location redirect after consent decision" >&2
  exit 1
fi

code="$(python3 - <<PY
import urllib.parse
u=urllib.parse.urlparse('''$location''')
q=urllib.parse.parse_qs(u.query)
print(q.get('code',[''])[0])
PY
)"
if [[ -z "$code" ]]; then
  echo "Missing authorization code in redirect: $location" >&2
  exit 1
fi

echo "[5/8] POST /oauth/token (authorization_code + PKCE)"
token_json="$(curl -sS -X POST "$GUARD_BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=$code&client_id=$CLIENT_ID&redirect_uri=$(python3 - <<PY
import urllib.parse
print(urllib.parse.quote('''$REDIRECT_URI''', safe=''))
PY
)&code_verifier=$code_verifier")"

oauth_access="$(printf '%s' "$token_json" | jq -r '.access_token // empty')"
oauth_refresh="$(printf '%s' "$token_json" | jq -r '.refresh_token // empty')"
if [[ -z "$oauth_access" ]]; then
  echo "Token exchange failed: $token_json" >&2
  exit 1
fi

echo "[6/8] GET /api/v1/auth/me with OAuth access token"
me_json="$(curl -sS "$GUARD_BASE_URL/api/v1/auth/me" -H "Authorization: Bearer $oauth_access")"
me_email="$(printf '%s' "$me_json" | jq -r '.email // empty')"
if [[ "$me_email" != "$new_email" ]]; then
  echo "Unexpected /me response: $me_json" >&2
  exit 1
fi

echo "[7/8] POST /oauth/revoke"
if [[ -n "$oauth_refresh" ]]; then
  curl -sS -X POST "$GUARD_BASE_URL/oauth/revoke" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "token=$oauth_refresh&token_type_hint=refresh_token" >/dev/null
fi

echo "[8/8] SUCCESS"
echo "OAuth2 smoke succeeded for user: $new_email"
