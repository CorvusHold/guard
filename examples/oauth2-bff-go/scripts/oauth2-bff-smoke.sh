#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXAMPLE_DIR="$ROOT_DIR/examples/oauth2-bff-go"
BACKEND_DIR="$EXAMPLE_DIR/backend"

if [[ ! -f "$BACKEND_DIR/.env" ]]; then
  echo "Missing $BACKEND_DIR/.env. Run scripts/bootstrap.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$BACKEND_DIR/.env"
set +a

GUARD_BASE_URL="${GUARD_BASE_URL:-http://localhost:8080}"
TENANT_ID="${TENANT_ID:-}"
CLIENT_ID="${OAUTH_CLIENT_ID:-}"
REDIRECT_URI="${OAUTH_REDIRECT_URI:-http://localhost:3004/oauth/callback}"
BACKEND_BASE_URL="${BACKEND_BASE_URL:-http://localhost:${PORT:-3004}}"
BFF_SCOPE="${OAUTH_SCOPE:-openid profile email offline_access}"

if [[ -z "$TENANT_ID" || -z "$CLIENT_ID" ]]; then
  echo "TENANT_ID and OAUTH_CLIENT_ID are required in backend/.env" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
cookies_file="$tmp_dir/cookies.txt"
headers_file="$tmp_dir/headers.txt"
backend_pid=""
cleanup() {
  if [[ -n "$backend_pid" ]]; then
    kill "$backend_pid" >/dev/null 2>&1 || true
    wait "$backend_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

echo "[0/9] Start BFF backend"
(
  cd "$BACKEND_DIR"
  set -a
  source "$BACKEND_DIR/.env"
  set +a
  exec go run .
) >"$tmp_dir/backend.log" 2>&1 &
backend_pid="$!"

for _ in $(seq 1 40); do
  if curl -sS "$BACKEND_BASE_URL/api/config" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
if ! curl -sS "$BACKEND_BASE_URL/api/config" >/dev/null 2>&1; then
  echo "BFF backend failed to start. Logs:" >&2
  cat "$tmp_dir/backend.log" >&2
  exit 1
fi

echo "[1/9] GET /oauth/login from BFF"
curl -sS -D "$headers_file" -o /dev/null -c "$cookies_file" "$BACKEND_BASE_URL/oauth/login"
location="$(grep -i '^Location:' "$headers_file" | awk '{print $2}' | tr -d '\r')"
if [[ -z "$location" ]]; then
  echo "BFF /oauth/login did not return Location header" >&2
  exit 1
fi

authorize_url="$location"
state="$(python3 -c 'import urllib.parse,sys;u=urllib.parse.urlparse(sys.argv[1]);q=urllib.parse.parse_qs(u.query);print(q.get("state",[""])[0])' "$authorize_url")"
code_challenge="$(python3 -c 'import urllib.parse,sys;u=urllib.parse.urlparse(sys.argv[1]);q=urllib.parse.parse_qs(u.query);print(q.get("code_challenge",[""])[0])' "$authorize_url")"
if [[ -z "$state" || -z "$code_challenge" ]]; then
  echo "authorize URL missing required parameters: $authorize_url" >&2
  exit 1
fi

echo "[2/9] Signup smoke user"
new_email="oauth-bff-smoke-$(openssl rand -hex 4)@example.com"
new_password="Password123!"
curl -sS -X POST "$GUARD_BASE_URL/api/v1/auth/password/signup" \
  -H 'X-Auth-Mode: json' \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"email\":\"$new_email\",\"password\":\"$new_password\",\"first_name\":\"OAuth\",\"last_name\":\"BFF\"}" >/dev/null

echo "[3/9] Password login for smoke user"
login_json="$(curl -sS -X POST "$GUARD_BASE_URL/api/v1/auth/password/login" \
  -H 'X-Auth-Mode: json' \
  -H 'Content-Type: application/json' \
  -d "{\"tenant_id\":\"$TENANT_ID\",\"email\":\"$new_email\",\"password\":\"$new_password\"}")"
user_access="$(printf '%s' "$login_json" | jq -r '.access_token // empty')"
if [[ -z "$user_access" ]]; then
  echo "password login failed: $login_json" >&2
  exit 1
fi

echo "[4/9] GET /oauth/authorize (reuse BFF state/challenge)"
nonce="bff-nonce-$(openssl rand -hex 8)"
encoded_redirect="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=""))' "$REDIRECT_URI")"
encoded_scope="$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=""))' "$BFF_SCOPE")"
authorize_direct="$GUARD_BASE_URL/oauth/authorize?client_id=$CLIENT_ID&redirect_uri=$encoded_redirect&response_type=code&scope=$encoded_scope&state=$state&nonce=$nonce&code_challenge=$code_challenge&code_challenge_method=S256"
consent_json="$(curl -sS -H "Authorization: Bearer $user_access" "$authorize_direct")"
consent_challenge="$(printf '%s' "$consent_json" | jq -r '.consent_challenge // empty')"
if [[ -z "$consent_challenge" ]]; then
  echo "authorize did not return consent challenge: $consent_json" >&2
  exit 1
fi

echo "[5/9] Approve consent"
consent_headers="$tmp_dir/consent-headers.txt"
curl -sS -o /dev/null -D "$consent_headers" -X POST "$GUARD_BASE_URL/oauth/authorize/decision" \
  -H "Authorization: Bearer $user_access" \
  -H 'Content-Type: application/json' \
  -d "{\"approved\":true,\"consent_challenge\":\"$consent_challenge\",\"client_id\":\"$CLIENT_ID\",\"redirect_uri\":\"$REDIRECT_URI\",\"response_type\":\"code\",\"scope\":\"$BFF_SCOPE\",\"state\":\"$state\",\"nonce\":\"$nonce\",\"code_challenge\":\"$code_challenge\",\"code_challenge_method\":\"S256\"}" || true
callback_location="$(grep -i '^Location:' "$consent_headers" | awk '{print $2}' | tr -d '\r')"
if [[ -z "$callback_location" ]]; then
  echo "missing callback Location after consent" >&2
  exit 1
fi

echo "[6/9] Call BFF callback with same session cookie"
curl -sS -o /dev/null -w '%{http_code}' -b "$cookies_file" -c "$cookies_file" "$callback_location" > "$tmp_dir/callback-status.txt"
callback_status="$(cat "$tmp_dir/callback-status.txt")"
if [[ "$callback_status" != "302" && "$callback_status" != "303" ]]; then
  echo "unexpected callback status: $callback_status" >&2
  exit 1
fi

echo "[7/9] Call BFF /api/me (should be authenticated)"
me_json="$(curl -sS -b "$cookies_file" "$BACKEND_BASE_URL/api/me")"
me_email="$(printf '%s' "$me_json" | jq -r '.email // empty')"
if [[ "$me_email" != "$new_email" ]]; then
  echo "unexpected /api/me response: $me_json" >&2
  exit 1
fi

echo "[8/9] Logout BFF session"
curl -sS -X POST -b "$cookies_file" "$BACKEND_BASE_URL/api/logout" >/dev/null

echo "[9/9] SUCCESS"
echo "OAuth2 BFF smoke succeeded for user: $new_email"
