#!/usr/bin/env bash
set -euo pipefail

# seed-sso-portal-e2e.sh
# Helper to mint a bootstrap admin token and tenant for the SSO Setup Portal
# fully wired E2E. Produces .env.sso-portal-e2e with:
#   - SSO_PORTAL_E2E_TENANT_ID
#   - SSO_PORTAL_E2E_ADMIN_TOKEN
# The admin token is a bootstrap token signed with JWT_SIGNING_KEY and belongs
# to an admin user in the bootstrap tenant.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_FILE=".env.sso-portal-e2e"
: >"$OUT_FILE"

compose="docker compose -f docker-compose.test.yml"

ENV_OUT="$(
  $compose exec -T api_test sh -lc '
    set -e
    export PATH=/usr/local/go/bin:/go/bin:$PATH
    eval "$(scripts/bootstrap-token.sh --prefix sso-portal-e2e)"
    printf "SSO_PORTAL_E2E_TENANT_ID=%s\n" "$BOOTSTRAP_TENANT_ID"
    printf "SSO_PORTAL_E2E_ADMIN_TOKEN=%s\n" "$GUARD_API_TOKEN"
    printf "SSO_PORTAL_E2E_ADMIN_USER_ID=%s\n" "$BOOTSTRAP_USER_ID"
  '
)"

# Load the generated env vars into this shell so we can seed the provider
eval "$ENV_OUT"

PROVIDER_SLUG="portal-e2e-oidc"

# Seed a native OIDC provider directly into the test DB. This avoids relying on
# external OIDC discovery during tests while still exercising the real portal
# link generator and portal session endpoints.
$compose exec -T db_test psql -U guard -d guard_test <<SQL
INSERT INTO sso_providers (
    tenant_id, name, slug, provider_type,
    issuer, client_id, client_secret,
    enabled, allow_signup, trust_email_verified,
    domains,
    created_by, updated_by
) VALUES (
    '${SSO_PORTAL_E2E_TENANT_ID}'::uuid,
    'Portal E2E OIDC',
    '${PROVIDER_SLUG}',
    'oidc',
    'https://accounts.google.com',
    'portal-e2e-client',
    'portal-e2e-secret',
    true,
    true,
    true,
    ARRAY['example.com']::text[],
    '${SSO_PORTAL_E2E_ADMIN_USER_ID}'::uuid,
    '${SSO_PORTAL_E2E_ADMIN_USER_ID}'::uuid
)
ON CONFLICT (tenant_id, slug) DO NOTHING;
SQL

printf '%s\n' "$ENV_OUT" >>"$OUT_FILE"
printf 'SSO_PORTAL_E2E_PROVIDER_SLUG=%s\n' "$PROVIDER_SLUG" >>"$OUT_FILE"

echo "Wrote SSO portal E2E env to $OUT_FILE (tenant, admin token, admin user, provider slug)"
