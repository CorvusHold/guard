#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bash "$SCRIPT_DIR/bootstrap.sh"
bash "$SCRIPT_DIR/oauth2-smoke.sh"

cat <<'EOF'

Workflow complete.

Next: run the interactive SPA demo
  cd examples/oauth2-poc
  pnpm install
  pnpm dev

Open http://localhost:3003 and validate:
  1) Sign in with OAuth2
  2) Signup helper then OAuth2
  3) Logout (revoke)
EOF
