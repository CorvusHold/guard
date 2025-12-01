#!/usr/bin/env bash
set -euo pipefail

# bootstrap-token.sh - helper that mints a short-lived admin JWT via the Go utility
# Usage:
#   scripts/bootstrap-token.sh [flags passed to cmd/bootstrap-token]
#
# By default it enforces env output (KEY=value pairs) so callers can eval/source it.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GO_CMD=${GO_CMD:-go}

args=()
has_output_flag=false
while (($#)); do
  case "$1" in
    -o|--output)
      has_output_flag=true
      args+=("$1")
      shift
      if (($#)); then
        args+=("$1")
        shift
      fi
      ;;
    --output=*)
      has_output_flag=true
      args+=("$1")
      shift
      ;;
    *)
      args+=("$1")
      shift
      ;;
  esac
done

if ! $has_output_flag; then
  args+=("--output" "env")
fi

exec "$GO_CMD" run ./cmd/bootstrap-token "${args[@]}"
