#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUMMARY_JSON="${ROOT_DIR}/reports/pr/coverage-summary.json"
THRESHOLD="${COVERAGE_THRESHOLD:-80}"

if [[ ! -f "${SUMMARY_JSON}" ]]; then
  echo "coverage summary missing: ${SUMMARY_JSON}" >&2
  echo "run: make coverage-audit" >&2
  exit 1
fi

python3 - "${SUMMARY_JSON}" "${THRESHOLD}" <<'PY'
import json, sys
summary_path = sys.argv[1]
threshold = float(sys.argv[2])

with open(summary_path, 'r', encoding='utf-8') as f:
    summary = json.load(f)

violations = []
for pkg in summary.get('packages', []):
    name = pkg.get('package', '')
    scope = pkg.get('scope', '')

    # Exclusions for generated/spec artifacts and non-actionable roots.
    if '/generated' in name or name.endswith('/mock') or name.endswith('/mocks'):
        continue
    if name in ('cmd', 'internal', 'sdk/go', 'sdk/ts/src/_other'):
        continue

    total = pkg.get('total_statements')
    if total is None:
        total = pkg.get('total_lines')
    if not total:
        # No measurable statements/lines in this bucket.
        continue

    pct = float(pkg.get('coverage_percent', 0.0))
    if pct < threshold:
        violations.append((scope, name, pct))

if violations:
    print(f"Coverage threshold check failed (< {threshold:.2f}%):")
    for scope, name, pct in sorted(violations, key=lambda x: x[2]):
        print(f" - [{scope}] {name}: {pct:.2f}%")
    sys.exit(1)

print(f"Coverage threshold check passed (>= {threshold:.2f}%).")
PY
