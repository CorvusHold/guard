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
warnings = []
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
    elif pct < 100.0:
        # Coverage between threshold and 100% - warn to encourage improvement
        warnings.append((scope, name, pct))

# Display warnings first (non-blocking)
if warnings:
    print(f"\n⚠️  Coverage warnings ({threshold:.2f}% <= coverage < 100%):")
    for scope, name, pct in sorted(warnings, key=lambda x: x[2]):
        gap = 100.0 - pct
        print(f"   [{scope}] {name}: {pct:.2f}% (gap: {gap:.2f}%)")
    print(f"\nThese packages meet the threshold but could be improved.\n")

# Display violations (blocking)
if violations:
    print(f"❌ Coverage threshold check FAILED (< {threshold:.2f}%):")
    for scope, name, pct in sorted(violations, key=lambda x: x[2]):
        gap = threshold - pct
        print(f"   [{scope}] {name}: {pct:.2f}% (gap: {gap:.2f}%)")
    print(f"\nCI will fail. Add tests to bring these packages above {threshold:.2f}%.\n")
    sys.exit(1)

print(f"✅ Coverage threshold check passed (>= {threshold:.2f}%).")
if not warnings:
    print(f"🎉 Perfect! All measured packages have 100% coverage.")
PY
