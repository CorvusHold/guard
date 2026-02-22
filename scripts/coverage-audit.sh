#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${ROOT_DIR}/reports/pr"
mkdir -p "${REPORT_DIR}"

SCOPE="${1:-all}"
RUN_BACKEND=false
RUN_SDK_GO=false
RUN_SDK_TS=false
case "${SCOPE}" in
  all)
    RUN_BACKEND=true
    RUN_SDK_GO=true
    RUN_SDK_TS=true
    ;;
  backend)
    RUN_BACKEND=true
    ;;
  go)
    RUN_SDK_GO=true
    ;;
  ts)
    RUN_SDK_TS=true
    ;;
  *)
    echo "[coverage-audit] unsupported scope: ${SCOPE} (expected: all|backend|go|ts)" >&2
    exit 1
    ;;
esac

BACKEND_PROFILE="${REPORT_DIR}/backend.cover.out"
SDK_GO_PROFILE="${REPORT_DIR}/sdk-go.cover.out"
SDK_TS_SUMMARY="${REPORT_DIR}/sdk-ts.coverage-summary.json"
BACKEND_JSON="${REPORT_DIR}/coverage-backend.json"
SDK_GO_JSON="${REPORT_DIR}/coverage-sdk-go.json"
SDK_TS_JSON="${REPORT_DIR}/coverage-sdk-ts.json"
MERGED_JSON="${REPORT_DIR}/coverage-summary.json"

audit_go_profile() {
  local profile="$1"
  local scope="$2"
  local output="$3"

  python3 - "$profile" "$scope" "$output" <<'PY'
import json, os, re, sys
from collections import defaultdict

profile, scope, output = sys.argv[1], sys.argv[2], sys.argv[3]
line_re = re.compile(r'^(?P<file>.+):\d+\.\d+,\d+\.\d+\s+(?P<stmts>\d+)\s+(?P<count>\d+)$')

excluded_patterns = [
    '.gen.go',
    '_gen.go',
    '/internal/db/sqlc/',
    '/sdk/go/api.gen.go',
    '/sdk/go/generate.go',
]

covered = defaultdict(float)
total = defaultdict(float)

with open(profile, 'r', encoding='utf-8') as f:
    for raw in f:
        raw = raw.strip()
        if not raw or raw.startswith('mode:'):
            continue
        m = line_re.match(raw)
        if not m:
            continue
        file_path = m.group('file').replace('\\', '/')
        stmts = float(m.group('stmts'))
        count = int(m.group('count'))
        # Exclude generated files from package coverage enforcement.
        if any(p in file_path or file_path.endswith(p) for p in excluded_patterns):
            continue

        pkg = os.path.dirname(file_path)
        for marker, prefix in [('/internal/', 'internal/'), ('/cmd/', 'cmd/'), ('/sdk/go/', 'sdk/go/')]:
            if marker in pkg:
                pkg = prefix + pkg.split(marker, 1)[1]
                break
        total[pkg] += stmts
        if count > 0:
            covered[pkg] += stmts

packages = []
for pkg in sorted(total.keys()):
    pct = (covered[pkg] / total[pkg] * 100.0) if total[pkg] else 0.0
    packages.append({
        'package': pkg,
        'coverage_percent': round(pct, 2),
        'covered_statements': int(covered[pkg]),
        'total_statements': int(total[pkg]),
    })

overall_cov = sum(covered.values())
overall_total = sum(total.values())
overall_pct = (overall_cov / overall_total * 100.0) if overall_total else 0.0

with open(output, 'w', encoding='utf-8') as f:
    json.dump({
        'scope': scope,
        'overall_coverage_percent': round(overall_pct, 2),
        'excluded_file_patterns': excluded_patterns,
        'packages': packages,
    }, f, indent=2)
PY
}

if [[ "${RUN_BACKEND}" == "true" ]]; then
  echo "[coverage-audit] Backend Go coverage..."
  (
    cd "${ROOT_DIR}"
    go test -covermode=atomic -coverprofile="${BACKEND_PROFILE}" ./internal/... ./cmd/...
  )
  audit_go_profile "${BACKEND_PROFILE}" "backend-go" "${BACKEND_JSON}"
fi

if [[ "${RUN_SDK_GO}" == "true" ]]; then
  echo "[coverage-audit] SDK Go coverage..."
  (
    cd "${ROOT_DIR}/sdk/go"
    go test -covermode=atomic -coverprofile="${SDK_GO_PROFILE}" ./...
  )
  audit_go_profile "${SDK_GO_PROFILE}" "sdk-go" "${SDK_GO_JSON}"
fi

if [[ "${RUN_SDK_TS}" == "true" ]]; then
  echo "[coverage-audit] SDK TS coverage..."
  (
    cd "${ROOT_DIR}/sdk/ts"
    npm ci
    npx vitest run --coverage.enabled=true --coverage.reporter=json-summary --coverage.reportsDirectory=coverage
  )
  cp "${ROOT_DIR}/sdk/ts/coverage/coverage-summary.json" "${SDK_TS_SUMMARY}"
  python3 - "${SDK_TS_SUMMARY}" "${SDK_TS_JSON}" <<'PY'
import json, os, sys
summary_path, output = sys.argv[1], sys.argv[2]
with open(summary_path, 'r', encoding='utf-8') as f:
    summary = json.load(f)

pkg_totals = {}
for file, data in summary.items():
    if file == 'total':
        continue
    norm = file.replace('\\', '/')
    if '/src/generated/' in norm:
        continue
    if '/src/' in norm:
        rel = norm.split('/src/', 1)[1]
        parts = rel.split('/')
        if len(parts) > 1:
            pkg = 'sdk/ts/src/' + parts[0]
        else:
            stem = parts[0].split('.', 1)[0]
            pkg = 'sdk/ts/src/' + stem
    else:
        pkg = 'sdk/ts/src/_other'

    entry = pkg_totals.setdefault(pkg, {'covered': 0.0, 'total': 0.0})
    lines = data.get('lines', {})
    entry['covered'] += float(lines.get('covered', 0.0))
    entry['total'] += float(lines.get('total', 0.0))

packages = []
overall_covered = 0.0
overall_total = 0.0
for pkg in sorted(pkg_totals):
    covered = pkg_totals[pkg]['covered']
    total = pkg_totals[pkg]['total']
    pct = (covered / total * 100.0) if total else 0.0
    overall_covered += covered
    overall_total += total
    packages.append({
        'package': pkg,
        'coverage_percent': round(pct, 2),
        'covered_lines': int(covered),
        'total_lines': int(total),
    })

overall_pct = (overall_covered / overall_total * 100.0) if overall_total else 0.0
with open(output, 'w', encoding='utf-8') as f:
    json.dump({
        'scope': 'sdk-ts',
        'overall_coverage_percent': round(overall_pct, 2),
        'packages': packages,
    }, f, indent=2)
PY
fi

if [[ "${SCOPE}" == "all" ]]; then
python3 - "${BACKEND_JSON}" "${SDK_GO_JSON}" "${SDK_TS_JSON}" "${MERGED_JSON}" <<'PY'
import json, sys
backend, sdk_go, sdk_ts, output = sys.argv[1:]
with open(backend, 'r', encoding='utf-8') as f:
    b = json.load(f)
with open(sdk_go, 'r', encoding='utf-8') as f:
    g = json.load(f)
with open(sdk_ts, 'r', encoding='utf-8') as f:
    t = json.load(f)

all_packages = []
for section in (b, g, t):
    for pkg in section.get('packages', []):
        p = dict(pkg)
        p['scope'] = section.get('scope')
        all_packages.append(p)

summary = {
    'generated_by': 'scripts/coverage-audit.sh',
    'threshold_percent': 80,
    'scopes': {
        'backend-go': b.get('overall_coverage_percent', 0),
        'sdk-go': g.get('overall_coverage_percent', 0),
        'sdk-ts': t.get('overall_coverage_percent', 0),
    },
    'packages': all_packages,
}

with open(output, 'w', encoding='utf-8') as f:
    json.dump(summary, f, indent=2)
PY

echo "[coverage-audit] Wrote summary: ${MERGED_JSON}"
fi
