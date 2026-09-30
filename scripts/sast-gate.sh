#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run Semgrep and apply the quality gate.
#
#   ./scripts/sast-gate.sh                          # fail on NEW findings
#   UPDATE_BASELINE=1 ./scripts/sast-gate.sh        # re-record the accepted set
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

CONFIG_ARGS=(
  --config p/typescript
  --config p/security-audit
  --config p/secrets
  --config .semgrep/rules.yml
)
SCAN_PATHS=(app/routes app/lib)
OUT="$(mktemp -d)/semgrep.json"
BASELINE=".semgrep/baseline.json"

echo "==> Running Semgrep over ${SCAN_PATHS[*]}"
semgrep "${CONFIG_ARGS[@]}" \
  --metrics=off --quiet --no-git-ignore \
  --exclude node_modules --exclude build --exclude frontend \
  --json --output "$OUT" "${SCAN_PATHS[@]}" || true

TOTAL="$(python3 -c "import json;print(len(json.load(open('$OUT'))['results']))")"
echo "==> Semgrep reported $TOTAL finding(s)"

if [ "${UPDATE_BASELINE:-0}" = "1" ]; then
  python3 scripts/sast-gate.py "$OUT" "$BASELINE" --update-baseline
  exit 0
fi

set +e
python3 scripts/sast-gate.py "$OUT" "$BASELINE"
STATUS=$?
set -e
exit $STATUS
