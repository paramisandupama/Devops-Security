#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run all five exploits against the UNMODIFIED application and capture the
# evidence. Every script should print EXPLOITED.
#
#   ./poc/run-before.sh http://localhost:3000 /path/to/juice-shop/lib/insecurity.ts
# ---------------------------------------------------------------------------
set -uo pipefail

TARGET="${1:-http://localhost:3000}"
BASELINE="${2:-/tmp/js-baseline/lib/insecurity.ts}"
OUT="${OUT:-evidence/before.txt}"

cd "$(dirname "$0")/.."
mkdir -p evidence

{
  echo "IE3142 - exploit evidence: VULNERABLE BASELINE"
  echo "target   : $TARGET"
  echo "baseline : $BASELINE"
  echo "date     : $(date -u '+%Y-%m-%d %H:%M:%SZ')"
  echo "node     : $(node --version)"
} | tee "$OUT"

for poc in poc/0[1-5]*.mjs; do
  echo "" | tee -a "$OUT"
  node "$poc" --url "$TARGET" --baseline "$BASELINE" 2>&1 | tee -a "$OUT"
done

echo "" | tee -a "$OUT"
echo "Written to $OUT"
