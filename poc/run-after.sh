#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Re-run the identical exploits against the HARDENED application.
# Every script should print BLOCKED, and its control check should show the
# legitimate feature still works.
#
#   ./poc/run-after.sh http://localhost:8080
# ---------------------------------------------------------------------------
set -uo pipefail

TARGET="${1:-http://localhost:8080}"
BASELINE="${2:-app/lib/insecurity.ts}"
OUT="${OUT:-evidence/after.txt}"

cd "$(dirname "$0")/.."
mkdir -p evidence

{
  echo "IE3142 - exploit evidence: HARDENED APPLICATION"
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
