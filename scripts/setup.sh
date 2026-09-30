#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# One-shot local setup.
#   ./scripts/setup.sh && docker compose up --build
# Then open http://localhost:8080
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> 1/3  Creating .env from the template"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "      created .env - review it before production use"
else
  echo "      .env already exists, leaving it alone"
fi

echo "==> 2/3  Generating the JWT signing key pair"
./scripts/generate-keys.sh

echo "==> 3/3  Checking the toolchain"
command -v docker >/dev/null 2>&1 && docker --version || { echo "      docker is required"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "      docker compose v2 is required"; exit 1; }

cat <<'TXT'

Setup complete.

  Start the stack:      docker compose up --build
  Open the shop:        http://localhost:8080
  With Vault instead:   docker compose -f docker-compose.yml -f docker-compose.vault.yml up --build

  Re-run the exploits:  node poc/01-sqli-auth-bypass.mjs --url http://localhost:8080
  Run the SAST gate:    ./scripts/sast-gate.sh
TXT
