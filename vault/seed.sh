#!/bin/sh
# ---------------------------------------------------------------------------
# Seeds HashiCorp Vault with the JWT signing key and issues a short-lived
# AppRole credential that the API container uses to read it at start-up.
#
# Runs once, as the "vault-init" one-shot service. Exits non-zero on any error
# so that `depends_on: service_completed_successfully` blocks the API tier.
# ---------------------------------------------------------------------------
set -eu

: "${VAULT_ADDR:?VAULT_ADDR is required}"
: "${VAULT_TOKEN:?VAULT_TOKEN is required}"

echo "[vault-init] waiting for ${VAULT_ADDR} ..."
until vault status >/dev/null 2>&1; do sleep 1; done

echo "[vault-init] enabling kv-v2 at secret/"
vault secrets enable -version=2 -path=secret kv 2>/dev/null || true

echo "[vault-init] writing secret/juice-shop"
# jq is not in the Vault image, so the PEM is embedded with awk.
JWT_PRIVATE_KEY="$(cat /run/secrets/jwt_private_key)"
escaped="$(printf '%s' "$JWT_PRIVATE_KEY" | awk '{printf "%s\\n", $0}')"
vault kv put secret/juice-shop jwt_private_key="$escaped"

echo "[vault-init] writing the least-privilege policy"
vault policy write juice-shop-api /vault/policy.hcl

echo "[vault-init] enabling AppRole"
vault auth enable approle 2>/dev/null || true
vault write auth/approle/role/juice-shop-api \
  token_policies="juice-shop-api" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h \
  secret_id_num_uses=0

mkdir -p /run/vault
vault read  -field=role_id   auth/approle/role/juice-shop-api/role-id   > /run/vault/role_id
vault write -f -field=secret_id auth/approle/role/juice-shop-api/secret-id > /run/vault/secret_id
chmod 640 /run/vault/role_id /run/vault/secret_id

echo "[vault-init] done - AppRole credentials written to /run/vault"
