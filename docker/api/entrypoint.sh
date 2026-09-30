#!/bin/sh
# ---------------------------------------------------------------------------
# Entrypoint for the API container.
#
# Secrets are resolved at START-UP, never at build time and never from the
# image. Two providers are supported and are selected by SECRET_PROVIDER:
#
#   file   : read the PEM from a Docker/Kubernetes secret file
#            (default path /run/secrets/jwt_private_key)
#   vault  : authenticate to HashiCorp Vault with AppRole and read the PEM
#            from the kv-v2 mount (see docker-compose.vault.yml)
#
# If no secret can be obtained the container exits non-zero. Failing closed is
# intentional: the application must never fall back to a baked-in key.
# ---------------------------------------------------------------------------
set -eu

SECRET_PROVIDER="${SECRET_PROVIDER:-file}"
JWT_SECRET_FILE="${JWT_SECRET_FILE:-/run/secrets/jwt_private_key}"

log() { echo "[entrypoint] $*"; }

case "$SECRET_PROVIDER" in

  file)
    log "provider=file  reading ${JWT_SECRET_FILE}"
    if [ ! -r "$JWT_SECRET_FILE" ]; then
      log "FATAL: ${JWT_SECRET_FILE} is missing or unreadable."
      log "       Generate a key pair with ./scripts/generate-keys.sh first."
      exit 1
    fi
    JWT_PRIVATE_KEY="$(cat "$JWT_SECRET_FILE")"
    export JWT_PRIVATE_KEY
    ;;

  vault)
    log "provider=vault  authenticating to ${VAULT_ADDR:-http://vault:8200}"
    : "${VAULT_ROLE_ID_FILE:?VAULT_ROLE_ID_FILE is required for the vault provider}"
    : "${VAULT_SECRET_ID_FILE:?VAULT_SECRET_ID_FILE is required for the vault provider}"
    ROLE_ID="$(cat "$VAULT_ROLE_ID_FILE")"
    SECRET_ID="$(cat "$VAULT_SECRET_ID_FILE")"

    LOGIN="$(wget -qO- --post-data "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}" \
             "${VAULT_ADDR:-http://vault:8200}/v1/auth/approle/login")"
    VAULT_TOKEN="$(printf '%s' "$LOGIN" | sed -n 's/.*"client_token":"\([^"]*\)".*/\1/p')"
    if [ -z "$VAULT_TOKEN" ]; then
      log "FATAL: AppRole login failed: $LOGIN"
      exit 1
    fi

    # Do not let the token leak into the application process environment.
    SECRET_JSON="$(wget -qO- --header="X-Vault-Token: ${VAULT_TOKEN}" \
                   "${VAULT_ADDR:-http://vault:8200}/v1/${VAULT_KV_MOUNT:-secret}/data/${VAULT_SECRET_PATH:-juice-shop}")"
    JWT_PRIVATE_KEY="$(printf '%s' "$SECRET_JSON" \
      | sed -n 's/.*"jwt_private_key":"\([^"]*\)".*/\1/p' \
      | sed 's/\\n/\n/g')"
    if [ -z "$JWT_PRIVATE_KEY" ]; then
      log "FATAL: secret juice-shop/jwt_private_key was empty."
      exit 1
    fi
    unset VAULT_TOKEN
    export JWT_PRIVATE_KEY
    log "provider=vault  secret retrieved (${#JWT_PRIVATE_KEY} bytes)"
    ;;

  *)
    log "FATAL: unknown SECRET_PROVIDER '$SECRET_PROVIDER'"
    exit 1
    ;;
esac

log "starting: $*"
exec "$@"
