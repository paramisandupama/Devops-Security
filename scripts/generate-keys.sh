#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Generate the JWT signing key pair used by the API container.
#
# The PRIVATE key is written to ./secrets/jwt_private_key, which is
#   * git-ignored,
#   * mounted into the container as a Docker secret (not copied into the image),
#   * or seeded into HashiCorp Vault by the Vault overlay.
#
# The PUBLIC key replaces app/encryptionkeys/jwt.pub. A public key is not a
# secret, so it is safe to commit - but it MUST match the private key in use,
# which is why rotating means regenerating both together.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")/.."

KEY_BITS="${KEY_BITS:-2048}"
SECRETS_DIR="secrets"
PRIVATE_KEY="$SECRETS_DIR/jwt_private_key"
PUBLIC_KEY="app/encryptionkeys/jwt.pub"

echo "==> Generating a ${KEY_BITS}-bit RSA key pair"
mkdir -p "$SECRETS_DIR"
umask 077
if openssl genrsa -traditional -out "$PRIVATE_KEY" "$KEY_BITS" 2>/dev/null; then
  :
else
  # OpenSSL 3 defaults to PKCS#8; -traditional produces the PKCS#1 PEM that
  # the application expects.
  openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEY_BITS" \
    -traditional -out "$PRIVATE_KEY"
fi
umask 022

openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null

echo "==> Private key : $PRIVATE_KEY   (git-ignored, mounted as a Docker secret)"
echo "==> Public key  : $PUBLIC_KEY    (committed - it is not a secret)"
echo
echo "Rotate both together whenever you suspect the private key has leaked:"
echo "    ./scripts/generate-keys.sh && docker compose restart api"
