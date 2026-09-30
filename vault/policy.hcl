// Least-privilege policy for the Juice Shop API container.
// It may read its own signing key and nothing else.
path "secret/data/juice-shop" {
  capabilities = ["read"]
}

path "secret/metadata/juice-shop" {
  capabilities = ["read"]
}

// Allow the container to renew/re-authenticate, nothing more.
path "auth/approle/login" {
  capabilities = ["create", "update"]
}

// Explicit deny - anything else is refused.
path "secret/*" {
  capabilities = ["deny"]
}

path "sys/*" {
  capabilities = ["deny"]
}
