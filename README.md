# Devops-Security
DevSecOps pipeline for securing an open-source application using Docker, GitHub Actions, SAST, dependency scanning, secrets scanning, and container image security scanning.

**IE3142 — DevOps Security · Year 3 Semester 1 · Group project (4 members)**

A hardened fork of **[OWASP Juice Shop v20.2.0](https://github.com/juice-shop/juice-shop)**
with a working DevSecOps pipeline: two containerised tiers, five findings that
were **exploited first and fixed afterwards**, and four automated security gates
in GitHub Actions, plus an OWASP ZAP DAST scan and HashiCorp Vault secret
injection as optional extras.

> Juice Shop is deliberately insecure training software. We use it *as the
> subject* of the exercise: every vulnerability below is demonstrated working
> against the unmodified application, then fixed, then re-attacked to prove the
> fix holds. This repository is not a template for a real shop — it is evidence
> that the pipeline catches real bugs.

---

## 1. Architecture

```
                       ┌──────────────────────── public internet ──────┐
  browser  ───────────►│  web  (NGINX 1.28 alpine)          :8080      │
                       │  · serves the Angular SPA bundle             │
                       │  · security headers, rate limits, 2 MiB cap  │
                       │  · reverse proxies /rest /api /socket.io     │
                       └────────────────────┬─────────────────────────┘
                                            │  frontend network (bridge)
                       ┌────────────────────▼─────────────────────────┐
                       │  api  (Node 22 · Express · Sequelize)  :3000  │
                       │  · REST API  · JWT auth  · SQLite on a volume│
                       └────────────────────┬─────────────────────────┘
                                            │  backend network (internal: true)
                       ┌────────────────────▼─────────────────────────┐
                       │  vault (HashiCorp Vault 1.18)         :8200   │
                       │  · issues jwt_private_key at runtime          │
                       └──────────────────────────────────────────────┘
```

Three trust boundaries: **internet → NGINX**, **NGINX → API**, **API → Vault**.
Only `web` publishes a port. The `backend` network is `internal: true`, so the
secret store has no route to the internet and is unreachable from the web tier.

| Component | Technology | Dockerfile |
|---|---|---|
| Web tier | NGINX 1.28 alpine | `docker/web/Dockerfile` |
| API tier | Node 22 · Express · Sequelize · SQLite | `docker/api/Dockerfile` |
| Secret store (optional) | HashiCorp Vault 1.18 | `docker-compose.vault.yml` |

---

## 2. Quick start

```bash
git clone <this-repo> && cd <this-repo>

./scripts/setup.sh          # creates .env and a fresh RSA signing key pair
docker compose up --build   # first build takes ~10 min (Angular compile)

open http://localhost:8080
```

With Vault instead of a Docker secret:

```bash
docker compose -f docker-compose.yml -f docker-compose.vault.yml up --build
```

Requirements: Docker Engine 24+ with Compose v2, and Node 22 if you want to run
the exploit scripts outside a container. Nothing else — no cloud account, no
Kubernetes, no paid subscription.

---

## 3. The five vulnerabilities

| ID | Vulnerability | CWE / OWASP | Where | PoC |
|---|---|---|---|---|
| V1 | SQL injection → authentication bypass | CWE-89 · A03:2021 | `app/routes/login.ts` | `poc/01-sqli-auth-bypass.mjs` |
| V2 | UNION SQL injection → credential dump | CWE-89 · A03:2021 | `app/routes/search.ts` | `poc/02-union-sqli-exfiltration.mjs` |
| V3 | Server-side request forgery | CWE-918 · A10:2021 | `app/routes/profileImageUrlUpload.ts` | `poc/03-ssrf-profile-image.mjs` |
| V4 | Broken object level authorization | CWE-639 · API1:2023 | `app/routes/basket.ts` | `poc/04-bola-basket.mjs` |
| V5 | Hard-coded RSA private key → token forgery | CWE-798 · A02:2021 | `app/lib/insecurity.ts` | `poc/05-hardcoded-key-jwt-forgery.mjs` |

Every PoC is a self-contained Node script with **no third-party dependencies**
that prints `EXPLOITED` or `BLOCKED` and includes a **control check** proving
the legitimate feature still works after the fix.

### Reproduce the before/after evidence

```bash
# Unmodified upstream application (a plain clone of juice-shop v20.2.0)
git clone --branch v20.2.0 https://github.com/juice-shop/juice-shop.git /tmp/js-baseline
cd /tmp/js-baseline && npm ci && npm start          # listens on :3000
node /path/to/this/repo/poc/01-sqli-auth-bypass.mjs --url http://localhost:3000   # EXPLOITED
node /path/to/this/repo/poc/05-hardcoded-key-jwt-forgery.mjs \
     --url http://localhost:3000 --baseline /tmp/js-baseline/lib/insecurity.ts    # EXPLOITED

# Hardened application in this repository
docker compose up --build
node poc/01-sqli-auth-bypass.mjs --url http://localhost:8080                      # BLOCKED
```

`poc/run-before.sh` and `poc/run-after.sh` run all five in sequence and tee the
output into `evidence/`.

---

## 4. The CI/CD pipeline

`.github/workflows/devsecops.yml` runs on every push and pull request:

| Gate | Tool | Blocking threshold |
|---|---|---|
| Build & test | `npm ci` + `tsc` + unit tests | any failure |
| **G1 SAST** | Semgrep (`p/typescript`, `p/security-audit`, `p/secrets`, `.semgrep/rules.yml`) | any **new** finding vs `.semgrep/baseline.json` |
| **G2 SCA** | `npm audit --omit=dev` | **CRITICAL** advisories |
| **G3 Secrets** | Gitleaks (full history) | any secret |
| **G4 Container** | Trivy image + Trivy IaC + CycloneDX SBOM | **HIGH/CRITICAL**, fixable |
| Extra — DAST | OWASP ZAP baseline against the running stack | reports only |

**G2 currently blocks the build for real**: the inherited dependency tree carries
7 critical and 16 high advisories (see `docs/REPORT.md`, §5). That red run is
included as evidence rather than hidden.

**Proving the gate blocks.** Trigger `Actions → DevSecOps Pipeline → Run
workflow → demo_gate_failure`. The job reintroduces the V1 SQL injection into
`app/routes/login.ts` and *succeeds only if the SAST gate fails*, printing the
two new findings (`express-sequelize-injection` and
`ie3142-sqli-sequelize-template-interpolation`) as proof.

Run the gate locally:

```bash
./scripts/sast-gate.sh                     # fails on NEW findings
UPDATE_BASELINE=1 ./scripts/sast-gate.sh   # re-record the accepted set
```

---

## 5. Secrets management

**No credential, key or connection string is committed to this repository.**

| Secret | How it is provisioned |
|---|---|
| `JWT_PRIVATE_KEY` (RSA signing key) | Docker secret `./secrets/jwt_private_key` (git-ignored), or HashiCorp Vault via AppRole at container start-up |
| `VAULT_TOKEN` | `.env`, git-ignored, never in the image |
| `GITHUB_TOKEN` | injected automatically by Actions |
| `.env` values | GitHub Actions encrypted secrets in CI |

The API entrypoint (`docker/api/entrypoint.sh`) **fails closed**: if the key
cannot be obtained the container exits non-zero rather than falling back to a
baked-in default — the exact failure mode that made V5 possible.

Rotate the key with `./scripts/generate-keys.sh`.

---

## 6. Repository layout

```
.github/workflows/devsecops.yml   CI/CD pipeline and the four gates
.semgrep/rules.yml                custom Semgrep rules (SSRF, BOLA, SQLi, keys)
.semgrep/baseline.json            reviewed, accepted findings (gate is diff-based)
.gitleaks.toml                    secrets-scanning configuration
app/                              hardened fork of OWASP Juice Shop v20.2.0
docker/api/                       API Dockerfile + secret-injecting entrypoint
docker/web/                       NGINX Dockerfile + hardened nginx.conf
docker-compose.yml                two tiers, three trust boundaries
docker-compose.vault.yml          Vault overlay (runtime secret injection)
vault/                            seed script + least-privilege policy
poc/                              five exploit scripts + runner scripts
scripts/                          setup, key rotation, SAST gate
docs/                             architecture diagram, threat model, report
```

---

## 7. Licence and attribution

The application code in `app/` is OWASP Juice Shop, © Bjoern Kimminich and
contributors, MIT licensed — see `app/LICENSE`. All security fixes, custom
rules, pipeline configuration, exploit scripts and documentation are the group's
own work and are described in `docs/REPORT.md`.
