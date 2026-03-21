# MILNET SSO System

**Enterprise Authentication Platform**

An authentication system combining threshold cryptography (FROST), post-quantum key exchange (ML-KEM-768), server-blind password auth (OPAQUE), forward-secret sessions (HKDF ratchet), OIDC/OAuth2, FIDO2/WebAuthn, and defense-in-depth process isolation.

**Live:** [http://34.44.125.235:8080](http://34.44.125.235:8080)
**GitHub:** [github.com/divyamohan1993/enterprise-sso-system](https://github.com/divyamohan1993/enterprise-sso-system)

## One-Click Deployment

```bash
git clone https://github.com/divyamohan1993/enterprise-sso-system.git
cd enterprise-sso-system/terraform
terraform init && terraform apply -auto-approve
# Wait ~10 min for build. URL printed at end.
```

## What's Implemented

### Core Auth Flow (Working End-to-End)
- **Gateway** — hash puzzle PoW with adaptive difficulty
- **Orchestrator** — ceremony state machine coordinating auth steps
- **OPAQUE** — real `opaque-ke` 4.0 (RFC 9497 OPRF, server never sees password)
- **TSS** — FROST threshold signing via `frost-ristretto255` 2.2 + ML-DSA-65 PQ signatures
- **Verifier** — O(1) token verification (FROST + ML-DSA + ratchet tag + DPoP)

### Standard SSO Protocol
- **OIDC Discovery** — `/.well-known/openid-configuration`
- **OAuth2 Authorization** — `/oauth/authorize` with PKCE (RFC 7636)
- **Token Endpoint** — `/oauth/token` (JWT ID tokens, HS512 signed)
- **UserInfo** — `/oauth/userinfo`
- **Client Registry** — register service portals as OAuth clients

### Security Features
- **Post-quantum KEM** — real ML-KEM-768 (FIPS 203) via `ml-kem` 0.2
- **Post-quantum signatures** — ML-DSA-65 (FIPS 204) nested over FROST
- **Threshold signing** — real FROST 3-of-5 via `frost-ristretto255` 2.2
- **Session ratcheting** — HKDF-SHA512 chains, wired into token builder + verifier
- **DPoP channel binding** — per-connection key hash verified
- **FIDO2/WebAuthn** — Windows Hello, YubiKey, platform authenticators
- **Duress PIN** — silent lockdown on coercion detection
- **TLS transport** — rustls with self-signed certs
- **BFT audit** — 7-node quorum-based replication
- **Key Transparency** — SHA3-256 Merkle tree with ML-DSA signed tree heads
- **Risk scoring** — 6 weighted signals, step-up auth triggers
- **Adaptive puzzle** — difficulty scales with connection load

### Admin and Frontend
- **REST API** — user/portal/device management with Bearer token auth
- **Web UI** — login, dashboard, portal simulator, audit viewer, security demo
- **First-run onboarding** — superuser creation on initial setup
- **PostgreSQL** — persistent storage (7 tables)
- **Auto-update** — pulls from GitHub every 15 minutes, rebuilds if changes

## Architecture

```
Client --> Gateway (puzzle) --> Orchestrator --> OPAQUE (password, OPRF)
                                             --> TSS (FROST + ML-DSA sign)
           Verifier <-- Token (any service portal verifies independently)
```

| Crate | Purpose |
|-------|---------|
| `common` | Shared types, domain separation, config, DB, duress, witness |
| `crypto` | X-Wing KEM, FROST, ML-DSA, receipts, entropy, DPoP, constant-time |
| `shard` | SHARD IPC protocol + TCP + TLS transport |
| `gateway` | Bastion Gateway: adaptive puzzle + forwarding |
| `orchestrator` | Ceremony state machine + sovereign ceremony |
| `opaque` | OPAQUE password auth (opaque-ke 4.0) + receipts |
| `tss` | Distributed FROST signing + receipt validation |
| `verifier` | Token verification (FROST + ML-DSA + ratchet + DPoP) |
| `ratchet` | Forward-secret HKDF-SHA512 sessions |
| `audit` | Hash-chained audit log + BFT replication |
| `kt` | SHA3-256 Merkle tree + signed tree heads |
| `risk` | Risk scoring + device tier enforcement |
| `admin` | REST API (axum) + static frontend serving |
| `sso-protocol` | OIDC/OAuth2 discovery, authorize, token, PKCE |
| `fido` | FIDO2/WebAuthn registration + authentication |
| `e2e` | Test suite (200+ tests) |

## Deployment

See [DEPLOY.md](DEPLOY.md) for full guide.

| Method | Command |
|--------|---------|
| Terraform (one-click) | `cd terraform && terraform init && terraform apply` |
| Docker Compose | `docker-compose up` |
| Manual | `cargo build --release -p admin && ./target/release/admin` |

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PORT` | 8080 | HTTP port |
| `DATABASE_URL` | postgres://milnet:...@localhost/milnet_sso | PostgreSQL |
| `RUST_LOG` | info | Log level |
| `ADMIN_API_KEY` | (auto-generated) | Admin Bearer token |

## License

MIT — Copyright (c) 2026 Divya Mohan ([dmj.one](https://dmj.one))

AI Architecture Partner: Claude (Anthropic)
