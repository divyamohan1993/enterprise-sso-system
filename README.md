# MILNET SSO System

**Enterprise Authentication Platform**

An authentication system combining threshold cryptography (FROST), post-quantum key exchange (ML-KEM-768), server-blind password auth (OPAQUE), forward-secret sessions (HKDF ratchet), OIDC/OAuth2, FIDO2/WebAuthn, and defense-in-depth process isolation.

**Live:** [https://sso-system.dmj.one](https://sso-system.dmj.one)
**Docs:** [https://sso-system.dmj.one/docs](https://sso-system.dmj.one/docs)
**Demo:** [https://sso-system-demo.dmj.one](https://sso-system-demo.dmj.one)
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
- **Gateway** — hash puzzle PoW with adaptive difficulty + X-Wing hybrid KEM session key establishment
- **Orchestrator** — ceremony state machine with risk scoring on every authentication
- **OPAQUE** — real `opaque-ke` 4.0 (RFC 9497 OPRF, server never sees password)
- **TSS** — distributed FROST 3-of-5 threshold signing with receipt chain validation + ML-DSA-65 PQ signatures
- **Verifier** — O(1) token verification service via SHARD (FROST + ML-DSA + ratchet tag + DPoP)
- **Ratchet** — forward-secret HKDF-SHA512 session management (create, advance, tag generation)
- **Risk Engine** — 6-signal risk scoring computed during every auth (step-up at 0.6, terminate at 0.8)

### Standard SSO Protocol
- **OIDC Discovery** — `/.well-known/openid-configuration`
- **OAuth2 Authorization** — `/oauth/authorize` with PKCE S256 validation (RFC 7636)
- **Token Endpoint** — `/oauth/token` (JWT ID tokens, HS512 signed)
- **UserInfo** — `/oauth/userinfo` (returns real user profile from DB)
- **JWKS** — `/oauth/jwks` (advertises HS512 signing algorithm)
- **Client Registry** — register service portals as OAuth clients
- **Google OAuth** — "Sign in with Google" federated login with auto-enrollment

### Security Features
- **Post-quantum KEM** — X-Wing hybrid combiner (ML-KEM-768 + X25519) wired into gateway sessions
- **Post-quantum signatures** — ML-DSA-65 (FIPS 204) nested over FROST, signs audit entries and tree heads
- **Threshold signing** — distributed FROST 3-of-5 via `frost-ristretto255` 2.2 (coordinator holds NO keys)
- **Session ratcheting** — HKDF-SHA512 chains with client+server entropy, per-session key management
- **DPoP channel binding** — real client public key extracted from auth payload (not random)
- **FIDO2/WebAuthn** — registration + authentication endpoints, Tier 1 ceremony check
- **Duress PIN** — registration endpoint + silent lockdown on detection (downgrades to Tier 4, revokes all sessions)
- **Multi-person ceremonies** — Level 3 (2-person) and Level 4 (3-person) approval with 15-min cooldown
- **TLS transport** — rustls with self-signed certs
- **BFT audit** — 7-node quorum-based replication with ML-DSA-65 signed entries
- **Key Transparency** — SHA3-256 Merkle tree with periodic ML-DSA-65 signed tree heads (every 60s)
- **Witness checkpoints** — periodic ML-DSA-65 signed audit+KT root snapshots (every 5 min)
- **Risk scoring** — 6 weighted signals (device, geo-velocity, network, time, access patterns, failed attempts)
- **Adaptive puzzle** — difficulty scales with connection load
- **Token expiry** — 1-hour max token age enforced in auth middleware
- **Login rate limiting** — 5 attempts per 30 minutes per username, automatic lockout
- **SecurityConfig enforcement** — tier-based token lifetimes (T1:5min, T2:10min, T3:15min, T4:2min)
- **Secret persistence** — cryptographic keys survive restarts via PostgreSQL-backed storage

### Admin and Frontend
- **REST API** — user/portal/device/ceremony management with Bearer token auth
- **Web UI** — login, admin dashboard, user portal, audit viewer, security demo
- **Integration Docs** — `/docs` page with getting started guide, code samples (7 languages), API reference, curl examples
- **Google OAuth** — "Sign in with Google" button on OAuth authorize page, auto-enrollment as Tier 4
- **First-run onboarding** — superuser creation on initial setup
- **PostgreSQL** — persistent storage (10 tables: users, devices, portals, audit_log, sessions, oauth_codes, server_config, fido_credentials, key_material, shard_sequences)
- **Auto-update** — pulls from GitHub every 15 minutes, rebuilds if changes

## What's New in v0.2.0

**Orchestration layer fully wired** — all cryptographic modules now operational in the runtime:

| Module | Before (v0.1.0) | After (v0.2.0) |
|--------|-----------------|-----------------|
| TSS (FROST 3-of-5) | Library only, no-op loop | Distributed signing with receipt validation |
| Session Ratcheting | Library only, epoch always 0 | Full session management via SHARD protocol |
| Risk Scoring | Library only, never consulted | Computed on every auth, step-up/terminate enforced |
| BFT Audit | Single-node, unsigned entries | 7-node quorum with ML-DSA-65 signed entries |
| Key Transparency | Library only, no tree signing | Periodic 60s ML-DSA-65 signed tree heads |
| DPoP Binding | Random key (broken) | Real client public key from auth payload |
| Verifier | Stub (printed "ready", exited) | Full SHARD service verifying tokens |
| Multi-Person Ceremonies | Library only | 3 API endpoints, Level 3/4 enforcement, cooldowns |
| Duress PIN | Library only | Registration + silent lockdown + session revocation |
| FIDO2 | Endpoints exist, never checked | Tier 1 ceremony integration |
| X-Wing KEM | Tests only | Gateway session key establishment |
| Witness Checkpoints | Not implemented | 5-min periodic ML-DSA-65 signed snapshots |
| Secret Persistence | Random keys on every restart | PostgreSQL-backed key survival |
| Token Security | No expiry, no rate limiting | 1-hour expiry + 5-attempt rate limiting |

**New features:**
- **Google OAuth** — "Sign in with Google" with auto-enrollment (Tier 4)
- **Public Docs** — `/docs` integration guide with 7 language samples
- **`/oauth/jwks`** — JWKS endpoint (was 404)
- **`/api/user/profile`** — User profile endpoint (was missing)
- **`/oauth/userinfo`** — Returns real user data (was dummy)

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
| `e2e` | End-to-end test suite |

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
| `SSO_ISSUER` | https://sso-system.dmj.one | OIDC issuer URL |
| `GOOGLE_CLIENT_ID` | (optional) | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | (optional) | Google OAuth client secret |
| `SSO_BASE_URL` | (optional) | Public base URL for Google callback |
| `DEMO_REDIRECT_URI` | https://sso-system-demo.dmj.one/callback | Demo app callback |

## License

MIT — Copyright (c) 2026 Divya Mohan ([dmj.one](https://dmj.one))

AI Architecture Partner: Claude (Anthropic)
