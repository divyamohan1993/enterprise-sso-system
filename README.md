# MILNET SSO

A single sign-on system built to survive total infrastructure compromise.

MILNET SSO combines threshold cryptography, post-quantum key exchange, server-blind password authentication, forward-secret sessions, and Byzantine fault-tolerant audit logging into one authentication platform. It was designed under the assumption that every component — the host, the network, the database, even individual service processes — could be compromised independently, and the system should still protect user credentials.

**Live system:** [sso-system.dmj.one](https://sso-system.dmj.one)
**Author:** [Divya Mohan](https://dmj.one) — AI architecture partner: Claude (Anthropic)

---

## The Problem

Most SSO systems treat security as a perimeter: a TLS certificate, a bcrypt hash, a session cookie. If an attacker gets past the perimeter — database dump, memory read, compromised process — they get everything.

MILNET SSO asks: what if we assume the perimeter is already breached?

- The **password server** never sees your password (OPAQUE protocol — the server authenticates you without ever learning what you typed)
- No single process holds the **signing key** (FROST 3-of-5 threshold signatures — an attacker must compromise 3 of 5 independent processes to forge a token)
- Session keys are **forward-secret** (HKDF-SHA512 ratchet — past sessions can't be decrypted even if current keys leak)
- The audit log is **tamper-proof** (hash-chained entries replicated across a 7-node BFT cluster — an attacker can't cover their tracks)
- Key exchange uses **post-quantum cryptography** (X-Wing hybrid: ML-KEM-768 + X25519 — resistant to both classical and quantum attacks)

Each of these properties holds independently. Compromising one doesn't weaken the others.

## Try It

No signup required. Log in at [sso-system.dmj.one](https://sso-system.dmj.one):

| Username | Password | Access |
|----------|----------|--------|
| `admin` | `admin` | Tier 1 (Sovereign) — admin panel, user management, audit log |
| `demo` | `demo` | Tier 3 (Sensor) — limited portal, read-only |

**Security demo** — tamper with a token and watch it get rejected:

![Security Demo](screenshots/security-demo.jpg)

**Integration docs** — code samples in 7 languages:

![Integration Docs](screenshots/docs.jpg)

## How It Works

A login flows through six isolated services, each holding only the secrets it needs:

```
Client ──► Gateway ──► Orchestrator ──► OPAQUE ──► TSS ──► Verifier
           (puzzle)    (state machine)  (password)  (sign)  (verify)
```

1. **Gateway** challenges the client with an adaptive hash puzzle (proof-of-work that scales with load), then establishes a session key using X-Wing hybrid KEM
2. **Orchestrator** runs the ceremony state machine — routing the request through authentication steps based on the required security tier
3. **OPAQUE** performs server-blind password authentication using `opaque-ke` 4.0 (RFC 9497). The server stores a cryptographic envelope, never a password hash
4. **TSS** validates the receipt chain from prior steps, then produces a threshold-signed token using FROST 3-of-5. No single node holds the signing key
5. **Verifier** checks the token in O(1) — FROST signature, ML-DSA-65 post-quantum signature, ratchet epoch tag, and DPoP channel binding
6. **Ratchet** manages forward-secret session keys — HKDF-SHA512 chains that advance every 30 seconds, with previous keys securely erased

Running alongside the auth flow:

- **Risk Engine** scores every authentication on 6 signals (device, geo-velocity, network, time-of-day, access patterns, failed attempts). Score above 0.6 triggers step-up auth; above 0.8 terminates the session
- **Audit** maintains a hash-chained, append-only log replicated across a 7-node BFT cluster with ML-DSA-65 signed entries
- **Key Transparency** builds a SHA3-256 Merkle tree over all credential operations, publishing ML-DSA-65 signed tree heads every 60 seconds

All inter-service communication uses the SHARD protocol — HMAC-SHA512 authenticated, replay-protected, with monotonic sequence counters and constant-time comparison.

## Authentication Tiers

Not all logins need the same security. MILNET SSO supports four ceremony tiers:

| Tier | Name | What It Requires | Token Lifetime |
|------|------|-----------------|----------------|
| 1 | Sovereign | Puzzle + OPAQUE + FIDO2 + Risk scoring | 5 min |
| 2 | Operational | Puzzle + OPAQUE + TOTP + Risk scoring | 10 min |
| 3 | Sensor | Puzzle + PSK/HMAC + Attestation | 15 min |
| 4 | Emergency | Shamir 7-of-13 + out-of-band verify | 2 min |

Actions are also tiered — reading a dashboard needs only a valid token, but rotating keys requires a two-person ceremony, and emergency shutdown requires three people plus a cooling period.

## Project Structure

MILNET SSO is a Rust workspace of 16 crates, each a separate process with its own trust boundary:

| Crate | What It Does |
|-------|-------------|
| `common` | Shared types, domain separation (11 unique prefixes), config, DB |
| `crypto` | X-Wing KEM, FROST, ML-DSA, receipts, entropy, DPoP, constant-time ops |
| `shard` | Inter-service IPC protocol with HMAC-SHA512 auth and replay protection |
| `gateway` | Bastion entry point: adaptive hash puzzle + X-Wing session keys |
| `orchestrator` | Ceremony state machine coordinating the auth flow |
| `opaque` | Server-blind password auth via `opaque-ke` 4.0 + receipt issuance |
| `tss` | Receipt chain validation + distributed FROST 3-of-5 threshold signing |
| `verifier` | O(1) token verification (~72us target) |
| `ratchet` | Forward-secret HKDF-SHA512 session management |
| `audit` | Hash-chained append-only log + 7-node BFT replication |
| `kt` | SHA3-256 Merkle tree for Key Transparency |
| `risk` | 6-signal risk scoring + device tier enforcement |
| `admin` | REST API (axum) + web frontend + Google OAuth |
| `sso-protocol` | OIDC/OAuth2: discovery, authorize, token, PKCE, userinfo, JWKS |
| `fido` | FIDO2/WebAuthn registration and authentication |
| `e2e` | End-to-end ceremony tests + attack simulation |

A TLA+ formal model in `formal-model/` verifies the Tier 2 ceremony state machine against 5 safety invariants and 1 liveness property.

## Standards Compliance

- **OAuth2/OIDC** — discovery (`/.well-known/openid-configuration`), authorization with PKCE S256 (RFC 7636), JWT tokens (RS256), JWKS, UserInfo
- **OPAQUE** — RFC 9497 OPRF-based server-blind password authentication
- **FROST** — threshold EdDSA signing via `frost-ristretto255` 2.2
- **FIDO2/WebAuthn** — registration and authentication endpoints for Tier 1 ceremonies
- **DPoP** — channel-bound tokens with real client public keys

## Deploy

### One-click (Terraform + GCP)

```bash
git clone https://github.com/divyamohan1993/enterprise-sso-system.git
cd enterprise-sso-system/terraform
terraform init && terraform apply -auto-approve
# ~10 min for Rust compilation. URL printed at end.
```

### Docker

```bash
docker-compose up
```

### Manual

```bash
cargo build --release -p admin
DATABASE_URL="postgres://milnet:password@localhost/milnet_sso" ./target/release/admin
```

See [DEPLOY.md](DEPLOY.md) for the full guide, environment variables, and GCP architecture.

## Build and Test

```bash
cargo build --workspace          # build all 16 crates
cargo test --workspace           # run 151+ tests
cargo clippy --workspace -- -D warnings  # lint (zero warnings)
cargo fmt --all -- --check       # format check
```

The test suite includes end-to-end ceremony flows, SSO multi-portal proofs, and attack simulations covering 37 threat vectors (DDoS, credential stuffing, token forgery, receipt chain attacks, session hijacking, privilege escalation, audit evasion).

## Design Documents

- [Architecture specification](docs/design/2026-03-21-milnet-sso-design.md) — 1,597-line design document covering threat model, cryptographic stack, 9 modules, 4 ceremony tiers, 5 action levels, key transparency protocol, audit system, failure modes, and 169 red-team findings
- [Implementation plan](docs/plans/2026-03-21-milnet-sso-implementation.md) — 8-phase, 52-task build plan
- [Formal model](formal-model/) — TLA+ state machine verification
- [Architecture overview](ARCHITECTURE.md) — security properties, module communication matrix, and protocol details

## Known Limitations

This is a research-grade system. Some components use placeholders or have incomplete implementations:

- Admin API authenticates locally — does not route through the full Gateway → Orchestrator → TSS pipeline
- FIDO2 is credential-exists check only — full WebAuthn signature verification is pending
- X-Wing KEM generates both sides locally (client-side encapsulation not yet wired)
- Rate limiter and access token map are in-memory (reset on restart, grow unbounded)
- KT root in witness checkpoints is a placeholder
- Audit entries from admin routes are unsigned (BFT cluster entries use ML-DSA-65)

See [CHANGELOG.md](CHANGELOG.md) for the full list and planned work.

## License

MIT — Copyright (c) 2026 [Divya Mohan](https://dmj.one)

AI Architecture Partner: Claude (Anthropic)
