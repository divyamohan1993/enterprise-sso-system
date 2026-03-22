# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-21

### Added

#### Architecture & Spec
- 1,597-line architecture specification with 8 appendices (A-H)
- TLA+ formal model with safety and liveness property verification
- 169 attack vectors identified across 6 review rounds (5 red team + 1 internal spec review), all mitigated

#### Core Modules (13 crates)
- `common` — shared types (Token, Receipt, AuditEntry), domain separation (11 prefixes), error types, action-level auth, security config, module communication matrix
- `crypto` — X-Wing hybrid KEM (real ML-KEM-768 + X25519), FROST threshold signing (real frost-ristretto255 3-of-5), receipt chain signing/validation, multi-source entropy combiner, constant-time comparison utilities
- `shard` — SHARD IPC protocol with HMAC-SHA512 authentication, replay protection (monotonic sequence counters), timestamp validation (±2s), async TCP transport with length-prefixed framing
- `gateway` — Bastion Gateway with hash puzzle challenge (PoW), request forwarding to orchestrator via SHARD
- `orchestrator` — ceremony state machine (PendingOpaque → PendingTss → Complete/Failed), auth coordination across OPAQUE and TSS
- `opaque` — password authentication with Argon2id (64 MiB, 3 iterations, 4 parallelism), credential store with constant-time verification, ceremony receipt issuance
- `tss` — receipt chain validation (session ID, hash linkage, signatures, DPoP binding), threshold token signing with FROST, token builder
- `verifier` — O(1) token signature verification (~72µs target), expiry check, tier validation
- `ratchet` — forward-secret session ratcheting (HKDF-SHA512 chains), 30-second epochs, ±3 epoch lookahead, server entropy mixing, 8-hour mandatory re-auth, secure key erasure (zeroize)
- `audit` — hash-chained append-only audit log with tamper detection, domain-separated entry hashing
- `kt` — SHA3-256 Merkle tree for Key Transparency, inclusion proof generation and verification
- `risk` — risk scoring engine (6 weighted signals, 4 levels), device tier enforcement (Sovereign/Operational/Sensor/Emergency), device registry

#### Authentication Features
- 4 ceremony tiers (Sovereign, Operational, Sensor, Emergency)
- 5 action-level classifications (Read, Modify, Privileged, Critical, Sovereign)
- Multi-person ceremony validation (2-person for Critical, 3-person cross-department for Sovereign)
- Single-use action tokens with abort deadlines

#### Cryptographic Properties
- Post-quantum hybrid key exchange: X-Wing combiner (ML-KEM-768 + X25519 via SHA3-256)
- Threshold signing: real FROST 3-of-5 via frost-ristretto255 2.2
- Password KDF: Argon2id (RFC 9106) with production parameters
- Forward secrecy: HKDF-SHA512 symmetric ratchet with per-epoch key erasure
- Domain separation: 11 unique prefixes preventing cross-protocol injection
- Constant-time comparisons: subtle::ConstantTimeEq enforced everywhere

#### Security Hardening
- 11 security vulnerabilities patched (4 critical, 4 high, 3 medium)
- Module communication matrix: 18 permitted channels enforced (not 72)
- Receipt signing key removed from wire protocol (TSS holds own key)
- Future-timestamped receipt rejection
- Audit hash includes all forensically significant fields

#### Testing
- 190+ tests across 13 crates
- End-to-end Tier 2 ceremony flow (gateway → orchestrator → opaque → tss → verifier)
- SSO multi-portal proof (single login, 5 service portals, independent verifiers)
- Advanced threat simulation (37 tests: DDoS, credential stuffing, token forgery, receipt chain attacks, SHARD protocol attacks, session hijacking, privilege escalation, audit evasion)
- Production validation (53 tests: all modules, edge cases, false positives, concurrent load)

#### CI/CD & Supply Chain
- GitHub Actions CI pipeline (fmt, clippy, test)
- Dependabot configured for weekly cargo dependency scanning
- cargo-deny configured (advisories, licenses, bans, sources all passing)
- Zero CVEs in dependency tree (cargo audit clean)

### Security Advisories
- RUSTSEC-2023-0089 (atomic-polyfill unmaintained) — transitive via postcard→heapless, no security impact, ignored in deny.toml

### Known Limitations
- ML-DSA-65 post-quantum signature: field exists in token format, not yet populated (ml-dsa crate is RC only)
- Full OPAQUE RFC 9807 protocol: using Argon2id server-side (opaque-ke 4.0 in deps, 3-message protocol requires wire protocol changes)
- TLS: rustls 0.23 in deps, transport currently plain TCP (PQ-hybrid TLS wiring is deployment task)
- BFT audit replication: single-node with correct data structures (7-node BFT is deployment task)
- DPoP channel binding: token field exists, not enforced in verification path yet

## [0.2.0] - 2026-03-22

### Added — Full Orchestration Wiring

All cryptographic modules wired from library-only into operational runtime:

#### Runtime Integration (Previously Library-Only)
- **Distributed FROST signing** — TSS service validates receipt chains and produces threshold-signed tokens via SHARD
- **Session ratcheting** — full SHARD protocol for session create/advance/tag with client+server entropy
- **Risk scoring** — computed on every authentication; step-up at 0.6, session termination at 0.8
- **BFT audit** — 7-node cluster with ML-DSA-65 signed entries, quorum of 5 required for commit
- **Key transparency** — periodic ML-DSA-65 signed tree heads every 60 seconds
- **Verifier service** — full SHARD listener accepting and verifying tokens (was a stub)
- **Witness checkpoints** — periodic ML-DSA-65 signed audit+KT root snapshots every 5 minutes
- **X-Wing hybrid KEM** — post-quantum session key establishment in gateway connections
- **Secret persistence** — `key_material` and `shard_sequences` PostgreSQL tables; keys survive restarts

#### Security Hardening
- **Multi-person ceremonies** — `POST /api/ceremony/initiate`, `/approve`, `GET /api/ceremony/{id}`; Level 3 requires 2 approvers, Level 4 requires 3; 15-min cooldown, max 1 Level-4 per 72h
- **Duress PIN** — `POST /api/auth/duress-pin` registration; silent lockdown on detection (downgrades to Tier 4, revokes all sessions, logs DuressDetected audit event)
- **FIDO2 ceremony check** — Tier 1 users with registered credentials trigger FIDO2 verification step
- **DPoP fix** — real client public key extracted from auth payload (was generating random key)
- **Token expiry enforcement** — 1-hour max token age checked in auth middleware
- **Login rate limiting** — 5 attempts per 30 minutes per username, automatic lockout
- **SecurityConfig enforcement** — tier-based token lifetimes (T1:5min, T2:10min, T3:15min, T4:2min)
- **PKCE validation** — `code_challenge_method` must be `S256` (was parsed but never validated)
- **DeviceRegistry wired** — in-memory device registry updated on enrollment (was unused)
- **Session revocation on duress** — all active sessions invalidated when duress PIN detected

#### New Features
- **Google OAuth** — "Sign in with Google" federated login; auto-enrollment as Tier 4; `/oauth/google/start` and `/oauth/google/callback` endpoints; Google button on OAuth authorize page; OPAQUE login guard for Google-only users
- **Public integration docs** — `/docs` page (1,457 lines) with getting started guide, OAuth2 flow walkthrough, endpoint reference (7 endpoints with param tables), JWT format, code samples (Python, Node.js, Java, Go, Rust, PHP, .NET), curl/PKCE examples, client registration info
- **`/oauth/jwks`** — JWKS endpoint advertising HS512 algorithm (was 404)
- **`/api/user/profile`** — real user profile endpoint (was missing)
- **`/oauth/userinfo`** — returns real user data from DB (was returning dummy Uuid::nil)

#### Deployment
- **Dockerfile** — now builds all 10 service binaries (was admin+gateway only)
- **Entrypoint** — fixed path mismatch between Dockerfile and entrypoint.sh
- **docker-compose** — added Google OAuth environment variables

### Fixed
- Panic on Google user creation failure → proper HTTP 500 response
- Google auto-enrollment tier 2 → tier 4 (minimal access until admin approval)
- Unused import warnings in admin routes
- Compiler warnings reduced to zero

### Known Limitations (Remaining)
- Admin API authenticates locally — does not route through full Gateway→Orchestrator→TSS pipeline for HMAC tokens (OIDC flow issues FROST-capable tokens)
- FIDO2 authentication is credential-exists check only — full WebAuthn signature verification not yet implemented
- Audit entries in admin routes are unsigned (BFT cluster uses ML-DSA, admin's in-memory AuditLog does not)
- KT root in witness checkpoints is placeholder `[0u8; 32]` (KT lives in separate service)
- X-Wing KEM generates both sides locally (placeholder until client-side encapsulation is wired)
- `access_tokens` HashMap has no TTL eviction (grows unbounded in long-running server)
- Rate limiter is in-memory only (resets on restart)

## [Unreleased]

### Planned
- Full admin→orchestrator routing for FROST-signed tokens on every login
- Full FIDO2 WebAuthn signature verification
- PQ-hybrid TLS (rustls with X25519MLKEM768)
- Full OPAQUE RFC 9807 interactive protocol
- Client SDK libraries (Rust, TypeScript, Python)
- KT service integration in witness checkpoints
- TTL eviction for access_token and rate limiter maps
