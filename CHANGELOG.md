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
- Nation-state attack simulation (37 tests: DDoS, credential stuffing, token forgery, receipt chain attacks, SHARD protocol attacks, session hijacking, privilege escalation, audit evasion)
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

## [Unreleased]

### Planned
- Full OPAQUE RFC 9807 interactive protocol
- PQ-hybrid TLS (rustls with X25519MLKEM768)
- ML-DSA-65 post-quantum token signatures
- BFT audit replication (7-node HotStuff)
- DPoP channel binding enforcement
- FIDO2/WebAuthn hardware key support
- Admin API for user/device/portal management
- Client SDK libraries (Rust, TypeScript, Python)
