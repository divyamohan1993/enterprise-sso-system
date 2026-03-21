# MILNET SSO System — Research-Grade Authentication Architecture

**Date:** 2026-03-21
**Status:** Design Complete — Pending Implementation Planning
**Classification:** Architecture Specification
**Red Team Rounds:** 2 (96 attack vectors analyzed, all addressed)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Threat Model](#2-threat-model)
3. [Trust Model & Core Philosophy](#3-trust-model--core-philosophy)
4. [System Architecture](#4-system-architecture)
5. [The Nine Modules](#5-the-nine-modules)
6. [Authentication Ceremonies](#6-authentication-ceremonies)
7. [Action-Level Authentication](#7-action-level-authentication)
8. [Session Management & Ratcheting](#8-session-management--ratcheting)
9. [Cryptographic Stack](#9-cryptographic-stack)
10. [Storage Architecture](#10-storage-architecture)
11. [Inter-Module Communication Protocol (SHARD)](#11-inter-module-communication-protocol-shard)
12. [DDoS Resistance](#12-ddos-resistance)
13. [Device Tier System & Anti-Spoofing](#13-device-tier-system--anti-spoofing)
14. [Key Transparency](#14-key-transparency)
15. [Audit System](#15-audit-system)
16. [Failure Modes & Self-Healing](#16-failure-modes--self-healing)
17. [Deployment & Binary Integrity](#17-deployment--binary-integrity)
18. [Supply Chain Security](#18-supply-chain-security)
19. [Performance Analysis](#19-performance-analysis)
20. [Red Team Findings & Mitigations](#20-red-team-findings--mitigations)
21. [Novelty Assessment](#21-novelty-assessment)

---

## 1. Executive Summary

This document specifies a research-grade Single Sign-On (SSO) system designed for military network (MILNET) deployment under the most extreme adversarial conditions. The system assumes **total compromise** of host, network, client devices, database, and even individual auth server processes — and still defends.

**No system combining all these properties has ever been built.** Research confirms that no publicly documented system — commercial, government, or academic — combines threshold token signing, OPAQUE password authentication, ratcheting sessions, key transparency, microkernel process isolation, and post-quantum cryptography in a single authentication system.

### Key Properties

- **Language:** Rust (memory-safe, zero GC, predictable latency)
- **Architecture:** 9 isolated mutually-distrusting processes
- **Password Auth:** T-OPAQUE (threshold OPRF, server-blind)
- **Token Signing:** FROST 3-of-5 threshold EdDSA + nested ML-DSA-65
- **Sessions:** HKDF-SHA512 symmetric ratchet with forward secrecy and post-compromise security
- **Key Exchange:** X25519 + ML-KEM-768 hybrid (mandatory, no fallback)
- **Action Auth:** 5-level classification with two-person sovereign ceremony
- **DDoS:** Equihash client puzzles with server nonce, adaptive difficulty
- **Audit:** 7-node BFT replicated, ML-DSA-65 signed, externally witnessed
- **Performance:** O(1) hot path (~72us token verify), full auth ceremony ~73ms
- **Host Compromise Resilience:** No complete secret exists anywhere; cloning yields nothing actionable

---

## 2. Threat Model

### Adversary Profile

- **Capability:** Nation-state with unlimited resources, years of patience
- **Access:** Raw internet exposure, no firewall, all traffic flows directly to system
- **Compromise Level:** Assume host, network, clients, database, individual processes all compromised simultaneously
- **Attack Types:** DDoS, APTs, supply chain, side-channel, physical, social engineering, insider threat, coercion — all simultaneously
- **Scale:** Hundreds of thousands of users under full mobilization surge
- **Devices:** Full spectrum — browsers, native apps, CLI, IoT sensors, field devices

### What We Trust

1. **Mathematical hardness assumptions** — lattice problems (ML-KEM, ML-DSA), discrete log (X25519, Ed25519), hash preimage resistance (SHA-512, SHA3-256, BLAKE3)
2. **Threshold quorums** — no single entity, only k-of-n agreement
3. **Physics** — entropy sources, hardware attestation roots

### What We Do NOT Trust

- Hardware (assumed compromised)
- Operating system (assumed rootkitted)
- Network (assumed MITM'd)
- Other processes on the same host (assumed hostile)
- Our own code at rest (assumed modifiable)
- Database (assumed publicly readable)
- Redis/cache (assumed compromised)
- Individual personnel (assumed coercible or corruptible)

---

## 3. Trust Model & Core Philosophy

### Zero-Knowledge Trust Architecture

- No component ever sees a complete secret
- No single compromise of any component yields actionable information
- Every assertion is cryptographically verifiable by any party
- All state is either ephemeral (dies with the process) or encrypted under threshold-split keys

### Defense in Depth Principles

1. **Module isolation:** Compromise of any module does not bypass another
2. **Threshold everything:** No single point holds a complete secret
3. **Fail-secure always:** Every failure mode defaults to MORE security, never less
4. **Asymmetric safety:** Destruction requires unanimous multi-party agreement; safety requires only single dissent
5. **End-to-end proofs:** Every security assertion is verifiable at the final consumer, not just at intermediate routers

### Device Tier Anti-Spoofing Principle

Device tier is determined by the SYSTEM, not by the device. Lower tiers do not get "easier access to the same things" — they get "equivalent-strength access to fewer things." An attacker spoofing as an IoT sensor gets IoT-level access only, which is useless for accessing command systems.

---

## 4. System Architecture

```
INTERNET (raw, hostile)
    |
    v
+-------------------------------------------------------------+
|  MODULE 1: BASTION GATEWAY                                  |
|  Proof-of-work client puzzles (Equihash + server nonce)     |
|  Adaptive rate limiting (token bucket + sliding window)     |
|  TLS 1.3 termination with PQ hybrid (X25519+ML-KEM-768)    |
|  Protocol validation and request sanitization               |
|  HOLDS ZERO SECRETS -- stateless, disposable, replaceable   |
+-----------------------------+-------------------------------+
                              | mTLS (PQ-hybrid, ephemeral)
                              v
+-------------------------------------------------------------+
|  MODULE 2: AUTH ORCHESTRATOR                                |
|  Routes auth ceremonies to appropriate modules              |
|  Enforces ceremony ordering via chained receipts            |
|  HOLDS NO KEYS -- dumb router, cannot forge receipts        |
|  Device tier assignment (server-determined)                  |
+--+------+------+------+------+------+------+---------------+
   |      |      |      |      |      |      |
   v      v      v      v      v      v      v

MODULE 3: THRESHOLD SIGNER (TSS)
  FROST 3-of-5 threshold EdDSA + nested ML-DSA-65
  Proactive share refresh every hour
  Verifies ALL ceremony receipts before signing

MODULE 4: CREDENTIAL VERIFIER (VRF)
  O(1) token verification via cached JWKS
  DPoP proof validation (channel binding)
  Ratchet epoch verification

MODULE 5: T-OPAQUE PASSWORD SERVICE
  RFC 9497 OPAQUE with threshold OPRF
  Server NEVER sees password in any form
  Even full DB + OPRF quorum compromise cannot derive passwords

MODULE 6: RATCHET SESSION MANAGER
  HKDF-SHA512 chain per session
  30-second epochs, +/-3 lookahead
  Forward secrecy + post-compromise security
  8-hour mandatory re-auth ceiling

MODULE 7: KEY TRANSPARENCY LOG
  SHA3-256 append-only Merkle tree
  Signed tree heads every 60 seconds
  Client-verifiable consistency proofs
  Batched updates (1-second windows)

MODULE 8: RISK SCORING ENGINE
  Continuous auth signals (device posture, geo-velocity, behavioral)
  Step-up auth triggers
  Device tier enforcement
  Anomaly detection

MODULE 9: AUDIT LOG (BFT-REPLICATED)
  7-node BFT (tolerates 2 Byzantine faults)
  ML-DSA-65 signed entries
  Hash-chained (tamper-evident)
  External witness checkpoints
```

---

## 5. The Nine Modules

### Module 1: Bastion Gateway

**Purpose:** Absorb DDoS, terminate TLS, validate protocol, route to orchestrator.

**Holds:** Zero secrets. Stateless. Can be killed and replaced without affecting auth state.

**Key behaviors:**
- Equihash client puzzle with server-provided random nonce (10s TTL, single-use)
- Adaptive puzzle difficulty: scales with load (10ms normal, 1-5s under DDoS)
- TLS 1.3 mandatory, PQ hybrid mandatory (no negotiation, no fallback)
- Request sanitization: size limits, encoding validation, header validation
- Rate limiting: per-IP token bucket + per-user sliding window

### Module 2: Auth Orchestrator

**Purpose:** Route authentication ceremonies. Dumb router, not a trust anchor.

**Holds:** No keys, no secrets, no signing capability.

**Key behaviors:**
- Determines device tier based on enrollment database (not client self-report)
- Routes ceremony steps to appropriate services
- CANNOT forge receipts (doesn't hold service signing keys)
- CANNOT manipulate action strings (FIDO2 challenges bind to action hash, delivered directly from initiating service to participant devices, bypassing orchestrator)
- Can only cause DoS (delay/drop), not integrity violations

### Module 3: Threshold Signer (TSS)

**Purpose:** Issue threshold-signed tokens. The final gatekeeper.

**Holds:** One share of the FROST threshold EdDSA signing key.

**Key behaviors:**
- REFUSES to sign unless ALL required ceremony receipts are present and valid
- Validates receipt chain: same ceremony_session_id, sequential hash chain, within TTL, correct action binding
- Proactive share refresh every hour (old shares become useless)
- If refresh fails 3 consecutive times: threshold raised from 3-of-5 to 4-of-5
- After 6 consecutive failures: signing suspended, human intervention required
- Nested signing: PQ signature covers (payload || FROST_signature)

### Module 4: Credential Verifier (VRF)

**Purpose:** Verify tokens on every API request. The hot path.

**Holds:** Public keys only. No private material.

**Key behaviors:**
- O(1) token verification: parse → ratchet epoch check → DPoP verify → signature verify → tier check → ratchet advance
- ~72 microseconds total per verification
- Cached JWKS (refreshed on key rotation events via pub/sub)
- Serves public keys to relying parties

### Module 5: T-OPAQUE Password Service

**Purpose:** Password authentication where the server never sees the password.

**Holds:** One share of the threshold OPRF key.

**Key behaviors:**
- RFC 9497 OPAQUE protocol
- Threshold OPRF: OPRF key is itself threshold-split (no single server compromise enables offline dictionary attack)
- Client-side Argon2id key stretching (64 MiB, 3 iterations, 4 parallelism)
- Server-side OPRF evaluation: ~1ms
- Issues a ceremony receipt signed with its receipt key (stored in HSM/TEE, separate from mTLS key)

### Module 6: Ratchet Session Manager

**Purpose:** Manage session lifecycle with forward secrecy and post-compromise security.

**Holds:** Current ratchet chain keys (ephemeral, zeroized on advancement).

**Key behaviors:**
- HKDF-SHA512 chain advancement per use or per 30-second epoch
- Lookahead window: ±3 epochs (tolerates packet loss without forced re-auth)
- Previous chain keys: securely erased via `zeroize` crate + `mlock()` + no swap
- DH ratchet step on re-auth AND every 8 hours (mandatory, non-extendable)
- Clone detection: cloned server's tokens rejected because real system has advanced
- Per-use advancement includes client-provided entropy (prevents clone prediction)

### Module 7: Key Transparency Log

**Purpose:** Detect credential tampering, even by the IdP itself.

**Holds:** Append-only Merkle tree.

**Key behaviors:**
- Every credential operation logged: registration, rotation, enrollment, revocation
- Leaf: H(user_id || operation || credential_hash || timestamp)
- Signed tree head (STH) published every 60 seconds with ML-DSA-65
- Batched updates in 1-second windows (rate limit: N ops per user per window)
- Consistency proofs served to any verifier
- Publicly auditable without revealing secrets

### Module 8: Risk Scoring Engine

**Purpose:** Continuous authentication and anomaly detection.

**Holds:** Behavioral baselines (no PII).

**Key behaviors:**
- Signals: device posture, geo-velocity, network context, access patterns, time-of-day
- O(1) weighted score computation from cached signals
- Step-up auth trigger when score exceeds threshold
- Device tier enforcement: Tier 3 tokens can only access Tier 3 resources
- Anomaly flagging: "sensor making non-sensor API calls" → session termination
- If module crashes: default to HIGHEST RISK (fail-secure)

### Module 9: Audit Log (BFT-Replicated)

**Purpose:** Tamper-proof record of all system events.

**Holds:** Complete event log.

**Key behaviors:**
- 7 BFT nodes across different administrative domains
- Tolerates 2 fully Byzantine (malicious) nodes
- Every entry: ML-DSA-65 signed, hash-chained to previous
- Ceremony transcripts: full receipt chains, FIDO2 attestations, timestamps
- Periodic Merkle root checkpoints to external immutable witness
- If audit module crashes: ALL AUTHENTICATION STOPS (unaudited auth is worse than no auth)

---

## 6. Authentication Ceremonies

### Ceremony Architecture: End-to-End Proofs

Each authentication step produces a cryptographic receipt that the TSS independently verifies. The orchestrator routes but cannot forge.

**Receipt structure:**
```
Receipt {
    ceremony_session_id: [u8; 32],  // shared across all steps
    step_id: u8,                     // which ceremony step
    prev_receipt_hash: [u8; 32],     // chain to previous receipt
    user_id: UUID,
    dpop_key_hash: [u8; 32],        // channel binding
    timestamp: i64,                  // microsecond precision
    nonce: [u8; 32],
    signature: Vec<u8>,             // issuing service's key (HSM-backed)
    ttl_seconds: u8,                // 30
}
```

**TSS validates:**
- All receipts share same `ceremony_session_id`
- Sequential `prev_receipt_hash` chain is unbroken
- All receipts within TTL
- Exactly the right receipts for the declared ceremony tier (no more, no fewer)
- All `dpop_key_hash` values match (same client)
- For action ceremonies: FIDO2 challenge includes H(action_string)

### The Four Ceremony Tiers

**Tier 1: SOVEREIGN** (Command staff, admin, classified access)
- Client puzzle (Equihash)
- OPAQUE password auth (threshold OPRF)
- FIDO2 hardware key (device-bound, enterprise attestation)
- Risk scoring (device posture, geo-velocity)
- Threshold token issuance (3-of-5 FROST + ML-DSA-65)
- DPoP channel binding
- Ratchet session initialization
- Token scope: ALL resources
- Token lifetime: 5 minutes (ratchets every use)

**Tier 2: OPERATIONAL** (Standard personnel, field operators)
- Client puzzle
- OPAQUE password auth
- TOTP or software authenticator (rate-limited per user, not per IP)
- Risk scoring
- Threshold token issuance
- DPoP channel binding
- Ratchet session initialization
- Token scope: OPERATIONAL resources only
- Token lifetime: 10 minutes

**Tier 3: SENSOR** (IoT, field sensors, automated systems)
- Client puzzle (reduced difficulty)
- Pre-shared key + HMAC-SHA512 challenge-response
- Hardware device attestation (registered OOB, measured boot PCRs)
- Risk scoring (behavioral baseline for device class)
- Threshold token issuance
- Token scope: SENSOR resources ONLY
- Token lifetime: 15 minutes

**Tier 4: EMERGENCY** (Disaster recovery)
- Shamir secret share reconstruction (k-of-n human operators)
- Out-of-band voice confirmation
- Time-limited, scope-limited emergency token
- Token scope: EMERGENCY resources only
- Token lifetime: 2 minutes, non-renewable

---

## 7. Action-Level Authentication

Beyond session auth, critical operations require per-action authentication.

### Action Classification Levels

| Level | Name | Requirement | Example |
|-------|------|-------------|---------|
| 0 | READ | Valid session token | View dashboard |
| 1 | MODIFY | Session + fresh DPoP proof | Update profile |
| 2 | PRIVILEGED | Session + step-up re-auth | Add user, view audit |
| 3 | CRITICAL | Two-person ceremony + time delay | Create admin, rotate keys |
| 4 | SOVEREIGN | Multi-person + cooling period + external witness | Emergency shutdown, disable audit |

### Level 4 Sovereign Ceremony (The Missile Problem)

Both participants on independent devices, independent network paths:

1. **Fresh FIDO2 tap** from each (proves physical presence NOW)
2. **Action-specific challenge** — unique nonce displayed on BOTH screens. FIDO2 challenge = H(action_string || ceremony_id || nonce). Action string delivered directly from initiating service to participant devices (NOT through orchestrator).
3. **Biometric + PIN** from each (something you ARE + KNOW)
4. **Commitment phase** — both sign H(action || nonce || time), TSS verifies both independently. Checks: two DIFFERENT people, two DIFFERENT devices.
5. **Abort window** (10 seconds) — default on timeout = ABORT. Proceed requires FIDO2-signed PROCEED from BOTH. Abort requires FIDO2-signed ABORT from ONE. Unsigned abort messages ignored.
6. **Mandatory cooling period** (15 minutes) — automated anomaly review, monitoring team notified, any authorized person can VETO (single veto = cancel). Hardcoded in TSS, not configurable at runtime.
7. **Cross-department requirement** — two participants must be from different organizational units. Collusion requires cross-departmental conspiracy.
8. **Action token issuance** — single-use, nonce-bound, threshold-signed, PQ-signed. Contains: action, authorized_by, device_attestations, timestamp, nonce, abort_deadline, max_executions=1.
9. **Target system verification** — independently verifies: threshold signature, two distinct authorized persons, abort deadline not exceeded, nonce never seen, action matches, max_executions not exceeded. ALSO performs real-time authorization check (token alone is insufficient).
10. **External witness** — ceremony hash published to separate immutable infrastructure.
11. **Immutable audit** — full ceremony transcript: FIDO2 proofs, biometric hashes, signatures, timestamps, device attestations. ML-DSA-65 signed, BFT replicated.

### Duress Protocol

Every FIDO2 device enrolled with two PINs:
- **Normal PIN:** Ceremony proceeds normally
- **Duress PIN:** Ceremony APPEARS to proceed but token contains coercion marker. Target system does NOT execute action, returns fake "success," triggers silent lockdown alert.

### Why Malicious Scripts Cannot Trigger Level 4

- FIDO2 requires physical capacitive touch (malware can't simulate)
- Biometric captured by secure hardware (malware can't inject)
- Two independent people on two independent devices (need simultaneous compromise of both)
- TSS verifies two DIFFERENT user IDs, DIFFERENT credentials, DIFFERENT devices
- 10-second abort window with safe default (timeout = abort)
- 15-minute cooling period with single-person veto
- Target system independently re-checks authorization at execution time

---

## 8. Session Management & Ratcheting

### Symmetric Ratchet (Per Session)

```
T0: chain_key_0 = HKDF-SHA512(master_secret, "ratchet-init" || client_entropy)
    token_0 = HMAC-SHA512(chain_key_0, claims_0)

T1: chain_key_1 = HKDF-SHA512(chain_key_0, "ratchet-advance" || client_entropy)
    token_1 = HMAC-SHA512(chain_key_1, claims_1)
    chain_key_0 SECURELY ERASED (zeroize + mlock)

T2: Attacker uses stolen token_0
    Server at chain_key_2: token_0 is from past epoch -> REJECTED
    Session terminated + alert
```

### Properties

- **Forward secrecy:** Past tokens underivable from current state
- **Post-compromise security:** DH ratchet step on re-auth heals the chain
- **Clone detection:** Cloned server stuck at old state; real server has advanced
- **Lookahead window:** ±3 epochs for network jitter tolerance
- **Mandatory re-auth:** 8 hours maximum, non-extendable (guarantees PCS healing)
- **Per-use client entropy:** Prevents clone prediction of ratchet advancement

---

## 9. Cryptographic Stack

### Library Selection

| Function | Library | Justification |
|----------|---------|---------------|
| PQ Key Exchange | `pqcrypto` (liboqs bindings) | FIPS 203 ML-KEM-768. Audited. |
| PQ Signatures | `pqcrypto` | FIPS 204 ML-DSA-65 + FIPS 205 SLH-DSA fallback. |
| Classical KEM | `x25519-dalek` | Constant-time X25519. NCC Group audited. |
| Threshold Signing | `frost-ed25519` (ZF FROST) | RFC 9591. Zcash Foundation. Audited. |
| OPAQUE | `opaque-ke` | RFC 9497. Meta's impl. NCC Group audited. |
| Ratchet | Custom (hkdf + sha2) | 20 lines, formally verifiable. |
| KDF | `argon2` | RFC 9106 Argon2id. 64 MiB, 3 iter, 4 parallel. |
| TLS | `rustls` + `rustls-post-quantum` | Memory-safe TLS 1.3. No OpenSSL. |
| AEAD | `aes-gcm-siv` | AES-256-GCM-SIV. Nonce-misuse resistant. |
| Hash | `sha2`, `sha3`, `blake3` | SHA-512 chains, SHA3-256 Merkle, BLAKE3 integrity. |
| HMAC | `hmac` | Constant-time HMAC-SHA512. |
| Secure Erase | `zeroize` | Compiler-fenced zeroization. |
| Random | `getrandom` | OS CSPRNG (/dev/urandom). |
| Serialization | `serde` + `postcard` | Binary. No JSON in hot path. |
| Client Puzzles | `equix` | Equihash variant (Tor). Memory-hard, GPU-resistant. |

### Rejected Alternatives

| Library | Reason for Rejection |
|---------|---------------------|
| OpenSSL | C code, massive attack surface, CVE history |
| ring | C/ASM wrapping; prefer pure-Rust |
| Node.js/JS crypto | Wrong language, no memory safety |
| Custom crypto | Never roll your own. All primitives from audited crates. |

### Hybrid Cryptography Rules

- PQ component is MANDATORY. No negotiation, no fallback.
- Nested signing: PQ signature covers (payload || classical_signature)
- Key combiner: shared_secret = KDF(ml_kem_ss || x25519_ss || context)
- Both classical AND PQ must be broken to compromise

---

## 10. Storage Architecture

### Data at Rest: Triple-Layer Encryption

**Layer 1: Full Disk Encryption** — dm-crypt/LUKS2, AES-256-XTS, key sealed to TPM PCRs

**Layer 2: Application-Level Encryption** — AES-256-GCM-SIV, encryption key threshold-split

**Layer 3: Field-Level Semantic Encryption** — Different keys per classification; OPAQUE envelopes encrypted under OPRF output (server can't decrypt without client password)

### Database Schema (PostgreSQL)

**device_enrollments:** device_id (UUID), tier (ENUM 1-4, server-assigned), attestation_hash, public_key, enrolled_at, enrolled_by, status. Note: No private keys, no secrets.

**user_credentials:** user_id (UUID), opaque_record (OPAQUE server registration — server cannot derive password), fido2_credentials (encrypted), credential_version (monotonic), kt_proof (Merkle inclusion proof).

**threshold_config:** share_id (UUID), share_data (encrypted, key derived from module runtime secret sealed to TPM + process attestation), share_epoch (invalidates old shares), refresh_at.

### Ephemeral Store (Redis with TLS + AUTH)

Ratchet chain states (encrypted), receipt cache (30s TTL), risk signals (no PII), puzzle nonces (short TTL), rate limit counters. All entries encrypted with ephemeral module runtime keys.

### The "Everything Cloned" Scenario

| Cloned Data | Attacker Can Do |
|-------------|-----------------|
| 1 threshold share | Nothing (need 3 of 5) |
| OPAQUE records | Cannot derive passwords |
| Encrypted MFA secrets | Cannot decrypt |
| FIDO2 public keys | Cannot forge signatures |
| Ratchet chain state | Tokens rejected (real system advanced) |
| Encrypted Redis dump | Cannot decrypt |
| Audit log | Read-only (cannot forge new entries) |
| KT Merkle tree | Read-only (cannot insert rogue creds) |
| Binary code | Modified binary fails attestation |
| Threshold share config | Encrypted under TPM-sealed key |

---

## 11. Inter-Module Communication Protocol (SHARD)

**Secure Hardened Authenticated Request Dispatch**

- Transport: Unix domain sockets (same host) or PQ-hybrid mTLS (cross-host)
- Encoding: postcard (binary serde) — no JSON, no protobuf
- Auth: Mutual TLS with per-connection ephemeral keys
- Replay: Monotonic counter + timestamp (±2s tolerance)
- Integrity: HMAC-SHA512 over entire message
- Ordering: Sequence numbers per channel

**Message format:**
```
[version: 1B][sender_module: 1B][sequence: 8B][timestamp: 8B][payload: var][HMAC-SHA512: 64B]
```

**Rejection conditions:** sequence <= last seen, timestamp > ±2s, HMAC mismatch, unknown sender, decryption failure.

---

## 12. DDoS Resistance

### Client Puzzle System

- Equihash variant with server-provided random nonce (per-request, 10s TTL, single-use)
- Precomputation impossible (nonce unknown until request)
- Adaptive difficulty: 10ms (normal) → 1-5s (under DDoS)
- Memory-hard: GPU/ASIC resistant

### Cost Asymmetry

- Attacker at 1M req/s: needs ~100,000 CPU cores (~$3,000/hour)
- Server puzzle verification: ~2ms per request
- Legitimate users: solve once (~100ms), proceed to auth

### Bounded Argon2 Concurrency

- Maximum 10 concurrent Argon2 operations server-side
- Client puzzles filter automated requests BEFORE password verification
- Prevents memory exhaustion attack (1000 IPs x 5 requests = 320GB without limit)

---

## 13. Device Tier System & Anti-Spoofing

### Tier Assignment

- Device tier determined by SYSTEM based on enrollment database
- Not self-reported by client
- Enrollment requires 2-party approval (enrollment officer + security officer)
- Full measured boot attestation (TPM PCR values vs known-good)
- Device health re-attestation on every authentication

### Tier Access Scoping

- Tier 3 tokens contain `auth_tier: 3` claim
- Resource servers check: `token.tier >= resource.min_tier`
- Network policy enforces: Tier 3 devices can only reach Tier 3 API endpoints
- No tier upgrade without full re-authentication at higher tier
- Tier downgrade: revokes all sessions, triggers incident investigation

### Why Spoofing as Tier 3 Gains Nothing

1. Must possess valid PSK (distributed OOB during physical enrollment)
2. Even if PSK stolen: hardware attestation check fails (hardware fingerprint mismatch)
3. Even if attestation forged: gets Tier 3 token, can only access SENSOR resources
4. Token modification breaks threshold signature (need 3-of-5 TSS)
5. Network policy blocks Tier 3 from reaching Tier 1/2 endpoints
6. Risk engine flags "sensor" making non-sensor API calls → session terminated

---

## 14. Key Transparency

### Merkle Tree

- SHA3-256 hash function
- Append-only: credential operations (register, rotate, enroll, revoke)
- Leaf: H(user_id || operation || credential_hash || timestamp)
- Signed tree head (STH) every 60 seconds with ML-DSA-65
- Batched updates in 1-second windows
- Rate-limited per user (prevents tree growth attack)

### Client Verification

- Clients request inclusion proof for their credentials
- Verify: "my credentials haven't been tampered with"
- Detects IdP compromise (rogue credential insertion)

### Monitor Verification

- Independent monitors verify consistency proofs
- Detect: "no rogue credentials were inserted for any user"
- Publicly auditable without revealing secrets

---

## 15. Audit System

### BFT Replication

- 7 nodes across different administrative domains (different providers, locations)
- Tolerates 2 fully Byzantine (malicious) nodes
- Any 3 honest nodes reconstruct complete log

### Entry Structure

```
AuditEntry {
    event_id: UUID,
    event_type: enum,
    user_ids: Vec<UUID>,
    device_ids: Vec<UUID>,
    ceremony_receipts: Vec<Receipt>,
    risk_score: f64,
    timestamp: i64,        // microsecond precision
    prev_hash: [u8; 32],   // chain to previous
    signature: Vec<u8>,    // ML-DSA-65
}
```

### External Witness

- Periodic Merkle root checkpoints to external immutable store
- Separate administrative domain from all BFT nodes
- Even total BFT compromise cannot rewrite witnessed history

### Audit Failure Mode

- If audit module crashes: ALL AUTHENTICATION STOPS
- Unaudited authentication is worse than no authentication

---

## 16. Failure Modes & Self-Healing

| Component | Failure | System Response |
|-----------|---------|-----------------|
| Gateway | Crash | LB routes to replica. Zero state lost. |
| Orchestrator | Crash | Queue briefly, failover. No secrets at risk. |
| TSS node | Crash | 4 of 5 remain. Need 3. Continue. Refresh on restart. |
| T-OPAQUE | Crash | New logins blocked. Existing sessions continue. Auto-restart. |
| Ratchet | Crash | Active sessions invalidated. Users re-auth. SAFE failure. |
| KT | Crash | Credential ops queue. Auth continues. |
| Risk Engine | Crash | Default to HIGHEST RISK. Step-up required. Fail-secure. |
| Audit | Crash | AUTH STOPS. No auth without audit. Deliberate. |
| Network partition | TSS can't form quorum | No new tokens. Existing tokens until epoch expiry. Alerts fire. |
| Clock skew | Roughtime disagrees | Halt token issuance. Fail-secure. |
| Ratchet desync | Client/server mismatch | ±3 lookahead: accept+resync. Beyond: force re-auth. |
| Share refresh fail | 3 consecutive | Raise threshold 3-of-5 → 4-of-5. Alert. |
| Share refresh fail | 6 consecutive | Signing suspended. Human intervention. |

**Principle:** Every failure mode defaults to MORE SECURITY, never less.

---

## 17. Deployment & Binary Integrity

### Build Pipeline

- Rust stable (1.85+), Edition 2024
- `#![forbid(unsafe_code)]` except crypto FFI boundary
- Static linking (musl libc) — zero runtime dependencies
- Reproducible builds: 3 independent environments, bit-identical outputs
- Build attestation: threshold-signed by 3-of-5 build engineers
- SLSA Level 4 provenance metadata
- Compiler: Rust toolchain pinned by hash, verified against multiple sources

### Container

- Distroless base (NO shell, NO package manager)
- Image signed with cosign (Sigstore)
- SBOM attached
- Kubernetes admission controller verifies: signature, hash, SBOM CVEs, approvals

### Runtime Attestation

- Each module on startup: SHA3-256(own_binary) vs transparency log
- Periodic re-verification every 10 minutes
- Module-to-module attestation before mTLS
- Modified binary → fails attestation → other modules refuse connection → alert

### Process Isolation (Linux)

- Separate UID per module
- Separate network namespace
- seccomp-bpf: ~30 syscall whitelist
- No filesystem access except own config
- No ptrace (prevents debugger attach)
- No CAP_SYS_PTRACE, no CAP_NET_RAW
- Memory locked (mlockall — no swap)
- ASLR + PIE + stack canaries + CFI
- Landlock LSM: restrict filesystem + network

---

## 18. Supply Chain Security

### Dependency Management

- All crate dependencies vendored into repository
- No network fetches during build
- Each dependency audited via cargo-vet with signed attestations from 2+ engineers
- Dependency updates require security review + multi-party approval

### Build Reproducibility

- 3 independent build environments (different hardware, OS, cloud)
- All 3 produce bit-identical binaries
- Any divergence → build rejected, investigation triggered

### Build Attestation

- Production binary signed with threshold signature (3-of-5 build engineers)
- Provenance metadata: source commit, builder identity, timestamp, dep hashes, toolchain
- Published to build transparency log

### Compiler Trust

- Rust toolchain pinned by hash
- Toolchain integrity verified against multiple independent sources
- Diverse double-compilation considered for Thompson attack resistance

---

## 19. Performance Analysis

### Hot Path (Token Verification) — O(1), ~72 microseconds

| Step | Operation | Complexity | Time |
|------|-----------|-----------|------|
| 1 | Parse token header (binary, fixed-size) | O(1) | ~10us |
| 2 | Check ratchet epoch (counter compare) | O(1) | ~1us |
| 3 | Verify DPoP binding (HMAC-SHA256) | O(1) | ~5us |
| 4 | Verify threshold signature (Ed25519) | O(1) | ~50us |
| 5 | Check tier vs resource (integer compare) | O(1) | ~1us |
| 6 | Advance ratchet (single HKDF) | O(1) | ~5us |
| **Total** | | **O(1)** | **~72us** |

### Warm Path (Full Auth Ceremony, Tier 1) — ~73ms

| Step | Operation | Time |
|------|-----------|------|
| 1 | Client puzzle verify | ~2ms |
| 2 | OPAQUE (server-side OPRF) | ~1ms |
| 3 | FIDO2 assertion verify | ~5ms |
| 4 | Risk score computation | ~1ms |
| 5 | Receipt collection | ~3ms |
| 6 | Threshold signing (3 nodes) | ~10ms |
| 7 | Ratchet initialization | ~1ms |
| 8 | DPoP binding | ~1ms |
| **Total (server-side)** | | **~24ms** |
| Client-side Argon2 (bottleneck) | | ~50ms |
| **End-to-end** | | **~73ms** |

### Key Transparency — O(log n) proof, O(1) verify

### Audit Append — O(1)

### Audit Verification — O(log n)

---

## 20. Red Team Findings & Mitigations

### Round 1: 56 Attack Vectors (Against Current Codebase)

The current NestJS implementation has zero of the proposed security properties. All 56 findings are addressed by the complete Rust rewrite specified in this document.

Critical findings in current code:
- Full signing key in single process memory
- Admin password logged in plaintext
- MFA bypass via direct userId submission
- Client secret never validated in OAuth
- Fake Kyber implementation (SHA3 pretending to be ML-KEM)
- No TLS anywhere
- Dual signing system conflict
- OAuth redirect URI prefix matching vulnerability

### Round 2: 40 Attack Vectors (Against Proposed Design)

All incorporated into the design:

**P0 (Critical):**
1. Coercion signal → Duress PIN protocol
2. Insider collusion → Time delay + cross-department requirement + external witness
3. Orchestrator trust → Direct action binding via FIDO2 challenge hash
4. Abort window ambiguity → Default=abort, FIDO2-signed proceed/abort
5. Supply chain → SLSA Level 4, threshold build attestation, vendored deps

**P1 (High):**
6. Receipt session binding → ceremony_session_id + hash chain
7. TOCTOU ceremony-to-execution → Real-time auth check at execution
8. Share refresh failure → Escalating threshold + suspension
9. OPRF key protection → Threshold OPRF (T-OPAQUE)
10. Ratchet desync → ±3 epoch lookahead
11. Mandatory re-auth → 8-hour hard ceiling

**P2 (Medium):** 29 additional findings all addressed (clock sync, action canonicalization, receipt key protection, PQ mandatory, ceremony pool size, puzzle precomputation, hybrid binding, FIDO2 timing, BFT node count, enrollment multi-party, KT rate limiting, and more).

---

## 21. Novelty Assessment

Based on exhaustive research, this system would be the first to combine:

| Property | Prior Art | Status |
|----------|-----------|--------|
| Threshold token signing in SSO | Blockchain MPC only | **Novel in SSO** |
| OPAQUE for IdP login | WhatsApp key backup only | **Novel in SSO** |
| T-OPAQUE (threshold OPRF) | Academic prototype only | **Novel in production** |
| Ratcheting session tokens | 1 academic paper | **Novel in production** |
| Key Transparency for auth | Google (messaging only) | **Novel in auth** |
| Microkernel isolation for auth | seL4/KasperskyOS (OS only) | **Novel in auth** |
| Crypto client puzzles in auth | Academic concept since 1999 | **Novel in production** |
| PQ crypto at auth protocol level | Transport layer only | **Novel at protocol level** |
| All combined | Nobody | **Unprecedented** |

No publicly documented system — DoD CAC/PIV, NSA CSfC, Google BeyondCorp, Microsoft Entra, NATO, Five Eyes — combines even three of these properties.

---

## Appendix A: Glossary

- **FROST:** Flexible Round-Optimized Schnorr Threshold signatures (RFC 9591)
- **OPAQUE:** Oblivious Pseudorandom Function-based Asymmetric PAKE (RFC 9497)
- **T-OPAQUE:** Threshold OPAQUE (OPRF key threshold-split)
- **ML-KEM:** Module-Lattice Key Encapsulation Mechanism (FIPS 203)
- **ML-DSA:** Module-Lattice Digital Signature Algorithm (FIPS 204)
- **SLH-DSA:** Stateless Hash-Based Digital Signature Algorithm (FIPS 205)
- **DPoP:** Demonstration of Proof of Possession (RFC 9449)
- **SHARD:** Secure Hardened Authenticated Request Dispatch (custom IPC protocol)
- **BFT:** Byzantine Fault Tolerant
- **KT:** Key Transparency
- **TSS:** Threshold Signing Service
- **HKDF:** HMAC-based Key Derivation Function
- **Equihash:** Memory-hard proof-of-work function
- **Roughtime:** Authenticated time protocol (Byzantine-tolerant)

## Appendix B: References

- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- RFC 9497 (OPAQUE / OPRFs Using Prime-Order Groups)
- RFC 9591 (FROST Threshold Signatures)
- RFC 9449 (DPoP)
- NIST SP 800-207 (Zero Trust Architecture)
- Signal Double Ratchet Specification
- Google Key Transparency
- CONIKS (Key Transparency)
- "Enhancing JWT Security Using Signal Protocol" (Springer, 2022)
- Herzberg et al., "Proactive Secret Sharing" (1995)
- NSA CNSA 2.0 FAQ
- W3C WebAuthn Level 3
- FIDO Alliance Attestation Whitepaper
