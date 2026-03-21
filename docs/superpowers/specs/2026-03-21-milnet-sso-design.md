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
| PQ Key Exchange | `libcrux-ml-kem` (Cryspen) | FIPS 203 ML-KEM-768. Formally verified constant-time. See Errata C.1. |
| PQ Signatures | `libcrux-ml-dsa` (Cryspen) | FIPS 204 ML-DSA-65. Formally verified. See Errata C.1. |
| Classical KEM | `x25519-dalek` >= 4.1.3 | Constant-time X25519. Pin post CVE-2024-58262. See Errata C.2. |
| Threshold Signing | `frost-ristretto255` (ZF FROST) + ROAST | RFC 9591. Cofactor-free. Liveness-guaranteed. See Errata C.6, C.15. |
| OPAQUE | `opaque-ke` | RFC 9497. Meta's impl. NCC Group audited. |
| Ratchet | Custom (hkdf + sha2) | 20 lines, formally verifiable. |
| KDF | `argon2` | RFC 9106 Argon2id. 64 MiB, 3 iter, 4 parallel. |
| TLS | `rustls` + `rustls-post-quantum` | Memory-safe TLS 1.3. No OpenSSL. |
| AEAD | `aes-gcm-siv` + Encrypt-then-HMAC for OPAQUE | AES-256-GCM-SIV general. Committing AEAD for OPAQUE envelopes. See Errata C.3. |
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

## Appendix B: Spec Review Errata (Round 1)

The following issues were identified during spec review and are resolved here.

### B.1: Token Structure — Dual-Layer (CRITICAL)

Tokens use TWO layers, not one:
- **Outer layer:** Threshold-signed (FROST Ed25519 + nested ML-DSA-65) JWT-like structure. This is what the TSS produces at ceremony completion. Contains claims, tier, scope, expiry, DPoP binding.
- **Inner layer:** HMAC-SHA512 ratchet tag appended per-use/per-epoch. The ratchet tag proves the token was used at a specific epoch. The verifier checks BOTH: (1) threshold signature on claims (using cached public key, O(1)), and (2) ratchet HMAC tag matches current or ±3 epoch (using in-memory chain state, O(1)).

This is NOT a contradiction — it is layered verification. The threshold signature proves issuance authority. The ratchet tag proves temporal freshness. Both are required.

### B.2: Receipt TTL (CRITICAL)

Receipt TTL is per-step, not per-ceremony. Each step's receipt has 30-second TTL from its issuance. The TSS validates each receipt against its own issuance timestamp, not against the ceremony start time. A 73ms ceremony easily fits. Human delay (fumbling for FIDO2 key) is between steps — the receipt for step N is not issued until step N completes. Clock is the TSS's own Roughtime-synchronized clock.

For ceremonies requiring human interaction (Level 3-4), the orchestrator issues a "ceremony-in-progress" hold at the TSS, extending the validation window to 120 seconds for human-interactive ceremonies. This hold is requested before the first receipt and cannot be forged (requires orchestrator mTLS identity).

### B.3: ML-DSA-65 Key Management (CRITICAL)

The ML-DSA-65 key for nested PQ signatures IS threshold-split. Each TSS node holds a share of both the Ed25519 key AND the ML-DSA-65 key. Threshold ML-DSA is achieved via the generic threshold signing framework: the coordinator collects partial signatures from t-of-n nodes and combines them. While threshold ML-DSA is not standardized (unlike FROST for Schnorr), the generic linear secret sharing approach works for ML-DSA because it is based on lattice operations that are compatible with additive secret sharing.

If threshold ML-DSA proves infeasible in implementation, the fallback is: one TSS node computes the full ML-DSA-65 signature (rotating which node per request), and the other nodes verify it before the combined token is released. This provides detection (malicious ML-DSA signatures are caught) but not prevention of a single-node ML-DSA forgery. The FROST layer provides the threshold guarantee; ML-DSA provides quantum resistance.

### B.4: Duress PIN Implementation (CRITICAL)

Standard FIDO2 authenticators do not support dual PINs. The implementation options:

1. **Custom firmware (preferred for MILNET):** Military-issue FIDO2 keys (e.g., custom YubiKey FIPS with modified firmware) that support duress PIN extension. This is feasible for a controlled military deployment where devices are issued centrally.

2. **Client-side software layer:** The client application (not the authenticator) accepts two PINs. Normal PIN proceeds normally. Duress PIN sends a pre-registered "canary" signal to the orchestrator before initiating the FIDO2 ceremony. The authenticator itself is unaware. Less secure (malware on client could detect the canary) but works with COTS hardware.

3. **Separate duress button:** A physical dead-man's switch or panic button on the device that triggers the duress protocol independently of the FIDO2 ceremony.

For MILNET deployment, option 1 is recommended. The spec acknowledges this requires custom hardware.

### B.5: Argon2 Client-Side vs Server-Side (CRITICAL)

In OPAQUE, Argon2 runs CLIENT-SIDE as part of the key stretching to derive the OPRF input. The server never runs Argon2 for OPAQUE authentication.

The "maximum 10 concurrent Argon2 operations server-side" refers to a SEPARATE concern: password quality validation during initial user enrollment/registration (where the server must verify the password meets complexity requirements by testing it against the KDF). This is a one-time operation, not per-login.

The DDoS cost calculation in Section 12 is corrected: the server-side bottleneck is the OPRF evaluation (~1ms), not Argon2. The memory exhaustion attack via Argon2 does not apply because Argon2 runs on the client.

### B.6: BFT Quorum Math (CRITICAL)

Corrected: With 7 nodes and f=2:
- BFT consensus requires 2f+1 = 5 honest nodes to agree
- The system tolerates 2 Byzantine faults
- "Any 3 honest nodes reconstruct" was INCORRECT. Corrected to: "requires 5 honest nodes for consensus; any 5 honest nodes produce a consistent view."
- Data replication uses standard BFT replication, not erasure coding.

### B.7: Ratchet ±3 Epoch Lookahead (IMPORTANT)

The ±3 lookahead creates a 90-second replay window. This is an intentional trade-off:
- Without lookahead: network jitter causes false rejections → availability impact
- With ±3: 90-second window where a stolen token might work

Mitigation: The DPoP channel binding means a stolen token can only be replayed on the same TLS connection (which the attacker would need to hijack, not just observe). The combination of ratcheting + DPoP means the attacker needs BOTH a stolen token AND control of the victim's TLS session, within 90 seconds. This is acceptable for the threat model.

The spec text claiming "stolen tokens die instantly" is corrected to: "stolen tokens are usable only within a ±90-second window AND only on the same TLS channel (DPoP-bound)."

### B.8: DPoP HMAC Algorithm (IMPORTANT)

Corrected: All HMAC operations use HMAC-SHA512 for consistency. The DPoP binding verification uses HMAC-SHA512, not HMAC-SHA256. Updated time estimate: ~7us (negligible impact on total).

### B.9: Key Lifecycle Management (CRITICAL — NEW SECTION)

Added to the spec:

**Initial FROST key generation:** Performed via a trusted dealer ceremony during system bootstrapping. The dealer generates the group secret, computes shares, distributes to TSS nodes over secure channels, and then DESTROYS the complete secret. Alternatively, a Distributed Key Generation (DKG) protocol is used where no single party ever holds the complete key. DKG is preferred.

**Key rotation (group key change):** Triggered by compromise detection or policy (e.g., annually). New DKG ceremony produces new group key. Old key retained for verification-only during transition period. All new tokens signed with new key. Old tokens verified with old key until expiry.

**TSS node revocation:** Compromised node is removed from the group. New DKG ceremony with N-1 remaining nodes + 1 new node. Old shares invalidated.

**Receipt signing keys:** Generated in HSM, rotated daily, old keys retained for 24h verification window.

### B.10: Disaster Recovery / Bootstrapping (CRITICAL — NEW SECTION)

**Cold start procedure:**
1. Minimum 3-of-5 TSS nodes must be online
2. Each node verifies own binary integrity against transparency log
3. Nodes perform mutual attestation
4. FROST DKG ceremony establishes new signing key (or restore from encrypted backup shares)
5. Orchestrator starts, discovers available modules
6. Gateway starts, begins accepting connections
7. Audit module MUST be running before any auth is permitted

**Backup:** Encrypted threshold shares backed up to geographically separate cold storage. k-of-n backup custodians required to restore. Backup verification tested quarterly.

**Tier 4 Emergency recovery:** Shamir secret share (5-of-9 human custodians) reconstructs a master recovery key that can bootstrap a minimal system (audit + 1 TSS + orchestrator + gateway) for emergency access.

### B.11: User Enrollment Ceremony (IMPORTANT — NEW SECTION)

**First user enrollment:**
1. Admin initiates enrollment (Level 2 action, requires step-up re-auth)
2. User receives enrollment token via secure out-of-band channel (in-person, encrypted email)
3. User presents enrollment token to system
4. OPAQUE registration: client-side key stretching → server stores OPAQUE record
5. FIDO2 credential registration: user taps hardware key → public key stored
6. KT log entry created for registration event
7. Device enrollment (if not already enrolled): 2-party approval
8. Audit entry: enrollment event with admin ID, user ID, devices, timestamp

### B.12: Revocation (IMPORTANT — NEW SECTION)

**User revocation:**
1. Admin initiates (Level 2 action)
2. User's OPAQUE record marked revoked in DB
3. All active sessions terminated: ratchet manager broadcasts "kill session" for user ID
4. FIDO2 credentials marked revoked
5. KT log entry for revocation
6. Audit entry for revocation
7. Immediate — no token can be verified for this user after revocation event

**Credential revocation (lost FIDO2 key):**
1. User authenticates via remaining factor + step-up
2. Lost key's public key marked revoked
3. KT log entry
4. New key enrollment ceremony

**Token revocation:** Not needed — ratchet advancement + short lifetimes (5-15 min) + DPoP binding make explicit token revocation unnecessary. Revoke the user or session, not individual tokens.

### B.13: Horizontal Scaling (IMPORTANT — NEW SECTION)

**Stateless modules (Gateway, Orchestrator, Verifier):** Horizontally scalable. Run N replicas behind load balancer. No shared state.

**Stateful modules (TSS):** Fixed at 5 nodes (threshold group). Not horizontally scalable — adding nodes requires DKG re-ceremony. Throughput: ~500 signings/sec (with 3-node participation per signing). For surge scenarios (100K+ users), use token caching: issue a slightly longer-lived token during surge that can be verified without TSS involvement, reducing TSS load.

**Ratchet Manager:** Partitioned by session ID. Each instance manages a shard of sessions. Horizontal scaling via consistent hash ring.

**T-OPAQUE:** Stateless per-request (OPRF evaluation). Horizontally scalable.

**KT Log:** Single writer (batched appends). Multiple read replicas for proof serving.

**Risk Engine:** Partitioned by user ID. Horizontally scalable.

**Audit:** Fixed at 7 BFT nodes. Not horizontally scalable (BFT complexity grows O(n^2)).

**Surge throughput estimate (revised):** With token caching during surge, the TSS bottleneck is mitigated. Verifier handles 100K+ verifications/sec (in-memory, O(1)). Auth ceremonies limited to ~500/sec by TSS — during surge, a queue with priority (Tier 1 first) manages backlog. 100K users authenticating over a 5-minute window = ~333/sec, within capacity.

### B.14: Token Format (IMPORTANT — NEW SECTION)

```
Token (binary, postcard-serialized):
  header:
    version: u8
    algorithm: u8 (0x01 = Ed25519+ML-DSA-65)
    tier: u8
  claims:
    sub: UUID (user_id)
    iss: [u8; 32] (issuer hash)
    iat: i64 (issued at, microseconds)
    exp: i64 (expires at, microseconds)
    scope: u32 (bitfield of resource scopes)
    dpop_hash: [u8; 32] (H(client DPoP public key))
    ceremony_id: [u8; 32]
    tier: u8
    ratchet_epoch: u64
  ratchet_tag: [u8; 64] (HMAC-SHA512 for current epoch)
  frost_signature: [u8; 64] (Ed25519 threshold signature over header+claims)
  pq_signature: Vec<u8> (ML-DSA-65 over header+claims+frost_signature)
```

Total size: ~3.5 KB (ML-DSA-65 signatures are ~3.3 KB). Compared to typical JWT: larger, but binary serialization compensates for parse overhead.

### B.15: FROST Coordinator Role (CRITICAL — NEW SECTION)

The **Auth Orchestrator** (Module 2) acts as the FROST coordinator. It collects partial signatures from t TSS nodes and aggregates them. FROST is secure against a malicious coordinator — the coordinator sees partial signatures but cannot forge a valid aggregate signature without t valid shares. A malicious coordinator can only cause DoS (refuse to aggregate), not forgery.

If the orchestrator is compromised and refuses to coordinate, any TSS node can act as fallback coordinator (FROST does not require a fixed coordinator). The TSS nodes detect coordinator failure via timeout and elect a new coordinator.

### B.16: KT Split-View Protection (IMPORTANT)

Key Transparency requires a gossip protocol to prevent split-view attacks. Added: clients and monitors periodically exchange signed tree heads (STHs) and verify consistency. If any two parties observe inconsistent STHs for the same epoch, a split-view attack is detected and an alert is triggered. The gossip protocol runs over the existing PQ-hybrid mTLS channels.

### B.17: mTLS Certificate Management (IMPORTANT)

Module certificates are issued by a private CA that is itself threshold-managed (the root CA private key is FROST-split across TSS nodes). Certificate lifetimes are 24 hours with automated renewal. Each module verifies the peer's certificate against the private CA root + the module attestation record (binary hash must match transparency log). "Ephemeral per-connection keys" refers to TLS session keys (ephemeral DH), not certificates — certificates are persistent (24h) and identity-bearing.

### B.18: Implementation Risk Acknowledgment (IMPORTANT)

This system combines 8+ techniques that are individually proven but have never been integrated. Implementation risks include: unknown interaction effects between components, performance characteristics under real load that differ from theoretical analysis, operational complexity of managing 9+ processes with threshold crypto, and the absence of a community of practice for troubleshooting. Mitigation: phased implementation with extensive integration testing, red-team exercises at each phase, and graceful degradation paths that allow falling back to simpler (but still secure) configurations during the maturation period.

### B.19: Risk Scoring Parameters (IMPORTANT)

Risk score = weighted sum of signals, range [0.0, 1.0]:
- Device attestation freshness: weight 0.25 (stale attestation increases risk)
- Geo-velocity: weight 0.20 (impossible travel between auth events)
- Network context: weight 0.15 (unusual IP range, VPN, Tor)
- Time-of-day: weight 0.10 (auth outside normal hours)
- Access pattern: weight 0.15 (unusual API calls for this user/device class)
- Failed attempt history: weight 0.15 (recent failures increase risk)

Thresholds:
- score < 0.3: normal (no action)
- 0.3 <= score < 0.6: elevated (increase logging, shorten token lifetime)
- 0.6 <= score < 0.8: high (require step-up re-authentication)
- score >= 0.8: critical (terminate session, require full ceremony)

Thresholds are configurable via Level 3 action (two-person approval). Changes audited.

### B.20: Ceremony Tier vs Device Tier Mapping (IMPORTANT)

- Device Tier determines the MAXIMUM ceremony level the device can perform
- Ceremony Tier determines the authentication strength REQUIRED for the resource
- A Tier 2 device CANNOT perform a Tier 1 ceremony (lacks FIDO2 hardware)
- A Tier 1 device CAN perform a Tier 2 ceremony (has all capabilities)
- Resource access requires: device_tier >= resource_tier AND ceremony completed at resource_tier level

### B.21: Equihash Cost Estimate Correction (SUGGESTION)

Corrected: At 10ms difficulty, one core does 100 puzzles/sec. For 1M req/s, attacker needs ~10,000 cores at normal difficulty. Under DDoS (1-5s difficulty), attacker needs 1M-5M core-seconds/sec = 1M-5M cores. The original estimate of 100,000 was for moderate difficulty (~100ms). Corrected in spec.

## Appendix C: Cryptographic Red Team Errata (Round 3)

Findings from IACR-level cryptographic analysis. 15 attack vectors identified, all addressed below.

### C.1: CRITICAL — Replace pqcrypto with libcrux

The `pqcrypto` crate wraps PQClean, which self-describes as "primarily for academic and experimental purposes." It has NO independent security audit, NO NIST KAT vector tests, and the KyberSlash timing attack (TCHES 2025) demonstrated key recovery in minutes on ARM via secret-dependent division instructions in the reference code.

**Fix:** Replace `pqcrypto` with **Cryspen's libcrux** for ML-KEM-768 and ML-DSA-65. libcrux provides:
- Formally verified constant-time behavior (using hax/F* extraction)
- NIST KAT vector compliance
- Independent security audit
- Spectre-hardened implementation with speculative load barriers

Updated library table:

| Function | Library (REVISED) | Justification |
|----------|-------------------|---------------|
| PQ Key Exchange | `libcrux-ml-kem` | Formally verified constant-time ML-KEM-768. Cryspen. |
| PQ Signatures | `libcrux-ml-dsa` | Formally verified ML-DSA-65. Cryspen. |
| Classical KEM | `x25519-dalek` >= 4.1.3 | Constant-time X25519. Pin version post CVE-2024-58262 fix. |

### C.2: CRITICAL — Pin curve25519-dalek >= 4.1.3

CVE-2024-58262 (RUSTSEC-2024-0344): timing variability in `Scalar29::sub` and `Scalar52::sub` caused by LLVM inserting conditional branches around masking operations. Fixed in v4.1.3 with volatile read barriers.

**Fix:** Pin `curve25519-dalek >= 4.1.3` in Cargo.toml. Add CI check that fails if any transitive dependency pulls an older version.

### C.3: HIGH — Use Committing AEAD for OPAQUE Envelopes

The partitioning oracle attack (Len et al., USENIX Security 2021) demonstrated that OPAQUE requires a CMT-4 secure (key-committing) AEAD. AES-256-GCM-SIV is nonce-misuse resistant but NOT proven CMT-4 secure. Non-committing AEAD enables offline dictionary attacks after server compromise by constructing ciphertexts that decrypt validly under multiple keys.

**Fix:** Use **Encrypt-then-HMAC** (AES-256-CTR + HMAC-SHA256) for OPAQUE envelopes. This is provably key-committing (the HMAC commits to the key). Alternatively, use the OPAQUE-recommended `Envelope` mode with an explicit key commitment scheme.

The `opaque-ke` crate's NCC Group audit (2021, v0.5.0) predates the partitioning oracle paper. Verify that the current version uses a committing AEAD or patch the AEAD layer.

### C.4: HIGH — Threshold OPRF Reconstruction Must Happen Client-Side

The spec routes OPRF evaluations through the Auth Orchestrator. In T-OPAQUE, each threshold OPRF node produces a partial evaluation. If the orchestrator collects these partial evaluations and combines them before forwarding to the client, it sees ALL partial evaluations — exactly the information needed for offline dictionary attack (the orchestrator can compute the full OPRF output for candidate passwords).

**Fix:** Partial OPRF evaluations must be forwarded INDIVIDUALLY to the client. The CLIENT performs the threshold reconstruction (Lagrange interpolation) of the OPRF output. The orchestrator sees encrypted partial evaluations but never the combined result. This preserves OPAQUE's security model where the server never sees the password-derived value.

Protocol flow:
```
Client → Orchestrator: blinded password element
Orchestrator → OPRF Node 1: blinded element
Orchestrator → OPRF Node 2: blinded element
Orchestrator → OPRF Node 3: blinded element
OPRF Node 1 → Client (directly via mTLS): partial evaluation 1
OPRF Node 2 → Client (directly via mTLS): partial evaluation 2
OPRF Node 3 → Client (directly via mTLS): partial evaluation 3
Client: combines partials → full OPRF output → OPAQUE key derivation
```

The orchestrator relays the initial blinded element but NEVER sees partial evaluations.

### C.5: HIGH — Threshold ML-DSA Implementation Strategy (Revised)

Additive secret sharing is NOT directly compatible with ML-DSA due to rejection sampling. The combined noise from independent signers exceeds rejection bounds with high probability, requiring expensive re-signing rounds. Research (Eprint 2026/013, "Efficient Threshold ML-DSA") shows this is feasible only for small parties (~6) with ~1MB communication per party.

**Revised strategy:**
1. **Primary:** Use the Quorus construction (Eprint 2025/1163) which is specifically designed for scalable threshold ML-DSA with practical communication overhead.
2. **Implementation:** Commission a custom implementation based on the Quorus paper, with formal verification and independent audit before deployment.
3. **Interim fallback:** Until threshold ML-DSA is production-ready, use the following:
   - FROST threshold Ed25519 provides the threshold guarantee
   - A SINGLE ML-DSA-65 signature is computed by ONE TSS node (rotated round-robin)
   - ALL other TSS nodes verify the ML-DSA-65 signature before releasing their FROST partial signatures
   - This means: you need 3-of-5 FROST agreement AND a valid ML-DSA-65 signature
   - A malicious ML-DSA signer can produce garbage → caught by verification → rotated out
   - A malicious ML-DSA signer can refuse to sign → detected by timeout → another node takes over
   - The ML-DSA layer provides PQ resistance; FROST provides threshold guarantee
4. **Risk:** The single ML-DSA signer is a temporary SPOF for PQ resistance (not for forgery — you still need the FROST threshold). Document this as a known limitation with a timeline for migrating to full threshold ML-DSA.

### C.6: HIGH — Adopt ROAST Wrapper for FROST Liveness

CertiK's research documents commitment equivocation attacks in decentralized FROST. Even in centralized mode, a compromised coordinator can selectively delay nonce commitments to prevent signing quorums from forming (liveness attack). RFC 9591 does not address this.

**Fix:** Wrap FROST with **ROAST** (Robust Asynchronous Schnorr Threshold Signatures, Ruffing et al., CCS 2022). ROAST guarantees that if t honest signers are available, a signature WILL be produced regardless of coordinator behavior. ROAST is backward-compatible with FROST — it is a coordination wrapper, not a new signing scheme.

### C.7: CRITICAL (Conditional) — FROST Nonce Tracking for Clone Detection

If a TSS node is cloned or restored from backup, its CSPRNG state may repeat, producing nonce collisions. Two partial signatures with the same nonce reveal the signer's secret share via `s1 - s2 = (c1 - c2) * sk_i`.

**Fix:**
1. The FROST coordinator MUST track all nonce commitments (per RFC 9591 Section 7.3). If a duplicate commitment is detected, the signing session is aborted and the node is quarantined.
2. Each TSS node maintains a persistent monotonic counter that is included in nonce generation: `nonce = H(secret_share || counter || randomness)`. The counter is persisted to durable storage and incremented on every signing session. Even after a clone/restore, the counter prevents repeating the same nonce (unless the attacker also resets the persistent counter AND controls the randomness source).
3. TSS nodes MUST NOT be restored from backup without generating fresh key shares via proactive refresh. Restoring a backup node is equivalent to enrolling a new node.

### C.8: MEDIUM-HIGH — Adopt X-Wing Hybrid KEM Combiner

The spec uses a generic `KDF(ml_kem_ss || x25519_ss || context)` combiner. X-Wing (Eprint 2024/039) provides a formal proof that this structure is IND-CCA secure when using SHA3-256 and including the ML-KEM ciphertext in the KDF input.

**Fix:** Adopt the **X-Wing combiner** specification:
```
shared_secret = SHA3-256(
    "X-Wing" ||
    ml_kem_shared_secret ||
    ml_kem_ciphertext ||
    x25519_shared_secret ||
    x25519_public_key_client ||
    x25519_public_key_server
)
```
This is provably IND-CCA secure if either ML-KEM or X25519 is secure. Use SHA3-256 (not HKDF-SHA512) for the KEM combiner to match X-Wing's proof.

### C.9: MEDIUM-HIGH — HKDF Ratchet Client Entropy Must Be Blinded

The attacker fully controls `client_entropy` in the ratchet advancement. While HKDF's PRF assumption holds when the chain key is secret, attacker-controlled input creates a chosen-input oracle. Additionally, HKDF is not collision-resistant for arbitrary inputs (Eprint 2025/657).

**Fix:**
1. Client entropy is blinded before use: `blinded_entropy = H(client_entropy || server_nonce)` where `server_nonce` is a random value generated by the ratchet manager and sent to the client per-epoch.
2. The ratchet formula becomes: `chain_key_{n+1} = HKDF-SHA512(chain_key_n, "ratchet-advance" || blinded_entropy)`
3. Neither party alone controls the KDF input. The attacker would need to control both the client entropy AND the server nonce to predict ratchet output.

### C.10: MEDIUM-HIGH — Comprehensive Domain Separation Scheme

Multiple sub-protocols use overlapping primitives (Ed25519, HMAC-SHA512, SHA-512). Without domain separation, cross-protocol message injection is possible.

**Fix:** Define a system-wide domain separation scheme:
```
All Ed25519 signatures include a domain prefix:
  FROST token signing:   "MILNET-SSO-v1-FROST-TOKEN" || payload
  Receipt signing:        "MILNET-SSO-v1-RECEIPT" || receipt_data
  DPoP proof:            "MILNET-SSO-v1-DPOP" || dpop_data
  Audit entry:           "MILNET-SSO-v1-AUDIT" || entry_data
  Module attestation:    "MILNET-SSO-v1-ATTEST" || binary_hash

All HMAC-SHA512 operations include a domain prefix:
  Ratchet advance:       "MILNET-SSO-v1-RATCHET" || chain_data
  SHARD message auth:    "MILNET-SSO-v1-SHARD" || message_data
  Token ratchet tag:     "MILNET-SSO-v1-TOKEN-TAG" || claims

All hash operations include a domain prefix:
  Merkle tree leaf:      "MILNET-SSO-v1-KT-LEAF" || leaf_data
  Receipt chain:         "MILNET-SSO-v1-RECEIPT-CHAIN" || prev_hash
  Action binding:        "MILNET-SSO-v1-ACTION" || action_data
```
No two operations in the system share the same domain prefix. This makes cross-protocol injection cryptographically impossible.

### C.11: MEDIUM — Nested Signature Verification Order

The nested signing (PQ over classical) creates a signature stripping risk if a future quantum computer breaks ML-DSA. The verifier MUST enforce both signatures are always present.

**Fix:** Token verification algorithm (mandatory, in order):
1. Parse token. If `pq_signature` field is missing → REJECT (not optional)
2. Verify ML-DSA-65 signature over `(header || claims || frost_signature)` → REJECT if invalid
3. Verify FROST Ed25519 signature over `(header || claims)` → REJECT if invalid
4. Both must pass. There is no "classical-only" mode. PQ is mandatory.

Additionally: FROST uses Ristretto encoding (cofactor-free). The spec MUST verify that the Ristretto-to-Ed25519 compatibility layer does not introduce cofactor-related malleability into the ML-DSA input. Use `frost-ristretto255` (not `frost-ed25519`) to avoid cofactor issues entirely.

### C.12: MEDIUM — Spectre Mitigations for Crypto Code

Spectre v1/v2 can break constant-time guarantees even in formally verified code (Serberus, IEEE S&P 2024). Speculative execution leaks secret-dependent memory accesses through cache timing.

**Fix:**
1. Compile all crypto modules with LLVM's **Speculative Load Hardening (SLH)**: `-C llvm-args=-x86-speculative-load-hardening`
2. Use `lfence` barriers after branch instructions in crypto hot paths
3. Pin to dedicated physical hardware (not VMs) for TSS nodes — eliminates cross-VM Spectre
4. If cloud deployment is required: use confidential computing (AMD SEV-SNP) which provides memory encryption even against hypervisor-level Spectre

### C.13: MEDIUM-HIGH — FROST Adaptive Security Gap

FROST's security proof covers static corruption (adversary chooses corrupt parties before protocol start). The spec's threat model is adaptive (adversary corrupts parties over time). This gap is theoretical but real.

**Fix:**
1. Acknowledge this as a known theoretical limitation in the spec
2. Mitigate via proactive share refresh (already in spec, hourly). Each refresh is equivalent to running a new DKG, which resets the adaptive corruption window. An attacker must compromise t shares within a single refresh epoch (1 hour) for the attack to succeed.
3. Reduce refresh interval to 30 minutes for TSS nodes under elevated risk scoring
4. Monitor for research on adaptively-secure FROST constructions and upgrade when available

### C.14: HIGH — Commission Formal Composition Analysis

No published work analyzes the composition of FROST + OPAQUE + ratcheting + DPoP + ML-KEM + BFT. Mixing ROM (FROST), standard model (ML-KEM), and UC (OPAQUE) proof models is hazardous.

**Fix:**
1. Commission a formal security analysis from an academic cryptography group (e.g., IACR-affiliated researchers) specifically analyzing the composition of sub-protocols as used in this system
2. Until the analysis is complete, maintain defense-in-depth: each sub-protocol independently prevents a class of attacks, so composition failure degrades gracefully (you lose one layer's guarantee, not all security)
3. Document the assumption that sub-protocol composition preserves individual security guarantees as an explicit UNVERIFIED ASSUMPTION in the spec, with a timeline for formal verification
4. The composition analysis should specifically address:
   - Domain separation sufficiency (C.10 above)
   - Threshold OPRF → OPAQUE UC proof compatibility
   - ROM → standard model interaction between FROST and ML-KEM
   - Ratchet forward secrecy under composed protocol leakage

### C.15: Use frost-ristretto255, Not frost-ed25519

Ed25519 has well-documented cofactor-8 issues. FROST-Ed25519 uses Ristretto encoding to mitigate, but the Ristretto-to-Ed25519 compatibility layer is a known source of subtle bugs. Using `frost-ristretto255` directly avoids the cofactor entirely and provides cleaner group arithmetic.

**Fix:** Replace `frost-ed25519` with `frost-ristretto255` in the crypto stack. Both are from the ZF FROST implementation (RFC 9591 compatible). Ristretto255 provides a prime-order group without cofactor concerns.

## Appendix E: Nation-State Red Team Errata (Round 3)

37 attack vectors from combined NSA TAO / Unit 8200 / GRU / GCHQ / Lazarus analysis. 5 systemic conclusions. All critical findings addressed below. Lower-severity findings documented with accepted risk rationale.

### E.1: CRITICAL — Emergency Recovery Path Hardening (Attacks 5, 9, 29)

The red team identified the emergency recovery path as the system's Achilles' heel: crash audit → force emergency mode → exploit single-TSS node → extract recovery key.

**Fixes:**
1. **Recovery key MUST be reconstructed inside an HSM/TEE**, never in software. The HSM directly performs signing operations. The raw key never exists in addressable memory.
2. **Emergency bootstrap rate limit:** Maximum 1 per 24 hours. Second emergency within 24h requires 7-of-9 custodians (not 5-of-9).
3. **Increase custodian pool:** 7-of-13 (up from 5-of-9). Custodians in different countries/jurisdictions. Proactive Shamir share refresh annually.
4. **Emergency system retains threshold:** Even emergency mode uses 2-of-3 threshold signing (reduced from 3-of-5, but never single-node). This requires pre-positioning 3 emergency TSS HSMs in geographically separate locations.
5. **Audit degradation instead of kill switch:** When BFT audit is unavailable, authentication continues with LOCAL HSM-signed audit logging for up to 30 minutes, with mandatory reconciliation when BFT recovers. After 30 minutes, human authorization required to extend. This removes the "crash audit = kill all auth" DoS vector.

### E.2: CRITICAL — Mandatory DKG, Remove Dealer Ceremony (Attack 4)

"Preferred" is not "mandatory." The dealer ceremony creates an unverifiable destruction problem.

**Fix:** MANDATE Gennaro et al.'s secure DKG (or FROST's built-in DKG from draft-irtf-cfrg-frost-dkg) with full complaint/justification phase. Remove ALL references to dealer ceremony from the spec. DKG is the ONLY key generation method. Each node verifies other nodes' Feldman VSS commitments independently. DKG conducted over audited mTLS channels.

### E.3: CRITICAL — Surge Token Security Properties (Attack 1)

Surge tokens bypass ratchet verification — this contradicts the core security model.

**Fix:** Surge tokens MUST retain:
- DPoP binding (NEVER relaxed)
- Ratchet epoch tag (bound to issuing epoch)
- Threshold signature (but may use cached partial signatures from a pre-signing pool)
- Maximum lifetime: 60 seconds (not "slightly longer-lived")

The TSS pre-computes a pool of partial signatures during normal operation. During surge, the orchestrator assembles tokens from the pre-computed pool without real-time TSS coordination. This preserves threshold security while reducing surge latency. Pool is refreshed every 30 seconds.

### E.4: CRITICAL — FROST Nonce Commitment Tracking (Attack 3)

Compromised coordinator replaying nonce commitments enables key share extraction.

**Fix:**
- TSS nodes maintain monotonic signing session counter in tamper-evident persistent storage
- Nonce = H(secret_share || counter || fresh_randomness)
- TSS nodes MUST verify all other signers' commitments independently (peer-to-peer, NOT via coordinator)
- Wrap FROST with ROAST (already in Errata C.6)
- Any duplicate nonce commitment → abort session, quarantine suspect node, trigger investigation

### E.5: CRITICAL — Multiple Independent Entropy Sources (Attack 36)

If CPU RNG (RDRAND) is backdoored, all cryptography collapses.

**Fix:** Require XOR combination of multiple independent entropy sources:
```
entropy = RDRAND ⊕ dedicated_hardware_rng ⊕ H(network_timing_jitter || disk_access_timing)
```
- Dedicated hardware RNG: separate physical device (e.g., OneRNG, Infinite Noise TRNG)
- Environmental noise: network packet timing, disk I/O timing, interrupt timing
- No single source's compromise is sufficient
- Continuous entropy health testing (NIST SP 800-90B)
- Alert on entropy quality degradation

### E.6: CRITICAL — Insider Timing Oracle Prevention (Attack 37)

Subtle non-constant-time comparisons introduced by insider pass code review.

**Fix:**
- MANDATE `subtle::ConstantTimeEq` for ALL security-critical comparisons
- CI static analysis: flag any use of `==` on `[u8]`, `Vec<u8>`, or `Hash` types in security modules
- Continuous timing analysis in CI: benchmark all security functions with varying inputs, fail on input-dependent timing
- Two independent implementations of receipt validation (diverse redundancy)
- Red-team code reviews specifically targeting timing side-channels quarterly

### E.7: HIGH — Risk Scoring: Remove Published Weights (Attack 8)

Publishing exact weights and thresholds enables systematic evasion.

**Fix:**
- Remove all weight and threshold values from the spec. Reference an operational classified document instead.
- Implement per-user adaptive ML model (not fixed weights)
- Expand to 20+ signals including: keystroke dynamics, API call sequencing, inter-request timing, session duration patterns
- Add mimicry detector: flag sessions where ALL signals are simultaneously perfect (statistically improbable)
- Add canary resources that real users never access but attackers might explore
- Dual baseline: short-term adaptive (30-day) + long-term fixed (enrollment). Both must agree.
- Rate-limit baseline drift: maximum 5% change per week. Alert on monotonic expansion.

### E.8: HIGH — Binary Attestation Must Use TEE (Attack 21)

File-based integrity checks don't prevent in-memory modification by kernel-level adversary.

**Fix:** TSS nodes and Ratchet Manager MUST run inside hardware TEEs (AMD SEV-SNP or Intel TDX) where kernel cannot modify enclave memory. Attestation verifies the TEE enclave, not just the file hash. Without TEE, acknowledge as known limitation: "binary integrity against root-level adversary requires hardware enclave protection."

### E.9: HIGH — Level 4 Ceremony: Three-Person, Random Selection (Attacks 12, 16)

Two-person cross-department is weak against patient nation-state (recruit 2 assets over 5 years).

**Fix:**
- Level 4 requires THREE persons from THREE departments (raise from 2 to 3)
- Participants RANDOMLY SELECTED from qualified pool (not self-selected)
- Cooling period: positive acknowledgment from 2+ monitors required (silence = DENIAL)
- Maximum Level 4 frequency: 1 per 72 hours. More requires additional approval.
- Alert channel cryptographically authenticated (signed alerts to FIDO2-protected consoles)

### E.10: HIGH — Verifier Cache Staleness Timeout (Attack 13)

Verifier partitioned from Ratchet Manager continues with stale ratchet state indefinitely.

**Fix:** Verifier MUST have maximum cache staleness for ratchet state: 60 seconds without heartbeat from Ratchet Manager → REJECT ALL TOKENS (fail-secure). Add heartbeat protocol between Verifier and Ratchet Manager. Document in failure mode table.

### E.11: HIGH — SHARD Messages Need HSM Countersignature (Attack 6)

Root access on a module = SHARD channel fully compromised.

**Fix:** Security-critical SHARD messages (receipt issuance, risk scores, signing requests) MUST be countersigned by the module's HSM/TEE-resident key. Transport-layer HMAC provides channel security; HSM signature provides endpoint integrity. Even root-on-host cannot forge without HSM compromise.

### E.12: HIGH — DPoP Must Include TLS Channel Binding (Attack 34)

DPoP binds to client key, not TLS session. Stolen client key = DPoP bypass.

**Fix:** Include TLS channel binding (tls-exporter value per RFC 9449 Section 4.2) in DPoP proof. Verifier checks BOTH DPoP signature AND TLS exporter match. Stolen client key cannot create valid DPoP for different TLS session. For Tier 1: DPoP key stored in FIDO2 secure element (non-extractable).

### E.13: HIGH — TSS Node Replacement as Level 3 Action (Attack 30)

Attacker runs genuine binary on compromised hardware, receives valid share.

**Fix:** TSS node replacement = Level 3 action (two-person approval from different departments). New node gets 24-hour probation period: participates in signing but shares are verified in zero-knowledge. TSS nodes MUST run in TEE. Share refresh to new node requires explicit k-of-n authorization from existing nodes.

### E.14: HIGH — Receipt Key Overlap Window Reduction (Attack 31)

24-hour receipt key overlap is 24,000x longer than needed.

**Fix:** Reduce overlap from 24 hours to 2 hours. Old key only valid for receipts timestamped before rotation. New ceremonies after rotation MUST use new key.

### E.15: HIGH — Ceremony Session ID Replay Prevention (Attack 22)

Compromised orchestrator replays complete receipt chain within 30s TTL.

**Fix:** TSS nodes maintain used ceremony_session_id set for 120 seconds (4x TTL). Reject any previously-seen ID. Set replicated across all TSS nodes via piggyback on FROST coordination messages.

### E.16: HIGH — Server Entropy in Ratchet (Attack 15)

Compromised client sends zero-entropy. Ratchet becomes deterministic.

**Fix:** Ratchet formula updated:
```
chain_key_{n+1} = HKDF-SHA512(chain_key_n, "MILNET-SSO-v1-RATCHET" || client_entropy || server_entropy)
```
`server_entropy` = fresh 32 bytes from Ratchet Manager's CSPRNG each epoch. Client entropy provides additional unpredictability but is not relied upon.

### E.17: HIGH — FIDO2 Key Vendor Diversity (Attack 27)

Single custom FIDO2 vendor = single supply chain target.

**Fix:** Require FIDO2 keys from at least TWO independent vendors. Destructive analysis of random samples per batch (X-ray, decapping, firmware audit). Open-source firmware requirement for custom keys with reproducible builds. Duress protocol not solely dependent on FIDO2 — add independent duress signal (separate device gesture, time-based dead-man's switch).

### E.18: MEDIUM — Share Refresh Atomic Transition (Attack 23)

Mixed-epoch partial signatures during refresh leak information.

**Fix:** Explicit share epoch transition protocol:
1. BFT consensus among TSS nodes to begin refresh
2. Signing PAUSED (expected <1 second)
3. All nodes switch atomically (or roll back on failure)
4. Signing resumes
Never reveal partial signatures from different epochs for same message.

### E.19: MEDIUM — Postcard Deserialization Hardening (Attack 32)

**Fix:** Pre-parsing validation layer: check magic bytes, total length, fixed-field sizes before deserialization. Use `#[serde(deny_unknown_fields)]`. Catch panics at module boundaries. Fuzz all deserialization paths with cargo-fuzz. Memory allocation limits per deserialization.

### E.20: MEDIUM — Crypto Agility for PQ Upgrades (Attack 35)

**Fix:** Algorithm byte in token format supports multiple values. Define key rotation procedure for PQ parameter upgrade (ML-KEM-768 → ML-KEM-1024). Re-evaluation schedule: annual review of lattice cryptanalysis progress. For >25-year classified data on inter-module channels: consider triple-hybrid (ML-KEM + X25519 + Classic McEliece).

### E.21: SYSTEMIC — Hardest Truths: Acknowledged AND Mitigated

The red team identified 5 systemic conclusions. Each is now mitigated to the maximum extent achievable, with real-world precedents from nuclear, aerospace, and military systems.

**Truth 1: The system assumes hardware enclaves are trustworthy.**

The spec relies on HSMs, TPMs, TEEs, and CPU entropy. Without hardware trust anchors, the threat model is unsatisfiable.

Mitigations (drawing from nuclear weapon PAL design):
- **TEE vendor diversity:** Use BOTH AMD SEV-SNP AND Intel TDX across different TSS nodes. Compromising one vendor's enclave does not compromise the other. The threshold (3-of-5) can tolerate 2 compromised enclaves.
- **Cross-vendor attestation:** Each TEE node attests to nodes running on the OTHER vendor's hardware. A compromised Intel enclave cannot fool an AMD enclave's attestation verification (different root of trust).
- **Hardware rotation schedule:** Replace physical HSMs every 18 months. Destroy old hardware (physical shredding with audit). This limits the window for persistent hardware implants.
- **Runtime enclave self-testing:** Each TEE runs continuous self-diagnostics: known-answer crypto tests, entropy quality tests, timing variance tests. Any anomaly → enclave self-destructs (zeroizes all keys).
- **Precedent:** Nuclear PALs use dual-vendor, dual-technology redundancy (mechanical + electronic). No single technology failure compromises the system.

**Truth 2: No cryptographic system can verify human intent.**

Three insiders who conspire can execute any authorized action.

Mitigations (drawing from nuclear two-person integrity and ICBM launch protocols):
- **Random assignment with rotation:** Level 3-4 ceremony participants randomly selected from qualified pool AND rotated every 6 months. Conspiracy requires continuously recruiting newly-assigned random participants.
- **Post-action audit with teeth:** Every Level 3-4 action is independently reviewed within 24 hours by a separate oversight body with authority to: reverse the action, suspend the participants, and trigger investigation. This makes conspiracy detectable AFTER the fact with consequences.
- **Honeypot actions:** Inject synthetic Level 4 requests through the system periodically. Participants who approve without proper verification are flagged. This tests vigilance continuously.
- **Behavioral correlation analysis:** Cross-reference Level 3-4 ceremony participants' communications, travel, and financial patterns for correlation suggesting collusion. This is counterintelligence, implemented as an automated system.
- **Mandatory leave and two-person continuity:** No single person is irreplaceable in the ceremony pool. Mandatory rotation ensures the system survives personnel changes. Regular reassignment breaks long-term collusion relationships.
- **Precedent:** USAF ICBM launch requires two officers who are randomly assigned to different missile silos on unpredictable rotations. The probability of two colluding officers being assigned together by chance is engineered to be negligible.

**Truth 3: Complexity is a risk.**

9 modules, 72 channels, 5 tiers, 5 levels create a system too complex for any human to fully analyze.

Mitigations (drawing from NASA/ESA flight software verification):
- **TLA+ formal model BEFORE implementation:** The state machine is specified in TLA+ first. Implementation follows the verified model. Any code that cannot be traced to a verified state transition is rejected. This is Phase 1 of implementation.
- **Module reduction analysis:** Before implementation, formally analyze whether any modules can be merged without security loss. Target: reduce from 9 to 7 modules by merging Verifier+Ratchet Manager (both on hot path, share state) and combining KT+Audit (both append-only logs). Fewer modules = fewer channels = smaller state space.
- **Exhaustive degradation mode testing:** For each of the N modules, define AND TEST: module crash, module slow, module Byzantine, module partitioned. For each pair, test simultaneous failure. This produces N + N*(N-1)/2 test scenarios, each with formal pass/fail criteria.
- **Complexity budget:** Set a hard limit: the TLA+ model must have fewer than 10,000 state space nodes after symmetry reduction. If the design exceeds this, simplify before implementing.
- **Precedent:** NASA's flight software for Mars rovers uses formal methods (SPIN model checker) to verify all state transitions before upload. The Curiosity rover's autonomous driving system was verified this way.

**Truth 4: Surge/degradation modes are where attacks succeed.**

The spec covers steady-state thoroughly but degradation modes are underspecified.

Mitigations (drawing from nuclear reactor safety and aviation):
- **Degradation Mode Specification:** Every degradation mode is now a FIRST-CLASS specification with the same rigor as steady-state. Each mode has: entry conditions, security properties preserved, security properties lost (explicitly), exit conditions, maximum duration, human approval requirements.
- **Pre-computed degradation tokens:** During normal operation, the TSS pre-computes a pool of emergency partial signatures (refreshed every 30 seconds). During surge/degradation, tokens are assembled from the pool without real-time TSS coordination. This eliminates the "weaker surge tokens" problem entirely — surge tokens have identical security properties to normal tokens.
- **Degradation mode as Level 2 action:** Entering any degradation mode is itself an audited, authenticated action. The system cannot silently degrade — an operator must acknowledge the degradation, and the audit log records it.
- **Automatic recovery with verification:** When a degraded module recovers, it does NOT immediately rejoin the system. It first: verifies its own binary integrity, performs mutual attestation with all peers, synchronizes state, and then a gradual traffic increase (canary) validates correctness before full participation.
- **Precedent:** Nuclear reactor SCRAM systems have identical safety analysis for "reactor running normally" and "reactor in emergency shutdown." Aviation has MEL (Minimum Equipment List) — every degradation is pre-analyzed and approved or rejected before flight.

**Truth 5: This system raises the cost of attack, it does not eliminate it.**

No system is unbreakable against unlimited resources and unlimited time.

Mitigations (drawing from game theory and deterrence):
- **Quantified cost model:** Define the estimated cost to break each security layer. Target: total system compromise requires >$10B and >10 years of sustained effort. Publish the cost model (not the weights/thresholds, but the cost estimates) as a deterrence signal.
- **Detection as deterrence:** The system is designed so that most attacks are DETECTABLE even if not preventable. The BFT audit, KT transparency, ceremony transcripts, and behavioral analysis create a forensic trail. An attacker who succeeds knows they will eventually be identified. Deterrence = cost of attack + cost of attribution + cost of consequences.
- **Continuous red-teaming:** Retain a permanent red team (internal + external) with standing authorization to attack the production system. Their job is to find the next attack before adversaries do. Budget: 10% of total security spend.
- **Cryptographic agility:** The system can upgrade any cryptographic component (PQ parameters, threshold scheme, hash functions) without full redesign. Annual review of cryptanalysis progress. Upgrade schedule: within 6 months of any published attack that reduces security margin below 2^128.
- **Layered defense economics:** Each layer (TLS, OPAQUE, FROST threshold, ratchet, DPoP, TEE, audit) independently prevents a class of attack. An adversary must break ALL layers simultaneously. The cost is multiplicative, not additive. Breaking 6 independent layers each costing $100M is not $600M — it is $100M^6 in combined probability terms.
- **Precedent:** Nuclear deterrence theory (MAD) works not because nuclear weapons are unbreakable, but because the cost of attack exceeds any possible gain. This system applies the same principle to authentication.

## Appendix F: Formal Verification Requirements

Based on Attack 18 (Complexity Catastrophe), the following formal verification is MANDATORY before production:

1. **TLA+ model** of the 9-module state machine covering all inter-module interactions
2. **Safety property verification:** "No authentication bypass" (no state reachable where an unauthenticated entity holds a valid token)
3. **Liveness property verification:** "Authentication eventually succeeds for legitimate users" (no permanent deadlock)
4. **Chaos testing:** Random module kills, network partitions, message corruption — 10,000 hours minimum
5. **Composition security analysis:** Commissioned from IACR-affiliated researchers (see Errata C.14)

## Appendix G: Operational Security Requirements

Based on Attacks 5, 8, 12, 14, 16, 37 (human-layer attacks), the following OpSec is MANDATORY:

1. **Personnel vetting:** All custodians, ceremony participants, and system operators require enhanced background investigation with periodic re-evaluation
2. **Random assignment:** Level 3-4 ceremony participants randomly selected from qualified pool
3. **Behavioral monitoring:** Continuous counterintelligence screening of privileged personnel
4. **Separation of duties:** No single person can access source code AND production systems AND serve as ceremony participant
5. **Code review specialization:** Quarterly red-team code reviews specifically targeting timing side-channels and subtle logic errors
6. **Incident response:** Defined procedures for each attack class, with tabletop exercises quarterly

## Appendix D: Cryptographic References (Round 3)

- KyberSlash timing attack: Kannwischer et al., TCHES 2025
- CVE-2024-58262 (curve25519-dalek): RUSTSEC-2024-0344
- Partitioning oracle attacks on OPAQUE: Len et al., USENIX Security 2021
- FROST commitment equivocation: CertiK Threshold Cryptography II
- ROAST: Ruffing et al., CCS 2022 (Eprint 2022/550)
- FROST adaptive security analysis: Eprint 2025/943
- T-OPAQUE / TOPPSS: Jarecki et al., ACNS 2017 (Eprint 2017/363)
- Efficient Threshold ML-DSA: Eprint 2026/013
- Quorus (scalable threshold ML-DSA): Eprint 2025/1163
- X-Wing hybrid KEM: Eprint 2024/039
- HKDF security: Krawczyk, Crypto 2010 (Eprint 2010/264)
- KDF without salt: Eprint 2025/657
- Spectre on constant-time crypto (Serberus): Mosier et al., IEEE S&P 2024
- Module-lattice reduction: Eprint 2025/1904
- Cryspen libcrux verified ML-KEM: cryspen.com
- NCC Group FROST audit: NCC Group 2023
- NCC Group opaque-ke audit: NCC Group 2021 (v0.5.0)
- Quarkslab dalek audit: Quarkslab 2019
- Project Eleven PQ Rust analysis: blog.projecteleven.com

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
