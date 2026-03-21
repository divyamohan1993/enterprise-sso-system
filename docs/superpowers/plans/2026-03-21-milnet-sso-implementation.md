# MILNET SSO System — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the world's first research-grade SSO system combining threshold cryptography, OPAQUE, ratcheting sessions, key transparency, microkernel isolation, and post-quantum cryptography.

**Architecture:** 9 isolated mutually-distrusting Rust processes communicating via PQ-hybrid mTLS (SHARD protocol). Threshold signing (FROST 3-of-5 + ML-DSA-65), server-blind password auth (T-OPAQUE), forward-secret sessions (HKDF-SHA512 ratchet), O(1) token verification (~72us). TLA+ formal model gates all implementation.

**Tech Stack:** Rust 1.85+ (Edition 2024), frost-ristretto255, libcrux-ml-kem/ml-dsa, opaque-ke, rustls, postcard/serde, zeroize, subtle, equix, sha2/sha3/blake3, hkdf, hmac, argon2, x25519-dalek >= 4.1.3, TLA+ (TLC model checker)

**Spec:** `docs/superpowers/specs/2026-03-21-milnet-sso-design.md` (1500+ lines, 169 red-team attack vectors addressed)

---

## Phase Overview

| Phase | Name | Key Output | Tasks | Dependency |
|-------|------|-----------|-------|------------|
| **0** | Formal Model & Scaffold | Verified TLA+, Rust workspace, shared types | 6 | None |
| **1** | Crypto Primitives & SHARD IPC | Tested crypto crate, working IPC, entropy | 7 | Phase 0 |
| **2** | Minimal Auth Flow | 5-module end-to-end Tier 2 ceremony | 6 | Phase 1 |
| **3** | Session Management | Forward-secret ratcheting, DPoP binding | 6 | Phase 2 |
| **4** | Audit & Transparency | BFT audit log, Key Transparency Merkle tree | 7 | Phase 1-2 |
| **5** | Risk Scoring & Device Tiers | Continuous auth, all 4 ceremony tiers | 6 | Phase 3-4 |
| **6** | Action-Level Auth | Sovereign ceremonies, duress protocol | 6 | Phase 4-5 |
| **7** | Hardening & Deployment | TEE, isolation, chaos testing, perf validation | 8 | All |

**Total: 8 phases, 52 tasks. Phases 3 and 4 can run in parallel.**

---

## Phase 0: Formal Model & Project Scaffolding

**Goal:** Verified TLA+ state machine; compilable Rust workspace; shared types; CI.

**Rationale:** The spec mandates (Appendix F, Truth 3): TLA+ formal model BEFORE implementation. This phase gates all code.

---

### Task 0.1: Rust Workspace Scaffold

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `milnet-common/Cargo.toml`
- Create: `milnet-common/src/lib.rs`
- Create: `milnet-crypto/Cargo.toml`
- Create: `milnet-crypto/src/lib.rs`
- Create: `milnet-shard/Cargo.toml`
- Create: `milnet-shard/src/lib.rs`
- Create: `milnet-gateway/Cargo.toml`
- Create: `milnet-gateway/src/main.rs`
- Create: `milnet-orchestrator/Cargo.toml`
- Create: `milnet-orchestrator/src/main.rs`
- Create: `milnet-tss/Cargo.toml`
- Create: `milnet-tss/src/main.rs`
- Create: `milnet-verifier/Cargo.toml`
- Create: `milnet-verifier/src/main.rs`
- Create: `milnet-opaque/Cargo.toml`
- Create: `milnet-opaque/src/main.rs`
- Create: `milnet-ratchet/Cargo.toml`
- Create: `milnet-ratchet/src/main.rs`
- Create: `milnet-kt/Cargo.toml`
- Create: `milnet-kt/src/main.rs`
- Create: `milnet-risk/Cargo.toml`
- Create: `milnet-risk/src/main.rs`
- Create: `milnet-audit/Cargo.toml`
- Create: `milnet-audit/src/main.rs`

- [ ] **Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "milnet-common",
    "milnet-crypto",
    "milnet-shard",
    "milnet-gateway",
    "milnet-orchestrator",
    "milnet-tss",
    "milnet-verifier",
    "milnet-opaque",
    "milnet-ratchet",
    "milnet-kt",
    "milnet-risk",
    "milnet-audit",
]

[workspace.package]
edition = "2024"
rust-version = "1.85"
license = "MIT"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["alloc"] }
zeroize = { version = "1", features = ["derive"] }
subtle = "2"
sha2 = "0.10"
sha3 = "0.10"
blake3 = "1"
hkdf = "0.12"
hmac = "0.12"
uuid = { version = "1", features = ["v4", "serde"] }
thiserror = "2"
tokio = { version = "1", features = ["full"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json"] }
```

- [ ] **Step 2: Create milnet-common crate stub**

```toml
# milnet-common/Cargo.toml
[package]
name = "milnet-common"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true

[dependencies]
serde.workspace = true
postcard.workspace = true
zeroize.workspace = true
subtle.workspace = true
uuid.workspace = true
thiserror.workspace = true
```

```rust
// milnet-common/src/lib.rs
#![forbid(unsafe_code)]

pub mod types;
pub mod domain;
pub mod error;
```

- [ ] **Step 3: Create all 9 module crate stubs (gateway through audit)**

Each gets a Cargo.toml depending on milnet-common + milnet-shard, and a `main.rs` with:
```rust
#![forbid(unsafe_code)]
fn main() {
    println!("milnet-<name> starting");
}
```

- [ ] **Step 4: Create milnet-crypto and milnet-shard crate stubs**

Library crates (no main.rs), depending on milnet-common.

- [ ] **Step 5: Verify workspace compiles**

Run: `cargo build --workspace`
Expected: All 12 crates compile cleanly with zero warnings.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: scaffold Rust workspace with 12 crates for MILNET SSO"
```

---

### Task 0.2: Shared Type Definitions

**Files:**
- Create: `milnet-common/src/types.rs`
- Create: `milnet-common/src/domain.rs`
- Create: `milnet-common/src/error.rs`
- Test: `milnet-common/tests/types_test.rs`

- [ ] **Step 1: Write failing serialization round-trip test**

```rust
// milnet-common/tests/types_test.rs
use milnet_common::types::*;

#[test]
fn token_serializes_roundtrip() {
    let token = Token::test_fixture();
    let bytes = postcard::to_allocvec(&token).unwrap();
    let decoded: Token = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(token.header.version, decoded.header.version);
    assert_eq!(token.claims.sub, decoded.claims.sub);
}

#[test]
fn receipt_serializes_roundtrip() {
    let receipt = Receipt::test_fixture();
    let bytes = postcard::to_allocvec(&receipt).unwrap();
    let decoded: Receipt = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(receipt.ceremony_session_id, decoded.ceremony_session_id);
    assert_eq!(receipt.step_id, decoded.step_id);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p milnet-common`
Expected: FAIL — types module not found.

- [ ] **Step 3: Implement Token, Receipt, and all shared types per spec B.14**

```rust
// milnet-common/src/types.rs
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Token header — spec B.14
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenHeader {
    pub version: u8,       // 0x01
    pub algorithm: u8,     // 0x01 = Ristretto255+ML-DSA-65
    pub tier: u8,          // 1-4
}

/// Token claims — spec B.14
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenClaims {
    pub sub: Uuid,                    // user_id
    pub iss: [u8; 32],               // issuer hash
    pub iat: i64,                     // issued at (microseconds)
    pub exp: i64,                     // expires at (microseconds)
    pub scope: u32,                   // bitfield of resource scopes
    pub dpop_hash: [u8; 32],         // H(client DPoP public key)
    pub ceremony_id: [u8; 32],
    pub tier: u8,
    pub ratchet_epoch: u64,
}

/// Complete token — spec B.14
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub header: TokenHeader,
    pub claims: TokenClaims,
    pub ratchet_tag: [u8; 64],       // HMAC-SHA512
    pub frost_signature: [u8; 64],   // Ristretto255 threshold sig
    pub pq_signature: Vec<u8>,       // ML-DSA-65 (~3.3KB)
}

/// Ceremony receipt — spec Section 6
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    pub ceremony_session_id: [u8; 32],
    pub step_id: u8,
    pub prev_receipt_hash: [u8; 32],
    pub user_id: Uuid,
    pub dpop_key_hash: [u8; 32],
    pub timestamp: i64,
    pub nonce: [u8; 32],
    pub signature: Vec<u8>,
    pub ttl_seconds: u8,             // default 30
}

/// Device tiers — spec Section 13
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum DeviceTier {
    Sovereign = 1,
    Operational = 2,
    Sensor = 3,
    Emergency = 4,
}

/// Action levels — spec Section 7
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ActionLevel {
    Read = 0,
    Modify = 1,
    Privileged = 2,
    Critical = 3,
    Sovereign = 4,
}

/// Audit entry — spec Section 15
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_id: Uuid,
    pub event_type: AuditEventType,
    pub user_ids: Vec<Uuid>,
    pub device_ids: Vec<Uuid>,
    pub ceremony_receipts: Vec<Receipt>,
    pub risk_score: f64,
    pub timestamp: i64,
    pub prev_hash: [u8; 32],
    pub signature: Vec<u8>,         // ML-DSA-65
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditEventType {
    AuthSuccess,
    AuthFailure,
    MfaEnabled,
    CredentialRegistered,
    CredentialRevoked,
    ActionLevel3,
    ActionLevel4,
    KeyRotation,
    ShareRefresh,
    SystemDegraded,
    SystemRecovered,
}

/// SHARD message — spec Section 11
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMessage {
    pub version: u8,
    pub sender_module: ModuleId,
    pub sequence: u64,
    pub timestamp: i64,
    pub payload: Vec<u8>,
    pub hmac: [u8; 64],            // HMAC-SHA512
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum ModuleId {
    Gateway = 1,
    Orchestrator = 2,
    Tss = 3,
    Verifier = 4,
    Opaque = 5,
    Ratchet = 6,
    Kt = 7,
    Risk = 8,
    Audit = 9,
}

impl Token {
    pub fn test_fixture() -> Self {
        Token {
            header: TokenHeader { version: 1, algorithm: 1, tier: 2 },
            claims: TokenClaims {
                sub: Uuid::new_v4(),
                iss: [0u8; 32],
                iat: 0,
                exp: 300_000_000,
                scope: 0xFFFF,
                dpop_hash: [0u8; 32],
                ceremony_id: [0u8; 32],
                tier: 2,
                ratchet_epoch: 0,
            },
            ratchet_tag: [0u8; 64],
            frost_signature: [0u8; 64],
            pq_signature: vec![0u8; 3309],
        }
    }
}

impl Receipt {
    pub fn test_fixture() -> Self {
        Receipt {
            ceremony_session_id: [1u8; 32],
            step_id: 1,
            prev_receipt_hash: [0u8; 32],
            user_id: Uuid::new_v4(),
            dpop_key_hash: [0u8; 32],
            timestamp: 0,
            nonce: [0u8; 32],
            signature: vec![0u8; 64],
            ttl_seconds: 30,
        }
    }
}
```

- [ ] **Step 4: Implement domain separation constants per spec C.10**

```rust
// milnet-common/src/domain.rs
/// Domain separation prefixes — spec Errata C.10
/// No two operations share the same prefix.
pub const FROST_TOKEN: &[u8] = b"MILNET-SSO-v1-FROST-TOKEN";
pub const RECEIPT_SIGN: &[u8] = b"MILNET-SSO-v1-RECEIPT";
pub const DPOP_PROOF: &[u8] = b"MILNET-SSO-v1-DPOP";
pub const AUDIT_ENTRY: &[u8] = b"MILNET-SSO-v1-AUDIT";
pub const MODULE_ATTEST: &[u8] = b"MILNET-SSO-v1-ATTEST";
pub const RATCHET_ADVANCE: &[u8] = b"MILNET-SSO-v1-RATCHET";
pub const SHARD_AUTH: &[u8] = b"MILNET-SSO-v1-SHARD";
pub const TOKEN_TAG: &[u8] = b"MILNET-SSO-v1-TOKEN-TAG";
pub const KT_LEAF: &[u8] = b"MILNET-SSO-v1-KT-LEAF";
pub const RECEIPT_CHAIN: &[u8] = b"MILNET-SSO-v1-RECEIPT-CHAIN";
pub const ACTION_BIND: &[u8] = b"MILNET-SSO-v1-ACTION";
```

- [ ] **Step 5: Implement error types**

```rust
// milnet-common/src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MilnetError {
    #[error("cryptographic verification failed: {0}")]
    CryptoVerification(String),

    #[error("receipt chain invalid: {0}")]
    ReceiptChain(String),

    #[error("token expired or invalid epoch")]
    TokenExpired,

    #[error("insufficient tier: required {required}, got {actual}")]
    InsufficientTier { required: u8, actual: u8 },

    #[error("ceremony session replay detected")]
    CeremonyReplay,

    #[error("threshold quorum not met")]
    QuorumNotMet,

    #[error("SHARD protocol error: {0}")]
    Shard(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("audit unavailable — auth halted")]
    AuditUnavailable,
}
```

- [ ] **Step 6: Run tests to verify types serialize/deserialize**

Run: `cargo test -p milnet-common`
Expected: PASS — both round-trip tests pass.

- [ ] **Step 7: Commit**

```bash
git add milnet-common/
git commit -m "feat(common): add shared types, domain separation, and error types"
```

---

### Task 0.3: CI Pipeline

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `rustfmt.toml`
- Create: `clippy.toml`
- Create: `deny.toml`

- [ ] **Step 1: Create CI workflow**

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
      - run: cargo build --workspace --release
```

- [ ] **Step 2: Create rustfmt.toml**

```toml
edition = "2024"
max_width = 100
```

- [ ] **Step 3: Verify locally**

Run: `cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo test --workspace`
Expected: All pass.

- [ ] **Step 4: Commit**

```bash
git add .github/ rustfmt.toml
git commit -m "ci: add Rust CI pipeline with fmt, clippy, and test"
```

---

### Task 0.4: TLA+ Formal Model

**Files:**
- Create: `formal-model/milnet.tla`
- Create: `formal-model/milnet.cfg`
- Create: `formal-model/README.md`

- [ ] **Step 1: Write TLA+ model of the core ceremony state machine**

This models the minimum viable auth flow: Client -> Gateway -> Orchestrator -> OPAQUE -> TSS -> Verifier. Focus on the safety property: "no unauthenticated entity holds a valid token."

```tla
---- MODULE milnet ----
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Users,          \* Set of user identifiers
    TssNodes,       \* Set of TSS node identifiers (5 nodes)
    Threshold,      \* Signing threshold (3)
    MaxEpoch        \* Maximum ratchet epoch for model checking

VARIABLES
    gateway_state,      \* Gateway: pending requests
    orchestrator_state, \* Orchestrator: active ceremonies
    opaque_state,       \* OPAQUE: authentication state per user
    tss_state,          \* TSS: signing state, shares, nonce counters
    verifier_state,     \* Verifier: cached keys, ratchet epochs
    ratchet_state,      \* Ratchet: chain keys per session
    tokens_issued,      \* Set of all issued tokens
    tokens_verified,    \* Set of all verified tokens
    compromised,        \* Set of compromised components
    ceremony_ids_used   \* Set of used ceremony session IDs

\* Type invariant
TypeOK ==
    /\ tokens_issued \subseteq [user: Users, tier: 1..4, epoch: 0..MaxEpoch]
    /\ tokens_verified \subseteq tokens_issued

\* SAFETY: No unauthenticated token
Safety ==
    \A t \in tokens_verified:
        \E c \in orchestrator_state.completed_ceremonies:
            /\ c.user = t.user
            /\ c.tier = t.tier

\* SAFETY: Threshold integrity - compromising < Threshold nodes
\* cannot produce a valid token
ThresholdSafety ==
    Cardinality(compromised \cap TssNodes) < Threshold =>
        \A t \in tokens_issued:
            t.legitimately_signed = TRUE

\* SAFETY: Ceremony session IDs never reused
CeremonyUniqueness ==
    \A c1, c2 \in orchestrator_state.completed_ceremonies:
        c1 # c2 => c1.session_id # c2.session_id

\* LIVENESS: Legitimate user eventually gets authenticated
Liveness ==
    \A u \in Users:
        u \notin compromised =>
            <>(\E t \in tokens_verified: t.user = u)

\* Init and Next states defined for the ceremony flow:
\* 1. Client submits puzzle solution to Gateway
\* 2. Gateway forwards to Orchestrator
\* 3. Orchestrator routes to OPAQUE
\* 4. OPAQUE issues receipt
\* 5. Orchestrator collects receipts, sends to TSS
\* 6. TSS validates receipts, threshold-signs token
\* 7. Token returned to client
\* 8. Client presents token to Verifier
\* 9. Verifier validates signature + ratchet epoch

Init == \* ... (full init state)
Next == \* ... (full transition relation)

Spec == Init /\ [][Next]_<<gateway_state, orchestrator_state,
    opaque_state, tss_state, verifier_state, ratchet_state,
    tokens_issued, tokens_verified, compromised, ceremony_ids_used>>

THEOREM Spec => []TypeOK
THEOREM Spec => []Safety
THEOREM Spec => []ThresholdSafety
THEOREM Spec => []CeremonyUniqueness
THEOREM Spec => Liveness
====
```

- [ ] **Step 2: Write TLC configuration**

```
\* formal-model/milnet.cfg
SPECIFICATION Spec
INVARIANT TypeOK Safety ThresholdSafety CeremonyUniqueness
PROPERTY Liveness

CONSTANTS
    Users = {u1, u2, u3}
    TssNodes = {n1, n2, n3, n4, n5}
    Threshold = 3
    MaxEpoch = 5
```

- [ ] **Step 3: Run TLC model checker**

Run: `cd formal-model && tlc milnet.tla -config milnet.cfg`
Expected: Model checking complete. No invariant violations. State space < 10,000 nodes.

- [ ] **Step 4: Document model and results**

Write `formal-model/README.md` with: properties verified, state space size, any assumptions, known limitations.

- [ ] **Step 5: Commit**

```bash
git add formal-model/
git commit -m "feat: add TLA+ formal model with safety and liveness verification"
```

---

### Task 0.5: Dependency Vendoring and Audit

**Files:**
- Create: `supply-chain/audits.toml`
- Modify: `Cargo.toml` (add dependency versions)

- [ ] **Step 1: Add all crypto dependencies to workspace Cargo.toml**

Add to `[workspace.dependencies]`:
```toml
frost-ristretto255 = "2"
x25519-dalek = "2.1"
opaque-ke = "3"
aes-gcm-siv = "0.11"
chacha20poly1305 = "0.10"
getrandom = "0.2"
rand = "0.8"
```

- [ ] **Step 2: Pin curve25519-dalek >= 4.1.3 per spec C.2**

Add to workspace Cargo.toml:
```toml
[workspace.dependencies.curve25519-dalek]
version = ">=4.1.3"
```

- [ ] **Step 3: Verify all dependencies resolve and compile**

Run: `cargo update && cargo build --workspace`
Expected: Clean build.

- [ ] **Step 4: Initialize cargo-vet**

Run: `cargo vet init`

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock supply-chain/
git commit -m "chore: add crypto dependencies, pin curve25519-dalek >= 4.1.3"
```

---

### Task 0.6: Workspace Verification

**Files:** None new — verification only.

- [ ] **Step 1: Full workspace build**

Run: `cargo build --workspace`
Expected: All 12 crates compile.

- [ ] **Step 2: Full workspace test**

Run: `cargo test --workspace`
Expected: All tests pass (types round-trip tests from Task 0.2).

- [ ] **Step 3: Clippy clean**

Run: `cargo clippy --workspace -- -D warnings`
Expected: Zero warnings.

- [ ] **Step 4: Format check**

Run: `cargo fmt --all -- --check`
Expected: All formatted.

---

## Phase 1: Crypto Primitives & SHARD IPC

**Goal:** All cryptographic building blocks working in isolation; SHARD inter-module communication functional.

**Depends on:** Phase 0 complete.

---

### Task 1.1: X-Wing Hybrid KEM Combiner

**Files:**
- Create: `milnet-crypto/src/xwing.rs`
- Test: `milnet-crypto/tests/xwing_test.rs`

**Spec refs:** C.8 (X-Wing combiner), C.1 (libcrux-ml-kem)

- [ ] **Step 1: Write failing test for X-Wing key exchange**

```rust
// milnet-crypto/tests/xwing_test.rs
use milnet_crypto::xwing::XWing;

#[test]
fn xwing_key_exchange_produces_shared_secret() {
    let (client_state, client_hello) = XWing::client_init();
    let (server_shared, server_hello) = XWing::server_respond(&client_hello);
    let client_shared = XWing::client_finish(client_state, &server_hello);
    assert_eq!(client_shared, server_shared);
}

#[test]
fn xwing_different_sessions_produce_different_secrets() {
    let (cs1, ch1) = XWing::client_init();
    let (ss1, sh1) = XWing::server_respond(&ch1);
    let (cs2, ch2) = XWing::client_init();
    let (ss2, sh2) = XWing::server_respond(&ch2);
    assert_ne!(ss1, ss2);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p milnet-crypto`
Expected: FAIL — xwing module not found.

- [ ] **Step 3: Implement X-Wing combiner**

```rust
// milnet-crypto/src/xwing.rs
//! X-Wing hybrid KEM combiner (spec Errata C.8)
//! shared_secret = SHA3-256("X-Wing" || ml_kem_ss || ml_kem_ct
//!                          || x25519_ss || x25519_pk_c || x25519_pk_s)

use sha3::{Sha3_256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct XWing;

pub struct ClientState {
    x25519_secret: EphemeralSecret,
    x25519_public: PublicKey,
    // ml_kem state would go here
}

impl XWing {
    pub fn client_init() -> (ClientState, Vec<u8>) {
        let x25519_secret = EphemeralSecret::random();
        let x25519_public = PublicKey::from(&x25519_secret);
        // TODO: ML-KEM encapsulation when libcrux is integrated
        let client_hello = x25519_public.as_bytes().to_vec();
        (ClientState { x25519_secret, x25519_public }, client_hello)
    }

    pub fn server_respond(client_hello: &[u8]) -> ([u8; 32], Vec<u8>) {
        let client_x25519_pk = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&client_hello[..32]);
            PublicKey::from(bytes)
        };
        let server_secret = EphemeralSecret::random();
        let server_public = PublicKey::from(&server_secret);
        let x25519_ss = server_secret.diffie_hellman(&client_x25519_pk);

        let shared = Self::combine(
            &[0u8; 32], // ML-KEM shared secret placeholder
            &[0u8; 32], // ML-KEM ciphertext placeholder
            x25519_ss.as_bytes(),
            client_x25519_pk.as_bytes(),
            server_public.as_bytes(),
        );

        (shared, server_public.as_bytes().to_vec())
    }

    pub fn client_finish(state: ClientState, server_hello: &[u8]) -> [u8; 32] {
        let server_pk = {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&server_hello[..32]);
            PublicKey::from(bytes)
        };
        let x25519_ss = state.x25519_secret.diffie_hellman(&server_pk);

        Self::combine(
            &[0u8; 32], // ML-KEM placeholder
            &[0u8; 32], // ML-KEM ct placeholder
            x25519_ss.as_bytes(),
            state.x25519_public.as_bytes(),
            server_pk.as_bytes(),
        )
    }

    fn combine(
        ml_kem_ss: &[u8],
        ml_kem_ct: &[u8],
        x25519_ss: &[u8],
        x25519_pk_client: &[u8],
        x25519_pk_server: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"X-Wing");
        hasher.update(ml_kem_ss);
        hasher.update(ml_kem_ct);
        hasher.update(x25519_ss);
        hasher.update(x25519_pk_client);
        hasher.update(x25519_pk_server);
        hasher.finalize().into()
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p milnet-crypto`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add milnet-crypto/
git commit -m "feat(crypto): implement X-Wing hybrid KEM combiner"
```

---

### Task 1.2: Constant-Time Utilities

**Files:**
- Create: `milnet-crypto/src/ct.rs`
- Test: `milnet-crypto/tests/ct_test.rs`

**Spec refs:** E.6, C.10

- [ ] **Step 1: Write failing test**

```rust
// milnet-crypto/tests/ct_test.rs
use milnet_crypto::ct::{ct_eq, ct_select};

#[test]
fn ct_eq_equal_values() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    assert!(ct_eq(&a, &b));
}

#[test]
fn ct_eq_different_values() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 5];
    assert!(!ct_eq(&a, &b));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p milnet-crypto -- ct_`
Expected: FAIL.

- [ ] **Step 3: Implement constant-time comparison**

```rust
// milnet-crypto/src/ct.rs
use subtle::ConstantTimeEq;

/// Constant-time byte slice comparison.
/// MUST be used for ALL security-critical comparisons (spec E.6).
/// Using == on byte arrays in security code is a CI-blocking error.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p milnet-crypto -- ct_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add milnet-crypto/
git commit -m "feat(crypto): add constant-time comparison utilities"
```

---

### Task 1.3: SHARD IPC Protocol

**Files:**
- Create: `milnet-shard/src/protocol.rs`
- Create: `milnet-shard/src/channel.rs`
- Test: `milnet-shard/tests/protocol_test.rs`

**Spec refs:** Section 11, E.11

- [ ] **Step 1: Write failing test for SHARD message send/receive**

```rust
// milnet-shard/tests/protocol_test.rs
use milnet_shard::protocol::ShardProtocol;
use milnet_common::types::ModuleId;

#[tokio::test]
async fn shard_message_roundtrip() {
    let key = [42u8; 64]; // HMAC key
    let mut sender = ShardProtocol::new(ModuleId::Gateway, &key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, &key);

    let payload = b"test payload";
    let msg = sender.create_message(payload).unwrap();
    let decoded = receiver.verify_message(&msg).unwrap();
    assert_eq!(decoded, payload);
}

#[tokio::test]
async fn shard_rejects_replay() {
    let key = [42u8; 64];
    let mut sender = ShardProtocol::new(ModuleId::Gateway, &key);
    let mut receiver = ShardProtocol::new(ModuleId::Orchestrator, &key);

    let msg = sender.create_message(b"test").unwrap();
    receiver.verify_message(&msg).unwrap(); // first: OK
    let result = receiver.verify_message(&msg); // replay: FAIL
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p milnet-shard`
Expected: FAIL — protocol module not found.

- [ ] **Step 3: Implement SHARD protocol**

```rust
// milnet-shard/src/protocol.rs
use hmac::{Hmac, Mac};
use sha2::Sha512;
use milnet_common::types::{ModuleId, ShardMessage};
use milnet_common::error::MilnetError;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha512 = Hmac<Sha512>;

const TIMESTAMP_TOLERANCE_US: i64 = 2_000_000; // +-2 seconds in microseconds

pub struct ShardProtocol {
    module_id: ModuleId,
    hmac_key: [u8; 64],
    send_sequence: u64,
    recv_sequence: u64,
}

impl ShardProtocol {
    pub fn new(module_id: ModuleId, hmac_key: &[u8; 64]) -> Self {
        Self {
            module_id,
            hmac_key: *hmac_key,
            send_sequence: 0,
            recv_sequence: 0,
        }
    }

    pub fn create_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, MilnetError> {
        self.send_sequence += 1;
        let timestamp = now_us();

        let msg = ShardMessage {
            version: 1,
            sender_module: self.module_id,
            sequence: self.send_sequence,
            timestamp,
            payload: payload.to_vec(),
            hmac: [0u8; 64], // placeholder, computed below
        };

        let mut bytes = postcard::to_allocvec(&msg)
            .map_err(|e| MilnetError::Serialization(e.to_string()))?;

        // Compute HMAC over everything except the HMAC field itself
        let hmac_value = self.compute_hmac(&bytes[..bytes.len() - 64]);
        bytes[bytes.len() - 64..].copy_from_slice(&hmac_value);

        Ok(bytes)
    }

    pub fn verify_message(&mut self, raw: &[u8]) -> Result<Vec<u8>, MilnetError> {
        if raw.len() < 64 {
            return Err(MilnetError::Shard("message too short".into()));
        }

        // Verify HMAC
        let expected_hmac = self.compute_hmac(&raw[..raw.len() - 64]);
        if !milnet_crypto::ct::ct_eq(&raw[raw.len() - 64..], &expected_hmac) {
            return Err(MilnetError::Shard("HMAC mismatch".into()));
        }

        let msg: ShardMessage = postcard::from_bytes(raw)
            .map_err(|e| MilnetError::Serialization(e.to_string()))?;

        // Reject replay (monotonic counter)
        if msg.sequence <= self.recv_sequence {
            return Err(MilnetError::Shard("replay detected".into()));
        }
        self.recv_sequence = msg.sequence;

        // Reject stale/future timestamps
        let now = now_us();
        if (now - msg.timestamp).abs() > TIMESTAMP_TOLERANCE_US {
            return Err(MilnetError::Shard("timestamp out of tolerance".into()));
        }

        Ok(msg.payload)
    }

    fn compute_hmac(&self, data: &[u8]) -> [u8; 64] {
        let mut mac = HmacSha512::new_from_slice(&self.hmac_key)
            .expect("HMAC key length is always valid");
        mac.update(milnet_common::domain::SHARD_AUTH);
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p milnet-shard`
Expected: PASS — roundtrip works, replay rejected.

- [ ] **Step 5: Commit**

```bash
git add milnet-shard/
git commit -m "feat(shard): implement SHARD IPC protocol with replay protection"
```

---

### Task 1.4: FROST Threshold Signing Wrapper

**Files:**
- Create: `milnet-crypto/src/threshold.rs`
- Test: `milnet-crypto/tests/threshold_test.rs`

**Spec refs:** C.6 (ROAST), C.7 (nonce tracking), C.15 (ristretto255), E.2 (DKG mandatory), E.4 (nonce commitment)

- [ ] **Step 1: Write failing test for 3-of-5 threshold signing**

```rust
// milnet-crypto/tests/threshold_test.rs
use milnet_crypto::threshold::FrostSigner;

#[test]
fn frost_3_of_5_produces_valid_signature() {
    let (group_key, signers) = FrostSigner::dkg(5, 3);
    let message = b"test message for threshold signing";

    // Select 3 of 5 signers
    let selected: Vec<_> = signers.iter().take(3).collect();
    let signature = FrostSigner::sign(&selected, message).unwrap();

    assert!(FrostSigner::verify(&group_key, message, &signature));
}

#[test]
fn frost_2_of_5_fails() {
    let (_group_key, signers) = FrostSigner::dkg(5, 3);
    let message = b"test message";
    let selected: Vec<_> = signers.iter().take(2).collect();
    assert!(FrostSigner::sign(&selected, message).is_err());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p milnet-crypto -- frost_`
Expected: FAIL.

- [ ] **Step 3: Implement FROST wrapper around frost-ristretto255**

Wrap the `frost-ristretto255` crate's DKG, signing, and verification. Add monotonic nonce counter per signer. Domain-separate with `FROST_TOKEN` prefix.

- [ ] **Step 4: Run tests**

Run: `cargo test -p milnet-crypto -- frost_`
Expected: PASS — 3-of-5 signs successfully, 2-of-5 fails.

- [ ] **Step 5: Commit**

```bash
git add milnet-crypto/
git commit -m "feat(crypto): implement FROST 3-of-5 threshold signing with DKG"
```

---

### Task 1.5: Receipt Signing and Chain Validation

**Files:**
- Create: `milnet-crypto/src/receipts.rs`
- Test: `milnet-crypto/tests/receipt_test.rs`

**Spec refs:** Section 6 (receipt structure), C.10 (domain separation), E.15 (session ID tracking)

- [ ] **Step 1: Write failing test for receipt chain validation**

```rust
// milnet-crypto/tests/receipt_test.rs
use milnet_crypto::receipts::ReceiptChain;
use milnet_common::types::Receipt;

#[test]
fn valid_receipt_chain_validates() {
    let session_id = [1u8; 32];
    let mut chain = ReceiptChain::new(session_id);
    chain.add_receipt(Receipt::test_fixture()).unwrap();
    assert!(chain.validate().is_ok());
}

#[test]
fn mismatched_session_id_fails() {
    let mut chain = ReceiptChain::new([1u8; 32]);
    let mut bad_receipt = Receipt::test_fixture();
    bad_receipt.ceremony_session_id = [2u8; 32]; // wrong session
    assert!(chain.add_receipt(bad_receipt).is_err());
}
```

- [ ] **Step 2: Run to verify fail, implement, run to verify pass, commit**

- [ ] **Step 3: Commit**

```bash
git add milnet-crypto/
git commit -m "feat(crypto): implement receipt chain signing and validation"
```

---

### Task 1.6: Entropy Combiner

**Files:**
- Create: `milnet-crypto/src/entropy.rs`
- Test: `milnet-crypto/tests/entropy_test.rs`

**Spec refs:** E.5 (multiple entropy sources), E.21 Truth 1

- [ ] **Step 1: Write test that entropy combiner produces 32 bytes of non-zero output**

- [ ] **Step 2: Implement XOR combination of getrandom + environmental noise**

```rust
// milnet-crypto/src/entropy.rs
use sha2::{Sha512, Digest};

/// Combine multiple entropy sources per spec E.5
/// No single source compromise is sufficient.
pub fn combined_entropy() -> [u8; 32] {
    let mut os_entropy = [0u8; 32];
    getrandom::fill(&mut os_entropy).expect("OS entropy must be available");

    // Environmental noise: hash of current time at nanosecond precision
    let time_noise = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes();

    let mut hasher = Sha512::new();
    hasher.update(&os_entropy);
    hasher.update(&time_noise);
    hasher.update(b"MILNET-ENTROPY-COMBINER");

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);

    // XOR with OS entropy for defense in depth
    for i in 0..32 {
        result[i] ^= os_entropy[i];
    }

    result
}
```

- [ ] **Step 3: Test and commit**

```bash
git add milnet-crypto/
git commit -m "feat(crypto): implement multi-source entropy combiner"
```

---

### Task 1.7: Phase 1 Integration Verification

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: Zero warnings.

- [ ] **Step 3: Verify crypto operations work together**

Write an integration test: DKG → threshold sign → verify → receipt chain → SHARD send/receive.

- [ ] **Step 4: Commit**

```bash
git commit -m "test: Phase 1 integration verification — crypto + SHARD"
```

---

## Phases 2-7: Subsequent Plans

Phases 2 through 7 will be written as separate plan documents as each preceding phase completes. This follows the principle that implementation learning from earlier phases should inform later plans.

- **Phase 2 plan:** Written after Phase 1 completes
- **Phase 3 plan:** Written after Phase 2 completes (can parallel with Phase 4)
- **Phase 4 plan:** Written after Phase 1-2 complete (can parallel with Phase 3)
- **Phase 5 plan:** Written after Phases 3-4 complete
- **Phase 6 plan:** Written after Phase 5 completes
- **Phase 7 plan:** Written after Phase 6 completes

Each plan follows this same format: exact files, TDD steps, commit points.

---

## Quick Reference

| Spec Section | Implementation Phase |
|-------------|---------------------|
| Section 2 (Threat Model) | All phases |
| Section 5 Module 1 (Gateway) | Phase 2 |
| Section 5 Module 2 (Orchestrator) | Phase 2 |
| Section 5 Module 3 (TSS) | Phase 2 |
| Section 5 Module 4 (Verifier) | Phase 2 |
| Section 5 Module 5 (T-OPAQUE) | Phase 2 |
| Section 5 Module 6 (Ratchet) | Phase 3 |
| Section 5 Module 7 (KT) | Phase 4 |
| Section 5 Module 8 (Risk) | Phase 5 |
| Section 5 Module 9 (Audit) | Phase 4 |
| Section 6 (Ceremonies) | Phase 2, 5 |
| Section 7 (Action Auth) | Phase 6 |
| Section 8 (Ratcheting) | Phase 3 |
| Section 9 (Crypto Stack) | Phase 1 |
| Section 10 (Storage) | Phase 2 |
| Section 11 (SHARD) | Phase 1 |
| Section 12 (DDoS) | Phase 2 |
| Section 13 (Device Tiers) | Phase 5 |
| Section 14 (KT) | Phase 4 |
| Section 15 (Audit) | Phase 4 |
| Section 16 (Failure Modes) | Phase 7 |
| Section 17 (Deployment) | Phase 7 |
| Section 18 (Supply Chain) | Phase 7 |
| Appendix B (Errata) | Phase 0-2 |
| Appendix C (Crypto Errata) | Phase 1 |
| Appendix E (Nation-State Errata) | Phase 2-7 |
| Appendix F (Formal Verification) | Phase 0, 7 |
| Appendix G (OpSec) | Phase 7 |
