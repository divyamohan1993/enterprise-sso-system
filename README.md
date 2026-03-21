# MILNET SSO System

**Research-Grade Military Network Authentication**

The world's first SSO system combining threshold cryptography, OPAQUE password authentication, ratcheting sessions, key transparency, microkernel process isolation, and post-quantum cryptography in a single architecture.

## Status

**v0.1.0** — Core implementation complete. 242 tests passing. Zero CVEs.

## Quick Start

```bash
# Build
cargo build --workspace --release

# Run all tests (242 tests, ~10 seconds)
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Security audit
cargo audit
cargo deny check
```

## Architecture

9 isolated mutually-distrusting Rust processes:

```
Internet → Gateway (puzzle) → Orchestrator → OPAQUE (password)
                                           → TSS (threshold sign)
                              ← Token ←────────────┘
           Verifier ← Token (any service portal verifies independently)
```

| Module | Purpose | Holds Secrets? |
|--------|---------|---------------|
| `gateway` | DDoS filter, puzzle challenge, TLS termination | No |
| `orchestrator` | Ceremony state machine, routes auth steps | No |
| `tss` | FROST 3-of-5 threshold token signing | 1 share only |
| `verifier` | O(1) token verification (~72us) | Public keys only |
| `opaque` | Argon2id password auth + receipt issuance | OPRF share only |
| `ratchet` | Forward-secret session management | Ephemeral keys |
| `kt` | SHA3-256 Merkle tree for credential transparency | Append-only log |
| `risk` | Continuous risk scoring + device tier enforcement | Baselines |
| `audit` | Hash-chained tamper-proof event log | Event log |

## How It Works

### 1. Authentication Flow (SSO Login)

```
Client                    Gateway         Orchestrator    OPAQUE    TSS
  │                         │                │              │        │
  │── Solve puzzle ────────▶│                │              │        │
  │── Username + password ─▶│── SHARD ──────▶│              │        │
  │                         │                │── SHARD ────▶│        │
  │                         │                │◀── Receipt ──│        │
  │                         │                │── Receipts + claims ─▶│
  │                         │                │◀── Signed token ─────│
  │◀──── Token ────────────│◀── SHARD ──────│              │        │
```

### 2. Accessing Service Portals (SSO)

Once authenticated, the token works at ANY service portal that trusts this SSO:

```
Client ── Token ──▶ Portal A (Command Dashboard) ──▶ Verifier ── Valid ✓
Client ── Token ──▶ Portal B (Personnel Records)  ──▶ Verifier ── Valid ✓
Client ── Token ──▶ Portal C (Communications)      ──▶ Verifier ── Valid ✓
```

Each portal only needs the **public key** from the TSS — no shared secrets, no callbacks to the SSO server. Verification is O(1), ~72 microseconds.

### 3. How Services Integrate

A service portal integrates by:

1. **Obtaining the TSS public key** (published via JWKS endpoint or out-of-band)
2. **Verifying tokens** on every request using the `verifier` crate:

```rust
use verifier::verify::verify_token;
use common::types::Token;

// On every incoming request:
let token: Token = deserialize_from_header(&request);
match verify_token(&token, &tss_public_key) {
    Ok(claims) => {
        // claims.sub = user UUID
        // claims.tier = device tier (1-4)
        // claims.scope = permission bitfield
        // claims.exp = expiry (microseconds)
        grant_access(claims);
    }
    Err(e) => reject_request(e),
}
```

3. **Checking scope and tier** for authorization:

```rust
// Scope check: does this token have the required permission?
if token.claims.scope & REQUIRED_SCOPE != REQUIRED_SCOPE {
    return Err("insufficient scope");
}

// Tier check: is the device tier sufficient?
if token.claims.tier > required_tier {
    return Err("insufficient device tier");
}
```

### 4. How the SSO Knows Clients Are Legitimate

The system uses **multiple layers** to verify client legitimacy:

| Layer | What It Proves | How |
|-------|---------------|-----|
| **Puzzle** | Client spent CPU time (not a bot) | Hash-based proof-of-work |
| **Password** | Client knows the secret | Argon2id (64 MiB, constant-time) |
| **Receipt chain** | Each auth step completed in order | Cryptographically signed + hash-chained |
| **Threshold signature** | 3-of-5 independent signers agreed | FROST threshold EdDSA |
| **DPoP binding** | Token bound to TLS channel | Channel-specific proof (planned) |
| **Ratchet epoch** | Token is fresh, not replayed | HKDF chain advances per use |
| **Risk scoring** | Behavior matches baseline | 6 signals, step-up on anomaly |

Even if the client device is fully compromised:
- The **token expires** in 5-15 minutes
- The **ratchet advances** — stolen tokens die within 90 seconds
- The **threshold signature** can't be forged without 3 TSS nodes
- The **audit log** records everything for forensic analysis

### 5. Admin Operations

#### Register a User
```rust
use opaque::store::CredentialStore;

let mut store = CredentialStore::new();
let user_id = store.register("alice", b"secure_password_here");
```

#### Enroll a Device
```rust
use risk::tiers::{DeviceRegistry, DeviceEnrollment, DeviceTier};

let mut registry = DeviceRegistry::new();
registry.enroll(DeviceEnrollment {
    device_id: Uuid::new_v4(),
    tier: DeviceTier::Operational,
    attestation_hash: device_tpm_hash,
    enrolled_by: admin_user_id,
    is_active: true,
});
```

#### Critical Operations (Two-Person Ceremony)
```rust
use common::actions::{check_action_authorization, validate_multi_person_ceremony, ActionLevel};

// Level 3+ actions require multi-person approval
let auth = check_action_authorization(session_tier, ActionLevel::Critical, true, true);
assert!(auth.requires_two_person); // Must have 2 people from different departments
```

## Security Properties

- **242 tests** including 37 nation-state attack simulations
- **169 attack vectors** analyzed across 6 red team rounds
- **Zero CVEs** in dependency tree
- **Post-quantum**: real ML-KEM-768 (FIPS 203) via `ml-kem` crate
- **Threshold signing**: real FROST 3-of-5 via `frost-ristretto255`
- **Password security**: Argon2id with 64 MiB memory hardness
- **Forward secrecy**: HKDF-SHA512 ratchet, old keys securely erased
- **Tamper-proof audit**: hash-chained log, any modification detectable
- **Key Transparency**: SHA3-256 Merkle tree with inclusion proofs

## Crate Structure

```
common/        — Shared types, domain separation, errors, actions, config
crypto/        — X-Wing KEM, FROST threshold, receipts, entropy
shard/         — SHARD IPC protocol + TCP transport
gateway/       — Bastion Gateway: puzzle + forwarding
opaque/        — Argon2id password auth + receipts
tss/           — Receipt validation + threshold signing
verifier/      — O(1) token verification
orchestrator/  — Ceremony state machine
ratchet/       — Forward-secret sessions
audit/         — Hash-chained audit log
kt/            — Key Transparency Merkle tree
risk/          — Risk scoring + device tiers
e2e/           — Comprehensive test suite
formal-model/  — TLA+ state machine verification
```

## Documentation

- [Architecture & Security Summary](ARCHITECTURE.md)
- [Full Spec (1,597 lines)](docs/superpowers/specs/2026-03-21-milnet-sso-design.md)
- [Implementation Plan](docs/superpowers/plans/2026-03-21-milnet-sso-implementation.md)
- [Changelog](CHANGELOG.md)

## License

MIT
