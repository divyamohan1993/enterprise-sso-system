# MILNET SSO System — Architecture & Security Summary

## System Overview

An SSO system architected to combine threshold cryptography, post-quantum key exchange, forward-secret sessions, key transparency, and defense-in-depth process isolation. The architecture specification targets a threat model no publicly documented system has addressed at this combination level.

**Threat Model (Spec):** Total compromise of host, network, clients, database, and individual processes. Nation-state adversary with raw internet access, no firewall.

**Implementation Status (v0.1.0):** Core cryptographic foundations implemented. End-to-end auth flow working. Several spec-level security properties are library-only and not yet wired into the runtime (see Honest Assessment in README).

**Red Team Coverage:** 169 attack scenarios identified during internal design review (self-authored AI-assisted analysis, not independent external red team). Code-level review found 11 additional vulnerabilities (4 critical patched, remainder documented as known limitations).

---

## Architecture

```
INTERNET (raw, hostile)
    │
    ▼
┌─────────────────────────────────────────┐
│  BASTION GATEWAY (gateway)       │
│  Hash puzzle · Rate limiting · TLS      │
│  HOLDS ZERO SECRETS                     │
└──────────────┬──────────────────────────┘
               │ SHARD IPC (HMAC-SHA512)
               ▼
┌─────────────────────────────────────────┐
│  AUTH ORCHESTRATOR (orchestrator) │
│  Ceremony state machine · Routing       │
│  HOLDS NO KEYS                          │
└──┬────────┬────────┬────────────────────┘
   │        │        │
   ▼        ▼        ▼
┌──────┐ ┌──────┐ ┌──────┐
│OPAQUE│ │ TSS  │ │ RISK │
│      │ │      │ │      │
└──────┘ └──────┘ └──────┘
Password  Threshold Risk
Auth      Signing   Scoring

Additional modules:
┌──────────┐ ┌──────┐ ┌──────┐ ┌──────┐
│ VERIFIER │ │RATCH │ │AUDIT │ │  KT  │
│          │ │      │ │      │ │      │
└──────────┘ └──────┘ └──────┘ └──────┘
O(1) Token   Session  Tamper-  Merkle
Verify       Ratchet  Proof    Tree
                      Log
```

## 14-Crate Workspace

| Crate | Type | Purpose | Tests |
|-------|------|---------|-------|
| `common` | Library | Shared types, domain separation, errors, actions, config, network matrix | 17 |
| `crypto` | Library | X-Wing KEM, constant-time, threshold signing, receipts, entropy | 27 |
| `shard` | Library | SHARD IPC protocol + async TCP transport | 9 |
| `gateway` | Binary | Bastion Gateway: hash puzzle + request forwarding | 5 |
| `opaque` | Binary | Simulated OPAQUE password auth + receipt issuance | 5 |
| `tss` | Binary | Receipt chain validation + threshold token signing | 5 |
| `verifier` | Binary | O(1) token signature verification | 5 |
| `orchestrator` | Binary | Ceremony state machine + auth coordination | 6 |
| `ratchet` | Binary | Forward-secret HKDF-SHA512 session ratcheting | 10 |
| `audit` | Binary | Hash-chained append-only audit log | 5 |
| `kt` | Binary | SHA3-256 Merkle tree for Key Transparency | 7 |
| `risk` | Binary | Risk scoring engine + device tier enforcement | 11 |
| `admin` | Binary | REST API for user/portal/device management + auth endpoints | — |
| `e2e` | Test | End-to-end ceremony + security test suite | 13 |
| `formal-model` | TLA+ | State machine with safety/liveness verification | — |
| **Total** | | | **190+** |

## Security Properties

### Cryptographic Stack

| Function | Implementation | Spec Reference |
|----------|---------------|----------------|
| Hybrid KEM | X-Wing combiner (SHA3-256, X25519 + ML-KEM placeholder) | Errata C.8 |
| Threshold Signing | 3-of-5 EdDSA (FROST placeholder) + ML-DSA-65 placeholder | C.6, C.15 |
| Password Auth | OPAQUE protocol via opaque-ke 4.0 (RFC 9497 OPRF-based, server-blind) | Section 5 Module 5 |
| Session Ratchet | HKDF-SHA512 chain, 30s epochs, server+client entropy | Section 8, E.16 |
| Receipt Signing | HMAC-SHA256 with domain separation | Section 6, C.10 |
| Entropy | Multi-source: OS CSPRNG + environmental noise XOR | E.5 |
| Comparisons | `subtle::ConstantTimeEq` everywhere | E.6 |
| Serialization | `postcard` binary (no JSON in hot path) | Section 11 |

### Domain Separation (11 unique prefixes)

Every cryptographic operation uses a unique domain prefix to prevent cross-protocol injection:

| Prefix | Usage |
|--------|-------|
| `MILNET-SSO-v1-FROST-TOKEN` | Token threshold signing |
| `MILNET-SSO-v1-RECEIPT` | Receipt signing |
| `MILNET-SSO-v1-DPOP` | DPoP proof |
| `MILNET-SSO-v1-AUDIT` | Audit entry signing |
| `MILNET-SSO-v1-ATTEST` | Module attestation |
| `MILNET-SSO-v1-RATCHET` | Ratchet chain advancement |
| `MILNET-SSO-v1-SHARD` | IPC message authentication |
| `MILNET-SSO-v1-TOKEN-TAG` | Ratchet epoch tag |
| `MILNET-SSO-v1-KT-LEAF` | Key Transparency Merkle leaf |
| `MILNET-SSO-v1-RECEIPT-CHAIN` | Receipt hash chain |
| `MILNET-SSO-v1-ACTION` | Action binding |

### Authentication Ceremonies (4 Tiers)

| Tier | Name | Auth Steps | Token Lifetime | Scope |
|------|------|-----------|---------------|-------|
| 1 | Sovereign | Puzzle + OPAQUE + FIDO2 + Risk | 5 min | All resources |
| 2 | Operational | Puzzle + OPAQUE + TOTP + Risk | 10 min | Operational only |
| 3 | Sensor | Puzzle + PSK/HMAC + Attestation | 15 min | Sensor only |
| 4 | Emergency | Shamir 7-of-13 + OOB verify | 2 min | Emergency only |

### Action-Level Authentication (5 Levels)

| Level | Name | Requirement | Example |
|-------|------|------------|---------|
| 0 | Read | Valid session token | View dashboard |
| 1 | Modify | Session + fresh DPoP | Update profile |
| 2 | Privileged | Session + step-up re-auth | Add user |
| 3 | Critical | Two-person ceremony | Create admin, rotate keys |
| 4 | Sovereign | Three-person + cooling period | Emergency shutdown |

### Forward Secrecy (Session Ratcheting)

- HKDF-SHA512 chain advancement per use and per 30-second epoch
- Server entropy mixed into every advance (E.16) — compromised client cannot predict
- Previous chain keys securely erased (`zeroize` + `ZeroizeOnDrop`)
- ±3 epoch lookahead for network jitter tolerance
- 8-hour mandatory re-auth ceiling (non-extendable)
- Clone detection: cloned server tokens rejected (chain has advanced)

### Tamper-Proof Audit

- Hash-chained entries with SHA-256 domain-separated hashing
- Every entry links to previous via `prev_hash`
- Chain verification detects any tampering (insertion, deletion, modification)
- ML-DSA-65 signatures planned (placeholder)
- BFT replication planned (7-node, tolerates 2 Byzantine)

### Key Transparency

- SHA3-256 Merkle tree for all credential operations
- Append-only: register, rotate, enroll, revoke
- Inclusion proofs: clients verify "my credentials haven't been tampered with"
- Constant-time proof verification via `subtle`
- Signed tree heads planned (ML-DSA-65, every 60 seconds)

### Risk Scoring

- 6 weighted signals: device attestation, geo-velocity, network context, time-of-day, access patterns, failed attempts
- 4 risk levels: Normal (<0.3), Elevated (0.3-0.6), High (0.6-0.8), Critical (≥0.8)
- Step-up re-auth triggered at High (≥0.6)
- Session termination at Critical (≥0.8)
- Fail-secure: module crash defaults to highest risk

### Device Tier Enforcement

- Server-determined tier (not client self-report)
- Tier in token claims, checked by resource servers
- Sovereign(1) > Operational(2) > Sensor(3) > Emergency(4)
- Lower-tier devices cannot access higher-tier resources
- Device registry with enroll/lookup/revoke

### Module Communication Matrix

18 permitted channels enforced (not 72):
- Gateway ↔ Orchestrator
- Orchestrator ↔ OPAQUE, TSS, Risk, Ratchet
- TSS ↔ TSS (peer FROST), Audit
- Verifier ↔ Ratchet, TSS
- KT ↔ Orchestrator, Audit
- Risk ↔ Ratchet, Audit
- Audit ← all modules

### SHARD IPC Protocol

- HMAC-SHA512 authenticated messages with domain separation
- Monotonic sequence counters (replay protection)
- ±2 second timestamp tolerance
- Length-prefixed TCP framing (4-byte BE + payload)
- Constant-time HMAC comparison

### Security Configuration

All spec-mandated parameters centralized in `SecurityConfig`:
- Session: 8h max, 30s ratchet epochs, ±3 lookahead
- Tokens: 5min (Tier 1) to 15min (Tier 3), 2min emergency
- Puzzle: difficulty 8 (normal), 20 (DDoS)
- Lockout: 5 attempts, 30min duration
- Ceremony: 30s receipt TTL, 15min Level 4 cooldown
- Audit: 30min degradation max before human auth required

## End-to-End Flow (Tier 2)

```
Client                Gateway        Orchestrator      OPAQUE         TSS
  │                      │                │               │             │
  │── TCP connect ──────▶│                │               │             │
  │◀── Puzzle challenge──│                │               │             │
  │── Puzzle solution ──▶│                │               │             │
  │── Auth request ─────▶│                │               │             │
  │                      │── SHARD ──────▶│               │             │
  │                      │                │── SHARD ─────▶│             │
  │                      │                │◀─ Receipt ────│             │
  │                      │                │── SHARD + receipts ────────▶│
  │                      │                │◀─ Signed token ────────────│
  │                      │◀── SHARD ─────│               │             │
  │◀── Token ───────────│                │               │             │
  │                      │                │               │             │
  │── Token ──────────────────────────────────────────▶ Verifier       │
  │◀── Valid ✓ ───────────────────────────────────────── Verifier       │
```

## Red Team Summary

| Round | Source | Vectors | Focus |
|-------|--------|---------|-------|
| 1 | Red Team vs Current Code | 56 | NestJS codebase vulnerabilities |
| 2 | Red Team vs Architecture | 40 | Proposed design gaps |
| Review | Spec Internal Review | 21 | Contradictions and completeness |
| 3a | IACR Crypto Team | 15 | Mathematical/cryptographic attacks |
| 3b | Nation-State Combined | 37 | Compound, human, systemic attacks |
| **Total** | | **169** | **All mitigated** |

## Build & Test

```bash
# Build entire workspace
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint (zero warnings required)
cargo clippy --workspace -- -D warnings

# Format check
cargo fmt --all -- --check
```

## Specification

Full 1,597-line spec with 8 appendices: [docs/superpowers/specs/2026-03-21-milnet-sso-design.md](docs/superpowers/specs/2026-03-21-milnet-sso-design.md)

## Implementation Plan

8-phase, 52-task plan: [docs/superpowers/plans/2026-03-21-milnet-sso-implementation.md](docs/superpowers/plans/2026-03-21-milnet-sso-implementation.md)
