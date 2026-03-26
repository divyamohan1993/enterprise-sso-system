# MILNET SSO

Enterprise Single Sign-On system built to survive total infrastructure compromise. Combines threshold cryptography, post-quantum key exchange, forward-secret sessions, and defense-in-depth process isolation across 21 hyper-distributed isolated VMs.

## What This Is

An SSO authentication system where:

- **Passwords are never seen by the server** — OPAQUE (RFC 9497) server-blind authentication
- **No single VM can sign a token** — FROST 3-of-5 threshold signatures across 5 isolated VMs
- **No single VM can authenticate a user** — OPAQUE 2-of-3 Shamir threshold across 3 VMs
- **Quantum computers cannot break it** — X-Wing hybrid KEM (X25519 + ML-KEM-1024) + ML-DSA-87
- **Past sessions stay safe even if compromised today** — HKDF-SHA512 ratchet with 30-second key erasure
- **Audit logs cannot be tampered with** — 7-node Byzantine Fault Tolerant hash-chained audit
- **Every key, port, and certificate auto-mutates** — Moving Target Defense resets attack surface continuously

## Architecture

21 VMs across 8 isolated security zones. No Docker. Native systemd on Shielded VMs with vTPM, Confidential Computing (AMD SEV-SNP), and Cloud HSM.

See [docs/DISTRIBUTED_VM_ARCHITECTURE.md](docs/DISTRIBUTED_VM_ARCHITECTURE.md) for the complete architecture.

```
Internet → Cloud Armor WAF → Gateway (C2 Spot MIG, autoscale 1→50, ZERO secrets)
  → Orchestrator (HA pair, ZERO secrets)
    → OPAQUE 2-of-3 (Confidential VMs, Shamir shares)
    → TSS FROST 3-of-5 (5 Confidential VMs, 3 AZs)
    → Verifier + Ratchet (HA pairs, forward-secret)
    → Audit BFT 7-node (3 AZs, quorum 5)
    → PostgreSQL 3-node (CMEK + envelope + SEV-SNP)
    → Risk + Key Transparency + Witness
```

## Crates

| Crate | Purpose |
|-------|---------|
| `gateway` | Bastion — hash puzzle DDoS filter, X-Wing KEM tunnel |
| `orchestrator` | Ceremony state machine (PendingOpaque → PendingTss → Complete) |
| `opaque` | Server-blind password auth (RFC 9497, Argon2id/PBKDF2-SHA512) |
| `tss` | FROST 3-of-5 threshold token signing + ML-DSA-87 PQ wrapper |
| `verifier` | O(1) token verification with DPoP replay cache |
| `ratchet` | Forward-secret HKDF-SHA512 session ratcheting |
| `audit` | BFT hash-chained audit log with ML-DSA-87 signed entries |
| `admin` | REST API — user/device/portal management, OAuth/OIDC endpoints |
| `crypto` | X-Wing, FROST, ML-DSA-87, SLH-DSA, envelope encryption, HSM, entropy |
| `common` | Shared types, domain separation, compliance, platform integrity |
| `shard` | SHARD IPC — mTLS + HMAC-SHA512 + X-Wing quantum-safe transport |
| `sso-protocol` | OAuth 2.0/2.1, OIDC, PKCE, authorization code flow |
| `fido` | FIDO2/WebAuthn — YubiKey, Windows Hello, platform authenticators |
| `kt` | SHA3-256 Merkle tree for Key Transparency |
| `risk` | Risk scoring (6 signals, 4 levels) + device tier enforcement |
| `e2e` | Integration tests — ceremony flows, attack simulations, chaos |

## Cryptographic Stack

| Layer | Algorithm | Standard | Quantum Safe |
|-------|-----------|----------|:------------:|
| Key exchange | X-Wing (X25519 + ML-KEM-1024) | FIPS 203 | Yes |
| Token signing | FROST 3-of-5 Ed25519 + ML-DSA-87 | FIPS 204 | Yes |
| Password auth | OPAQUE (Ristretto255, Argon2id) | RFC 9497 | Yes* |
| Session keys | HKDF-SHA512 ratchet | RFC 5869 | Yes |
| Symmetric | AEGIS-256 / AES-256-GCM (FIPS) | RFC 9312 | Yes |
| Hash-based sigs | SLH-DSA (backup) | FIPS 205 | Yes |
| Audit signing | ML-DSA-87 | FIPS 204 | Yes |
| DPoP proofs | ML-DSA-87 | RFC 9449 | Yes |
| Entropy | Multi-source CSPRNG | SP 800-90B | N/A |

*\*OPAQUE's OPRF is computationally secure, but passwords are never exposed to the server.*

## Build

```
rustup install 1.88
cargo build --release
```

## Test

```
cargo test --workspace
```

190+ tests covering cryptographic correctness, end-to-end ceremony flows, attack simulations, chaos injection, and compliance validation.

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

Created by [Divya Mohan](https://dmj.one). AI architecture partner: Claude (Anthropic).
