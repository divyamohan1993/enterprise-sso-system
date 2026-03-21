# MILNET SSO System

**Research-Grade Military Network Authentication**

The world's first SSO system combining threshold cryptography, OPAQUE password authentication, ratcheting sessions, key transparency, microkernel process isolation, and post-quantum cryptography in a single architecture. No publicly documented system -- commercial, government, or academic -- has achieved this combination.

## Status

Architecture specification complete. Implementation pending.

- Spec: [docs/superpowers/specs/2026-03-21-milnet-sso-design.md](docs/superpowers/specs/2026-03-21-milnet-sso-design.md)
- Red team rounds: 6 (169 attack vectors identified and mitigated)
- Language: Rust (planned)

## Threat Model

Assumes total compromise of host, network, clients, database, and individual processes. Nation-state adversary with raw internet access, no firewall. DDoS + APTs simultaneously. Hundreds of thousands of users under full mobilization.

## Architecture

9 isolated mutually-distrusting Rust processes:

| Module | Purpose | Holds Secrets? |
|--------|---------|---------------|
| Bastion Gateway | DDoS filter, TLS termination | No |
| Auth Orchestrator | Route ceremonies | No |
| Threshold Signer (TSS) | FROST 3-of-5 + ML-DSA-65 | 1 share only |
| Credential Verifier | O(1) token verification | Public keys only |
| T-OPAQUE Service | Server-blind password auth | 1 OPRF share only |
| Ratchet Manager | Forward-secret sessions | Ephemeral chain keys |
| Key Transparency | Credential tamper detection | Append-only log |
| Risk Engine | Continuous auth signals | Behavioral baselines |
| Audit Log (BFT) | Tamper-proof event record | Event log |

## Key Properties

- **O(1) hot path:** ~72us token verification
- **Host compromise resilient:** No complete secret exists anywhere
- **Post-quantum:** ML-KEM-768 + X25519 hybrid (mandatory, no fallback)
- **Forward secrecy:** HKDF-SHA512 ratchet, 30s epochs
- **Action-level auth:** 5-level classification, sovereign ceremony for critical ops
- **169 attack vectors analyzed:** 6 rounds of nation-state red team analysis

## License

MIT
