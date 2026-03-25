# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |

Only the latest release on the default branch receives security patches.
Older versions are not backported unless a critical vulnerability affects deployed systems.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, email **[DEPLOY: configure actual security reporting email]** with:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce or a proof-of-concept (if available).
3. The affected component(s) and version(s).
4. Your recommended severity (Critical / High / Medium / Low).

You will receive an acknowledgment within **48 hours** and a detailed response
within **7 business days** indicating next steps.

## Security Update Policy

- **Critical/High** vulnerabilities: patch released within 72 hours of confirmation.
- **Medium** vulnerabilities: patch released within 14 days.
- **Low** vulnerabilities: addressed in the next scheduled release.

All security patches are accompanied by a GitHub Security Advisory (GHSA)
and an entry in the CHANGELOG.

## Dependency Management

This project uses:

- **cargo-deny** to enforce license compliance, advisory checks, and source provenance.
- **cargo-audit** for complementary vulnerability scanning against the RustSec Advisory Database.
- A pinned Rust toolchain (`rust-toolchain.toml`) for reproducible builds.
- `deny.toml` configured with `unknown-registry = "deny"` and `unknown-git = "deny"` to
  block dependencies from untrusted registries or Git repositories.

## CNSA 2.0 Compliance Statement

This system is designed to align with the NSA Commercial National Security Algorithm
Suite 2.0 (CNSA 2.0) requirements where applicable:

- **Key Agreement**: X25519 / ML-KEM (where supported by dependencies).
- **Digital Signatures**: Ed25519 / ML-DSA (where supported by dependencies).
- **Hashing**: SHA-384 / SHA-512 used for all internal integrity checks.
- **Symmetric Encryption**: AES-256-GCM for authenticated encryption.

CNSA 2.0 mandates a transition to quantum-resistant algorithms by 2030 for national
security systems. This project tracks post-quantum readiness through its cryptographic
provider abstractions and will adopt NIST-standardized PQC algorithms as the Rust
ecosystem matures support for them.

Note: Full CNSA 2.0 compliance depends on the underlying cryptographic libraries
(e.g., `ring`, `aws-lc-rs`) and their FIPS validation status. Deployers should
verify that their specific configuration meets their compliance requirements.
