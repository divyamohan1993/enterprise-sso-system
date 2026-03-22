# CNSA 2.0 Algorithm Compliance Status

**System:** MILNET SSO (enterprise-sso-system)
**Date:** 2026-03-22
**Revision:** 1.0
**Reference:** NSA CNSA Suite 2.0 (September 2022, updated March 2024)

This document maps CNSA 2.0 required algorithms to the MILNET SSO implementation and assesses transition timeline compliance.

---

## CNSA 2.0 Algorithm Requirements

### Key Establishment

| CNSA 2.0 Requirement | Implementation | Status | File Reference | Notes |
|----------------------|---------------|--------|---------------|-------|
| ML-KEM-1024 (FIPS 203) | `ml-kem` crate, `MlKem1024` | **Implemented** | `crypto/src/xwing.rs:11` | Used in X-Wing hybrid combiner. Full encapsulate/decapsulate with real ML-KEM-1024. |
| X25519 (classical, hybrid only) | `x25519-dalek` crate | **Implemented** | `crypto/src/xwing.rs:13` | Combined with ML-KEM-1024 in X-Wing hybrid KEM. Provides defense-in-depth during PQ transition. |
| Hybrid KEM combiner | SHA3-256 X-Wing combiner | **Implemented** | `crypto/src/xwing.rs:176-194` | `SHA3-256("X-Wing" \|\| ml_kem_ss \|\| ml_kem_ct \|\| x25519_ss \|\| x25519_pk_client \|\| x25519_pk_server)` |

### Digital Signatures

| CNSA 2.0 Requirement | Implementation | Status | File Reference | Notes |
|----------------------|---------------|--------|---------------|-------|
| ML-DSA-87 (FIPS 204) | `ml-dsa` crate, `MlDsa87` | **Implemented** | `crypto/src/pq_sign.rs:6-9` | Used for audit entry signing, signed tree heads, witness checkpoints. Nested signing: PQ signature covers `(payload \|\| FROST_signature)`. |
| ML-DSA-65 (FIPS 204) | Referenced in architecture | **Partial** | `audit/src/bft.rs` | BFT audit entries and KT tree heads reference ML-DSA-65 signing. Actual implementation uses ML-DSA-87. |

**Note on ML-DSA parameter set:** CNSA 2.0 requires ML-DSA-87 (Category 5 security). The system implements ML-DSA-87 in `crypto/src/pq_sign.rs`. Architecture documents reference ML-DSA-65 in some places; the actual crypto implementation uses the stronger ML-DSA-87.

### Symmetric Encryption

| CNSA 2.0 Requirement | Implementation | Status | File Reference | Notes |
|----------------------|---------------|--------|---------------|-------|
| AES-256 | AES-256-GCM via `aes-gcm` crate | **Implemented** | `crypto/src/seal.rs:12-13` | Used for envelope encryption (key wrapping). 12-byte random nonces, authenticated encryption with AAD. |

### Hash Functions

| CNSA 2.0 Requirement | Implementation | Status | File Reference | Notes |
|----------------------|---------------|--------|---------------|-------|
| SHA-384 or SHA-512 | SHA-512 via `sha2` crate | **Implemented** | `crypto/src/seal.rs:9`, `crypto/src/entropy.rs:15` | HKDF-SHA512 for key derivation. HMAC-SHA512 for IPC authentication. |
| SHA3-256 | `sha3` crate | **Implemented** | `crypto/src/xwing.rs:12` | X-Wing KEM combiner. KT Merkle tree (SHA3-256). |

### Key Derivation

| CNSA 2.0 Requirement | Implementation | Status | File Reference | Notes |
|----------------------|---------------|--------|---------------|-------|
| HKDF (SP 800-56C) | HKDF-SHA512 via `hkdf` crate | **Implemented** | `crypto/src/seal.rs:9` | Master -> KEK -> DEK hierarchy. Domain-separated derivation with unique info strings. |

---

## Approved Exceptions (Non-PQ Algorithms with Justification)

| Algorithm | Usage | Justification | File Reference |
|-----------|-------|--------------|---------------|
| SHA-256 (PKCE S256) | OAuth2 PKCE code challenge | Required by RFC 7636. PKCE code verifiers are ephemeral (single-use, seconds-lived). No quantum threat to ephemeral challenge-response. | `sso-protocol/src/pkce.rs` |
| SHA-256 (WebAuthn) | FIDO2 client data hash | Required by W3C WebAuthn specification. Hardware authenticators (YubiKey, etc.) implement SHA-256 in firmware. Cannot be changed without new hardware. | `fido/src/verification.rs:94` |
| SHA-256 (Audit chain) | Hash-chain linking for audit entries | Audit chain integrity is also protected by ML-DSA-87 signatures on BFT entries. SHA-256 chain provides tamper detection; PQ signatures provide non-repudiation. Defense-in-depth. | `audit/src/log.rs` |
| SHA-256 (HMAC-SHA256) | Receipt signing | Receipts are ephemeral (30-second TTL). HMAC-SHA256 is not vulnerable to Grover's algorithm in the same way as hash preimage; HMAC security is bounded by key length (256-bit). | `crypto/src/receipts.rs` |
| EdDSA (Ristretto255) | FROST threshold signing | Classical FROST is nested under ML-DSA-87 post-quantum signature. Stripping the PQ layer would require forging ML-DSA-87. | `crypto/src/threshold.rs` |
| X25519 | X-Wing hybrid KEM (classical component) | Combined with ML-KEM-1024 in hybrid. Security degrades gracefully: if X25519 is broken by quantum, ML-KEM-1024 still protects. If ML-KEM-1024 has implementation flaw, X25519 still protects. | `crypto/src/xwing.rs` |
| RS256 (RSA-2048 + SHA-256) | OIDC JWT signing | Required for broad OIDC client compatibility. JWKS endpoint serves RS256. Tokens are short-lived (5-15 min). Migration path: add ML-DSA JWKS key alongside RS256 when ecosystem supports it. | `sso-protocol/src/tokens.rs` |

---

## CNSA 2.0 Transition Timeline Compliance

| Milestone | CNSA 2.0 Deadline | System Status | Notes |
|-----------|-------------------|---------------|-------|
| Software/firmware supporting ML-KEM | 2025 | **Met** | ML-KEM-1024 implemented in X-Wing hybrid KEM. |
| Prefer PQ for key establishment | 2026 | **Met** | X-Wing hybrid KEM is the default for all session key establishment. |
| Exclusively PQ for key establishment | 2030 | **On Track** | Classical X25519 component can be removed from X-Wing when PQ-only is mandated. Architecture supports this. |
| Software/firmware supporting ML-DSA | 2025 | **Met** | ML-DSA-87 implemented for audit signatures, tree heads, witness checkpoints. |
| Prefer PQ for digital signatures | 2028 | **On Track** | ML-DSA-87 already used for high-integrity operations. FROST tokens nested under ML-DSA-87. |
| Exclusively PQ for digital signatures | 2033 | **On Track** | FROST EdDSA can be replaced with threshold ML-DSA when threshold PQ signature schemes are standardized. |
| AES-256 for symmetric encryption | Now | **Met** | AES-256-GCM used for all envelope encryption. |
| SHA-384+ for hashing | Now | **Met** | SHA-512 and SHA3-256 used for all security-critical hashing. SHA-256 only in exceptions noted above. |

---

## Crate Validation Status

| Crate | Version | FIPS Validated | CNSA 2.0 Algorithm | Notes |
|-------|---------|---------------|-------------------|-------|
| `ml-kem` | (workspace) | **No** | ML-KEM-1024 | Pure Rust implementation. Not yet submitted for FIPS validation. See FIPS-140-3-READINESS.md. |
| `ml-dsa` | (workspace) | **No** | ML-DSA-87 | Pure Rust implementation. Not yet submitted for FIPS validation. |
| `aes-gcm` | (workspace) | **No** | AES-256-GCM | RustCrypto implementation. aws-lc-rs (FIPS-validated) available as alternative backend. |
| `sha2` | (workspace) | **No** | SHA-512 | RustCrypto implementation. aws-lc-rs available as alternative. |
| `sha3` | (workspace) | **No** | SHA3-256 | RustCrypto implementation. |
| `x25519-dalek` | (workspace) | **No** | X25519 | dalek-cryptography implementation. |
| `frost-ristretto255` | 2.2 | **No** | EdDSA (threshold) | ZCash Foundation implementation. |
| `aws-lc-rs` | (via rustls) | **Yes** (pending) | TLS primitives | Used by rustls. AWS-LC is in FIPS validation process (CMVP). |

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|-----------|
| `ml-kem` and `ml-dsa` crates are not FIPS-validated | High (for regulated environments) | Use `ProductionKeySource` trait to delegate PQ operations to a FIPS-validated HSM when available. Monitor CMVP for Rust PQ module submissions. |
| RS256 JWT signing is not PQ-resistant | Medium | Tokens are short-lived (5-15 min). Add ML-DSA JWKS key when OIDC ecosystem supports PQ algorithms. |
| SHA-256 in audit chain, PKCE, WebAuthn | Low | Ephemeral use cases (PKCE, receipts). Audit chain additionally protected by ML-DSA-87 signatures. WebAuthn SHA-256 is hardware-mandated. |
