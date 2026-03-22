# FIPS 140-3 Readiness Assessment

**System:** MILNET SSO (enterprise-sso-system)
**Date:** 2026-03-22
**Revision:** 1.0
**Target:** FIPS 140-3 Level 3 (for key management module)

This document assesses the system's readiness for FIPS 140-3 validation and identifies the path to compliance.

---

## Current Cryptographic Library Inventory

### Libraries Used in Production Paths

| Library | Algorithm(s) | FIPS Validated | CMVP Status | Usage in System |
|---------|-------------|---------------|-------------|-----------------|
| `aws-lc-rs` | TLS primitives (AES, SHA, ECDH, RSA) | **In Process** | AWS-LC CMVP submission pending (certificate expected 2025-2026) | Used by rustls for TLS 1.3. `Cargo.toml:52` specifies `features = ["aws_lc_rs"]`. |
| `ml-kem` (RustCrypto) | ML-KEM-1024 (FIPS 203) | **No** | No CMVP submission | X-Wing hybrid KEM. `crypto/src/xwing.rs`. |
| `ml-dsa` (RustCrypto) | ML-DSA-87 (FIPS 204) | **No** | No CMVP submission | Audit signatures, tree heads, witness checkpoints. `crypto/src/pq_sign.rs`. |
| `aes-gcm` (RustCrypto) | AES-256-GCM | **No** | No CMVP submission | Envelope encryption (key wrapping). `crypto/src/seal.rs`. |
| `sha2` (RustCrypto) | SHA-256, SHA-512 | **No** | No CMVP submission | HKDF, HMAC, audit chain, receipt signing. Multiple files. |
| `sha3` (RustCrypto) | SHA3-256 | **No** | No CMVP submission | X-Wing combiner, KT Merkle tree. `crypto/src/xwing.rs`, `kt/src/lib.rs`. |
| `hkdf` (RustCrypto) | HKDF-SHA512 | **No** | No CMVP submission | Key derivation (master -> KEK -> DEK). `crypto/src/seal.rs`. |
| `hmac` (RustCrypto) | HMAC-SHA256, HMAC-SHA512 | **No** | No CMVP submission | SHARD IPC auth, receipt signing, DPoP. Multiple files. |
| `frost-ristretto255` (ZCash) | FROST EdDSA (threshold) | **No** | No CMVP submission | Threshold token signing. `crypto/src/threshold.rs`. |
| `x25519-dalek` | X25519 ECDH | **No** | No CMVP submission | Classical component of X-Wing KEM. `crypto/src/xwing.rs`. |
| `opaque-ke` | OPAQUE OPRF | **No** | No CMVP submission | Server-blind password authentication. `opaque/src/opaque_impl.rs`. |
| `argon2` | Argon2id KDF | **No** | Not a FIPS-approved algorithm | Password hashing (used alongside OPAQUE). `opaque/src/store.rs`. |
| `getrandom` | OS CSPRNG | **N/A** | Wraps OS-provided RNG | Entropy source. Used system-wide. |

---

## FIPS 140-3 Level 3 Requirements Mapping

### Physical Security (Level 3)

| Requirement | Status | Path to Compliance |
|-------------|--------|-------------------|
| Tamper-evident enclosure for cryptographic module | **Not Applicable** (software module) | For Level 3 physical, requires HSM. `ProductionKeySource` trait (`crypto/src/seal.rs:237-251`) provides the abstraction for HSM delegation. |
| Environmental failure protection | **Not Applicable** (software module) | HSM provides this. Software module targets Level 1 operational environment. |
| Identity-based operator authentication | **Partial** | Multi-person ceremonies for critical operations. `SecurityConfig` enforces `level4_cooldown_secs` and `level4_max_per_72h`. |

### Cryptographic Module Specification (Level 3)

| Requirement | Status | Notes |
|-------------|--------|-------|
| Defined cryptographic boundary | **Partial** | The `crypto` crate serves as the logical cryptographic boundary. All crypto operations centralized there. However, `opaque-ke` and `frost-ristretto255` perform crypto outside this boundary. |
| Approved algorithms only | **Partial** | Core algorithms (AES-256, SHA-2, SHA-3, ML-KEM, ML-DSA) are NIST-approved. Argon2id is not a FIPS-approved algorithm (RFC 9106 but no FIPS standard). EdDSA over Ristretto255 is not FIPS-approved (FIPS 186-5 approves Ed25519/Ed448). |
| Approved RNG | **Met** | `getrandom` crate wraps OS CSPRNG (`/dev/urandom` / `RDRAND`). Entropy combiner adds environmental noise and hardware RNG. Health tests per SP 800-90B. |
| Self-tests | **Partial** | Entropy health self-tests (repetition count, adaptive proportion). Canary integrity tests on memory buffers. No known-answer tests (KATs) for all algorithms at startup. |
| Key zeroization | **Met** | `zeroize` + `ZeroizeOnDrop` on all key types. `mlock` prevents swap. `MADV_DONTDUMP` excludes from core dumps. Manual zeroization on panic paths. |

### Key Management (Level 3)

| Requirement | Status | Notes |
|-------------|--------|-------|
| Key generation uses approved RNG | **Met** | All key generation uses `getrandom` (OS CSPRNG). ML-DSA-87 keys from 32-byte seed via `getrandom`. FROST DKG uses `rand::thread_rng()` (backed by OS RNG). |
| Key establishment uses approved methods | **Met** | HKDF-SHA512 (SP 800-56C). X-Wing hybrid KEM (ML-KEM-1024 + X25519). |
| Key storage protects against unauthorized disclosure | **Met** | AES-256-GCM envelope encryption. Purpose-bound KEK derivation. `mlock` for in-memory keys. |
| Key destruction is complete | **Met** | `zeroize` on drop for all key types. `munlock` after zeroize. Canary zeroization. |
| Key separation by purpose | **Met** | 11 unique domain separation prefixes. HKDF info strings include purpose. Different KEKs per table, service, and operation. |

---

## HSM Integration Architecture

The system is designed for HSM integration through the `ProductionKeySource` trait:

```
ProductionKeySource trait (crypto/src/seal.rs:237-251)
    |
    |-- load_master_key()       -> MasterKey
    |-- rotate_master_key()     -> MasterKey
    |-- seal_with_hardware()    -> sealed bytes
    |-- unseal_with_hardware()  -> plaintext bytes
    |
    Implementations:
    |-- SoftwareKeySource       (development/testing, crypto/src/seal.rs:261-299)
    |-- [Future] Pkcs11KeySource   (PKCS#11 HSM)
    |-- [Future] AwsCloudHsmSource (AWS CloudHSM)
    |-- [Future] YubiHsmSource     (YubiHSM2)
```

### HSM Implementation Notes (from code comments)

From `crypto/src/seal.rs:234-236`:
- **PKCS#11:** Use `C_WrapKey`/`C_UnwrapKey` with `CKM_AES_KEY_WRAP_KWP`
- **AWS CloudHSM:** Use AES key wrap with OAEP padding
- **YubiHSM2:** Use `wrap-data` command with wrap key

### What the HSM Would Protect

| Key Material | Current Location | HSM Target |
|-------------|-----------------|-----------|
| Master Key (root of hierarchy) | Software (`MasterKey` in process memory) | HSM non-extractable key slot |
| FROST signing key shares | Software (`KeyPackage` in TSS process) | HSM key slots (one per TSS node) |
| ML-DSA-87 signing key | Software (`PqSigningKey` in process memory) | HSM key slot with sign-only policy |
| OPAQUE server key | Software (`ServerSetup` in OPAQUE process) | HSM key slot |
| SHARD HMAC keys | Software (per-channel HMAC keys) | HSM-derived session keys |

---

## Path to FIPS 140-3 Level 3

### Phase 1: Algorithm Compliance (Estimated: 3-6 months)

| Task | Description | Effort |
|------|------------|--------|
| Replace Argon2id | Substitute with PBKDF2-HMAC-SHA512 (SP 800-132) or use OPAQUE without server-side KDF (OPAQUE's OPRF provides the password hardening). | Medium |
| Replace Ristretto255 | Migrate FROST from `frost-ristretto255` to `frost-ed25519` (FIPS 186-5 approved curve) or directly to threshold ML-DSA when available. | High |
| Add Known Answer Tests | Implement startup KATs for: AES-256-GCM, SHA-256, SHA-512, SHA3-256, HMAC-SHA512, HKDF-SHA512, ML-KEM-1024, ML-DSA-87. | Medium |
| Add conditional self-tests | Implement pairwise consistency tests for all key generation. | Low |

### Phase 2: FIPS-Validated Library Migration (Estimated: 6-12 months)

| Task | Description | Effort |
|------|------------|--------|
| aws-lc-rs for symmetric crypto | Replace `aes-gcm`, `sha2`, `hmac`, `hkdf` with `aws-lc-rs` equivalents. aws-lc-rs is pursuing FIPS 140-3 validation. | Medium |
| Monitor ml-kem/ml-dsa validation | Track CMVP submissions for Rust ML-KEM and ML-DSA implementations. No validated Rust PQ implementations exist as of March 2026. | Ongoing |
| PKCS#11 HSM integration | Implement `Pkcs11KeySource` for the `ProductionKeySource` trait. Target: Thales Luna, AWS CloudHSM, or Marvell LiquidSecurity. | High |
| HSM-backed FROST signing | Move FROST key shares into HSM slots. Signing operations delegate to HSM via PKCS#11. | High |

### Phase 3: Validation Submission (Estimated: 12-24 months)

| Task | Description | Effort |
|------|------------|--------|
| Define cryptographic boundary | Document the exact module boundary (which code is inside the validated module). | Medium |
| CAVP algorithm testing | Submit algorithms for CAVP (Cryptographic Algorithm Validation Program) testing. | High |
| CMVP submission | Submit the module for FIPS 140-3 validation through an accredited lab. | Very High |
| Operational environment documentation | Document supported platforms, OS requirements, and deployment constraints. | Medium |

---

## Current FIPS-Adjacent Protections

Even without formal FIPS 140-3 validation, the system implements the following FIPS-informed protections:

| Protection | FIPS Relevance | Implementation |
|-----------|---------------|----------------|
| Key zeroization on drop | FIPS 140-3 Section 7.9.7 | `zeroize` + `ZeroizeOnDrop` on all key types |
| Memory locking (mlock) | FIPS 140-3 Section 7.8 | `crypto/src/memguard.rs` -- `mlock`, `MADV_DONTDUMP` |
| Core dump prevention | FIPS 140-3 Section 7.8 | `PR_SET_DUMPABLE`, `PR_SET_NO_NEW_PRIVS` |
| Entropy health tests | SP 800-90B Section 4.4 | Repetition count test, adaptive proportion test |
| Key separation by purpose | FIPS 140-3 Section 7.9.1 | 11 domain separation prefixes, HKDF info strings |
| Tamper detection | FIPS 140-3 Section 7.11 | Hash-chained audit log, canary words on buffers |
| Self-tests | FIPS 140-3 Section 9 | Entropy health tests, canary verification |
| Fail-closed on crypto failure | FIPS 140-3 Section 9 | `entropy_fail_closed`, mlock panic in production |

---

## Risk Summary

| Gap | Impact | Timeline to Close |
|-----|--------|-------------------|
| No FIPS 140-3 validated Rust PQ crypto exists | Cannot achieve FIPS validation for PQ components | Dependent on ecosystem (12-36 months) |
| Argon2id is not FIPS-approved | Module would fail algorithm compliance | 3-6 months (replace with PBKDF2 or defer to OPAQUE OPRF) |
| Ristretto255 is not FIPS-approved | FROST signing uses non-approved curve | 6-12 months (migrate to Ed25519 or threshold ML-DSA) |
| No startup KATs | FIPS 140-3 requires known-answer tests on power-up | 1-3 months (implementation only) |
| No HSM integration implemented | Master key lives in software process memory | 6-12 months (PKCS#11 implementation against ProductionKeySource) |
