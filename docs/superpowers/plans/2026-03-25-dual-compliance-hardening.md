# Dual-Compliance Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement full DoD + Indian government compliance hardening across all 6 layers: FIPS mode, AEGIS-256 symmetric, ML-DSA-87 PQ upgrade, CAC/PIV auth, compliance engine, STIG checks, dual-cloud Terraform, CMMC gap closure, and 100+ chaos/failure tests.

**Architecture:** Layered bottom-up — each layer builds on the previous. Layer 0 (crypto foundations) enables Layer 1 (CAC/PIV) which enables Layer 2 (compliance) and so on. All symmetric encryption uses AEGIS-256 by default with AES-256-GCM as FIPS fallback. Algorithm-ID byte in wire format ensures future algorithm additions never break existing data. All PQ signatures upgraded to ML-DSA-87 (Level 5) for 2031 headroom.

**Tech Stack:** Rust 1.88, aegis 0.6 (AEGIS-256), pbkdf2 0.12 (FIPS KSF), cryptoki 0.10 (PKCS#11), ml-dsa 0.1.0-rc.7 (MlDsa87), existing workspace deps (sha2, hkdf, hmac, aes-gcm, frost-ristretto255, opaque-ke 4.0)

**Spec:** `docs/superpowers/specs/2026-03-25-dual-compliance-hardening-design.md`

**Testing:** C2 spot VM (asia-south1-a), `MILNET_DEV_MODE_KEY` for developer mode, `RUST_MIN_STACK=8388608`, `cargo test --workspace --no-fail-fast`

**Existing test baseline:** 558 tests across 30 executables. All must continue passing after each task.

---

## File Structure

### New Files (Layer 0 — Crypto Foundations)
- `common/src/fips.rs` — FIPS mode runtime toggle (AtomicBool + HMAC-SHA512 proof)
- `crypto/src/kdf.rs` — Dual KSF trait (Argon2id + PBKDF2-HMAC-SHA512)
- `crypto/src/symmetric.rs` — Unified AEAD abstraction (AEGIS-256 default, AES-256-GCM FIPS)

### New Files (Layer 1 — CAC/PIV)
- `crypto/src/cac.rs` — PKCS#11 session management, card info extraction
- `common/src/cac_auth.rs` — CAC authentication flow, cert chain validation

### New Files (Layer 2 — Compliance)
- `common/src/compliance.rs` — Compliance policy engine (DPDP Act + DoD)
- `common/src/data_residency.rs` — Region validation (India + GovCloud)

### New Files (Layer 3 — STIG)
- `common/src/stig.rs` — Programmatic STIG/CIS checks (40+ checks)

### New Files (Layer 4 — Terraform)
- `terraform/aws-govcloud/main.tf` + modules (vpc, cloudhsm, rds, ec2, iam, kms, secretsmanager)
- `terraform/gcp-india/main.tf` + modules (vpc, cloud-hsm, cloud-sql, compute, iam, kms, gcs)
- `deploy/bare-metal/security/cloud-hsm-init.sh`

### New Files (Layer 5 — CMMC)
- `common/src/cmmc.rs` — CMMC 2.0 Level 3 practice assessor
- `common/src/siem_webhook.rs` — External SIEM webhook integration

### New Files (Layer 6 — Chaos Tests)
- `e2e/src/chaos.rs` — Chaos/failure injection test engine

### Modified Files (28 total — see spec section "Modified Files" for complete list)

---

## Task 1: Add New Dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crypto/Cargo.toml`
- Modify: `common/Cargo.toml`
- Modify: `deny.toml`

- [ ] **Step 1: Add aegis, pbkdf2, cryptoki to workspace Cargo.toml**

Add under `[workspace.dependencies]`:
```toml
aegis = "0.6"
pbkdf2 = "0.12"
cryptoki = "0.10"
```

- [ ] **Step 2: Add aegis and pbkdf2 to crypto/Cargo.toml**

Under `[dependencies]`:
```toml
aegis = { workspace = true }
pbkdf2 = { workspace = true }
```

- [ ] **Step 3: Add cryptoki to common/Cargo.toml**

Under `[dependencies]`:
```toml
cryptoki = { workspace = true, optional = true }
```

Add feature:
```toml
[features]
cac = ["cryptoki"]
```

- [ ] **Step 4: Update deny.toml if needed**

Check that aegis, pbkdf2, cryptoki licenses are in the allowlist (MIT/Apache-2.0 — they are).

- [ ] **Step 5: Verify workspace compiles**

Run: `cargo check --workspace`
Expected: compiles with no errors

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml crypto/Cargo.toml common/Cargo.toml deny.toml
git commit -m "deps: add aegis 0.6, pbkdf2 0.12, cryptoki 0.10 for hardening"
```

---

## Task 2: FIPS Mode Runtime Toggle (`common/src/fips.rs`)

**Files:**
- Create: `common/src/fips.rs`
- Modify: `common/src/lib.rs` (add `pub mod fips;`)
- Modify: `common/src/config.rs` (add fips fields to SecurityConfig)

- [ ] **Step 1: Write failing tests for FIPS mode**

Create `common/src/fips.rs` with `#[cfg(test)] mod tests` containing:
- `test_fips_mode_default_off()` — `is_fips_mode()` returns false initially
- `test_fips_mode_toggle_unchecked()` — set/unset for testing
- `test_fips_mode_proof_generation_and_verification()` — generate proof, verify succeeds
- `test_fips_mode_wrong_proof_rejected()` — bad proof rejected
- `test_fips_mode_production_forces_on()` — when MILNET_PRODUCTION set, cannot disable
- `test_fips_mode_blocks_argon2id()` — verify FIPS mode flag makes KSF check return FIPS-only
- `test_fips_mode_allows_pbkdf2()` — verify PBKDF2 is selectable in FIPS mode
- `test_fips_mode_blocks_aegis256()` — verify FIPS mode forces AES-256-GCM
- `test_fips_mode_allows_aes256gcm()` — verify AES-256-GCM works in FIPS mode
- `test_pq_minimum_level_enforcement()` — SecurityConfig with pq_minimum_level=3 → violation

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p common fips -- --no-fail-fast 2>&1 | tail -5`
Expected: FAIL (module doesn't exist yet)

- [ ] **Step 3: Implement fips.rs**

Full implementation following the pattern in `common/src/config.rs` (DeveloperModeConfig):
- `FIPS_MODE: AtomicBool`
- `FIPS_ACTIVATION_KEY: OnceLock<Option<[u8; 32]>>`
- `load_fips_activation_key()` — reads `MILNET_FIPS_MODE_KEY` env, scrubs it
- `is_fips_mode() -> bool` — Relaxed AtomicBool read
- `FipsModeConfig` struct with `set_fips_mode(enabled, proof_hex)`, `set_fips_mode_unchecked(enabled)`
- `verify_fips_proof(proof_hex, action) -> bool` — HMAC-SHA512
- `generate_fips_proof(key, action) -> String`
- Domain: `b"MILNET-FIPS-MODE-v1"`
- Production constraint: if `crate::sealed_keys::is_production()`, refuse to disable

- [ ] **Step 4: Add `pub mod fips;` to common/src/lib.rs**

Add after the `pub mod error_response;` line.

- [ ] **Step 5: Add FIPS fields to SecurityConfig in common/src/config.rs**

Add fields:
```rust
pub fips_mode: bool,
pub pq_minimum_level: u8,
pub require_pq_signatures: bool,
pub require_pq_key_exchange: bool,
pub ksf_algorithm: String,
pub symmetric_algorithm: String,
```

Add to `Default`:
```rust
fips_mode: false,
pq_minimum_level: 5,
require_pq_signatures: true,
require_pq_key_exchange: true,
ksf_algorithm: "argon2id-v19".into(),
symmetric_algorithm: "aegis-256".into(),
```

Add to `validate_production_config()`:
```rust
if !self.fips_mode {
    violations.push("fips_mode must be true in production".into());
}
if self.pq_minimum_level < 5 {
    violations.push("pq_minimum_level must be >= 5 (CNSA 2.0 Level 5)".into());
}
if !self.require_pq_signatures {
    violations.push("require_pq_signatures must be true in production".into());
}
if !self.require_pq_key_exchange {
    violations.push("require_pq_key_exchange must be true in production".into());
}
```

- [ ] **Step 6: Run all tests**

Run: `cargo test -p common -- --no-fail-fast`
Expected: all pass (existing + new fips tests)

- [ ] **Step 7: Commit**

```bash
git add common/src/fips.rs common/src/lib.rs common/src/config.rs
git commit -m "feat: add FIPS mode runtime toggle with cryptographic activation proof"
```

---

## Task 3: Symmetric Encryption Abstraction (`crypto/src/symmetric.rs`)

**Files:**
- Create: `crypto/src/symmetric.rs`
- Modify: `crypto/src/lib.rs` (add `pub mod symmetric;`)

- [ ] **Step 1: Write failing tests**

In `crypto/src/symmetric.rs`, write tests:
- `test_aegis256_encrypt_decrypt_roundtrip()` — encrypt, decrypt, plaintext matches
- `test_aegis256_wrong_key_fails()` — decrypt with different key returns error
- `test_aegis256_tampered_ciphertext_fails()` — flip a byte, decrypt fails
- `test_aegis256_nonce_uniqueness()` — two encryptions produce different ciphertexts
- `test_aes256gcm_encrypt_decrypt_roundtrip()` — explicit AES-256-GCM path
- `test_algo_id_byte_correct()` — AEGIS ciphertext starts with 0x01, AES with 0x02
- `test_cross_algorithm_decrypt()` — encrypt with AEGIS, attempt decrypt as AES → fail (wrong algo)
- `test_legacy_aes256gcm_no_algo_byte()` — raw AES-256-GCM (no prefix) → auto-detected as legacy
- `test_active_algorithm_follows_fips()` — set FIPS on, verify returns Aes256Gcm; off → Aegis256
- `test_empty_plaintext_roundtrip()` — zero-length data works
- `test_large_plaintext_roundtrip()` — 1MB data works

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p crypto symmetric -- --no-fail-fast 2>&1 | tail -5`
Expected: FAIL

- [ ] **Step 3: Implement symmetric.rs**

Full implementation:
- `SymmetricAlgorithm` enum: `Aegis256 = 0x01`, `Aes256Gcm = 0x02`
- `active_algorithm()` — checks `common::fips::is_fips_mode()`
- `encrypt(key, plaintext, aad)` — calls `encrypt_with(active_algorithm(), ...)`
- `decrypt(key, sealed, aad)`:
  - Read first byte
  - If 0x01: AEGIS-256 (nonce=32, tag=32)
  - If 0x02: AES-256-GCM (nonce=12, tag=16)
  - Else: legacy AES-256-GCM (no prefix byte — nonce=first 12 bytes, rest is ciphertext+tag)
- `encrypt_with(algo, key, plaintext, aad)`:
  - Generate random nonce (32 bytes for AEGIS, 12 for AES)
  - Encrypt with chosen algorithm
  - Return: `algo_id || nonce || ciphertext || tag`
- AEGIS-256 via `aegis::aegis256::Aegis256`
- AES-256-GCM via `aes_gcm::Aes256Gcm`

- [ ] **Step 4: Add `pub mod symmetric;` to crypto/src/lib.rs**

- [ ] **Step 5: Run all tests**

Run: `cargo test -p crypto -- --no-fail-fast`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add crypto/src/symmetric.rs crypto/src/lib.rs
git commit -m "feat: add AEGIS-256 symmetric encryption with AES-256-GCM FIPS fallback"
```

---

## Task 4: Dual KSF Abstraction (`crypto/src/kdf.rs`)

**Files:**
- Create: `crypto/src/kdf.rs`
- Modify: `crypto/src/lib.rs` (add `pub mod kdf;`)

- [ ] **Step 1: Write failing tests**

- `test_argon2id_stretch_roundtrip()`
- `test_pbkdf2_sha512_stretch_roundtrip()`
- `test_pbkdf2_sha512_deterministic()` — same input → same output
- `test_pbkdf2_sha512_different_salt()` — different salt → different output
- `test_active_ksf_follows_fips()` — FIPS on → "pbkdf2-sha512", off → "argon2id-v19"
- `test_pbkdf2_iteration_count()` — verify 210,000 iterations used

- [ ] **Step 2: Implement kdf.rs**

- `KeyStretchingFunction` trait
- `Argon2idKsf` struct (64 MiB, 3 iters, 4 lanes)
- `Pbkdf2Sha512Ksf` struct (210,000 iters, HMAC-SHA512)
- `active_ksf_id() -> &'static str`
- `stretch_password(password, salt) -> Result<Vec<u8>, String>` — dispatches based on FIPS mode

- [ ] **Step 3: Run tests, verify pass**

- [ ] **Step 4: Commit**

```bash
git add crypto/src/kdf.rs crypto/src/lib.rs
git commit -m "feat: add dual KSF abstraction (Argon2id + PBKDF2-SHA512 for FIPS)"
```

---

## Task 5: FIPS KAT Expansion (`crypto/src/fips_kat.rs`)

**Files:**
- Modify: `crypto/src/fips_kat.rs`

- [ ] **Step 1: Add PBKDF2-SHA512 KAT**

Add `kat_pbkdf2_sha512()` with known test vector adapted from RFC 6070 for SHA-512.

- [ ] **Step 2: Add AEGIS-256 KAT**

Add `kat_aegis256()` with test vector from RFC 9312 appendix.

- [ ] **Step 3: Register both in run_all_kats()**

- [ ] **Step 4: Run all crypto tests**

Run: `cargo test -p crypto -- --no-fail-fast`
Expected: all pass including new KATs

- [ ] **Step 5: Commit**

```bash
git add crypto/src/fips_kat.rs
git commit -m "feat: add PBKDF2-SHA512 and AEGIS-256 known-answer tests"
```

---

## Task 6: ML-DSA-87 Upgrade for DPoP (`crypto/src/dpop.rs`)

**Files:**
- Modify: `crypto/src/dpop.rs`

- [ ] **Step 1: Change type aliases from MlDsa65 to MlDsa87**

```rust
pub type DpopSigningKey = SigningKey<MlDsa87>;
pub type DpopVerifyingKey = VerifyingKey<MlDsa87>;
pub type DpopSignature = ml_dsa::Signature<MlDsa87>;
```

- [ ] **Step 2: Change dpop_key_hash to SHA-512 (returns [u8; 64])**

```rust
pub fn dpop_key_hash(client_public_key: &[u8]) -> [u8; 64] {
    use sha2::{Sha512, Digest};
    let mut hasher = Sha512::new();
    hasher.update(client_public_key);
    hasher.finalize().into()
}
```

- [ ] **Step 3: Update all tests in dpop.rs to use MlDsa87 and [u8; 64]**

- [ ] **Step 4: Run tests**

Run: `RUST_MIN_STACK=8388608 cargo test -p crypto dpop -- --no-fail-fast`
Expected: all pass (ML-DSA-87 needs more stack)

- [ ] **Step 5: Commit**

```bash
git add crypto/src/dpop.rs
git commit -m "security: upgrade DPoP to ML-DSA-87 (Level 5) + SHA-512 key hash"
```

---

## Task 7: ML-DSA-87 Upgrade for Receipts (`crypto/src/receipts.rs`)

**Files:**
- Modify: `crypto/src/receipts.rs`

- [ ] **Step 1: Change type aliases from MlDsa65 to MlDsa87**

- [ ] **Step 2: Update all tests**

- [ ] **Step 3: Run tests, verify pass**

- [ ] **Step 4: Commit**

```bash
git add crypto/src/receipts.rs
git commit -m "security: upgrade receipt signing to ML-DSA-87 (Level 5)"
```

---

## Task 8: dpop_hash Size Change [u8; 32] → [u8; 64] (All Call Sites)

**Files:**
- Modify: `common/src/types.rs` — TokenClaims.dpop_hash, Receipt.dpop_key_hash
- Modify: `gateway/src/wire.rs` — OrchestratorRequest.dpop_key_hash
- Modify: `gateway/src/server.rs` — SHA-512 for dpop key hash computation
- Modify: `orchestrator/src/messages.rs` — dpop_key_hash
- Modify: `orchestrator/src/service.rs` — MlDsa65→MlDsa87, dpop_key_hash
- Modify: `opaque/src/messages.rs` — dpop_key_hash
- Modify: `opaque/src/service.rs` — MlDsa65→MlDsa87, dpop_key_hash
- Modify: `verifier/src/verify.rs` — [0u8; 64] sentinel, ct_eq uses
- Modify: `verifier/src/main.rs` — [0u8; 64] comparison
- Modify: `tss/src/token_builder.rs` — if dpop_hash referenced
- Modify: all test files with hardcoded `[0xBB; 32]` or `[0u8; 32]` dpop values

- [ ] **Step 1: Update common/src/types.rs**

Change `TokenClaims.dpop_hash: [u8; 32]` → `[u8; 64]`
Change `Receipt.dpop_key_hash: [u8; 32]` → `[u8; 64]`
Update `Token::test_fixture()` and `Receipt::test_fixture()` to use 64-byte values.

- [ ] **Step 2: Fix all compilation errors**

The type change will cascade compile errors to every file using these structs. Fix each one:
- Wire types: `[u8; 32]` → `[u8; 64]`
- Zero sentinels: `[0u8; 32]` → `[0u8; 64]`
- Constant-time comparisons: `ct_eq_32` → `ct_eq` (or add `ct_eq_64`)
- Test fixtures: `[0xBB; 32]` → `[0xBB; 64]` etc.

- [ ] **Step 3: Update gateway/src/server.rs dpop hash computation**

Change from SHA-256 to SHA-512 for computing the DPoP key hash from KEM ciphertext.

- [ ] **Step 4: Update orchestrator and opaque ML-DSA-65 → ML-DSA-87**

In `orchestrator/src/service.rs`: replace `MlDsa65` with `MlDsa87` in `from_seed()` calls.
In `opaque/src/service.rs`: replace `use ml_dsa::{KeyGen, MlDsa65}` with `MlDsa87`.

- [ ] **Step 5: Run full workspace test**

Run: `RUST_MIN_STACK=8388608 cargo test --workspace --no-fail-fast`
Expected: all 558+ tests pass

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "security: upgrade dpop_hash to SHA-512 [u8;64], ML-DSA-87 everywhere"
```

---

## Task 9: Upgrade seal.rs and envelope.rs to AEGIS-256

**Files:**
- Modify: `crypto/src/seal.rs`
- Modify: `crypto/src/envelope.rs`

- [ ] **Step 1: Write new tests**

In seal.rs tests:
- `test_seal_aegis256_roundtrip()`
- `test_seal_fips_aes256gcm_roundtrip()` — set FIPS mode, seal/unseal
- `test_seal_legacy_backward_compat()` — create old-format AES-256-GCM sealed data, verify new unseal reads it

In envelope.rs tests:
- `test_envelope_aegis256_roundtrip()`
- `test_envelope_fips_fallback()`
- `test_envelope_legacy_backward_compat()`

- [ ] **Step 2: Modify DerivedKek::seal() and unseal() to use crypto::symmetric**

Replace direct `aes_gcm` usage with `crypto::symmetric::encrypt/decrypt`.

- [ ] **Step 3: Modify envelope encrypt/decrypt similarly**

- [ ] **Step 4: Run tests**

Run: `RUST_MIN_STACK=8388608 cargo test -p crypto -- --no-fail-fast`
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add crypto/src/seal.rs crypto/src/envelope.rs
git commit -m "security: upgrade seal and envelope to AEGIS-256 with legacy AES-GCM compat"
```

---

## Task 10: Upgrade SHARD Protocol to AEGIS-256

**Files:**
- Modify: `shard/src/protocol.rs`

- [ ] **Step 1: Write new tests**

- `test_shard_aegis256_encryption()`
- `test_shard_fips_aes256gcm_encryption()` — FIPS path

- [ ] **Step 2: Replace AES-256-GCM with crypto::symmetric dispatch**

- [ ] **Step 3: Run shard tests**

Run: `cargo test -p shard -- --no-fail-fast`
Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add shard/src/protocol.rs
git commit -m "security: upgrade SHARD IPC encryption to AEGIS-256"
```

---

## Task 11: Upgrade Backup and Attestation

**Files:**
- Modify: `common/src/backup.rs`
- Modify: `crypto/src/attest.rs`

- [ ] **Step 1: Upgrade backup to v2 format with AEGIS-256**

- New magic: `MILBK002`
- Use `crypto::symmetric::encrypt/decrypt`
- Backward compat: `MILBK001` → legacy AES-256-GCM

- [ ] **Step 2: Upgrade attestation to FIPS-aware hashing**

- `hash_file()`: BLAKE3 (non-FIPS) or SHA-512 truncated (FIPS)
- Add `hash_algorithm` field to `AttestationManifest`

- [ ] **Step 3: Run tests**

- [ ] **Step 4: Commit**

```bash
git add common/src/backup.rs crypto/src/attest.rs
git commit -m "security: upgrade backup to AEGIS-256, attestation to FIPS-aware hashing"
```

---

## Task 12: OPAQUE FIPS Cipher Suite

**Files:**
- Modify: `opaque/src/opaque_impl.rs`
- Modify: `opaque/src/store.rs`
- Modify: `opaque/src/service.rs`

- [ ] **Step 1: Write tests**

- `test_opaque_fips_registration()` — register with OpaqueCsFips, login succeeds
- `test_opaque_ksf_migration()` — register Argon2id, enable FIPS, re-register as PBKDF2
- `test_opaque_adaptive_verify()` — verify_password_adaptive uses correct cipher suite

- [ ] **Step 2: Add Pbkdf2Sha512 wrapper and OpaqueCsFips**

In `opaque_impl.rs`: implement `Pbkdf2Sha512` struct with `opaque_ke::Ksf` trait.

- [ ] **Step 3: Update CredentialStore for dual cipher suites**

Add `ksf_algorithm` to `UserRecord`, `server_setup_fips` to `CredentialStore`, adaptive methods.

- [ ] **Step 4: Update service.rs for FIPS-aware routing**

`handle_request()` checks FIPS mode, routes to correct cipher suite.
**Note:** `opaque/src/service.rs` was already modified in Task 8 (MlDsa65→MlDsa87). This step adds FIPS-routing logic on top of those prior changes — both edits must coexist.

- [ ] **Step 5: Run tests**

Run: `RUST_MIN_STACK=8388608 cargo test -p opaque -- --no-fail-fast`
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add opaque/src/opaque_impl.rs opaque/src/store.rs opaque/src/service.rs
git commit -m "feat: add OPAQUE FIPS cipher suite (PBKDF2-SHA512) with transparent migration"
```

---

## Task 13: ML-DSA-87 for KT Tree Heads

**Files:**
- Modify: `kt/src/merkle.rs`
- Modify: `kt/src/main.rs`

- [ ] **Step 1: Change ML-DSA-65 to ML-DSA-87 in tree head signing/verification**

- [ ] **Step 2: Run tests**

- [ ] **Step 3: Commit**

```bash
git add kt/src/merkle.rs kt/src/main.rs
git commit -m "security: upgrade KT tree head signing to ML-DSA-87"
```

---

## Task 14: Full Layer 0 Integration Test

- [ ] **Step 1: Run full workspace test with FIPS toggling**

Run: `RUST_MIN_STACK=8388608 cargo test --workspace --no-fail-fast`
Expected: all tests pass (558 existing + ~30 new)

- [ ] **Step 2: Commit any remaining fixes**

---

## Task 15: CAC/PIV PKCS#11 Module (`crypto/src/cac.rs`)

**Files:**
- Create: `crypto/src/cac.rs`
- Modify: `crypto/src/lib.rs`

- [ ] **Step 1: Write tests**

- `test_cac_card_type_enum()`
- `test_cac_card_info_fields()`
- `test_cac_error_display()`
- `test_cac_sign_mechanism_variants()`
- `test_cac_cert_fingerprint_sha512()` — SHA-512 hash of test DER cert

- [ ] **Step 2: Implement cac.rs**

Full `CacCardInfo`, `CardType`, `CacError`, `SignMechanism`, `Pkcs11Session` structs.
PKCS#11 operations via `cryptoki` crate — real implementation, not stubs.

- [ ] **Step 3: Run tests, commit**

---

## Task 16: CAC Authentication Flow (`common/src/cac_auth.rs`)

**Files:**
- Create: `common/src/cac_auth.rs`
- Modify: `common/src/lib.rs`
- Modify: `common/src/config.rs` (add CAC config fields)

- [ ] **Step 1: Write tests**

- `test_cac_card_info_extraction()` — parse DER cert, extract subject DN, serial, issuer, policy OIDs
- `test_cac_challenge_response_flow()`
- `test_cac_cert_chain_validation()`
- `test_cac_revoked_cert_rejected()` — cert marked revoked in CRL, authentication fails
- `test_cac_clearance_extraction_dod()`
- `test_cac_clearance_extraction_indian()`
- `test_cac_tier_enforcement()`
- `test_cac_edipi_tagging()` — authenticate, verify EDIPI appears in CacCardInfo and audit log
- `test_cac_pin_lockout()`
- `test_cac_session_timeout()`
- `test_cac_card_removal_detection()` — simulate card removal mid-session, session invalidated
- `test_indian_dsc_authentication()` — Indian DSC cert, CCA-signed, authenticate with eSign challenge
- `test_cac_audit_logging()`

- [ ] **Step 2: Implement CacAuthenticator**

Full implementation: challenge generation, cert chain validation, OCSP/CRL checking, clearance extraction.

- [ ] **Step 3: Add CAC config fields to SecurityConfig**

- [ ] **Step 4: Run tests, commit**

---

## Task 17: Compliance Engine (`common/src/compliance.rs`)

**Files:**
- Create: `common/src/compliance.rs`
- Modify: `common/src/lib.rs`

- [ ] **Step 1: Write tests**

- `test_compliance_india_data_residency()`
- `test_compliance_india_audit_retention_365()`
- `test_compliance_dod_audit_retention_2555()`
- `test_compliance_cross_border_blocked()`
- `test_compliance_pii_encryption_enforced()`
- `test_compliance_classification_ceiling()`
- `test_compliance_cert_in_incident_deadline()`
- `test_compliance_dual_mode()`
- `test_compliance_startup_validation()`

- [ ] **Step 2: Implement ComplianceEngine**

Full `ComplianceRegime`, `ComplianceConfig`, `ComplianceEngine`, `ComplianceViolation` types.

- [ ] **Step 3: Run tests, commit**

---

## Task 18: Data Residency (`common/src/data_residency.rs`)

**Files:**
- Create: `common/src/data_residency.rs`
- Modify: `common/src/lib.rs`

- [ ] **Step 1: Write tests**

- `test_region_policy_india()` — asia-south1/2 allowed, us-east1 blocked
- `test_region_policy_govcloud()` — us-gov-west-1/east-1 allowed, us-east-1 blocked
- `test_replication_india_internal()` — asia-south1 → asia-south2 OK
- `test_replication_india_cross_border()` — asia-south1 → us-east1 BLOCKED

- [ ] **Step 2: Implement RegionPolicy**

- [ ] **Step 3: Run tests, commit**

---

## Task 19: Compliance-Aware Audit Retention

**Files:**
- Modify: `audit/src/log.rs`

- [ ] **Step 1: Add compliance_regime to RetentionPolicy**

- [ ] **Step 2: Enforce minimum retention in enforce_retention()**

CERT-In: 365 days. DoD: 2555 days. Block deletion of entries below minimum age.

- [ ] **Step 3: Write tests**

- `test_retention_cert_in_blocks_recent()`
- `test_retention_cert_in_allows_old()`
- `test_retention_dod_blocks_recent()`

- [ ] **Step 4: Run tests, commit**

---

## Task 20: PII Encryption Enforcement

**Files:**
- Modify: `common/src/encrypted_db.rs`

- [ ] **Step 1: Write tests**

- `test_pii_field_encrypted_roundtrip()` — encrypt PII field, decrypt, matches original
- `test_pii_field_compliance_check_enforced()` — compliance engine rejects unencrypted PII when required
- `test_pii_field_uses_aegis256_default()` — verify AEGIS-256 used when not in FIPS mode
- `test_pii_field_uses_aes256gcm_fips()` — verify AES-256-GCM when FIPS mode enabled

- [ ] **Step 2: Implement encrypt_pii_field()**

```rust
pub fn encrypt_pii_field(
    field_name: &str,
    value: &[u8],
    kek: &crypto::seal::DerivedKek,
    compliance: &crate::compliance::ComplianceEngine,
) -> Result<Vec<u8>, MilnetError> {
    compliance.check_pii_encryption(true, field_name)
        .map_err(|v| MilnetError::Compliance(v.detail))?;
    crypto::symmetric::encrypt(kek.as_bytes(), value, field_name.as_bytes())
        .map_err(|e| MilnetError::Encryption(e))
}
```

- [ ] **Step 3: Run tests, commit**

```bash
git add common/src/encrypted_db.rs
git commit -m "feat: add PII field encryption enforcement for DPDP Act compliance"
```

---

## Task 21: STIG Auditor (`common/src/stig.rs`)

**Files:**
- Create: `common/src/stig.rs`
- Modify: `common/src/lib.rs`
- Modify: `common/src/startup_checks.rs`

- [ ] **Step 1: Write tests**

- `test_stig_check_struct_fields()`
- `test_stig_severity_ordering()`
- `test_stig_summary_counts()`
- `test_stig_json_output_format()`
- `test_stig_cat_i_blocks_startup_production()`
- `test_stig_cat_i_warns_dev_mode()`
- Tests for individual checks (mock sysctl values)

- [ ] **Step 2: Implement StigAuditor with 40+ checks**

Each check reads from /proc/sys or /sys and returns StigCheck.
Categories: Kernel, Filesystem, Network, Authentication, Audit, Crypto, Process, Service.

- [ ] **Step 3: Integrate with startup_checks.rs**

Add `run_stig_audit()` call. Cat I failure blocks startup in production.

- [ ] **Step 4: Run tests, commit**

---

## Task 22: GCP India Terraform

**Files:**
- Create: `terraform/gcp-india/main.tf`
- Create: `terraform/gcp-india/variables.tf`
- Create: `terraform/gcp-india/outputs.tf`
- Create: `terraform/gcp-india/modules/vpc/main.tf`
- Create: `terraform/gcp-india/modules/cloud-hsm/main.tf`
- Create: `terraform/gcp-india/modules/cloud-sql/main.tf`
- Create: `terraform/gcp-india/modules/compute/main.tf`
- Create: `terraform/gcp-india/modules/iam/main.tf`
- Create: `terraform/gcp-india/modules/kms/main.tf`
- Create: `terraform/gcp-india/modules/gcs/main.tf`

- [ ] **Step 1: Write all Terraform files**

All resources constrained to asia-south1/asia-south2 only. GCS buckets with location: IN. Org policy denying non-Indian IPs.

- [ ] **Step 2: Validate with terraform fmt and terraform validate**

- [ ] **Step 3: Commit**

---

## Task 23: AWS GovCloud Terraform

**Files:**
- Create: `terraform/aws-govcloud/main.tf`
- Create: `terraform/aws-govcloud/variables.tf`
- Create: `terraform/aws-govcloud/outputs.tf`
- Create: `terraform/aws-govcloud/modules/vpc/main.tf`
- Create: `terraform/aws-govcloud/modules/cloudhsm/main.tf`
- Create: `terraform/aws-govcloud/modules/rds/main.tf`
- Create: `terraform/aws-govcloud/modules/ec2/main.tf`
- Create: `terraform/aws-govcloud/modules/iam/main.tf`
- Create: `terraform/aws-govcloud/modules/kms/main.tf`
- Create: `terraform/aws-govcloud/modules/secretsmanager/main.tf`

- [ ] **Step 1: Write all Terraform files**

All resources in us-gov-west-1/us-gov-east-1. CloudHSM cluster. RDS with FIPS mode. FIPS endpoints only.

- [ ] **Step 2: Validate, commit**

---

## Task 24: Cloud HSM Init Script

**Files:**
- Create: `deploy/bare-metal/security/cloud-hsm-init.sh`
- Modify: `deploy/bare-metal/install.sh` (add --cloud-provider and --compliance-regime flags)

- [ ] **Step 1: Write cloud-hsm-init.sh**

Support GCP KMS, AWS CloudHSM, and Thales Luna PKCS#11.

- [ ] **Step 2: Update install.sh with new flags**

- [ ] **Step 3: Commit**

---

## Task 24b: Terraform Validation Tests

**Files:**
- Create: `e2e/tests/terraform_validation.rs` (or shell script tests)

- [ ] **Step 1: Write region validation tests**

- `test_terraform_gcp_india_plan()` — terraform validate for gcp-india
- `test_terraform_aws_govcloud_plan()` — terraform validate for aws-govcloud
- `test_data_residency_terraform_india()` — grep all .tf for region, verify only asia-south*
- `test_data_residency_terraform_govcloud()` — grep all .tf for region, verify only us-gov-*
- `test_install_script_gcp_flag()` — run install.sh --cloud-provider=gcp in dry-run, verify env
- `test_install_script_aws_flag()` — run install.sh --cloud-provider=aws in dry-run, verify env

- [ ] **Step 2: Run tests, commit**

---

## Task 25: CMMC Assessor (`common/src/cmmc.rs`)

**Files:**
- Create: `common/src/cmmc.rs`
- Modify: `common/src/lib.rs`

- [ ] **Step 1: Write tests**

- `test_cmmc_assessor_loads_all_practices()`
- `test_cmmc_score_calculation()`
- `test_cmmc_gaps_returns_only_unmet()`
- `test_cmmc_family_summary()`

- [ ] **Step 2: Implement CmmcAssessor with 110+ practices**

Map NIST 800-171 controls to system capabilities. Automated checks for AC, AU, IA, SC, SI families.

- [ ] **Step 3: Run tests, commit**

---

## Task 26: SIEM Webhook (`common/src/siem_webhook.rs`)

**Files:**
- Create: `common/src/siem_webhook.rs`
- Modify: `common/src/lib.rs`
- Modify: `common/src/siem.rs` (add webhook dispatch)

- [ ] **Step 1: Write tests**

- `test_siem_webhook_event_serialization()`
- `test_siem_webhook_batch_size()`
- `test_siem_webhook_config_from_env()`

- [ ] **Step 2: Implement SiemWebhook**

HTTP POST to configurable endpoint, batch mode, configurable flush interval. Auth via bearer token.

- [ ] **Step 3: Integrate with SecurityEvent::emit()**

If webhook configured, also send to external SIEM.

- [ ] **Step 4: Run tests, commit**

---

## Task 27: Admin API Endpoints for CAC, STIG, CMMC

**Files:**
- Modify: `admin/src/routes.rs`

- [ ] **Step 1: Add CAC routes**

POST /api/cac/enroll, POST /api/cac/authenticate, GET /api/cac/cards/:user_id, DELETE /api/cac/cards/:card_id, POST /api/cac/verify-cert, GET /api/cac/readers

- [ ] **Step 2: Add STIG/CMMC routes**

GET /api/stig/audit, GET /api/stig/failures, GET /api/cmmc/assess, GET /api/cmmc/gaps

- [ ] **Step 3: Add compliance route**

GET /api/compliance/status — returns current compliance regime and violations

- [ ] **Step 4: Run admin tests, commit**

---

## Task 28: Chaos Test Engine (`e2e/src/chaos.rs`)

**Files:**
- Create: `e2e/src/chaos.rs`
- Modify: `e2e/src/lib.rs` (add `pub mod chaos;`)
- Create: `e2e/tests/chaos_network.rs`
- Create: `e2e/tests/chaos_crypto.rs`
- Create: `e2e/tests/chaos_auth.rs`
- Create: `e2e/tests/chaos_byzantine.rs`
- Create: `e2e/tests/chaos_clock.rs`
- Create: `e2e/tests/chaos_resource.rs`
- Create: `e2e/tests/chaos_compliance.rs`
- Create: `e2e/tests/chaos_pq.rs`

- [ ] **Step 1: Create chaos engine framework**

`ChaosEngine`, `ChaosScenario` trait, `ChaosResult` struct.

- [ ] **Step 2: Implement network failure tests**

TSS quorum/below-quorum, BFT audit partition, latency injection, TCP RST mid-ceremony.

- [ ] **Step 3: Implement crypto failure tests**

Entropy exhaustion/bias, HSM unavailable/intermittent, TPM PCR mismatch, key rotation during sessions, FROST share corruption.

- [ ] **Step 4: Implement auth failure tests**

Brute force lockout, username enumeration timing, DPoP replay, CAC PIN lockout, receipt forgery/replay, token revocation, ratchet forward secrecy/clone detection, duress PIN.

- [ ] **Step 5: Implement Byzantine fault tests**

1/2/3 lying audit nodes, partition-then-rejoin.

- [ ] **Step 6: Implement clock skew tests**

Receipt ±30s tolerance, ceremony timeout, token expiry edges, SHARD ±2s tolerance.

- [ ] **Step 7: Implement resource exhaustion tests**

Memory pressure key protection, connection flood, rate limiting, audit capacity, revocation list capacity.

- [ ] **Step 8: Implement compliance tests**

Full FIPS ceremony, Indian compliance flow, DoD compliance flow, dual compliance.

- [ ] **Step 9: Implement PQ strength verification tests**

All sigs ML-DSA-87, all KEM ML-KEM-1024, no classical-only accepted, AEGIS-256 default, dpop 64-byte sentinel.

- [ ] **Step 10: Run all chaos tests**

Run: `RUST_MIN_STACK=8388608 cargo test -p e2e chaos -- --no-fail-fast`
Expected: all pass

- [ ] **Step 11: Commit**

```bash
git add e2e/
git commit -m "test: add 60+ chaos/failure injection tests for all security properties"
```

---

## Task 29: Final Integration Validation

- [ ] **Step 1: Run full workspace test**

Run: `RUST_MIN_STACK=8388608 cargo test --workspace --no-fail-fast`
Expected: all tests pass (~660 total: 558 existing + ~100 new)

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Run cargo fmt**

Run: `cargo fmt --all -- --check`
Expected: no formatting issues

- [ ] **Step 4: Run cargo deny**

Run: `cargo deny check`
Expected: no violations

- [ ] **Step 5: Final commit if needed**

---

## Execution Notes

- **SPEC WARNING:** The spec's "File Change Summary → Modified Files" section contains stale "XChaCha20" labels that should read "AEGIS-256". The spec body and this plan both use AEGIS-256 consistently. If you read the spec summary as a quick reference, ignore the "XChaCha20" labels — the correct algorithm is AEGIS-256 everywhere. Similarly, the spec's test name `test_symmetric_backward_compat_aes_to_xchacha()` maps to `test_legacy_aes256gcm_no_algo_byte()` in this plan. The spec's `kat_xchacha20_poly1305()` function name should be `kat_aegis256()`.
- **Stack size:** Always use `RUST_MIN_STACK=8388608` (8MB) for ML-DSA-87 operations
- **Developer mode:** Set `MILNET_DEV_MODE_KEY` for verbose error reporting during development
- **FIPS testing:** Toggle FIPS mode between tests to verify both paths
- **Test VM:** Use C2 spot VM in asia-south1-a for final validation
- **Commit frequency:** One commit per task (or per logical sub-task for large tasks)
- **No stubs:** Every function must have real implementation and real tests
