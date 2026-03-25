# MILNET SSO Dual-Compliance Hardening — Full Design Specification

**Date:** 2026-03-25
**Approach:** Layered Bottom-Up (6 layers, dependency-ordered)
**Target:** US DoD (DISA STIG, FIPS 140-3, CMMC 2.0, FedRAMP) + Indian Government (DPDP Act 2023, MeitY, CERT-In, CII)
**PQ Horizon:** 2031 (CNSA 2.0 exclusive PQ key establishment by 2030, exclusive PQ signatures by 2033)
**Crypto Policy:** Maximum security — strongest available algorithms at every layer. Future-proof: algorithm selection is a runtime enum, adding new algorithms never breaks existing data.
**Symmetric:** AEGIS-256 (RFC 9312) as default — 256-bit key, 256-bit nonce, 256-bit auth tag, nonce-misuse resistant. AES-256-GCM as FIPS fallback only (until AEGIS receives NIST approval, expected ~2027-2028 post-RFC 9312). All encrypted data carries an algorithm-ID byte so decryption auto-selects the right path — switching algorithms later is a config change, not a code change.
**Deployment:** GCP (asia-south1/asia-south2) + AWS GovCloud (us-gov-west-1/us-gov-east-1)
**Testing:** C2 spot VM (asia-south1-a), developer mode ON with cryptographic key, verbose errors

---

## Cryptographic Upgrade Policy

Every algorithm choice targets **maximum post-quantum security valid through 2031+**.
Algorithm selection is a runtime enum — adding future algorithms (e.g., NIST-approved AEGIS, new PQ schemes) requires only adding an enum variant and algorithm-ID byte. Existing encrypted data remains readable forever.

| Use Case | Current | Upgraded To | Rationale |
|----------|---------|-------------|-----------|
| Key Encapsulation | ML-KEM-1024 + X25519 (X-Wing) | **Same** — already CNSA 2.0 Level 5 | Maximum PQ security |
| Digital Signatures (audit, receipts, DPoP, tree heads) | ML-DSA-65 (Level 3) | **ML-DSA-87** (Level 5) everywhere | 2031 headroom, CNSA 2.0 |
| Threshold Signing | FROST Ristretto255 | **Same** — nested under ML-DSA-87 wrapper | Classical inside PQ envelope |
| Symmetric Encryption (default) | AES-256-GCM | **AEGIS-256** (RFC 9312) | 256-bit nonce + 256-bit tag + nonce-misuse resistant. Strongest modern AEAD. |
| Symmetric Encryption (FIPS fallback) | AES-256-GCM | **AES-256-GCM** (retained until AEGIS gets NIST approval) | FIPS 197/SP 800-38D mandated |
| Hashing | SHA-256 in some paths | **SHA-512 everywhere** (SHA-256 only where RFC-mandated: PKCE) | CNSA 2.0, 256-bit PQ security |
| KDF | HKDF-SHA512 | **Same** — already maximum | SP 800-56C |
| MAC | HMAC-SHA512 | **Same** — already maximum | FIPS 198-1 |
| Password Stretching (non-FIPS) | Argon2id | **Same** — best available | Memory-hard, GPU-resistant |
| Password Stretching (FIPS) | N/A | **PBKDF2-HMAC-SHA512** (210K iterations) | Only FIPS-approved KSF |
| Attestation (non-FIPS) | BLAKE3 | **BLAKE3** (retained for speed) | Authenticated by HMAC-SHA512 |
| Attestation (FIPS) | BLAKE3 | **SHA-512** | FIPS approved |
| Hash-Based Signatures | SLH-DSA-SHA2-256f | **Same** — FIPS 205 | Stateless post-quantum |
| Stateful Signatures | LMS H=20 | **Same** — SP 800-208 | Firmware signing |
| DPoP Key Hash | SHA-256 (32 bytes) | **SHA-512 (64 bytes)** | Full PQ security margin |
| Certificate Pinning | SHA-256 | **SHA-512** | Full PQ security margin |
| Envelope Encryption (default) | AES-256-GCM | **AEGIS-256** | 256-bit tag, nonce-misuse safe |
| Envelope Encryption (FIPS) | AES-256-GCM | **AES-256-GCM** | FIPS until AEGIS approved |
| SHARD IPC Encryption (default) | AES-256-GCM | **AEGIS-256** | 256-bit tag, nonce-misuse safe |
| SHARD IPC Encryption (FIPS) | AES-256-GCM | **AES-256-GCM** | FIPS until AEGIS approved |
| Backup Encryption | AES-256-GCM | **AEGIS-256** (default) / **AES-256-GCM** (FIPS) | Consistency |

**Why AEGIS-256 over AEGIS-256:**
- AEGIS-256 has a **256-bit auth tag** (vs 128-bit for Poly1305) — 2^128 times harder to forge
- AEGIS-256 has a **256-bit nonce** (vs 192-bit for XChaCha20) — even safer at scale
- AEGIS-256 is **nonce-misuse resistant** — accidental nonce reuse only leaks equality, not auth key
- AEGIS-256 is **faster** on all modern CPUs (uses AES-NI round functions, ~0.5 cycles/byte)
- AEGIS-256 has an RFC (9312, 2023) and is on NIST's review path

**Rule:** Every encryption call site checks `is_fips_mode()` and selects the appropriate algorithm. Non-FIPS defaults to AEGIS-256. FIPS forces AES-256-GCM. The algorithm-ID byte in the wire format means switching later is seamless — old data always decryptable.

**Future-proofing:** The `SymmetricAlgorithm` enum is extensible. When AEGIS gets NIST approval, the FIPS path switches to AEGIS by adding one variant. When post-quantum symmetric schemes emerge (e.g., Saturnin, Gaston), they slot in the same way. No existing data breaks because every ciphertext self-identifies its algorithm.

---

## Layer 0: FIPS Mode Toggle + PBKDF2 Path + PQ Maximization

### 0.1 New Module: `common/src/fips.rs`

Runtime FIPS mode with cryptographic activation (same pattern as developer mode).

```
Global state:
  FIPS_MODE: AtomicBool (default: false)
  FIPS_ACTIVATION_KEY: OnceLock<Option<[u8; 32]>>

Env vars:
  MILNET_FIPS_MODE=1          — enable at startup
  MILNET_FIPS_MODE_KEY=<hex>  — 32-byte activation key for runtime toggle

Functions:
  load_fips_activation_key()        — call once at startup, scrub env
  is_fips_mode() -> bool            — lock-free AtomicBool read
  set_fips_mode(enabled, proof_hex) — requires HMAC-SHA512 proof
  verify_fips_proof(proof, action)  — HMAC-SHA512(key, "MILNET-FIPS-MODE-v1" || action)
  generate_fips_proof(key, action)  — offline proof generation

Constraints:
  - Production mode (MILNET_PRODUCTION) FORCES fips_mode=true (cannot disable)
  - Developer mode can coexist with FIPS mode (for testing FIPS paths)
  - FIPS mode blocks: Argon2id, BLAKE3, AEGIS-256 (until NIST-approved), non-NIST curves
  - FIPS mode allows: AES-256-GCM (sole FIPS symmetric AEAD), SHA-2 family, SHA-3 family, HKDF-SHA512,
    HMAC-SHA512, ML-KEM-1024, ML-DSA-65/87, SLH-DSA, PBKDF2-HMAC-SHA512,
    FROST Ristretto255 (nested under ML-DSA-87 PQ wrapper)
```

### 0.2 New Module: `crypto/src/kdf.rs`

Dual key-stretching abstraction for OPAQUE password hashing.

```
trait KeyStretchingFunction: Send + Sync {
    fn stretch(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, String>;
    fn algorithm_id() -> &'static str;
    fn is_fips_approved() -> bool;
}

Argon2idKsf:
  - memory: 64 MiB, iterations: 3, parallelism: 4
  - output: 32 bytes
  - algorithm_id: "argon2id-v19"
  - is_fips_approved: false

Pbkdf2Sha512Ksf:
  - iterations: 210_000 (OWASP 2024 recommendation)
  - hash: HMAC-SHA512
  - output: 32 bytes
  - algorithm_id: "pbkdf2-sha512"
  - is_fips_approved: true

active_ksf() -> &'static str:
  returns "pbkdf2-sha512" if is_fips_mode(), else "argon2id-v19"
```

### 0.3 New Module: `crypto/src/symmetric.rs`

Unified symmetric encryption abstraction — extensible enum, algorithm-ID tagged wire format.

```
pub enum SymmetricAlgorithm {
    Aegis256,     // Default: 256-bit nonce, 256-bit tag, nonce-misuse resistant (RFC 9312)
    Aes256Gcm,    // FIPS fallback: 96-bit nonce, 128-bit tag (FIPS 197/SP 800-38D)
    // Future variants slot in here without breaking existing data:
    // Aegis256Fips,  // When NIST approves AEGIS — replaces Aes256Gcm as FIPS default
    // PostQuantumAead,  // When PQ symmetric AEADs emerge
}

pub fn active_algorithm() -> SymmetricAlgorithm;
  // Returns Aes256Gcm if is_fips_mode(), else Aegis256

pub fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
  // Dispatches to active algorithm. Nonce generated from CSPRNG.
  // Wire format: algorithm_id (1 byte) || nonce || ciphertext || tag
  // Self-describing: any future code can always decrypt by reading the algo byte

pub fn decrypt(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
  // Reads algorithm_id byte, dispatches to correct decryption
  // Supports ALL algorithms forever (decrypt old data with any past algorithm)
  // Legacy (no algo byte): attempts AES-256-GCM for pre-upgrade data

pub fn encrypt_with(algo: SymmetricAlgorithm, key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
  // Explicit algorithm selection (for tests and migration)

Constants:
  AEGIS256_NONCE_LEN: usize = 32     // 256 bits
  AEGIS256_TAG_LEN: usize = 32       // 256 bits (maximum authentication strength)
  AES_GCM_NONCE_LEN: usize = 12      // 96 bits
  AES_GCM_TAG_LEN: usize = 16        // 128 bits
  ALGO_ID_AEGIS256: u8 = 0x01
  ALGO_ID_AES256GCM: u8 = 0x02
  // 0x03-0xFF reserved for future algorithms
```

### 0.4 Changes to `opaque/src/opaque_impl.rs`

Add a second OPAQUE cipher suite for FIPS mode with concrete Pbkdf2Sha512 wrapper.

```
// Existing (non-FIPS):
pub struct OpaqueCs;
impl CipherSuite for OpaqueCs {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = argon2::Argon2<'static>;
}

// New (FIPS):
pub struct OpaqueCsFips;
impl CipherSuite for OpaqueCsFips {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Pbkdf2Sha512;
}

// Concrete Pbkdf2Sha512 wrapper implementing opaque_ke::Ksf trait:
pub struct Pbkdf2Sha512;

impl opaque_ke::Ksf for Pbkdf2Sha512 {
    // opaque_ke::Ksf trait requires:
    //   fn hash<L: ArrayLength<u8>>(
    //     &self,
    //     input: GenericArray<u8, L>,
    //   ) -> Result<Output<L>, InternalError>;
    //
    // Implementation:
    //   1. Use input bytes as password
    //   2. Salt: first 16 bytes of input (or zeros if input < 16)
    //   3. Call pbkdf2::pbkdf2_hmac::<Sha512>(input, salt, 210_000, &mut output)
    //   4. Return GenericArray of requested length L
    //
    // The 210_000 iteration count is per OWASP 2024 for PBKDF2-HMAC-SHA512.
    // pbkdf2 crate version: 0.12 (uses digest 0.10 compatible traits)
}
```

### 0.5 Changes to `opaque/src/store.rs`

Support dual cipher suites for transparent KSF migration.

```
UserRecord gains:
  pub ksf_algorithm: String,  // "argon2id-v19" or "pbkdf2-sha512"

CredentialStore gains:
  server_setup_fips: Option<ServerSetup<OpaqueCsFips>>,

New methods:
  new_dual() -> Self  — initializes both ServerSetup variants
  register_with_password_fips(username, password) -> Uuid
  verify_password_adaptive(username, password) -> Result<Uuid>
    — checks ksf_algorithm, uses correct cipher suite
    — on success with non-FIPS KSF in FIPS mode: triggers re-registration
  migrate_user_ksf(username, password) -> Result<()>
```

### 0.6 Changes to `crypto/src/attest.rs`

FIPS-aware file hashing.

```
hash_file() changes:
  if is_fips_mode() → SHA-512 truncated to 32 bytes
  else → BLAKE3 (faster, authenticated by HMAC-SHA512 in manifest)

AttestationManifest gains:
  pub hash_algorithm: String,  // "blake3" or "sha512-t256"
```

### 0.7 Changes to `crypto/src/seal.rs`

Switch to AEGIS-256 for key sealing (non-FIPS), AES-256-GCM for FIPS.

```
DerivedKek::seal() and unseal() now use crypto::symmetric::encrypt/decrypt
  — Automatically selects algorithm based on FIPS mode
  — Legacy migration: if first byte is NOT a recognized algorithm_id (0x01 or 0x02),
    treat the entire blob as legacy AES-256-GCM (no algorithm_id prefix).
    This handles pre-existing sealed data that has raw nonce||ciphertext||tag format.
    The first byte of a 12-byte AES-GCM nonce is random and statistically will not
    be 0x01 or 0x02 with >99% probability. For the rare collision case, a secondary
    check validates the total length: legacy = 12+N+16, new = 1+nonce+N+16.
```

### 0.8 Changes to `crypto/src/envelope.rs`

Same dual-algorithm switch for field-level encryption.

```
encrypt() and decrypt() now use crypto::symmetric::encrypt/decrypt
  — AEGIS-256 default, AES-256-GCM in FIPS mode
  — Legacy migration: same strategy as seal.rs — if first byte is not a
    recognized algorithm_id, attempt legacy AES-256-GCM decryption.
    This ensures all existing encrypted database fields remain readable.
```

### 0.9 Changes to `shard/src/protocol.rs`

SHARD IPC encryption upgraded.

```
ShardProtocol encrypt/decrypt uses crypto::symmetric module
  — AEGIS-256 for non-FIPS (192-bit nonce = no nonce exhaustion risk even at scale)
  — AES-256-GCM for FIPS
  — HMAC-SHA512 MAC unchanged (already maximum)
```

### 0.10 Changes to `common/src/backup.rs`

Backup encryption upgraded.

```
export_backup() / import_backup() use crypto::symmetric module
  — Magic bytes updated: MILBK002 (v2 format with algorithm ID)
  — Backward compatible: v1 (MILBK001) always AES-256-GCM, v2 reads algorithm byte
```

### 0.11 PQ Upgrades — ML-DSA-65 to ML-DSA-87 Everywhere

```
crypto/src/dpop.rs:
  DpopSigningKey = SigningKey<MlDsa87>     (was MlDsa65)
  DpopVerifyingKey = VerifyingKey<MlDsa87> (was MlDsa65)
  DpopSignature = Signature<MlDsa87>       (was MlDsa65)
  dpop_key_hash() returns [u8; 64]         (was [u8; 32] — now SHA-512)

crypto/src/receipts.rs:
  ReceiptSigningKey = SigningKey<MlDsa87>     (was MlDsa65)
  ReceiptVerifyingKey = VerifyingKey<MlDsa87> (was MlDsa65)
  ReceiptSignature = Signature<MlDsa87>       (was MlDsa65)

kt/src/merkle.rs:
  Tree head signing uses ML-DSA-87 keypair (was ML-DSA-65)

orchestrator/src/service.rs:
  Replace MlDsa65 with MlDsa87 in receipt verification key generation
  (currently calls ml_dsa::MlDsa65::from_seed() — must change to MlDsa87)

opaque/src/service.rs:
  Replace MlDsa65 with MlDsa87 in ReceiptSigner key generation
  (currently uses ml_dsa::{KeyGen, MlDsa65} — must change to MlDsa87)

dpop_hash size change [u8; 32] → [u8; 64] — ALL affected files:
  common/src/types.rs:
    TokenClaims.dpop_hash: [u8; 64]     (was [u8; 32])
    Receipt.dpop_key_hash: [u8; 64]     (was [u8; 32])
  gateway/src/wire.rs:
    OrchestratorRequest.dpop_key_hash: [u8; 64]  (was [u8; 32])
  orchestrator/src/messages.rs:
    OrchestratorRequest.dpop_key_hash: [u8; 64]  (was [u8; 32])
  opaque/src/messages.rs:
    OpaqueRequest::LoginStart.dpop_key_hash: [u8; 64]  (was [u8; 32])
  opaque/src/service.rs:
    dpop_key_hash parameter: [u8; 64]   (was [u8; 32])
  verifier/src/verify.rs:
    Zero-sentinel: [0u8; 64]            (was [0u8; 32])
    ct_eq_64() for DPoP comparison      (was ct_eq_32())
  verifier/src/main.rs:
    dpop_hash comparison: [0u8; 64]     (was [0u8; 32])
  All test files with hardcoded dpop_hash values updated to 64 bytes

All SHA-256 uses audited and upgraded to SHA-512 except:
  - PKCE code_challenge (SHA-256 required by RFC 7636) — keep
  - WebAuthn RP ID hash (SHA-256 required by WebAuthn spec) — keep
  Everything else → SHA-512
```

### 0.12 FIPS KAT Expansion

```
crypto/src/fips_kat.rs adds:
  kat_pbkdf2_sha512() — RFC 6070 test vector adapted for SHA-512
  kat_aegis256() — AEGIS-256 known test vector from RFC 9312 appendix (non-FIPS, validates implementation)

run_all_kats() adds both new tests
```

### 0.13 SecurityConfig Additions

```
common/src/config.rs SecurityConfig gains:
  pub fips_mode: bool,
  pub pq_minimum_level: u8,           // 5 = CNSA 2.0 Level 5
  pub require_pq_signatures: bool,     // reject classical-only sigs
  pub require_pq_key_exchange: bool,   // reject non-PQ KEM
  pub ksf_algorithm: String,           // "argon2id-v19" or "pbkdf2-sha512"
  pub symmetric_algorithm: String,     // "aegis256-poly1305" or "aes-256-gcm"

validate_production_config() gains:
  if !fips_mode → violation
  if pq_minimum_level < 5 → violation
  if !require_pq_signatures → violation
  if !require_pq_key_exchange → violation
```

### 0.14 Tests (Layer 0)

```
test_fips_mode_toggle_with_proof()
test_fips_mode_production_forced()
test_fips_mode_blocks_argon2id()
test_fips_mode_allows_pbkdf2()
test_fips_mode_blocks_aegis256()
test_fips_mode_allows_aes256gcm()
test_pbkdf2_kat_rfc6070()
test_pbkdf2_roundtrip()
test_aegis256_encrypt_decrypt_roundtrip()
test_aegis256_wrong_key_fails()
test_aegis256_tampered_ciphertext_fails()
test_aegis256_nonce_uniqueness()
test_symmetric_backward_compat_aes_to_xchacha()
  — encrypt with AES-256-GCM (old format), decrypt with new module → works
test_symmetric_algo_id_byte_correct()
  — verify wire format starts with correct algorithm ID
test_opaque_registration_fips()
test_opaque_migration_argon2id_to_pbkdf2()
test_attestation_fips_sha512()
test_attestation_non_fips_blake3()
test_dpop_mldsa87_upgrade()
test_receipt_mldsa87_upgrade()
test_dpop_key_hash_sha512_64bytes()
test_seal_aegis256_roundtrip()
test_seal_fips_aes256gcm_roundtrip()
test_shard_aegis256_encryption()
test_shard_fips_aes256gcm_encryption()
test_backup_v2_aegis256()
test_backup_v1_backward_compat()
test_pq_minimum_level_enforcement()
test_envelope_aegis256_roundtrip()
test_envelope_fips_fallback()
test_seal_legacy_aes256gcm_backward_compat()
  — seal with old format (no algo ID), unseal with new module → works
test_envelope_legacy_aes256gcm_backward_compat()
  — encrypt with old format, decrypt with new module → works
```

---

## Layer 1: CAC/PIV Smart Card Authentication (PKCS#11)

### 1.1 New Module: `crypto/src/cac.rs`

Full CAC/PIV integration with real PKCS#11 operations.

```
pub struct CacCardInfo {
    pub card_serial: String,
    pub card_issuer: String,
    pub subject_dn: String,
    pub edipi: Option<String>,          // DoD 10-digit ID
    pub aadhaar_vid: Option<String>,    // Indian Virtual ID
    pub affiliation: String,
    pub cert_fingerprint: [u8; 64],     // SHA-512 of PIV auth cert
    pub pin_verified: bool,
    pub card_type: CardType,
    pub clearance_level: u8,
    pub tags: HashMap<String, String>,
    pub inserted_at: i64,
    pub removed_at: Option<i64>,
    pub reader_id: String,
    pub facility_code: String,
}

pub enum CardType {
    CacMilitary, CacCivilian, Piv, PivI, DerivedPiv,
    IndianDsc, IndianESign,
}

pub struct Pkcs11Session { ... }
impl Pkcs11Session {
    pub fn open(library_path: &str, slot_id: u64) -> Result<Self, CacError>;
    pub fn login_user(pin: &[u8]) -> Result<(), CacError>;
    pub fn logout() -> Result<(), CacError>;
    pub fn find_certificate(label: &str) -> Result<Vec<u8>, CacError>;
    pub fn sign_data(key_label: &str, data: &[u8], mechanism: SignMechanism) -> Result<Vec<u8>, CacError>;
    pub fn verify_signature(cert_der: &[u8], data: &[u8], sig: &[u8]) -> Result<bool, CacError>;
    pub fn get_card_info() -> Result<CacCardInfo, CacError>;
    pub fn close(self);
}

pub enum SignMechanism { RsaPkcs, EcdsaP256, EcdsaP384 }
pub enum CacError { LibraryNotFound, SlotNotAvailable, LoginFailed, PinLocked, ... }
```

### 1.2 New Module: `common/src/cac_auth.rs`

CAC authentication flow with cert chain validation, OCSP/CRL revocation checking.

```
pub struct CacAuthenticator { ... }
impl CacAuthenticator {
    pub fn new(config: CacConfig) -> Result<Self, CacError>;
    pub fn authenticate(&self, pin: &[u8], challenge: &[u8; 32]) -> Result<(CacCardInfo, Vec<u8>), CacError>;
    pub fn verify_challenge_response(&self, cert_der: &[u8], challenge: &[u8; 32], signature: &[u8]) -> Result<bool, CacError>;
    pub fn extract_clearance(cert_der: &[u8]) -> u8;
    pub fn extract_indian_clearance(cert_der: &[u8]) -> u8;
    pub fn check_revocation(&self, cert_der: &[u8]) -> Result<RevocationStatus, CacError>;
}

Tier integration:
  Tier 1 (Sovereign): CAC/PIV REQUIRED + FIDO2 + OPAQUE
  Tier 2 (Operational): CAC/PIV or FIDO2 + OPAQUE
  Tier 3 (Sensor): CAC/PIV or OPAQUE
  Tier 4 (Emergency): CAC/PIV with duress detection
```

### 1.3 Admin API Endpoints

```
POST   /api/cac/enroll
POST   /api/cac/authenticate
GET    /api/cac/cards/:user_id
DELETE /api/cac/cards/:card_id
POST   /api/cac/verify-cert
GET    /api/cac/readers
```

### 1.4 SecurityConfig Additions

```
cac_enabled, cac_pkcs11_library, cac_pkcs11_slot, cac_required_tiers,
cac_trusted_ca_paths, cac_ocsp_url, cac_crl_urls, cac_policy_oids,
cac_pin_max_retries, cac_session_timeout_secs,
indian_dsc_enabled, indian_esign_enabled
```

### 1.5 Tests (Layer 1)

```
test_cac_card_info_extraction()
test_cac_challenge_response()
test_cac_cert_chain_validation()
test_cac_revoked_cert_rejected()
test_cac_pin_lockout()
test_cac_clearance_extraction_dod()
test_cac_clearance_extraction_indian()
test_cac_tier_enforcement()
test_cac_edipi_tagging()
test_cac_session_timeout()
test_cac_card_removal_detection()
test_indian_dsc_authentication()
test_cac_audit_logging()
```

---

## Layer 2: Data Residency and Compliance Engine

### 2.1 New Module: `common/src/compliance.rs`

Runtime compliance policy engine.

```
pub enum ComplianceRegime { UsDod, IndianGovt, Dual }

pub struct ComplianceConfig {
    pub regime: ComplianceRegime,
    pub data_residency_regions: Vec<String>,
    pub audit_retention_days: u64,         // 365 CERT-In, 2555 DoD
    pub require_data_classification: bool,
    pub max_classification_level: u8,
    pub pii_encryption_required: bool,     // DPDP Act
    pub cross_border_transfer_blocked: bool,
    pub cert_in_incident_reporting_hours: u64,  // 6 hours
    pub itar_controls_enabled: bool,
    pub meity_empanelled_cloud_only: bool,
}

pub struct ComplianceEngine { ... }
impl ComplianceEngine {
    pub fn new(config: ComplianceConfig) -> Self;
    pub fn check_data_residency(&self, target_region: &str) -> Result<(), ComplianceViolation>;
    pub fn check_pii_encryption(&self, is_encrypted: bool, field_name: &str) -> Result<(), ComplianceViolation>;
    pub fn check_audit_retention(&self, current_retention_days: u64) -> Result<(), ComplianceViolation>;
    pub fn check_classification_allowed(&self, level: u8) -> Result<(), ComplianceViolation>;
    pub fn check_cross_border(&self, source: &str, dest: &str) -> Result<(), ComplianceViolation>;
    pub fn check_incident_reporting_deadline(&self, incident_time: i64) -> Result<i64, ComplianceViolation>;
    pub fn validate_deployment(&self) -> Vec<ComplianceViolation>;
}
```

### 2.2 New Module: `common/src/data_residency.rs`

Region validation with India and GovCloud policies.

```
pub struct RegionPolicy { ... }
impl RegionPolicy {
    pub fn india_only() -> Self;
    pub fn us_govcloud_only() -> Self;
    pub fn dual_india_govcloud() -> Self;
    pub fn validate_storage(&self, region: &str) -> Result<(), String>;
    pub fn validate_replication(&self, source: &str, dest: &str) -> Result<(), String>;
    pub fn validate_backup(&self, location: &str) -> Result<(), String>;
}

const INDIA_REGIONS: &[&str] = &["asia-south1", "asia-south2"];
const GOVCLOUD_REGIONS: &[&str] = &["us-gov-west-1", "us-gov-east-1"];
```

### 2.3 Changes to `audit/src/log.rs`

Compliance-aware retention enforcement.

```
RetentionPolicy gains:
  pub compliance_regime: ComplianceRegime,
  pub cert_in_min_retention_days: u64,  // 365
  pub dod_min_retention_days: u64,      // 2555

enforce_retention() enforces minimum before any deletion.
```

### 2.4 Changes to `common/src/encrypted_db.rs`

PII field-level encryption enforcement for DPDP Act.

```
pub fn encrypt_pii_field(field_name: &str, value: &[u8], kek: &DerivedKek, compliance: &ComplianceEngine) -> Result<Vec<u8>, MilnetError>;
  — Checks compliance.check_pii_encryption() before proceeding
  — Uses crypto::symmetric::encrypt() (XChaCha20 or AES-256-GCM)
```

### 2.5 Tests (Layer 2)

```
test_compliance_india_data_residency()
test_compliance_india_audit_retention()
test_compliance_dod_audit_retention()
test_compliance_cross_border_blocked()
test_compliance_pii_encryption_enforced()
test_compliance_classification_ceiling()
test_compliance_cert_in_incident_deadline()
test_compliance_dual_mode()
test_compliance_startup_validation()
test_region_policy_india()
test_region_policy_govcloud()
```

---

## Layer 3: DISA STIG Hardening Functions

### 3.1 New Module: `common/src/stig.rs`

Programmatic STIG/CIS benchmark validation.

```
pub struct StigCheck { pub id, title, severity, category, status, detail, remediation }
pub enum StigSeverity { CatI, CatII, CatIII }
pub enum StigCategory { Kernel, Filesystem, Network, Authentication, Audit, Crypto, Process, Service }
pub enum StigStatus { Pass, Fail, NotApplicable, Manual }

pub struct StigAuditor { ... }
impl StigAuditor {
    pub fn new() -> Self;
    pub fn run_all(&mut self) -> &[StigCheck];
    pub fn failures(&self) -> Vec<&StigCheck>;
    pub fn cat_i_failures(&self) -> Vec<&StigCheck>;
    pub fn summary(&self) -> StigSummary;
    pub fn to_json(&self) -> String;
}

Checks implemented (40+):
  Kernel: ASLR, ptrace_scope, kptr_restrict, dmesg_restrict, perf_paranoid,
          unprivileged_bpf, modules_disabled, core_pattern, suid_dumpable, mmap_min_addr
  Network: ip_forward, rp_filter, accept_redirects, tcp_syncookies,
           accept_source_route, send_redirects
  Filesystem: /tmp noexec, /var/tmp noexec, sticky bits
  Authentication: password min length (15), complexity, lockout (3 attempts, 1800s)
  Crypto: kernel FIPS mode, SSH ciphers, SSH MACs, TLS min version
  Service: no unnecessary services, nftables active, time sync active
  Process: no unexpected SUID binaries
```

### 3.2 Integration

```
Startup: run_stig_audit() — Cat I failure blocks startup in production
Admin API: GET /api/stig/audit, GET /api/stig/failures
```

### 3.3 Tests (Layer 3)

```
test_stig_check_aslr_pass/fail()
test_stig_check_ptrace_scope()
test_stig_network_checks_all_pass()
test_stig_crypto_fips_kernel()
test_stig_summary_counts()
test_stig_cat_i_blocks_startup_production()
test_stig_cat_i_warns_dev_mode()
test_stig_json_output_format()
```

---

## Layer 4: GovCloud + India Dual-Deploy Terraform

### 4.1 `terraform/aws-govcloud/`

```
modules: vpc, cloudhsm, rds, ec2, iam, kms, secretsmanager
  — All resources in us-gov-west-1/us-gov-east-1 ONLY
  — CloudHSM cluster (FIPS 140-3 Level 3)
  — RDS PostgreSQL with FIPS mode + encryption at rest
  — EC2 instances for MILNET services
```

### 4.2 `terraform/gcp-india/`

```
modules: vpc, cloud-hsm, cloud-sql, compute, iam, kms, gcs
  — All resources in asia-south1/asia-south2 ONLY
  — Cloud HSM (FIPS 140-3 Level 3)
  — Cloud SQL with CMEK encryption
  — GCS buckets with location: IN
  — Org policy: deny non-IN IPs
```

### 4.3 Changes to `deploy/bare-metal/install.sh`

```
New flags: --cloud-provider=gcp|aws|onprem
           --compliance-regime=dod|india|dual
```

### 4.4 New: `deploy/bare-metal/security/cloud-hsm-init.sh`

HSM initialization per cloud provider (GCP KMS, AWS CloudHSM, Thales Luna).

### 4.5 Tests (Layer 4)

```
test_terraform_gcp_india_plan()
test_terraform_aws_govcloud_plan()
test_install_script_gcp_flag()
test_install_script_aws_flag()
test_data_residency_terraform_india()
test_data_residency_terraform_govcloud()
```

---

## Layer 5: CMMC 2.0 / NIST 800-171 Gap Closure

### 5.1 New Module: `common/src/cmmc.rs`

CMMC 2.0 Level 3 practice assessment engine (110+ practices).

```
pub struct CmmcPractice { pub id, family, title, level, status, evidence, gap }
pub enum PracticeStatus { Met, PartiallyMet, NotMet, NotApplicable }

pub struct CmmcAssessor { ... }
impl CmmcAssessor {
    pub fn new() -> Self;
    pub fn assess(&mut self) -> &[CmmcPractice];
    pub fn gaps(&self) -> Vec<&CmmcPractice>;
    pub fn score(&self) -> (usize, usize, usize);
}
```

### 5.2 Specific Gap Closures

```
Gap SC-8: Startup check verifying TLS actually in use (not just configured)
Gap AU-4: Auto-archive at 80% capacity, SIEM alert at 90%
Gap SI-4: New common/src/siem_webhook.rs — external SIEM webhook with batching
Gap IA-12: CAC/PIV provides certificate-based identity proofing
Gap SC-12(1): Key backup/restore via backup.rs with HSM-stored backup KEK
```

### 5.3 Tests (Layer 5)

```
test_cmmc_assessor_runs_all_practices()
test_cmmc_sc8_tls_enforcement()
test_cmmc_au4_capacity_auto_archive()
test_cmmc_si4_siem_webhook()
test_cmmc_ia12_identity_proofing()
test_cmmc_sc12_key_backup_roundtrip()
test_cmmc_family_summary()
```

---

## Layer 6: Hardened Test Suites (Chaos/Failure Injection)

### 6.1 New Module: `e2e/src/chaos.rs`

Real-world failure simulation engine.

### 6.2 Chaos Scenarios (~60 tests)

**Network Failure:**
- TSS quorum with 2/5 nodes partitioned → signing succeeds
- TSS below quorum (3/5 partitioned) → signing fails gracefully
- BFT audit with 3/7 partitioned → append succeeds (4 honest)
- BFT below quorum (4/7 partitioned) → appends fail safely
- 5-second latency injection → circuit breaker opens
- TCP RST mid-ceremony → clean failure, no state leak

**Cryptographic Failure:**
- Entropy exhaustion → retry, fallback, or fail-closed
- Entropy bias detection → SP 800-90B health test catches
- HSM unavailable → fail closed, no software fallback
- HSM intermittent → retry with backoff, no key leak
- TPM PCR mismatch → unseal fails, service refuses start
- Key rotation during active sessions → old sessions continue, new use new key
- FROST share corruption (1/5) → detected, 3 honest shares still sign
- FROST share corruption (3/5) → signing impossible

**Authentication Failure:**
- Password brute force (100 attempts) → lockout after 5
- Username enumeration timing → <5ms difference (statistical test)
- DPoP replay → detected via cache
- DPoP channel binding mismatch → rejected
- CAC PIN brute force → card locked after 3
- Receipt forgery → ML-DSA-87 verification fails
- Receipt replay → ceremony_session_id mismatch
- Token after revocation → O(1) rejection
- Ratchet forward secrecy → old keys irrecoverable
- Ratchet clone detection → nonce reuse caught
- Duress PIN → silent lockdown

**Byzantine Fault:**
- 1 lying audit node → detected, 6 honest maintain chain
- 2 colluding audit nodes → BFT consensus holds (5 quorum)
- 3 colluding nodes → exceeds f=2, alert emitted
- Partition then rejoin → chain consistent, no data loss

**Clock Skew:**
- Receipt timestamp ±30s tolerance
- Ceremony timeout on clock jump
- Token expiry edge cases
- SHARD timestamp ±2s tolerance

**Resource Exhaustion:**
- Memory pressure → mlocked keys NOT swapped
- Connection flood (1000) → puzzle difficulty scales to 24
- Rate limit per IP → 11th request blocked
- Audit log capacity → auto-archive at 80%

**Compliance:**
- Full FIPS ceremony end-to-end (PBKDF2, AES-256-GCM, ML-DSA-87)
- Full Indian compliance flow (data residency, PII encryption, 365-day retention)
- Full DoD compliance flow (CAC, FIPS, STIG, classification labels)
- Dual compliance (both regimes simultaneously)

**PQ Strength Verification:**
- All signatures ML-DSA-87 (not 65)
- All KEM ML-KEM-1024 (not 768)
- No classical-only signatures accepted when require_pq_signatures=true
- All symmetric: AEGIS-256 (non-FIPS) or AES-256-GCM (FIPS)
- DPoP zero-sentinel 64-byte check:
  - Token with dpop_hash [0u8; 64] → correctly treated as unbound
  - Token with 32-byte hash zero-padded to 64 → NOT incorrectly accepted as unbound
  - Verifier uses ct_eq_64() for constant-time comparison

### 6.3 Test Infrastructure

```
All tests on C2 spot VM:
  MILNET_DEV_MODE_KEY=<hex>  (activation key for developer mode)
  MILNET_FIPS_MODE=0         (test both paths)
  RUST_MIN_STACK=8388608
  RUST_LOG=debug
  cargo test --workspace --no-fail-fast
```

---

## File Change Summary

### New Files (19):
1. `common/src/fips.rs`
2. `crypto/src/kdf.rs`
3. `crypto/src/symmetric.rs`
4. `crypto/src/cac.rs`
5. `common/src/cac_auth.rs`
6. `common/src/compliance.rs`
7. `common/src/data_residency.rs`
8. `common/src/stig.rs`
9. `common/src/cmmc.rs`
10. `common/src/siem_webhook.rs`
11. `e2e/src/chaos.rs`
12-18. `terraform/aws-govcloud/` (main.tf + 7 modules)
19-25. `terraform/gcp-india/` (main.tf + 7 modules)
26. `deploy/bare-metal/security/cloud-hsm-init.sh`

### Modified Files (28):
1. `common/src/lib.rs` — new module declarations
2. `common/src/config.rs` — FIPS, PQ, CAC, compliance, symmetric algo fields
3. `common/src/startup_checks.rs` — STIG audit, FIPS enforcement
4. `common/src/encrypted_db.rs` — PII encryption enforcement
5. `common/src/siem.rs` — new event types
6. `common/src/types.rs` — dpop_hash to [u8; 64], Receipt.dpop_key_hash to [u8; 64]
7. `common/src/backup.rs` — XChaCha20 + v2 format
8. `crypto/src/lib.rs` — add kdf, symmetric, cac modules
9. `crypto/src/fips_kat.rs` — PBKDF2 + XChaCha20 KATs
10. `crypto/src/attest.rs` — FIPS-aware hashing
11. `crypto/src/dpop.rs` — ML-DSA-65→87, dpop_key_hash() returns [u8; 64]
12. `crypto/src/receipts.rs` — ML-DSA-65→87
13. `crypto/src/seal.rs` — XChaCha20 default + legacy AES-256-GCM migration
14. `crypto/src/envelope.rs` — same dual-algorithm switch + legacy migration
15. `shard/src/protocol.rs` — XChaCha20 for non-FIPS
16. `opaque/src/opaque_impl.rs` — add OpaqueCsFips + Pbkdf2Sha512 wrapper
17. `opaque/src/store.rs` — dual cipher suite, KSF migration
18. `opaque/src/service.rs` — FIPS-aware routing, MlDsa65→MlDsa87
19. `opaque/src/messages.rs` — dpop_key_hash to [u8; 64]
20. `orchestrator/src/service.rs` — MlDsa65→MlDsa87 for receipt verification
21. `orchestrator/src/messages.rs` — dpop_key_hash to [u8; 64]
22. `gateway/src/wire.rs` — dpop_key_hash to [u8; 64]
23. `gateway/src/server.rs` — SHA-512 for dpop key hash computation
24. `verifier/src/verify.rs` — dpop_hash [0u8; 64] sentinel, ct_eq_64()
25. `verifier/src/main.rs` — dpop_hash comparison to [0u8; 64]
26. `admin/src/routes.rs` — CAC, STIG, CMMC endpoints
27. `audit/src/log.rs` — compliance-aware retention
28. `kt/src/merkle.rs` — ML-DSA-87 for tree heads

### Dependencies to Add (Cargo.toml):
- `aegis = "0.6"` — AEGIS-256 AEAD with hardware AES-NI acceleration (RFC 9312)
- `pbkdf2 = "0.12"` — new crate for FIPS KSF (pure Rust, HMAC-SHA512)
- `cryptoki = "0.10"` — PKCS#11 safe Rust bindings for CAC/PIV (NOT the older `pkcs11` crate)

### ~100 new test functions across all layers
