# Advanced Cryptographic Hardening — Addendum Specification

**Date:** 2026-03-25
**Extends:** `2026-03-25-dual-compliance-hardening-design.md`
**Scope:** SSE, ZKP, Adaptive Crypto, Honey Encryption, Proactive Share Refresh, PQ Blockchain

---

## 1. Searchable Symmetric Encryption (SSE) — Zero-Trust Database

**Problem:** Current design decrypts PII for username lookups. The DB sees plaintext during queries — violates zero-trust.

**Solution:** Blind Index Pattern. The DB never sees plaintext. Ever.

### Architecture:
```
WRITE PATH:
  plaintext_username → HMAC-SHA512(blind_key, username) → blind_index (first 32 bytes)
  plaintext_username → symmetric::encrypt(enc_key, username) → encrypted_username
  Store: (blind_index, encrypted_username) in DB

READ PATH:
  search_username → HMAC-SHA512(blind_key, search_username) → blind_index
  SELECT encrypted_username WHERE blind_index = $1
  symmetric::decrypt(enc_key, encrypted_username) → plaintext
```

### New Module: `common/src/sse.rs`

```rust
pub struct BlindIndex {
    blind_key: [u8; 64],  // HMAC-SHA512 key (separate from encryption key)
}

impl BlindIndex {
    pub fn new(blind_key: [u8; 64]) -> Self;
    pub fn derive_from_master(master: &[u8; 32], purpose: &str) -> Self;
    pub fn compute(&self, plaintext: &[u8]) -> [u8; 32];  // HMAC-SHA512 truncated to 32
    pub fn compute_full(&self, plaintext: &[u8]) -> [u8; 64];  // Full HMAC-SHA512
}

pub struct EncryptedField {
    pub blind_index: [u8; 32],
    pub ciphertext: Vec<u8>,  // symmetric::encrypt output
}

pub fn encrypt_searchable(
    blind_key: &BlindIndex,
    enc_key: &[u8; 32],
    plaintext: &[u8],
    field_name: &str,
) -> Result<EncryptedField, String>;

pub fn search_index(
    blind_key: &BlindIndex,
    search_term: &[u8],
) -> [u8; 32];

pub fn decrypt_field(
    enc_key: &[u8; 32],
    ciphertext: &[u8],
    field_name: &str,
) -> Result<Vec<u8>, String>;
```

### Applied to: usernames, emails, EDIPI, Aadhaar VID, IP addresses in audit logs.

---

## 2. Zero-Knowledge Proofs

### New Module: `crypto/src/zkp.rs`

Using `bulletproofs` crate (Ristretto255-based range proofs).

### 2.1 Classification Range Proof

Prove "my clearance level >= required_level" without revealing exact level.

```rust
pub struct ClassificationProof {
    pub proof: Vec<u8>,          // Bulletproof bytes
    pub commitment: Vec<u8>,     // Pedersen commitment to the value
}

pub fn prove_classification_range(
    clearance_level: u8,         // Secret: actual level (0-5)
    min_required: u8,            // Public: minimum required
    blinding: &[u8; 32],        // Random blinding factor
) -> Result<ClassificationProof, String>;

pub fn verify_classification_range(
    proof: &ClassificationProof,
    min_required: u8,
) -> bool;
```

### 2.2 Compliance Attestation Proof

Prove "system passes N of M compliance checks" without revealing which ones failed.

```rust
pub struct ComplianceAttestation {
    pub proof: Vec<u8>,
    pub total_checks: u32,
    pub threshold: u32,          // Public: minimum passing
    pub commitment: Vec<u8>,     // Commitment to actual pass count
}

pub fn prove_compliance_threshold(
    passed_count: u32,           // Secret: actual passes
    total: u32,                  // Public: total checks
    threshold: u32,              // Public: minimum required
    blinding: &[u8; 32],
) -> Result<ComplianceAttestation, String>;

pub fn verify_compliance_threshold(
    attestation: &ComplianceAttestation,
) -> bool;
```

### 2.3 Audit Integrity Proof

Prove "audit chain of length N is intact" without revealing contents.

```rust
pub struct AuditIntegrityProof {
    pub proof: Vec<u8>,
    pub chain_length: u64,
    pub root_hash_commitment: Vec<u8>,
}

pub fn prove_audit_integrity(
    chain_root: &[u8; 64],      // Secret: actual root hash
    chain_length: u64,
    blinding: &[u8; 32],
) -> Result<AuditIntegrityProof, String>;

pub fn verify_audit_integrity(
    proof: &AuditIntegrityProof,
    expected_length: u64,
) -> bool;
```

---

## 3. Adaptive Cryptographic Framework

### New Module: `crypto/src/adaptive.rs`

Risk-engine-driven automatic crypto escalation. No human intervention.

### Threat Levels (mapped from RiskLevel):
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CryptoThreatLevel {
    Normal,    // RiskLevel::Normal (score < 0.3)
    Elevated,  // RiskLevel::Elevated (0.3-0.6)
    High,      // RiskLevel::High (0.6-0.8)
    Critical,  // RiskLevel::Critical (>= 0.8)
}
```

### Escalation Matrix:
```
Normal:
  - Symmetric: AEGIS-256 (single layer)
  - Signing: ML-DSA-87
  - KEM: X-Wing (ML-KEM-1024 + X25519)
  - Ratchet: 10-second epochs

Elevated:
  - Symmetric: AEGIS-256 + HMAC-SHA512 verify tag (double authentication)
  - Signing: ML-DSA-87 + SLH-DSA dual-sign (hedge against single-algo break)
  - KEM: X-Wing with fresh ephemeral per message
  - Ratchet: 5-second epochs (faster forward secrecy)
  - SIEM: real-time event streaming (no batching)

High:
  - Symmetric: Triple-layer hedged encryption:
      AEGIS-256(ChaCha20-Poly1305(AES-256-GCM(plaintext)))
    If ANY layer is broken, the other two protect the data.
  - Signing: ML-DSA-87 + SLH-DSA + FROST (triple redundant)
  - KEM: Double encapsulation (X-Wing + standalone ML-KEM-1024)
  - Ratchet: 1-second epochs
  - Sessions: force re-authentication every 60 seconds

Critical:
  - All of High +
  - Per-message re-keying (fresh KEM per encrypted message)
  - Honey encryption for all responses (attacker can't tell real from fake)
  - TSS threshold raised: 4-of-5 (was 3-of-5)
  - Automatic session termination for all non-Sovereign users
  - SIEM: immediate webhook flush
  - All new sessions require CAC/PIV + FIDO2 + OPAQUE (triple factor)
```

### Implementation:
```rust
pub struct AdaptiveCrypto {
    current_level: AtomicU8,
    escalation_history: Mutex<Vec<(i64, CryptoThreatLevel)>>,
}

impl AdaptiveCrypto {
    pub fn new() -> Self;
    pub fn current_level(&self) -> CryptoThreatLevel;
    pub fn escalate(&self, new_level: CryptoThreatLevel);
    pub fn deescalate(&self);  // Only after sustained low-risk period (15 min)

    /// Encrypt with current threat level.
    pub fn encrypt_adaptive(
        &self, key: &[u8; 32], plaintext: &[u8], aad: &[u8]
    ) -> Result<Vec<u8>, String>;

    /// Decrypt — reads threat level tag from ciphertext, uses correct layers.
    pub fn decrypt_adaptive(
        &self, key: &[u8; 32], sealed: &[u8], aad: &[u8]
    ) -> Result<Vec<u8>, String>;

    /// Sign with current threat level (single, dual, or triple signature).
    pub fn sign_adaptive(
        &self, signing_keys: &AdaptiveSigningKeys, message: &[u8]
    ) -> Result<AdaptiveSignature, String>;

    pub fn verify_adaptive(
        &self, verifying_keys: &AdaptiveVerifyingKeys,
        message: &[u8], signature: &AdaptiveSignature
    ) -> bool;
}

// Wire format: threat_level (1 byte) || layer_count (1 byte) || layers...
// Each layer: algo_id (1 byte) || nonce || ciphertext || tag
// Decryption peels layers in reverse order.
```

### Integration with Risk Engine:
```rust
// In orchestrator/src/service.rs, after computing risk score:
let threat_level = CryptoThreatLevel::from_risk_score(risk_score);
adaptive_crypto.escalate(threat_level);
```

---

## 4. Honey Encryption

### New Module: `crypto/src/honey.rs`

Wrong key produces plausible-looking fake data. Attacker can't distinguish real from fake.

```rust
pub struct HoneyEncrypted {
    pub ciphertext: Vec<u8>,
    pub distribution_seed: [u8; 32],  // Seed for the plausible distribution
}

/// Honey-encrypt: real key → real plaintext, wrong key → plausible fake.
pub fn honey_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    distribution: &PlausibleDistribution,
) -> Result<HoneyEncrypted, String>;

/// Honey-decrypt: always succeeds, always returns something plausible.
/// Only with the CORRECT key do you get the REAL plaintext.
pub fn honey_decrypt(
    key: &[u8; 32],
    honey: &HoneyEncrypted,
    distribution: &PlausibleDistribution,
) -> Vec<u8>;

/// Plausible data distributions for different field types.
pub enum PlausibleDistribution {
    Username,      // Generates plausible usernames (john.doe, jane.smith, etc.)
    Email,         // Generates plausible emails
    MilitaryId,    // Generates plausible EDIPI (10-digit)
    IpAddress,     // Generates plausible IPs
    TokenPayload,  // Generates plausible JWT-like structures
}

impl PlausibleDistribution {
    /// Generate a plausible value from a seed.
    pub fn generate(&self, seed: &[u8; 32]) -> Vec<u8>;
}
```

### How it works:
1. Map plaintext to a point in the distribution's domain (DTE — Distribution-Transforming Encoder)
2. Encrypt the mapped point with the real key
3. On decryption with wrong key, the random-looking output maps back to a DIFFERENT plausible point
4. Attacker sees a valid-looking username, can't tell it's fake

---

## 5. Proactive FROST Share Refresh

### Changes to `crypto/src/threshold.rs`

Using `frost_core::keys::refresh` (available in frost-ristretto255 2.2+).

```rust
pub struct ShareRefreshResult {
    pub new_shares: Vec<SignerShare>,
    pub refresh_epoch: u64,
    pub old_shares_invalidated: bool,
}

impl ThresholdGroup {
    /// Refresh all shares without changing the group public key.
    /// Old shares become useless after refresh.
    pub fn refresh_shares(&self, current_shares: &[SignerShare]) -> Result<ShareRefreshResult, String>;

    /// Schedule automatic refresh every `interval_secs`.
    pub fn start_refresh_schedule(
        &self,
        current_shares: Vec<SignerShare>,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()>;
}

// Default refresh interval: 24 hours
// After refresh, old share #3 (even if stolen yesterday) can't sign
```

---

## 6. Post-Quantum Blockchain (Audit Chain)

### Changes to `audit/src/log.rs` and new `audit/src/blockchain.rs`

The audit chain is already a hash chain with BFT consensus. Upgrade to explicit PQ blockchain:

```rust
pub struct PqBlock {
    pub block_number: u64,
    pub prev_block_hash: [u8; 64],   // SHA-512 of previous block
    pub merkle_root: [u8; 64],       // SHA-512 Merkle root of entries in this block
    pub timestamp: i64,
    pub entries: Vec<AuditEntry>,     // Transactions in this block
    pub proposer_id: usize,          // BFT node that proposed this block
    pub pq_signature: Vec<u8>,       // ML-DSA-87 signature over block header
    pub bft_attestations: Vec<BftAttestation>, // Quorum attestations (5-of-7)
    pub state_root: [u8; 64],        // SHA-512 hash of cumulative state (running hash of all blocks)
}

pub struct BftAttestation {
    pub node_id: usize,
    pub block_hash: [u8; 64],
    pub pq_signature: Vec<u8>,       // ML-DSA-87 from this node
    pub timestamp: i64,
}

pub struct PqBlockchain {
    blocks: Vec<PqBlock>,
    pending_entries: Vec<AuditEntry>,
    signing_key: PqSigningKey,       // ML-DSA-87
    verifying_keys: Vec<PqVerifyingKey>, // Per-node verifying keys
    block_interval_secs: u64,        // Default: 10 seconds
    max_entries_per_block: usize,    // Default: 100
}

impl PqBlockchain {
    pub fn new(signing_key: PqSigningKey, verifying_keys: Vec<PqVerifyingKey>) -> Self;

    /// Add an audit entry to pending pool.
    pub fn submit_entry(&mut self, entry: AuditEntry);

    /// Propose a new block from pending entries.
    pub fn propose_block(&mut self) -> Result<PqBlock, String>;

    /// Verify a proposed block (called by BFT attestors).
    pub fn verify_block(&self, block: &PqBlock) -> bool;

    /// Attest to a block (sign with this node's ML-DSA-87 key).
    pub fn attest_block(&self, block: &PqBlock) -> BftAttestation;

    /// Finalize a block after receiving quorum attestations.
    pub fn finalize_block(&mut self, block: PqBlock, attestations: Vec<BftAttestation>) -> Result<(), String>;

    /// Verify the entire chain from genesis.
    pub fn verify_chain(&self) -> bool;

    /// Get block by number.
    pub fn get_block(&self, number: u64) -> Option<&PqBlock>;

    /// Get chain height.
    pub fn height(&self) -> u64;

    /// Get chain state root (cumulative hash).
    pub fn state_root(&self) -> [u8; 64];

    /// Compute Merkle root of entries in a block.
    pub fn compute_merkle_root(entries: &[AuditEntry]) -> [u8; 64];
}
```

### Properties:
- **Post-Quantum:** All block signatures and attestations use ML-DSA-87
- **BFT Finality:** Block finalized only with 5-of-7 attestations (Byzantine fault tolerance)
- **Merkle Root:** Each block has a Merkle root over its entries (efficient inclusion proofs)
- **State Root:** Running cumulative hash — allows light clients to verify chain state
- **Immutable:** Finalized blocks cannot be modified (PQ signatures + hash chain)
- **Tamper-Evident:** Any modification breaks the hash chain AND invalidates PQ signatures

---

## New Dependencies

```toml
bulletproofs = "5.0"   # Range proofs (Ristretto255-based)
```

## File Summary

### New Files:
1. `common/src/sse.rs` — Searchable Symmetric Encryption (blind index)
2. `crypto/src/zkp.rs` — Zero-Knowledge Proofs (classification, compliance, audit)
3. `crypto/src/adaptive.rs` — Adaptive crypto framework
4. `crypto/src/honey.rs` — Honey encryption
5. `audit/src/blockchain.rs` — Post-Quantum Blockchain

### Modified Files:
1. `crypto/src/threshold.rs` — Proactive share refresh
2. `crypto/src/lib.rs` — New module declarations
3. `common/src/lib.rs` — SSE module
4. `audit/src/lib.rs` — Blockchain module
5. `Cargo.toml` — bulletproofs dep
