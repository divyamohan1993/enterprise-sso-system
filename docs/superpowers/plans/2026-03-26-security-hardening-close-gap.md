# MILNET SSO Security Hardening — Close the 28% Gap

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all code-level weaknesses from the security assessment scorecard, closing the 28-point gap to achieve world-class SSO security. Skip external/bureaucratic items (FIPS validation, FedRAMP, red team). Distribute all services, encrypt everything, eliminate single points of failure.

**Architecture:** Every token claim is encrypted (JWE-style envelope encryption). Audit metadata is encrypted at rest with searchable blind indexes. OPAQUE becomes threshold (2-of-3). X-Wing pinning is mandatory. Database gets HA with streaming replication. HSM becomes default key source. All production panics replaced with fail-closed error handling. Full test coverage for admin API, FIDO2, and gateway.

**Tech Stack:** Rust, AES-256-GCM/AEGIS-256 envelope encryption, FROST threshold signing, ML-KEM-1024, ML-DSA-65, PostgreSQL streaming replication, PKCS#11 HSM

---

## File Structure

### New Files
- `crypto/src/jwe.rs` — Token payload encryption (JWE-style envelope)
- `common/src/encrypted_audit.rs` — Encrypted audit entry wrapper with blind indexes
- `common/src/db_ha.rs` — Database HA: connection routing, health checks, failover
- `common/src/backup.rs` (extend) — Tested backup/restore procedures
- `opaque/src/threshold.rs` — Threshold OPAQUE 2-of-3 implementation
- `admin/tests/admin_routes_test.rs` — Admin API test suite
- `fido/tests/fido_test.rs` — FIDO2 registration/authentication tests
- `gateway/tests/gateway_unit_test.rs` — Gateway unit tests
- `common/src/distributed_session.rs` — Distributed session store
- `e2e/tests/hardening_validation_test.rs` — Validates all hardening measures

### Modified Files
- `common/src/types.rs` — Add `EncryptedToken` wrapper, encrypted claims
- `tss/src/token_builder.rs` — Encrypt claims before signing
- `verifier/src/verify.rs` — Decrypt claims during verification
- `audit/src/log.rs` — Encrypt metadata fields
- `crypto/src/xwing.rs` — Make fingerprint pinning mandatory
- `crypto/src/hsm.rs` — Make HSM default, software fallback requires explicit opt-in
- `opaque/src/opaque_impl.rs` — Add threshold wrapper
- `ratchet/src/chain.rs` — Replace panics with Results
- `common/src/sealed_keys.rs` — Replace panics with Results
- `Cargo.toml` — Add new dependencies if needed

---

## Phase 1: Token Encryption (JWE)

### Task 1: Create JWE Envelope Encryption Module

**Files:**
- Create: `crypto/src/jwe.rs`
- Modify: `crypto/src/lib.rs`

- [ ] **Step 1: Create `crypto/src/jwe.rs` with token encryption**

```rust
// JWE-style token payload encryption using AES-256-GCM envelope encryption.
// Token claims are encrypted before being included in the token structure,
// ensuring claims are never transmitted or stored in plaintext.
```

Implement:
- `encrypt_claims(claims: &TokenClaims, dek: &[u8; 32]) -> EncryptedClaims`
- `decrypt_claims(encrypted: &EncryptedClaims, dek: &[u8; 32]) -> Result<TokenClaims, MilnetError>`
- `EncryptedClaims` struct: `nonce: [u8; 12], ciphertext: Vec<u8>, tag: [u8; 16]`
- AAD: `MILNET-JWE-CLAIMS-v1`

- [ ] **Step 2: Add `pub mod jwe;` to `crypto/src/lib.rs`**

- [ ] **Step 3: Unit tests for JWE round-trip, wrong-key rejection, tamper detection**

### Task 2: Add EncryptedToken Type

**Files:**
- Modify: `common/src/types.rs`

- [ ] **Step 1: Add EncryptedToken struct**

```rust
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedToken {
    pub header: TokenHeader,
    pub encrypted_claims: Vec<u8>,  // JWE-encrypted claims
    pub claims_nonce: [u8; 12],     // JWE nonce
    pub ratchet_tag: [u8; 64],
    pub frost_signature: [u8; 64],
    pub pq_signature: Vec<u8>,
}
```

### Task 3: Integrate JWE into Token Builder

**Files:**
- Modify: `tss/src/token_builder.rs`

- [ ] **Step 1: Encrypt claims in `build_token_distributed`**

After signing, encrypt the claims before embedding them in the final token. The signature is over the plaintext claims (for verifier-side verification after decryption).

### Task 4: Integrate JWE into Token Verifier

**Files:**
- Modify: `verifier/src/verify.rs`

- [ ] **Step 1: Add claims decryption to `verify_token_inner`**

Decrypt claims first, then proceed with existing verification logic. The claims DEK is distributed via SHARD to authorized verifiers only.

---

## Phase 2: Audit Metadata Encryption

### Task 5: Create Encrypted Audit Entry Module

**Files:**
- Create: `common/src/encrypted_audit.rs`
- Modify: `common/src/lib.rs`

- [ ] **Step 1: Create encrypted audit entry wrapper**

Encrypt: `user_ids`, `device_ids`, `event_type`, `risk_score`, `ceremony_receipts`
Keep plaintext: `event_id`, `timestamp`, `prev_hash`, `signature`, `classification` (needed for chain verification and MAC)

Add blind index for searchable encrypted fields using HMAC-SHA256:
- `user_id_blind_index: Vec<[u8; 32]>` — HMAC(key, user_id) for searching by user
- `event_type_blind_index: [u8; 32]` — HMAC(key, event_type) for filtering

### Task 6: Integrate Encrypted Audit into AuditLog

**Files:**
- Modify: `audit/src/log.rs`

- [ ] **Step 1: Add encryption key parameter to `append()` and `append_signed()`**
- [ ] **Step 2: Encrypt metadata fields before storing, decrypt on read**
- [ ] **Step 3: Add search-by-blind-index methods**

---

## Phase 3: X-Wing Pinning Mandatory + SHARD Hardening

### Task 7: Make X-Wing Key Fingerprint Pinning Mandatory

**Files:**
- Modify: `crypto/src/xwing.rs`

- [ ] **Step 1: Add key fingerprint to XWingPublicKey**

```rust
impl XWingPublicKey {
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(b"MILNET-XWING-FP-v1");
        h.update(&self.to_bytes());
        h.finalize().into()
    }
}
```

- [ ] **Step 2: Add mandatory pinning to encapsulate/decapsulate**

`xwing_encapsulate` and `xwing_decapsulate` must accept an `expected_fingerprint: &[u8; 32]` parameter. Reject if fingerprint doesn't match (MITM protection).

### Task 8: Enforce SHARD Encryption on All Channels

**Files:**
- Modify: `shard/src/protocol.rs`

- [ ] **Step 1: Verify all SHARD messages use authenticated encryption**
- [ ] **Step 2: Reject plaintext SHARD messages (no fallback)**

---

## Phase 4: Production Panic Elimination

### Task 9: Replace Panics in Ratchet Chain

**Files:**
- Modify: `ratchet/src/chain.rs`

- [ ] **Step 1: Convert 8 panics to `Result<_, MilnetError>`**

Replace `panic!("ratchet: client_entropy must not be all-zero")` etc. with `return Err(MilnetError::CryptoVerification(...))`. Update all callers.

### Task 10: Replace Panics in Sealed Keys

**Files:**
- Modify: `common/src/sealed_keys.rs`

- [ ] **Step 1: Convert startup panics to `Result` types**

The sealed_keys panics are fail-fast startup checks. Convert to `Result` but maintain fail-closed: callers must propagate errors and refuse to start.

### Task 11: Replace Panics in Main Binaries

**Files:**
- Modify: `ratchet/src/main.rs`, `tss/src/main.rs`, `admin/src/main.rs`

- [ ] **Step 1: Convert `panic!` in main functions to proper error logging + `process::exit(1)`**

### Task 12: Set `panic = "abort"` in Release Profile

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add release profile settings**

```toml
[profile.release]
panic = "abort"
lto = true
codegen-units = 1
```

---

## Phase 5: Threshold OPAQUE (2-of-3)

### Task 13: Implement Threshold OPAQUE

**Files:**
- Create: `opaque/src/threshold.rs`
- Modify: `opaque/src/lib.rs`

- [ ] **Step 1: Create threshold OPAQUE wrapper**

Implement 2-of-3 threshold OPAQUE using secret sharing of the OPRF seed:
- Split OPRF seed into 3 Shamir shares (threshold=2)
- Each OPAQUE server holds one share
- Registration/login requires 2-of-3 servers to reconstruct the OPRF evaluation
- No single server compromise reveals passwords

```rust
pub struct ThresholdOpaqueServer {
    server_id: u8,
    oprf_share: [u8; 32],
    threshold: u8,
    total_servers: u8,
}

pub struct ThresholdOpaqueCoordinator {
    threshold: u8,
    total_servers: u8,
}
```

- [ ] **Step 2: Implement distributed registration**
- [ ] **Step 3: Implement distributed login**
- [ ] **Step 4: Tests for threshold OPAQUE (2-of-3 succeeds, 1-of-3 fails)**

---

## Phase 6: Database HA & Distribution

### Task 14: Database Connection Routing and Health

**Files:**
- Create: `common/src/db_ha.rs`
- Modify: `common/src/lib.rs`

- [ ] **Step 1: Create HA pool with primary/replica routing**

```rust
pub struct HaPool {
    primary: PgPool,
    replicas: Vec<PgPool>,
    health_check_interval: Duration,
}

impl HaPool {
    pub fn write_pool(&self) -> &PgPool { &self.primary }
    pub fn read_pool(&self) -> &PgPool { /* round-robin replicas */ }
    pub async fn health_check(&self) -> HealthStatus { ... }
    pub async fn failover(&mut self) -> Result<(), MilnetError> { ... }
}
```

- [ ] **Step 2: Add backup/restore functions with verification**

```rust
pub async fn create_backup(pool: &PgPool, path: &str) -> Result<BackupManifest, MilnetError>
pub async fn verify_backup(manifest: &BackupManifest) -> Result<bool, MilnetError>
pub async fn restore_backup(manifest: &BackupManifest, target: &PgPool) -> Result<(), MilnetError>
```

### Task 15: Distributed Session Persistence

**Files:**
- Create: `common/src/distributed_session.rs`

- [ ] **Step 1: Create distributed session store**

Replace memory-only sessions with encrypted PostgreSQL-backed sessions with replication:

```rust
pub struct DistributedSessionStore {
    pool: HaPool,
    encryption_key: [u8; 32],
}
```

Sessions are encrypted at rest, replicated across DB nodes, and expire automatically.

---

## Phase 7: HSM as Default Key Source

### Task 16: Make HSM Default, Require Explicit Software Opt-in

**Files:**
- Modify: `crypto/src/hsm.rs`

- [ ] **Step 1: Change default backend selection**

Current: software fallback is default, HSM is opt-in.
New: HSM (PKCS#11) is default, software requires `MILNET_HSM_BACKEND=software` AND `MILNET_ALLOW_SOFTWARE_KEYS=true`.

- [ ] **Step 2: Add key ceremony initialization**

```rust
pub async fn initialize_key_ceremony(hsm: &dyn HsmKeyOps) -> Result<KeyCeremonyResult, HsmError> {
    // Generate master KEK in HSM
    // Generate FROST signing key shares
    // Generate OPAQUE OPRF seed shares
    // Generate audit signing key
    // All keys stay in HSM, only handles returned
}
```

---

## Phase 8: Admin API Tests

### Task 17: Comprehensive Admin Route Tests

**Files:**
- Create: `admin/tests/admin_routes_test.rs`

- [ ] **Step 1: Test CSRF protection**
- [ ] **Step 2: Test RBAC enforcement (all 5 roles)**
- [ ] **Step 3: Test user registration/management endpoints**
- [ ] **Step 4: Test device enrollment endpoints**
- [ ] **Step 5: Test audit log inspection endpoints**
- [ ] **Step 6: Test portal management endpoints**
- [ ] **Step 7: Test token revocation endpoints**
- [ ] **Step 8: Test rate limiting and error handling**
- [ ] **Step 9: Test Google OAuth integration**
- [ ] **Step 10: Test multi-person ceremony for destructive actions**

---

## Phase 9: FIDO2 Tests

### Task 18: FIDO2 Registration and Authentication Tests

**Files:**
- Create: `fido/tests/fido_test.rs`

- [ ] **Step 1: Test registration options generation**
- [ ] **Step 2: Test registration response verification (valid attestation)**
- [ ] **Step 3: Test registration with excludeCredentials**
- [ ] **Step 4: Test authentication options generation**
- [ ] **Step 5: Test authentication response verification**
- [ ] **Step 6: Test sign count validation (clone detection)**
- [ ] **Step 7: Test RP ID mismatch rejection**
- [ ] **Step 8: Test user verification flag enforcement**
- [ ] **Step 9: Test multiple authenticator types (platform, cross-platform)**
- [ ] **Step 10: Test EdDSA, ES256, RS256 algorithm support**

---

## Phase 10: Gateway + Module Unit Tests

### Task 19: Gateway Unit Tests

**Files:**
- Create: `gateway/tests/gateway_unit_test.rs`

- [ ] **Step 1: Test hash puzzle generation and validation**
- [ ] **Step 2: Test DDoS mode difficulty escalation**
- [ ] **Step 3: Test distributed rate limiting**
- [ ] **Step 4: Test TLS configuration (cipher suites, versions)**

### Task 20: Unit Tests Across Core Modules

- [ ] **Step 1: Add unit tests to `verifier/src/verify.rs`** — test each verification path
- [ ] **Step 2: Add unit tests to `orchestrator/src/ceremony.rs`** — test state machine transitions
- [ ] **Step 3: Add unit tests to `risk/src/scoring.rs`** — test risk calculation edge cases
- [ ] **Step 4: Add unit tests to `shard/src/protocol.rs`** — test replay protection, message auth

---

## Phase 11: Distributed Session Persistence & Multi-Node

### Task 21: Distributed Configuration

**Files:**
- Modify: `common/src/config.rs`

- [ ] **Step 1: Add multi-node configuration**

```rust
pub struct ClusterConfig {
    pub node_id: String,
    pub nodes: Vec<NodeConfig>,
    pub replication_factor: u8,
    pub consensus_threshold: u8,
}
```

### Task 22: E2E Hardening Validation Tests

**Files:**
- Create: `e2e/tests/hardening_validation_test.rs`

- [ ] **Step 1: Test token claims are never plaintext on the wire**
- [ ] **Step 2: Test audit metadata is encrypted at rest**
- [ ] **Step 3: Test X-Wing pinning rejects mismatched fingerprints**
- [ ] **Step 4: Test OPAQUE threshold requires 2-of-3**
- [ ] **Step 5: Test DB failover under replica loss**
- [ ] **Step 6: Test HSM key operations**
- [ ] **Step 7: Test no panics in production code paths**

---

## Execution Order (Parallelizable Groups)

**Group A (Independent — run in parallel):**
- Task 1-4: Token Encryption (JWE)
- Task 5-6: Audit Metadata Encryption
- Task 7-8: X-Wing Pinning + SHARD
- Task 9-12: Panic Elimination

**Group B (Depends on Group A crypto modules):**
- Task 13: Threshold OPAQUE
- Task 14-15: Database HA
- Task 16: HSM Default

**Group C (Independent — run in parallel):**
- Task 17: Admin API Tests
- Task 18: FIDO2 Tests
- Task 19-20: Gateway + Unit Tests

**Group D (Depends on all above):**
- Task 21-22: Distributed Config + E2E Validation
