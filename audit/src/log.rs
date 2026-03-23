//! CNSA 2.0 compliant audit log with SHA-512 hash chain.
use common::domain;
use common::types::{AuditEntry, AuditEventType, Receipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Wire request type for audit service.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditRequest {
    pub event_type: AuditEventType,
    pub user_ids: Vec<Uuid>,
    pub device_ids: Vec<Uuid>,
    pub risk_score: f64,
    pub metadata: Vec<u8>,
}

/// Wire response type from audit service.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditResponse {
    pub success: bool,
    pub event_id: Option<Uuid>,
    pub error: Option<String>,
}

/// How often (in number of appended entries) to run automatic chain verification.
const VERIFY_CHAIN_INTERVAL: usize = 100;

pub struct AuditLog {
    entries: Vec<AuditEntry>,
    last_hash: [u8; 64],
    /// Set to `true` if an automatic `verify_chain()` check ever fails.
    tamper_detected: bool,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: [0u8; 64],
            tamper_detected: false,
        }
    }

    /// Construct an AuditLog from pre-existing entries (e.g., loaded from disk).
    /// Does NOT automatically verify the chain; caller should invoke `verify_chain()`
    /// after construction to validate integrity.
    pub fn from_entries(entries: Vec<AuditEntry>) -> Self {
        let last_hash = entries.last().map(hash_entry).unwrap_or([0u8; 64]);
        Self {
            entries,
            last_hash,
            tamper_detected: false,
        }
    }

    pub fn append(
        &mut self,
        event_type: AuditEventType,
        user_ids: Vec<Uuid>,
        device_ids: Vec<Uuid>,
        risk_score: f64,
        ceremony_receipts: Vec<Receipt>,
    ) -> &AuditEntry {
        let entry = AuditEntry {
            event_id: Uuid::new_v4(),
            event_type,
            user_ids,
            device_ids,
            ceremony_receipts,
            risk_score,
            timestamp: now_us(),
            prev_hash: self.last_hash,
            signature: Vec::new(), // placeholder for ML-DSA-65
        };
        self.last_hash = hash_entry(&entry);
        self.entries.push(entry);
        self.periodic_verify();
        self.entries.last().unwrap()
    }

    pub fn verify_chain(&self) -> bool {
        self.verify_chain_with_key(None)
    }

    /// Verify chain integrity: hash linkage AND (optionally) ML-DSA-65 signatures.
    pub fn verify_chain_with_key(&self, verifying_key: Option<&crypto::pq_sign::PqVerifyingKey>) -> bool {
        let mut expected_prev = [0u8; 64];
        for entry in &self.entries {
            if entry.prev_hash != expected_prev {
                return false;
            }
            // Verify signature if present and key provided
            if let Some(vk) = verifying_key {
                if !entry.signature.is_empty() {
                    let hash = hash_entry(entry);
                    if !crypto::pq_sign::pq_verify_raw(vk, &hash, &entry.signature) {
                        return false;
                    }
                }
            }
            expected_prev = hash_entry(entry);
        }
        true
    }

    /// Returns `true` if no tampering has been detected by periodic verification.
    /// Once tamper is detected, this returns `false` permanently.
    pub fn is_integrity_intact(&self) -> bool {
        !self.tamper_detected
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Append an entry and sign it with ML-DSA-65.
    pub fn append_signed(
        &mut self,
        event_type: AuditEventType,
        user_ids: Vec<Uuid>,
        device_ids: Vec<Uuid>,
        risk_score: f64,
        ceremony_receipts: Vec<Receipt>,
        signing_key: &crypto::pq_sign::PqSigningKey,
    ) -> &AuditEntry {
        let mut entry = AuditEntry {
            event_id: Uuid::new_v4(),
            event_type,
            user_ids,
            device_ids,
            ceremony_receipts,
            risk_score,
            timestamp: now_us(),
            prev_hash: self.last_hash,
            signature: Vec::new(),
        };
        let hash = hash_entry(&entry);
        entry.signature = crypto::pq_sign::pq_sign_raw(signing_key, &hash);
        self.last_hash = hash;
        self.entries.push(entry);
        self.periodic_verify();
        self.entries.last().unwrap()
    }

    /// Append a pre-built entry directly (used by BFT replication layer).
    /// Validates hash chain linkage before accepting.
    pub fn append_raw(&mut self, entry: AuditEntry) -> Result<(), String> {
        // Validate hash chain linkage
        if entry.prev_hash != self.last_hash {
            return Err("append_raw: prev_hash does not match current chain head".into());
        }
        self.last_hash = hash_entry(&entry);
        self.entries.push(entry);
        self.periodic_verify();
        Ok(())
    }

    /// Run `verify_chain()` every `VERIFY_CHAIN_INTERVAL` entries.
    /// If verification fails, log a CRITICAL error and set `tamper_detected`.
    fn periodic_verify(&mut self) {
        if self.entries.len() % VERIFY_CHAIN_INTERVAL == 0 {
            if !self.verify_chain() {
                self.tamper_detected = true;
                tracing::error!(
                    "CRITICAL: audit log chain verification FAILED at entry {}. \
                     Possible tampering detected!",
                    self.entries.len()
                );
            }
        }
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash an audit entry using SHA-512 (CNSA 2.0 compliant).
///
/// Includes ALL fields (event_id, event_type, user_ids, device_ids,
/// ceremony_receipts, risk_score, timestamp, prev_hash) with length prefixes
/// for variable-length lists to prevent length-extension collisions.
pub fn hash_entry(entry: &AuditEntry) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(domain::AUDIT_ENTRY);
    hasher.update(entry.event_id.as_bytes());

    // Include event_type in the hash to prevent type-confusion attacks
    let event_type_bytes =
        postcard::to_allocvec(&entry.event_type).unwrap_or_default();
    hasher.update(&event_type_bytes);

    // Include user_ids with length prefix to prevent length-extension collisions.
    // The u64 count disambiguates e.g. [A, B] from [AB] even if UUIDs were
    // concatenated without boundaries (they are fixed-size, but the count still
    // prevents confusion when the list is empty vs. absent).
    hasher.update((entry.user_ids.len() as u64).to_le_bytes());
    for uid in &entry.user_ids {
        hasher.update(uid.as_bytes());
    }

    // Include device_ids with length prefix
    hasher.update((entry.device_ids.len() as u64).to_le_bytes());
    for did in &entry.device_ids {
        hasher.update(did.as_bytes());
    }

    // Include ceremony_receipts with length prefix.
    // Hash every field of each receipt to bind them into the entry hash.
    hasher.update((entry.ceremony_receipts.len() as u64).to_le_bytes());
    for receipt in &entry.ceremony_receipts {
        hasher.update(&receipt.ceremony_session_id);
        hasher.update([receipt.step_id]);
        hasher.update(&receipt.prev_receipt_hash);
        hasher.update(receipt.user_id.as_bytes());
        hasher.update(&receipt.dpop_key_hash);
        hasher.update(receipt.timestamp.to_le_bytes());
        hasher.update(&receipt.nonce);
        hasher.update(&receipt.signature);
        hasher.update([receipt.ttl_seconds]);
    }

    // Include risk_score to prevent score tampering
    hasher.update(entry.risk_score.to_le_bytes());
    hasher.update(entry.timestamp.to_le_bytes());
    hasher.update(entry.prev_hash);

    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}
