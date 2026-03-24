//! CNSA 2.0 compliant audit log with SHA-512 hash chain.
use common::domain;
use common::types::{AuditEntry, AuditEventType, Receipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
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

/// Default maximum entries to keep in memory before triggering archival.
const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// Log retention policy for compliance with long-term audit requirements.
#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    /// Maximum age of retained logs in days (default: 2555 = ~7 years).
    pub max_age_days: u64,
    /// Maximum total archive size in megabytes (default: 10240 = 10 GB).
    pub max_archive_size_mb: u64,
    /// Whether to automatically archive when limits are exceeded.
    pub auto_archive: bool,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: 2555,       // ~7 years
            max_archive_size_mb: 10240, // 10 GB
            auto_archive: true,
        }
    }
}

pub struct AuditLog {
    entries: Vec<AuditEntry>,
    last_hash: [u8; 64],
    /// Set to `true` if an automatic `verify_chain()` check ever fails.
    tamper_detected: bool,
    /// Maximum entries to keep in memory. When exceeded, archival is triggered.
    max_entries: usize,
    /// Optional directory for automatic archival on overflow.
    archive_dir: Option<String>,
    /// Retention policy controlling archival and size limits.
    pub retention_policy: RetentionPolicy,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: [0u8; 64],
            tamper_detected: false,
            max_entries: DEFAULT_MAX_ENTRIES,
            archive_dir: None,
            retention_policy: RetentionPolicy::default(),
        }
    }

    /// Create an AuditLog with a custom max_entries limit and archive directory.
    pub fn new_with_limits(max_entries: usize, archive_dir: Option<String>) -> Self {
        Self {
            entries: Vec::new(),
            last_hash: [0u8; 64],
            tamper_detected: false,
            max_entries,
            archive_dir,
            retention_policy: RetentionPolicy::default(),
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
            max_entries: DEFAULT_MAX_ENTRIES,
            archive_dir: None,
            retention_policy: RetentionPolicy::default(),
        }
    }

    /// Set the archive directory for automatic overflow archival.
    pub fn set_archive_dir(&mut self, dir: String) {
        self.archive_dir = Some(dir);
    }

    /// Set the maximum entries limit.
    pub fn set_max_entries(&mut self, max: usize) {
        self.max_entries = max;
    }

    /// Append an audit entry, always signing it with ML-DSA-65.
    ///
    /// Every audit entry MUST be signed. This prevents log entries from
    /// being forged or injected without possession of the signing key.
    pub fn append(
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
        self.auto_archive();
        self.enforce_retention();
        self.entries.last().unwrap()
    }

    pub fn verify_chain(&self) -> bool {
        self.verify_chain_with_key(None)
    }

    /// Verify chain integrity: hash linkage AND (optionally) ML-DSA-65 signatures.
    ///
    /// When a verifying key is provided, ALL entries MUST have valid signatures.
    /// Unsigned entries are rejected during verification to prevent log injection.
    pub fn verify_chain_with_key(&self, verifying_key: Option<&crypto::pq_sign::PqVerifyingKey>) -> bool {
        let mut expected_prev = [0u8; 64];
        for entry in &self.entries {
            if entry.prev_hash != expected_prev {
                return false;
            }
            // When a verifying key is provided, reject unsigned entries
            if let Some(vk) = verifying_key {
                if entry.signature.is_empty() {
                    return false;
                }
                let hash = hash_entry(entry);
                if !crypto::pq_sign::pq_verify_raw(vk, &hash, &entry.signature) {
                    return false;
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

    /// Return the total number of entries currently in memory.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
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
        self.auto_archive();
        self.enforce_retention();
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
        self.auto_archive();
        Ok(())
    }

    /// Archive old entries to a JSON lines file in the given directory.
    ///
    /// Keeps the last `max_entries` entries in memory and writes the rest
    /// to an archive file with a timestamp suffix.  The hash chain is
    /// preserved across archives by keeping `last_hash` intact.
    ///
    /// Returns the count of archived entries.
    pub fn archive_old_entries(&mut self, archive_dir: &str) -> Result<usize, String> {
        if self.entries.len() <= self.max_entries {
            return Ok(0);
        }

        let archive_count = self.entries.len() - self.max_entries;

        // Ensure the archive directory exists.
        std::fs::create_dir_all(archive_dir)
            .map_err(|e| format!("failed to create archive dir {:?}: {}", archive_dir, e))?;

        // Build archive filename with timestamp.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let archive_path =
            std::path::Path::new(archive_dir).join(format!("audit_archive_{}.jsonl", timestamp));

        // Write the old entries to the archive file.
        let entries_to_archive: Vec<AuditEntry> = self.entries.drain(..archive_count).collect();

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&archive_path)
            .map_err(|e| format!("failed to open archive file {:?}: {}", archive_path, e))?;

        for entry in &entries_to_archive {
            let json = serde_json::to_string(entry)
                .map_err(|e| format!("failed to serialize entry: {}", e))?;
            writeln!(file, "{}", json)
                .map_err(|e| format!("failed to write to archive: {}", e))?;
        }

        file.sync_data()
            .map_err(|e| format!("failed to sync archive file: {}", e))?;

        tracing::info!(
            "Archived {} audit entries to {:?} ({} entries remain in memory)",
            archive_count,
            archive_path,
            self.entries.len()
        );

        Ok(archive_count)
    }

    /// Enforce the retention policy: trigger archival if entries exceed limits
    /// and warn if the archive directory is approaching the size cap.
    pub fn enforce_retention(&mut self) {
        // Auto-archive if entries exceed max and retention policy allows it
        if self.retention_policy.auto_archive && self.entries.len() > self.max_entries {
            if let Some(ref dir) = self.archive_dir.clone() {
                match self.archive_old_entries(dir) {
                    Ok(count) if count > 0 => {
                        tracing::info!("Retention: archived {} entries", count);
                    }
                    Err(e) => {
                        tracing::error!("Retention: archival failed: {}", e);
                    }
                    _ => {}
                }
            }
        }

        // Check archive directory size against the configured limit
        if let Some(ref dir) = self.archive_dir {
            let dir_size_mb = dir_size_bytes(dir) / (1024 * 1024);
            let limit = self.retention_policy.max_archive_size_mb;
            if limit > 0 && dir_size_mb >= limit * 80 / 100 {
                tracing::warn!(
                    "Retention: archive directory {:?} is at {} MB / {} MB ({}%)",
                    dir,
                    dir_size_mb,
                    limit,
                    dir_size_mb * 100 / limit.max(1)
                );
            }
        }
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
                common::siem::SecurityEvent::tamper_detected(
                    &format!("audit log chain verification FAILED at entry {}", self.entries.len())
                );
            }
        }
    }

    /// Trigger automatic archival when entries exceed max_entries.
    fn auto_archive(&mut self) {
        if self.entries.len() > self.max_entries {
            if let Some(ref dir) = self.archive_dir.clone() {
                match self.archive_old_entries(dir) {
                    Ok(count) if count > 0 => {
                        tracing::info!("Auto-archived {} audit entries", count);
                    }
                    Err(e) => {
                        tracing::error!("Auto-archival failed: {}", e);
                    }
                    _ => {}
                }
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

/// Calculate total size (in bytes) of all files in a directory (non-recursive
/// for simplicity — archive files are stored flat).
fn dir_size_bytes(dir: &str) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}
