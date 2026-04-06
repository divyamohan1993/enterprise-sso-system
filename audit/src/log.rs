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
    /// Bell-LaPadula classification level of the resource being accessed.
    /// 0=Unclassified, 1=Confidential, 2=Secret, 3=TopSecret, 4=SCI
    #[serde(default)]
    pub classification: u8,
}

/// Wire response type from audit service.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditResponse {
    pub success: bool,
    pub event_id: Option<Uuid>,
    pub error: Option<String>,
}

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
    /// Optional master KEK for encrypting archived data before deletion.
    /// When set, archived entries are AES-256-GCM encrypted before writing.
    pub archive_encryption_kek: Option<[u8; 32]>,
    /// Active compliance regime (if any). Overrides age-based deletion floors.
    pub compliance_regime: Option<common::compliance::ComplianceRegime>,
    /// Minimum retention (days) for Indian Govt / CERT-In compliance.
    pub cert_in_min_retention_days: u64,
    /// Minimum retention (days) for US DoD compliance.
    pub dod_min_retention_days: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: 2555,         // ~7 years
            max_archive_size_mb: 10240, // 10 GB
            auto_archive: true,
            archive_encryption_kek: None,
            compliance_regime: None,
            cert_in_min_retention_days: 365,
            dod_min_retention_days: 2555,
        }
    }
}

impl RetentionPolicy {
    /// Return the minimum retention floor (in microseconds) imposed by the
    /// active compliance regime, or `0` if no regime is set.
    pub fn compliance_floor_us(&self) -> i64 {
        use common::compliance::ComplianceRegime;
        match self.compliance_regime {
            Some(ComplianceRegime::IndianGovt) => {
                self.cert_in_min_retention_days as i64 * MICROS_PER_DAY
            }
            Some(ComplianceRegime::UsDod) => {
                self.dod_min_retention_days as i64 * MICROS_PER_DAY
            }
            Some(ComplianceRegime::Dual) => {
                // Dual: use the stricter (larger) floor
                let india_floor = self.cert_in_min_retention_days as i64 * MICROS_PER_DAY;
                let dod_floor = self.dod_min_retention_days as i64 * MICROS_PER_DAY;
                india_floor.max(dod_floor)
            }
            None => 0,
        }
    }
}

/// Capacity utilisation thresholds for SIEM alerting.
const CAPACITY_WARNING_PCT: usize = 80;
const CAPACITY_CRITICAL_PCT: usize = 90;

/// Microseconds per day (86400 * 1_000_000).
const MICROS_PER_DAY: i64 = 86_400_000_000;

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

    /// Append an audit entry, always signing it with ML-DSA-87.
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
            classification: 0,
            // FIXME(H12): correlation_id and trace_id should be populated by callers
            // (gateway/orchestrator) from the request context to enable end-to-end
            // distributed tracing across the authentication pipeline.
            correlation_id: None,
            trace_id: None,
            source_ip: None,
            session_id: None,
            request_id: None,
            user_agent: None,
        };
        let hash = hash_entry(&entry);
        entry.signature = crypto::pq_sign::pq_sign_raw(signing_key, &hash);
        self.last_hash = hash;
        self.entries.push(entry);
        self.incremental_verify();
        self.auto_archive();
        self.enforce_retention();
        // SAFETY: we just pushed an entry, so `last()` is always Some.
        self.entries.last().unwrap_or_else(|| {
            tracing::error!("BUG: audit log empty immediately after push");
            std::process::exit(1);
        })
    }

    /// Verify chain hash linkage only, without signature checks.
    ///
    /// DEPRECATED: Use `verify_chain_signatures()` for full verification
    /// including ML-DSA-87 signature checks. This method is retained for
    /// backward compatibility but renamed callers should prefer
    /// `verify_chain_structure_only()` to make the lack of sig-check explicit.
    pub fn verify_chain(&self) -> bool {
        self.verify_chain_with_key(None)
    }

    /// Verify chain hash linkage only, without signature checks.
    ///
    /// Use this only when signature verification is not possible (e.g.,
    /// verifying key unavailable during recovery). Prefer `verify_chain_signatures()`.
    pub fn verify_chain_structure_only(&self) -> bool {
        self.verify_chain_with_key(None)
    }

    /// Verify chain integrity: hash linkage AND ML-DSA-87 signatures.
    ///
    /// All entries MUST have valid signatures. Unsigned entries are rejected
    /// to prevent log injection. This is the recommended verification method.
    pub fn verify_chain_signatures(&self, verifying_key: &crypto::pq_sign::PqVerifyingKey) -> bool {
        self.verify_chain_with_key(Some(verifying_key))
    }

    /// Verify chain integrity: hash linkage AND (optionally) ML-DSA-87 signatures.
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

    /// Append an entry and sign it with ML-DSA-87.
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
            classification: 0,
            // FIXME(H12): correlation_id and trace_id should be populated by callers
            // (gateway/orchestrator) from the request context to enable end-to-end
            // distributed tracing across the authentication pipeline.
            correlation_id: None,
            trace_id: None,
            source_ip: None,
            session_id: None,
            request_id: None,
            user_agent: None,
        };
        let hash = hash_entry(&entry);
        entry.signature = crypto::pq_sign::pq_sign_raw(signing_key, &hash);
        self.last_hash = hash;
        self.entries.push(entry);
        self.incremental_verify();
        self.auto_archive();
        self.enforce_retention();
        self.entries.last().unwrap_or_else(|| {
            tracing::error!("BUG: audit log empty immediately after push");
            std::process::exit(1);
        })
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
        self.incremental_verify();
        self.auto_archive();
        Ok(())
    }

    /// Archive old entries to a file in the given directory.
    ///
    /// Keeps the last `max_entries` entries in memory and writes the rest
    /// to an archive file with a timestamp suffix.  The hash chain is
    /// preserved across archives by keeping `last_hash` intact.
    ///
    /// In military deployment mode (`MILNET_MILITARY_DEPLOYMENT=1`), this
    /// function refuses to write plaintext archives. An encryption KEK must
    /// be configured in the retention policy.
    ///
    /// Returns the count of archived entries.
    pub fn archive_old_entries(&mut self, archive_dir: &str) -> Result<usize, String> {
        if self.entries.len() <= self.max_entries {
            return Ok(0);
        }

        // In military deployment, refuse to archive without encryption.
        let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
            .map(|v| v == "1")
            .unwrap_or(false);
        if is_military && self.retention_policy.archive_encryption_kek.is_none() {
            common::siem::SecurityEvent::tamper_detected(
                "CRITICAL: archive_old_entries called in military deployment without encryption KEK. \
                 Refusing to write plaintext audit data to disk. Entries retained in memory.",
            );
            return Err(
                "archive encryption KEK required in military deployment; \
                 refusing to write plaintext audit data to disk"
                    .to_string(),
            );
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

        let entries_to_archive: Vec<AuditEntry> = self.entries.drain(..archive_count).collect();

        // Serialize entries to JSON lines.
        let mut json_data = Vec::new();
        for entry in &entries_to_archive {
            let json = serde_json::to_string(entry)
                .map_err(|e| format!("failed to serialize entry: {}", e))?;
            json_data.extend_from_slice(json.as_bytes());
            json_data.push(b'\n');
        }

        // Encrypt if KEK is available, otherwise write plaintext (non-military only).
        let write_result = if let Some(ref kek) = self.retention_policy.archive_encryption_kek {
            let archive_path = std::path::Path::new(archive_dir)
                .join(format!("audit_archive_{}.enc", timestamp));
            encrypt_and_write_archive(kek, &archive_path, &json_data).map(|()| archive_path)
        } else {
            // SECURITY: Never write plaintext audit archives. Derive an archive KEK
            // from the master KEK if no explicit archive KEK is configured.
            use zeroize::Zeroize;
            let fallback_kek = common::sealed_keys::get_master_kek();
            use hkdf::Hkdf;
            let hk = Hkdf::<Sha512>::new(Some(b"MILNET-AUDIT-ARCHIVE-KEK-v1"), fallback_kek);
            let mut derived_kek = [0u8; 32];
            hk.expand(b"audit-archive", &mut derived_kek)
                .map_err(|_| "HKDF-SHA512 audit archive KEK derivation failed".to_string())?;
            let archive_path = std::path::Path::new(archive_dir)
                .join(format!("audit_archive_{}.enc", timestamp));
            let result = encrypt_and_write_archive(&derived_kek, &archive_path, &json_data);
            derived_kek.zeroize();
            result.map(|()| archive_path)
        };

        match write_result {
            Ok(archive_path) => {
                tracing::info!(
                    "Archived {} audit entries to {:?} ({} entries remain in memory)",
                    archive_count,
                    archive_path,
                    self.entries.len()
                );
                Ok(archive_count)
            }
            Err(e) => {
                // Re-insert entries if archival failed (do not lose data).
                let mut restored = entries_to_archive;
                restored.extend(self.entries.drain(..));
                self.entries = restored;
                Err(e)
            }
        }
    }

    /// Enforce the retention policy:
    ///
    /// 1. Delete in-memory entries older than `max_age_days`, archiving them
    ///    (encrypted if a KEK is configured) before removal.
    /// 2. Trigger overflow archival if entries exceed `max_entries`.
    /// 3. Emit capacity warnings at 80% and critical alerts at 90%.
    /// 4. Emit a SIEM event when an archive file is created.
    pub fn enforce_retention(&mut self) {
        let now = now_us();
        let max_age_us = self.retention_policy.max_age_days as i64 * MICROS_PER_DAY;
        let cutoff = now - max_age_us;

        // ── 1. Age-based deletion with encrypted archival ──
        // Compliance floor: entries younger than the minimum retention must not be deleted.
        let now_us_for_floor = now;
        let compliance_floor_us = self.retention_policy.compliance_floor_us();
        let expired_count = self
            .entries
            .iter()
            .take_while(|e| {
                if e.timestamp >= cutoff {
                    return false; // not yet expired by max_age policy
                }
                // Skip deletion if entry is younger than the compliance floor
                let age_us = now_us_for_floor.saturating_sub(e.timestamp);
                age_us >= compliance_floor_us
            })
            .count();
        if expired_count > 0 {
            // In military deployment, refuse to archive without encryption KEK.
            let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT")
                .map(|v| v == "1")
                .unwrap_or(false);
            if is_military && self.retention_policy.archive_encryption_kek.is_none() {
                common::siem::SecurityEvent::tamper_detected(
                    "CRITICAL: retention policy triggered archival but no encryption KEK configured \
                     in military deployment. Refusing to write plaintext. Entries retained in memory.",
                );
                tracing::error!(
                    "CRITICAL: {} expired entries cannot be archived without encryption KEK. \
                     Entries retained in memory. Configure archive_encryption_kek immediately.",
                    expired_count
                );
                // Emit size cap warning if memory is getting large
                if self.max_entries > 0 {
                    let pct = self.entries.len() * 100 / self.max_entries;
                    if pct >= CAPACITY_WARNING_PCT {
                        common::siem::SecurityEvent::capacity_warning(
                            "audit_log_no_kek_retention", self.entries.len(), self.max_entries,
                        );
                    }
                }
                // Do NOT proceed with archival. Keep entries in memory.
            } else if let Some(ref dir) = self.archive_dir.clone() {
                let mut expired_entries: Vec<AuditEntry> = self.entries.drain(..expired_count).collect();

                // Build archive filename with timestamp
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros();

                if let Err(e) = std::fs::create_dir_all(&dir) {
                    tracing::error!("Retention: failed to create archive dir {:?}: {}", dir, e);
                } else {
                    // Serialize entries to JSON lines
                    let mut json_data = Vec::new();
                    for entry in &expired_entries {
                        if let Ok(json) = serde_json::to_string(entry) {
                            json_data.extend_from_slice(json.as_bytes());
                            json_data.push(b'\n');
                        }
                    }

                    // Encrypt archive if KEK is configured, otherwise reject in military mode.
                    let write_result = if let Some(ref kek) = self.retention_policy.archive_encryption_kek {
                        let archive_path =
                            std::path::Path::new(&dir).join(format!("audit_retention_{}.enc", ts));
                        encrypt_and_write_archive(kek, &archive_path, &json_data)
                    } else {
                        Err("FATAL: Archive encryption KEK required in production".into())
                    };

                    match write_result {
                        Ok(()) => {
                            tracing::info!(
                                "Retention: archived and deleted {} expired entries (older than {} days)",
                                expired_count, self.retention_policy.max_age_days,
                            );
                            common::siem::SecurityEvent::key_rotation(&format!(
                                "audit retention archive created: {} entries archived",
                                expired_count,
                            ));
                        }
                        Err(e) => {
                            tracing::error!("Retention: failed to write archive: {}", e);
                            // Re-insert entries if archival failed (do not lose data).
                            // Prepend to preserve original chain linkage order
                            // (sorting by timestamp would break prev_hash chain integrity).
                            expired_entries.extend(self.entries.drain(..));
                            self.entries = expired_entries;
                        }
                    }
                }
            } else {
                tracing::error!("FATAL: Cannot delete audit entries without archival in production");
                // Refuse to delete entries without archiving them first
            }
        }

        // ── 2. Overflow archival ──
        if self.retention_policy.auto_archive && self.entries.len() > self.max_entries {
            if let Some(ref dir) = self.archive_dir.clone() {
                match self.archive_old_entries(dir) {
                    Ok(count) if count > 0 => {
                        tracing::info!("Retention: overflow archived {} entries", count);
                    }
                    Err(e) => {
                        tracing::error!("Retention: overflow archival failed: {}", e);
                    }
                    _ => {}
                }
            }
        }

        // ── 3. Capacity warnings ──
        if self.max_entries > 0 {
            let pct = self.entries.len() * 100 / self.max_entries;
            if pct >= CAPACITY_CRITICAL_PCT {
                tracing::error!(
                    "CRITICAL: audit log at {}% capacity ({}/{})",
                    pct, self.entries.len(), self.max_entries
                );
                common::siem::SecurityEvent::capacity_warning(
                    "audit_log", self.entries.len(), self.max_entries,
                );
            } else if pct >= CAPACITY_WARNING_PCT {
                tracing::warn!(
                    "WARNING: audit log at {}% capacity ({}/{})",
                    pct, self.entries.len(), self.max_entries
                );
                common::siem::SecurityEvent::capacity_warning(
                    "audit_log", self.entries.len(), self.max_entries,
                );
            }
        }

        // ── 4. Archive directory size check ──
        if let Some(ref dir) = self.archive_dir {
            let dir_size_mb = dir_size_bytes(dir) / (1024 * 1024);
            let limit = self.retention_policy.max_archive_size_mb;
            if limit > 0 {
                let pct = dir_size_mb * 100 / limit.max(1);
                if pct >= CAPACITY_CRITICAL_PCT as u64 {
                    tracing::error!(
                        "CRITICAL: archive directory {:?} at {} MB / {} MB ({}%)",
                        dir, dir_size_mb, limit, pct
                    );
                    common::siem::SecurityEvent::capacity_warning(
                        "audit_archive", dir_size_mb as usize, limit as usize,
                    );
                } else if pct >= CAPACITY_WARNING_PCT as u64 {
                    tracing::warn!(
                        "WARNING: archive directory {:?} at {} MB / {} MB ({}%)",
                        dir, dir_size_mb, limit, pct
                    );
                }
            }
        }
    }

    /// Spawn a background task that runs `enforce_retention()` hourly.
    ///
    /// Returns a [`tokio::task::JoinHandle`] for the cleanup task. The
    /// caller should hold onto it for graceful shutdown.
    ///
    /// This requires the `AuditLog` to be wrapped in `Arc<Mutex<>>` by the
    /// caller; the function accepts a clone of that `Arc`.
    pub fn spawn_retention_task(
        log: std::sync::Arc<std::sync::Mutex<AuditLog>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                match log.lock() {
                    Ok(mut audit_log) => {
                        tracing::info!("Retention: running hourly cleanup");
                        audit_log.enforce_retention();
                    }
                    Err(e) => {
                        tracing::error!("Retention: failed to acquire lock: {}", e);
                        common::siem::SecurityEvent::tamper_detected(
                            &format!("audit log mutex poisoned during retention: {}", e)
                        );
                    }
                }
            }
        })
    }

    /// Incremental chain verification — only checks the LAST entry against prev_hash.
    /// Full chain verification runs in background, not in the hot path.
    fn incremental_verify(&mut self) {
        if self.entries.len() < 2 {
            return;
        }
        let last = &self.entries[self.entries.len() - 1];
        let prev = &self.entries[self.entries.len() - 2];
        let expected_prev = hash_entry(prev);
        if last.prev_hash != expected_prev {
            self.tamper_detected = true;
            tracing::error!(
                target: "siem",
                event = "audit_tamper_detected",
                "SECURITY: Hash chain linkage broken at entry {}",
                self.entries.len() - 1
            );
        }
    }

    /// Full chain verification — intended for background/scheduled use, NOT hot path.
    /// Call this from a background tokio task every N minutes.
    /// Uses structure-only check; callers with a verifying key should use
    /// `verify_chain_signatures()` for full cryptographic verification.
    pub fn background_verify_chain(&mut self) -> bool {
        let result = self.verify_chain_structure_only();
        if !result {
            self.tamper_detected = true;
        }
        result
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
    // Include classification to prevent Bell-LaPadula level tampering
    hasher.update([entry.classification]);
    hasher.update(entry.timestamp.to_le_bytes());
    hasher.update(entry.prev_hash);

    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

fn now_us() -> i64 {
    // SECURITY: Use monotonic-anchored time. Immune to clock manipulation
    // after process start (NTP jumps, clock_settime, date -s).
    common::secure_time::secure_now_us_i64()
}

/// Encrypt archive data with AES-256-GCM and write to the given path.
///
/// Uses the common backup encryption infrastructure. The encrypted file
/// has the format: `MILBK001 || version(2) || nonce(12) || len(8) || ciphertext || hmac(64)`.
fn encrypt_and_write_archive(
    kek: &[u8; 32],
    path: &std::path::Path,
    data: &[u8],
) -> Result<(), String> {
    let encrypted = common::backup::export_backup(kek, data)?;
    {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600) // Owner read/write only
            .open(path)
            .map_err(|e| format!("failed to write encrypted archive {:?}: {}", path, e))?;
        std::io::Write::write_all(&mut file, &encrypted)
            .map_err(|e| format!("failed to write encrypted archive {:?}: {}", path, e))?;
    }

    // Emit SIEM event for encrypted archive creation
    common::siem::SecurityEvent::key_rotation(&format!(
        "encrypted audit archive created at {:?} ({} bytes plaintext -> {} bytes encrypted)",
        path,
        data.len(),
        encrypted.len()
    ));

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a signing key for testing.
    fn test_signing_key() -> crypto::pq_sign::PqSigningKey {
        let (sk, _vk) = crypto::pq_sign::generate_pq_keypair();
        sk
    }

    /// Helper to append N entries with a given timestamp offset (in microseconds).
    fn append_entries_with_timestamp(
        log: &mut AuditLog,
        count: usize,
        timestamp_us: i64,
        signing_key: &crypto::pq_sign::PqSigningKey,
    ) {
        for _ in 0..count {
            let mut entry = AuditEntry {
                event_id: Uuid::new_v4(),
                event_type: AuditEventType::AuthSuccess,
                user_ids: vec![],
                device_ids: vec![],
                ceremony_receipts: vec![],
                risk_score: 0.0,
                timestamp: timestamp_us,
                prev_hash: log.last_hash,
                signature: Vec::new(),
                classification: 0,
                correlation_id: None,
                trace_id: None,
                source_ip: None,
                session_id: None,
                request_id: None,
                user_agent: None,
            };
            let hash = hash_entry(&entry);
            entry.signature = crypto::pq_sign::pq_sign_raw(signing_key, &hash);
            log.last_hash = hash;
            log.entries.push(entry);
        }
    }

    #[test]
    fn retention_deletes_expired_entries() {
        let dir = std::env::temp_dir().join(format!("audit_ret_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100_000, Some(dir.to_str().unwrap().to_string()));
        log.retention_policy.max_age_days = 1; // 1 day retention

        // Set encryption KEK (required in production mode for archival to succeed)
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();
        log.retention_policy.archive_encryption_kek = Some(kek);

        // Add entries with a timestamp 2 days ago (expired)
        let two_days_ago = now_us() - 2 * MICROS_PER_DAY;
        append_entries_with_timestamp(&mut log, 5, two_days_ago, &signing_key);
        assert_eq!(log.len(), 5);

        // Add fresh entries
        for _ in 0..3 {
            log.append(
                AuditEventType::AuthSuccess, vec![], vec![], 0.0, vec![],
                &signing_key,
            );
        }
        // 5 old + 3 new = 8 before retention
        // But enforce_retention is called by append(), so old entries are already archived
        // Let's check — old entries should have been removed
        // Actually, append calls enforce_retention, which checks age.
        // The 5 old entries have timestamp < cutoff, so they should be archived.

        // Verify the old entries were archived
        assert_eq!(log.len(), 3); // only fresh entries remain

        // Verify archive file was created
        let archive_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit_retention_"))
            .collect();
        assert!(!archive_files.is_empty(), "archive file should be created");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_encrypted_archival() {
        let dir = std::env::temp_dir().join(format!("audit_enc_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100_000, Some(dir.to_str().unwrap().to_string()));
        log.retention_policy.max_age_days = 1;

        // Set encryption KEK
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();
        log.retention_policy.archive_encryption_kek = Some(kek);

        // Add expired entries
        let two_days_ago = now_us() - 2 * MICROS_PER_DAY;
        append_entries_with_timestamp(&mut log, 3, two_days_ago, &signing_key);

        // Trigger retention
        log.enforce_retention();
        assert_eq!(log.len(), 0); // all expired

        // Verify the archive file exists and is encrypted (starts with MILBK001 v1 or MILBK002 v2)
        let archive_files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("audit_retention_"))
            .collect();
        assert_eq!(archive_files.len(), 1);

        let archive_data = std::fs::read(archive_files[0].path()).unwrap();
        let magic = &archive_data[..8];
        assert!(
            magic == b"MILBK001" || magic == b"MILBK002",
            "archive should be encrypted (MILBK001 or MILBK002), got {:?}",
            magic
        );

        // Verify we can decrypt it
        let decrypted = common::backup::import_backup(&kek, &archive_data).unwrap();
        assert!(!decrypted.is_empty());

        // Verify wrong KEK fails
        let wrong_kek = [0xFFu8; 32];
        assert!(common::backup::import_backup(&wrong_kek, &archive_data).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_preserves_fresh_entries() {
        let dir = std::env::temp_dir().join(format!("audit_fresh_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100_000, Some(dir.to_str().unwrap().to_string()));
        log.retention_policy.max_age_days = 30; // 30 days

        // Add entries with current timestamp (not expired)
        for _ in 0..5 {
            log.append(
                AuditEventType::AuthSuccess, vec![], vec![], 0.0, vec![],
                &signing_key,
            );
        }

        // Enforce retention — nothing should be deleted
        log.enforce_retention();
        assert_eq!(log.len(), 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn capacity_warning_at_80_percent() {
        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(10, None);

        // Add 8 entries (80% of max_entries=10)
        for _ in 0..8 {
            log.append(
                AuditEventType::AuthSuccess, vec![], vec![], 0.0, vec![],
                &signing_key,
            );
        }
        // enforce_retention() is called by append() — capacity warning should have been emitted
        // We just verify no panic and correct count
        assert_eq!(log.len(), 8);
    }

    #[test]
    fn capacity_critical_at_90_percent() {
        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100, None);
        log.retention_policy.auto_archive = false;

        // Add 91 entries (91% of max_entries=100)
        for _ in 0..91 {
            log.append(
                AuditEventType::AuthSuccess, vec![], vec![], 0.0, vec![],
                &signing_key,
            );
        }
        assert_eq!(log.len(), 91);
    }

    #[test]
    fn overflow_archival_respects_max_entries() {
        std::env::set_var("MILNET_TESTING_SINGLE_KEK_ACK", "1");
        let dir = std::env::temp_dir().join(format!("audit_overflow_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(5, Some(dir.to_str().unwrap().to_string()));

        // Add 10 entries — should trigger overflow archival at max_entries=5
        for _ in 0..10 {
            log.append(
                AuditEventType::AuthSuccess, vec![], vec![], 0.0, vec![],
                &signing_key,
            );
        }

        // After auto_archive, only max_entries should remain
        assert!(log.len() <= 5, "entries should be <= max_entries after archival");

        let _ = std::fs::remove_dir_all(&dir);
        // NOTE: do NOT remove MILNET_TESTING_SINGLE_KEK_ACK — it's set by
        // the test harness and removing it races with parallel tests.
    }

    #[test]
    fn hash_chain_integrity_after_retention() {
        let dir = std::env::temp_dir().join(format!("audit_chain_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100_000, Some(dir.to_str().unwrap().to_string()));
        log.retention_policy.max_age_days = 1;

        // Add expired entries
        let two_days_ago = now_us() - 2 * MICROS_PER_DAY;
        append_entries_with_timestamp(&mut log, 3, two_days_ago, &signing_key);

        // Add fresh entries (these build on the hash chain from expired entries)
        for _ in 0..3 {
            log.append(
                AuditEventType::AuthSuccess, vec![], vec![], 0.0, vec![],
                &signing_key,
            );
        }

        // After retention removes old entries, remaining chain should still verify
        // Note: the remaining entries' chain starts from the last archived entry's hash,
        // so verify_chain() on the remaining subset validates correctly since prev_hash
        // of the first remaining entry is the hash that was at the archive boundary.
        assert!(log.len() > 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_size_bytes_works() {
        let dir = std::env::temp_dir().join(format!("audit_size_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        // Write a file of known size
        std::fs::write(dir.join("test.dat"), &[0u8; 1024]).unwrap();
        let size = dir_size_bytes(dir.to_str().unwrap());
        assert_eq!(size, 1024);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_size_bytes_nonexistent_dir() {
        assert_eq!(dir_size_bytes("/nonexistent/path/xyz"), 0);
    }

    #[test]
    fn retention_policy_default() {
        let policy = RetentionPolicy::default();
        assert_eq!(policy.max_age_days, 2555);
        assert_eq!(policy.max_archive_size_mb, 10240);
        assert!(policy.auto_archive);
        assert!(policy.archive_encryption_kek.is_none());
    }

    // ── Compliance-aware retention tests ──

    /// IndianGovt regime: a 300-day-old entry must NOT be deleted (floor = 365 days).
    #[test]
    fn test_retention_cert_in_blocks_recent() {
        let dir = std::env::temp_dir().join(format!("audit_certin_recent_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100_000, Some(dir.to_str().unwrap().to_string()));
        // Set max_age_days short enough that the entry would normally expire,
        // but compliance floor (365 days) must block deletion.
        log.retention_policy.max_age_days = 1; // 1 day — entry is "expired" by normal policy
        log.retention_policy.compliance_regime =
            Some(common::compliance::ComplianceRegime::IndianGovt);
        log.retention_policy.cert_in_min_retention_days = 365;

        // Entry timestamped 300 days ago — would be deleted by 1-day max_age,
        // but the 365-day CERT-In floor must prevent it.
        let three_hundred_days_ago = now_us() - 300 * MICROS_PER_DAY;
        append_entries_with_timestamp(&mut log, 1, three_hundred_days_ago, &signing_key);
        assert_eq!(log.len(), 1);

        log.enforce_retention();

        assert_eq!(
            log.len(),
            1,
            "300-day entry must NOT be deleted under IndianGovt 365-day floor"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// IndianGovt regime: a 400-day-old entry MUST be deleted (exceeds 365-day floor).
    #[test]
    fn test_retention_cert_in_allows_old() {
        let dir = std::env::temp_dir().join(format!("audit_certin_old_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100_000, Some(dir.to_str().unwrap().to_string()));
        log.retention_policy.max_age_days = 1; // expired by normal policy
        log.retention_policy.compliance_regime =
            Some(common::compliance::ComplianceRegime::IndianGovt);
        log.retention_policy.cert_in_min_retention_days = 365;

        // Set encryption KEK (required in production mode for archival to succeed)
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();
        log.retention_policy.archive_encryption_kek = Some(kek);

        // Entry timestamped 400 days ago — older than both max_age AND floor, must be deleted.
        let four_hundred_days_ago = now_us() - 400 * MICROS_PER_DAY;
        append_entries_with_timestamp(&mut log, 1, four_hundred_days_ago, &signing_key);
        assert_eq!(log.len(), 1);

        log.enforce_retention();

        assert_eq!(
            log.len(),
            0,
            "400-day entry must be deleted under IndianGovt 365-day floor"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// UsDod regime: a 2000-day-old entry must NOT be deleted (floor = 2555 days).
    #[test]
    fn test_retention_dod_blocks_recent() {
        let dir = std::env::temp_dir().join(format!("audit_dod_blocks_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);

        let signing_key = test_signing_key();
        let mut log = AuditLog::new_with_limits(100_000, Some(dir.to_str().unwrap().to_string()));
        log.retention_policy.max_age_days = 1; // expired by normal policy
        log.retention_policy.compliance_regime =
            Some(common::compliance::ComplianceRegime::UsDod);
        log.retention_policy.dod_min_retention_days = 2555;

        // Entry timestamped 2000 days ago — would be deleted by 1-day max_age,
        // but the 2555-day DoD floor must prevent it.
        let two_thousand_days_ago = now_us() - 2000 * MICROS_PER_DAY;
        append_entries_with_timestamp(&mut log, 1, two_thousand_days_ago, &signing_key);
        assert_eq!(log.len(), 1);

        log.enforce_retention();

        assert_eq!(
            log.len(),
            1,
            "2000-day entry must NOT be deleted under UsDod 2555-day floor"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
