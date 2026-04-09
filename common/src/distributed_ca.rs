//! Distributed Certificate Authority with threshold signing.
//!
//! The CA signing key is split across multiple nodes using FROST threshold
//! signatures. No single node holds the complete CA key. Certificate signing
//! requires quorum agreement (t-of-n).
//!
//! On leader failure:
//! - New leader elected via Raft
//! - All nodes share the same CA public key (from DKG)
//! - Any quorum can sign new certificates
//! - Existing certificates remain valid (public key unchanged)

use crate::raft::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Revocation Quorum ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    pub serial: u64,
    pub requester_id: NodeId,
    pub reason: String,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationVote {
    pub serial: u64,
    pub voter_id: NodeId,
    pub timestamp: i64,
}

pub struct RevocationQuorum {
    pub required: usize,
    pending: HashMap<u64, Vec<RevocationVote>>,
}

impl RevocationQuorum {
    pub fn new(required: usize) -> Self { Self { required, pending: HashMap::new() } }

    pub fn add_vote(&mut self, vote: RevocationVote) -> bool {
        let votes = self.pending.entry(vote.serial).or_default();
        if votes.iter().any(|v| v.voter_id == vote.voter_id) { return votes.len() >= self.required; }
        votes.push(vote);
        votes.len() >= self.required
    }

    pub fn has_quorum(&self, serial: u64) -> bool {
        self.pending.get(&serial).map(|v| v.len() >= self.required).unwrap_or(false)
    }

    pub fn clear(&mut self, serial: u64) { self.pending.remove(&serial); }
}

// ── CA Persistence ───────────────────────────────────────────────────────────

/// Persisted snapshot of CA state, loaded on startup.
pub struct CaPersistedState {
    pub issued: HashMap<u64, IssuedCert>,
    pub next_serial: u64,
    pub revoked: Vec<u64>,
}

/// Trait for persisting CA certificate state across restarts.
///
/// Every mutation (issue, revoke, serial bump) must be durable before the
/// operation is considered complete. Implementations must fsync.
pub trait CaPersistence: Send + Sync {
    /// Persist a newly issued certificate.
    fn save_issued(&self, cert: &IssuedCert) -> Result<(), String>;
    /// Persist the next serial number before it is used (prevents reuse on crash).
    fn save_serial(&self, serial: u64) -> Result<(), String>;
    /// Persist a revocation event.
    fn save_revocation(&self, serial: u64) -> Result<(), String>;
    /// Load all persisted CA state on startup.
    fn load_state(&self) -> Result<CaPersistedState, String>;
}

/// File-backed CA persistence. Writes to `{dir}/` with fsync + atomic rename.
///
/// Directory layout:
///   issued/<serial>.bin   -- postcard-serialized IssuedCert
///   serial.bin            -- current next_serial (u64 LE)
///   revoked.bin           -- postcard-serialized Vec<u64>
pub struct FileCaPersistence {
    dir: std::path::PathBuf,
}

impl FileCaPersistence {
    pub fn new(dir: &std::path::Path) -> Result<Self, String> {
        let issued_dir = dir.join("issued");
        std::fs::create_dir_all(&issued_dir)
            .map_err(|e| format!("create CA persistence dir: {e}"))?;
        Ok(Self { dir: dir.to_path_buf() })
    }

    /// Atomic write: write to .tmp, fsync, rename.
    fn atomic_write(&self, path: &std::path::Path, data: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(data)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
        drop(f);
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))?;
        Ok(())
    }
}

impl CaPersistence for FileCaPersistence {
    fn save_issued(&self, cert: &IssuedCert) -> Result<(), String> {
        let data = postcard::to_allocvec(cert).map_err(|e| format!("serialize issued: {e}"))?;
        let path = self.dir.join("issued").join(format!("{}.bin", cert.serial));
        self.atomic_write(&path, &data)
    }

    fn save_serial(&self, serial: u64) -> Result<(), String> {
        let path = self.dir.join("serial.bin");
        self.atomic_write(&path, &serial.to_le_bytes())
    }

    fn save_revocation(&self, _serial: u64) -> Result<(), String> {
        // Re-read current revoked list from the issued certs (marked revoked=true)
        // and persist the full revocation list. This is simpler and crash-safe.
        // For the revocation list, we just append-persist the full list each time.
        // Load all issued certs to find revoked ones.
        let state = self.load_state()?;
        let revoked: Vec<u64> = state.revoked;
        let data = postcard::to_allocvec(&revoked).map_err(|e| format!("serialize revoked: {e}"))?;
        let path = self.dir.join("revoked.bin");
        self.atomic_write(&path, &data)
    }

    fn load_state(&self) -> Result<CaPersistedState, String> {
        let mut issued = HashMap::new();
        let mut revoked = Vec::new();

        // Load issued certs
        let issued_dir = self.dir.join("issued");
        if issued_dir.exists() {
            let entries = std::fs::read_dir(&issued_dir)
                .map_err(|e| format!("read issued dir: {e}"))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("read dir entry: {e}"))?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("bin") {
                    let data = std::fs::read(&path)
                        .map_err(|e| format!("read {}: {e}", path.display()))?;
                    let cert: IssuedCert = postcard::from_bytes(&data)
                        .map_err(|e| format!("deserialize {}: {e}", path.display()))?;
                    if cert.revoked {
                        revoked.push(cert.serial);
                    }
                    issued.insert(cert.serial, cert);
                }
            }
        }

        // Load next_serial
        let serial_path = self.dir.join("serial.bin");
        let next_serial = if serial_path.exists() {
            let data = std::fs::read(&serial_path)
                .map_err(|e| format!("read serial: {e}"))?;
            if data.len() == 8 {
                u64::from_le_bytes(data.try_into().unwrap())
            } else {
                // Derive from issued certs
                issued.keys().copied().max().unwrap_or(0) + 1
            }
        } else {
            issued.keys().copied().max().unwrap_or(0) + 1
        };

        // Also load revoked list from revoked.bin if it exists (cross-check)
        let revoked_path = self.dir.join("revoked.bin");
        if revoked_path.exists() {
            let data = std::fs::read(&revoked_path)
                .map_err(|e| format!("read revoked: {e}"))?;
            if let Ok(persisted_revoked) = postcard::from_bytes::<Vec<u64>>(&data) {
                // Merge: union of cert-level revoked flags and explicit revocation list
                for s in persisted_revoked {
                    if !revoked.contains(&s) {
                        revoked.push(s);
                    }
                }
            }
        }

        Ok(CaPersistedState {
            issued,
            next_serial,
            revoked,
        })
    }
}

/// No-op persistence for tests. State lives in memory only.
pub struct NullCaPersistence;

impl CaPersistence for NullCaPersistence {
    fn save_issued(&self, _cert: &IssuedCert) -> Result<(), String> { Ok(()) }
    fn save_serial(&self, _serial: u64) -> Result<(), String> { Ok(()) }
    fn save_revocation(&self, _serial: u64) -> Result<(), String> { Ok(()) }
    fn load_state(&self) -> Result<CaPersistedState, String> {
        Ok(CaPersistedState {
            issued: HashMap::new(),
            next_serial: 1,
            revoked: Vec::new(),
        })
    }
}

/// Certificate Signing Request for the distributed CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSigningRequest {
    pub module_name: String,
    pub subject_alt_names: Vec<String>,
    pub requested_by: NodeId,
    pub timestamp: i64,
    pub validity_hours: u32,
}

/// Issued certificate record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCert {
    pub serial: u64,
    pub module_name: String,
    pub subject_alt_names: Vec<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub issuer_quorum: Vec<NodeId>,
    pub fingerprint: Vec<u8>,
    pub revoked: bool,
}

/// Configuration for the distributed CA.
#[derive(Debug, Clone)]
pub struct DistributedCaConfig {
    /// Minimum signers required (FROST threshold)
    pub threshold: usize,
    /// Total CA signer nodes
    pub total_signers: usize,
    /// Default certificate validity (hours)
    pub default_validity_hours: u32,
    /// Maximum certificate validity (hours)
    pub max_validity_hours: u32,
    /// Auto-renewal threshold (renew when less than this many hours remain)
    pub renewal_threshold_hours: u32,
}

impl Default for DistributedCaConfig {
    fn default() -> Self {
        Self {
            threshold: 3,
            total_signers: 5,
            default_validity_hours: 720,  // 30 days
            max_validity_hours: 8760,     // 1 year
            renewal_threshold_hours: 168, // 7 days
        }
    }
}

/// The distributed CA state.
/// In production, the actual signing is delegated to FROST threshold signing
/// via the TSS service. This module manages the certificate lifecycle.
pub struct DistributedCa {
    config: DistributedCaConfig,
    /// Issued certificates by serial number
    issued: HashMap<u64, IssuedCert>,
    /// Next serial number
    next_serial: u64,
    /// Revoked certificate serials
    revoked: Vec<u64>,
    /// CA public key fingerprint (SHA-512 of the FROST group verifying key)
    ca_fingerprint: Vec<u8>,
    /// Persistence backend for CA state
    persistence: Box<dyn CaPersistence>,
    revocation_quorum: RevocationQuorum,
    /// Retired CA keys kept during grace period for verifying existing certs.
    retired_keys: Vec<RetiredCaKey>,
}

impl DistributedCa {
    /// Create a new DistributedCa with no persistence (in-memory only, for tests).
    pub fn new(config: DistributedCaConfig, ca_fingerprint: Vec<u8>) -> Self {
        Self::with_persistence(config, ca_fingerprint, Box::new(NullCaPersistence))
    }

    pub fn revocation_quorum_mut(&mut self) -> &mut RevocationQuorum { &mut self.revocation_quorum }

    /// Create a new DistributedCa with a persistence backend.
    /// Loads any previously persisted state from disk.
    pub fn with_persistence(
        config: DistributedCaConfig,
        ca_fingerprint: Vec<u8>,
        persistence: Box<dyn CaPersistence>,
    ) -> Self {
        let (issued, next_serial, revoked) = match persistence.load_state() {
            Ok(state) => (state.issued, state.next_serial, state.revoked),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "failed to load persisted CA state, starting fresh"
                );
                (HashMap::new(), 1, Vec::new())
            }
        };
        tracing::info!(
            issued = issued.len(),
            next_serial = next_serial,
            revoked = revoked.len(),
            "distributed CA initialized"
        );
        let revocation_quorum = RevocationQuorum::new(2);
        Self {
            config,
            issued,
            next_serial,
            revoked,
            ca_fingerprint,
            persistence,
            revocation_quorum,
            retired_keys: Vec::new(),
        }
    }

    /// Request a certificate. Returns the CSR details for threshold signing.
    pub fn create_csr(
        &self,
        module_name: &str,
        sans: Vec<String>,
        requested_by: NodeId,
    ) -> CertSigningRequest {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        CertSigningRequest {
            module_name: module_name.to_string(),
            subject_alt_names: sans,
            requested_by,
            timestamp: now,
            validity_hours: self.config.default_validity_hours,
        }
    }

    /// Record a certificate as issued (after threshold signing completes).
    pub fn record_issued(
        &mut self,
        csr: &CertSigningRequest,
        quorum: Vec<NodeId>,
        fingerprint: Vec<u8>,
    ) -> u64 {
        let serial = self.next_serial;
        // Persist the next serial BEFORE using it. If we crash after persisting
        // but before issuing, we skip a serial (safe). If we crash before
        // persisting, we reuse the serial on restart (also safe, since the cert
        // was never recorded). Belt-and-suspenders: persist serial+1 first.
        self.next_serial += 1;
        if let Err(e) = self.persistence.save_serial(self.next_serial) {
            tracing::error!(error = %e, serial = self.next_serial, "failed to persist next_serial");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let expires = now + (csr.validity_hours as i64 * 3600);

        let cert = IssuedCert {
            serial,
            module_name: csr.module_name.clone(),
            subject_alt_names: csr.subject_alt_names.clone(),
            issued_at: now,
            expires_at: expires,
            issuer_quorum: quorum,
            fingerprint,
            revoked: false,
        };
        self.issued.insert(serial, cert.clone());
        if let Err(e) = self.persistence.save_issued(&cert) {
            tracing::error!(error = %e, serial = serial, "failed to persist issued certificate");
        }
        serial
    }

    /// Submit a revocation vote. Requires quorum (2 of N coordinators).
    pub fn revoke(&mut self, serial: u64, voter_id: NodeId) -> bool {
        if !self.issued.contains_key(&serial) { return false; }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
        let vote = RevocationVote { serial, voter_id, timestamp: now };
        let quorum_reached = self.revocation_quorum.add_vote(vote);
        let is_military = std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok();
        let is_mlp_ack = std::env::var("MILNET_MLP_MODE_ACK").ok().as_deref() == Some("1");
        let emergency_bypass = is_military && is_mlp_ack && !quorum_reached;
        if emergency_bypass {
            tracing::error!(target: "siem", serial = serial, "SIEM:CRITICAL emergency single-entity revocation");
            crate::siem::SecurityEvent::circuit_breaker_opened("emergency_single_entity_revocation");
        }
        if quorum_reached || emergency_bypass {
            self.execute_revocation(serial);
            self.revocation_quorum.clear(serial);
            true
        } else {
            tracing::info!(serial = serial, "revocation vote recorded, awaiting quorum");
            false
        }
    }

    fn execute_revocation(&mut self, serial: u64) {
        if let Some(cert) = self.issued.get_mut(&serial) {
            cert.revoked = true;
            self.revoked.push(serial);
            if let Err(e) = self.persistence.save_issued(cert) {
                tracing::error!(error = %e, serial = serial, "failed to persist revoked cert");
            }
            if let Err(e) = self.persistence.save_revocation(serial) {
                tracing::error!(error = %e, serial = serial, "failed to persist revocation");
            }
        }
    }

    /// Check if a certificate is valid (not revoked, not expired).
    pub fn is_valid(&self, serial: u64) -> bool {
        if let Some(cert) = self.issued.get(&serial) {
            if cert.revoked {
                return false;
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            cert.expires_at > now
        } else {
            false
        }
    }

    /// Get certificates that need renewal.
    pub fn needs_renewal(&self) -> Vec<&IssuedCert> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let threshold = self.config.renewal_threshold_hours as i64 * 3600;
        self.issued
            .values()
            .filter(|c| !c.revoked && c.expires_at - now < threshold)
            .collect()
    }

    /// Get all revoked certificate serials (for CRL distribution).
    pub fn revocation_list(&self) -> &[u64] {
        &self.revoked
    }

    /// CA public key fingerprint.
    pub fn ca_fingerprint(&self) -> &[u8] {
        &self.ca_fingerprint
    }

    /// Total issued certificates.
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }
}

// ── CA Key Rotation Ceremony ──────────────────────────────────────────────
//
// SECURITY: The CA signing key MUST be rotated periodically. Rotation uses
// Pedersen DKG to generate a new FROST threshold key, cross-certifies old->new,
// and distributes new key packages to all nodes. The old key is maintained for
// a configurable grace period to verify existing certificates.

/// Event logged to SIEM when a CA key rotation occurs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaRotationEvent {
    pub timestamp: i64,
    pub old_key_fingerprint: Vec<u8>,
    pub new_key_fingerprint: Vec<u8>,
    /// Cross-certificate: old CA signs new CA's verifying key.
    pub cross_cert: Vec<u8>,
    /// Node IDs that approved the rotation.
    pub approvers: Vec<NodeId>,
}

/// Vote cast by a node to approve a CA key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationVote {
    pub voter_id: NodeId,
    pub new_key_fingerprint: Vec<u8>,
    pub timestamp: i64,
}

/// Tracks pending rotation votes and enforces quorum.
pub struct RotationQuorum {
    pub required: usize,
    pending_votes: Vec<RotationVote>,
}

impl RotationQuorum {
    pub fn new(required: usize) -> Self {
        Self { required, pending_votes: Vec::new() }
    }

    pub fn add_vote(&mut self, vote: RotationVote) -> bool {
        if self.pending_votes.iter().any(|v| v.voter_id == vote.voter_id) {
            return self.pending_votes.len() >= self.required;
        }
        self.pending_votes.push(vote);
        self.pending_votes.len() >= self.required
    }

    pub fn has_quorum(&self) -> bool {
        self.pending_votes.len() >= self.required
    }

    pub fn approvers(&self) -> Vec<NodeId> {
        self.pending_votes.iter().map(|v| v.voter_id).collect()
    }

    pub fn clear(&mut self) {
        self.pending_votes.clear();
    }
}

/// Retired CA key kept during the grace period for verifying existing certs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetiredCaKey {
    pub fingerprint: Vec<u8>,
    pub retired_at: i64,
    pub grace_period_secs: i64,
    pub cross_cert: Vec<u8>,
}

impl RetiredCaKey {
    /// Returns true if this retired key is still within its grace period.
    pub fn is_in_grace_period(&self, now: i64) -> bool {
        now < self.retired_at + self.grace_period_secs
    }
}

/// Default grace period for retired CA keys (7 days in seconds).
const DEFAULT_CA_KEY_GRACE_PERIOD_SECS: i64 = 7 * 24 * 3600;

/// Result of a CA key rotation ceremony.
#[derive(Debug, Clone)]
pub struct CaRotationResult {
    pub event: CaRotationEvent,
    pub new_fingerprint: Vec<u8>,
}

impl DistributedCa {
    /// Initiate a CA key rotation ceremony.
    ///
    /// Requires quorum approval (same threshold as revocation). The ceremony:
    /// 1. Generates new FROST threshold key via Pedersen DKG (simulated by
    ///    the caller providing the new verifying key fingerprint and cross-cert).
    /// 2. Signs a cross-certificate from old CA to new CA.
    /// 3. Updates the CA verifying key.
    /// 4. Retires old key with a configurable grace period.
    /// 5. Logs rotation event to SIEM.
    ///
    /// All nodes MUST independently verify the cross-certificate chain before
    /// accepting the new key.
    ///
    /// `new_key_fingerprint`: SHA-512 fingerprint of the new FROST group verifying key.
    /// `cross_cert`: Signature of old CA over new CA's verifying key (the caller
    ///     performs the actual FROST threshold signing ceremony to produce this).
    /// `rotation_quorum`: Quorum tracker with accumulated approval votes.
    /// `grace_period_secs`: How long the old key stays valid (default 7 days).
    pub fn rotate_ca_key(
        &mut self,
        new_key_fingerprint: Vec<u8>,
        cross_cert: Vec<u8>,
        rotation_quorum: &mut RotationQuorum,
        grace_period_secs: Option<i64>,
    ) -> Result<CaRotationResult, String> {
        // Require quorum approval before proceeding.
        if !rotation_quorum.has_quorum() {
            return Err(format!(
                "CA key rotation requires quorum ({} of {} votes). Current: {}",
                rotation_quorum.required,
                rotation_quorum.required,
                rotation_quorum.pending_votes.len()
            ));
        }

        // Validate inputs.
        if new_key_fingerprint.is_empty() {
            return Err("new CA key fingerprint must not be empty".into());
        }
        if cross_cert.is_empty() {
            return Err("cross-certificate must not be empty".into());
        }
        if new_key_fingerprint == self.ca_fingerprint {
            return Err("new CA key fingerprint must differ from current key".into());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let grace = grace_period_secs.unwrap_or(DEFAULT_CA_KEY_GRACE_PERIOD_SECS);
        let old_fingerprint = self.ca_fingerprint.clone();

        // Retire the old key with grace period.
        let retired = RetiredCaKey {
            fingerprint: old_fingerprint.clone(),
            retired_at: now,
            grace_period_secs: grace,
            cross_cert: cross_cert.clone(),
        };

        // Store retired key in the retired keys list.
        self.retired_keys.push(retired);

        // Prune expired retired keys.
        self.retired_keys.retain(|k| k.is_in_grace_period(now));

        let approvers = rotation_quorum.approvers();

        // Update to new CA key.
        self.ca_fingerprint = new_key_fingerprint.clone();

        let event = CaRotationEvent {
            timestamp: now,
            old_key_fingerprint: old_fingerprint,
            new_key_fingerprint: new_key_fingerprint.clone(),
            cross_cert,
            approvers: approvers.clone(),
        };

        // Log to SIEM.
        tracing::warn!(
            target: "siem",
            old_fp = hex::encode(&event.old_key_fingerprint),
            new_fp = hex::encode(&event.new_key_fingerprint),
            approver_count = approvers.len(),
            grace_period_secs = grace,
            "SIEM:CA_KEY_ROTATION CA signing key rotated via quorum ceremony"
        );
        crate::siem::SecurityEvent::circuit_breaker_opened("ca_key_rotation");

        rotation_quorum.clear();

        Ok(CaRotationResult {
            event,
            new_fingerprint: new_key_fingerprint,
        })
    }

    /// Check if a fingerprint matches the current CA key or any retired key
    /// still within its grace period. Use this when verifying existing certs
    /// that may have been signed by a previous CA key.
    pub fn is_known_ca_fingerprint(&self, fingerprint: &[u8]) -> bool {
        if self.ca_fingerprint == fingerprint {
            return true;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.retired_keys.iter().any(|k| {
            k.is_in_grace_period(now) && k.fingerprint == fingerprint
        })
    }

    /// Get all retired CA keys still within their grace period.
    pub fn active_retired_keys(&self) -> Vec<&RetiredCaKey> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.retired_keys.iter().filter(|k| k.is_in_grace_period(now)).collect()
    }
}

// ── CA Redundancy: Primary/Secondary Failover ──
//
// SECURITY: The CA must NOT be a single point of failure. In a military
// deployment, if the primary CA instance is compromised or unavailable,
// a secondary CA must seamlessly take over certificate issuance using
// the same FROST group verifying key (since the signing key is threshold-split
// across all nodes, any quorum can sign regardless of which CA instance
// coordinates the ceremony).

/// Status of a CA instance in the redundant pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaInstanceStatus {
    /// Actively issuing certificates.
    Primary,
    /// Hot standby, ready to take over.
    Secondary,
    /// Instance is unreachable or failed health checks.
    Unavailable,
}

/// A single CA instance in the redundant CA pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaInstance {
    pub instance_id: String,
    pub node_id: NodeId,
    pub status: CaInstanceStatus,
    pub last_health_check: i64,
    /// Number of consecutive failed health checks.
    pub consecutive_failures: u32,
}

/// Configuration for the redundant CA pool.
#[derive(Debug, Clone)]
pub struct RedundantCaConfig {
    /// Maximum consecutive health check failures before failover.
    pub max_failures_before_failover: u32,
    /// Health check interval in seconds.
    pub health_check_interval_secs: u64,
    /// Maximum age of a CA certificate before rotation (hours).
    pub ca_cert_max_age_hours: u32,
}

impl Default for RedundantCaConfig {
    fn default() -> Self {
        Self {
            max_failures_before_failover: 3,
            health_check_interval_secs: 10,
            ca_cert_max_age_hours: 8760, // 1 year
        }
    }
}

/// Manages a pool of CA instances with automatic failover.
///
/// The redundant CA pool ensures that certificate issuance continues
/// even if the primary CA instance fails. Because the signing key is
/// threshold-split (FROST), any CA instance coordinating a quorum of
/// signers can issue valid certificates.
pub struct RedundantCaPool {
    config: RedundantCaConfig,
    instances: Vec<CaInstance>,
    /// The underlying distributed CA state (shared across instances).
    ca: DistributedCa,
    /// Timestamp of last CA certificate rotation.
    last_ca_rotation: i64,
}

impl RedundantCaPool {
    /// Create a new redundant CA pool with the given instances.
    pub fn new(
        config: RedundantCaConfig,
        ca: DistributedCa,
        instances: Vec<CaInstance>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        Self {
            config,
            instances,
            ca,
            last_ca_rotation: now,
        }
    }

    /// Get the current primary CA instance, if any.
    pub fn primary(&self) -> Option<&CaInstance> {
        self.instances
            .iter()
            .find(|i| i.status == CaInstanceStatus::Primary)
    }

    /// Get all secondary (standby) instances.
    pub fn secondaries(&self) -> Vec<&CaInstance> {
        self.instances
            .iter()
            .filter(|i| i.status == CaInstanceStatus::Secondary)
            .collect()
    }

    /// Record a health check result for a CA instance.
    ///
    /// If the primary exceeds `max_failures_before_failover`, the pool
    /// automatically promotes a secondary to primary.
    pub fn record_health_check(&mut self, instance_id: &str, healthy: bool) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut failover_target: Option<String> = None;

        // Update the instance's health status.
        if let Some(instance) = self.instances.iter_mut().find(|i| i.instance_id == instance_id) {
            instance.last_health_check = now;
            if healthy {
                instance.consecutive_failures = 0;
                if instance.status == CaInstanceStatus::Unavailable {
                    // Recovered instance becomes a secondary.
                    instance.status = CaInstanceStatus::Secondary;
                    tracing::info!(
                        instance_id = %instance_id,
                        "CA instance recovered, demoted to secondary"
                    );
                }
            } else {
                instance.consecutive_failures += 1;
                if instance.consecutive_failures >= self.config.max_failures_before_failover {
                    let was_primary = instance.status == CaInstanceStatus::Primary;
                    instance.status = CaInstanceStatus::Unavailable;
                    tracing::error!(
                        instance_id = %instance_id,
                        failures = instance.consecutive_failures,
                        "CA instance marked unavailable"
                    );

                    // If the primary failed, trigger failover.
                    if was_primary {
                        failover_target = self.promote_secondary();
                    }
                }
            }
        }

        failover_target
    }

    /// Promote the first available secondary to primary.
    ///
    /// Returns the instance_id of the newly promoted primary, or None if
    /// no secondaries are available (total CA failure -- SIEM critical alert).
    fn promote_secondary(&mut self) -> Option<String> {
        for instance in &mut self.instances {
            if instance.status == CaInstanceStatus::Secondary {
                instance.status = CaInstanceStatus::Primary;
                tracing::warn!(
                    instance_id = %instance.instance_id,
                    "FAILOVER: secondary CA promoted to primary"
                );
                crate::siem::SecurityEvent::circuit_breaker_opened("distributed_ca_failover");
                return Some(instance.instance_id.clone());
            }
        }

        // No secondaries available -- critical failure.
        tracing::error!(
            "CRITICAL: No secondary CA instances available for failover. \
             Certificate issuance is UNAVAILABLE."
        );
        None
    }

    /// Check if the CA certificate needs rotation based on age.
    pub fn needs_ca_rotation(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let age_hours = (now - self.last_ca_rotation) / 3600;
        age_hours >= self.config.ca_cert_max_age_hours as i64
    }

    /// Record that a CA certificate rotation has been performed.
    pub fn record_ca_rotation(&mut self) {
        self.last_ca_rotation = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        tracing::info!("CA certificate rotation recorded");
    }

    /// Access the underlying distributed CA.
    pub fn ca(&self) -> &DistributedCa {
        &self.ca
    }

    /// Access the underlying distributed CA mutably.
    pub fn ca_mut(&mut self) -> &mut DistributedCa {
        &mut self.ca
    }

    /// Total number of CA instances in the pool.
    pub fn instance_count(&self) -> usize {
        self.instances.len()
    }

    /// Number of available (non-unavailable) instances.
    pub fn available_count(&self) -> usize {
        self.instances
            .iter()
            .filter(|i| i.status != CaInstanceStatus::Unavailable)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn node(n: u8) -> NodeId {
        NodeId(Uuid::from_bytes([n; 16]))
    }

    fn make_ca() -> DistributedCa {
        DistributedCa::new(
            DistributedCaConfig::default(),
            vec![0xCA; 64],
        )
    }

    #[test]
    fn test_csr_creation() {
        let ca = make_ca();
        let csr = ca.create_csr(
            "gateway",
            vec!["gateway.milnet.mil".into()],
            node(1),
        );
        assert_eq!(csr.module_name, "gateway");
        assert_eq!(csr.subject_alt_names, vec!["gateway.milnet.mil"]);
        assert_eq!(csr.validity_hours, 720);
        assert!(csr.timestamp > 0);
    }

    #[test]
    fn test_certificate_issuance() {
        let mut ca = make_ca();
        let csr = ca.create_csr(
            "orchestrator",
            vec!["orch.milnet.mil".into()],
            node(1),
        );
        let quorum = vec![node(1), node(2)];
        let serial = ca.record_issued(&csr, quorum, vec![0xFF; 32]);
        assert_eq!(serial, 1);
        assert_eq!(ca.issued_count(), 1);

        // Second issuance gets serial 2
        let csr2 = ca.create_csr("verifier", vec![], node(2));
        let serial2 = ca.record_issued(&csr2, vec![node(2), node(3)], vec![0xEE; 32]);
        assert_eq!(serial2, 2);
        assert_eq!(ca.issued_count(), 2);
    }

    #[test]
    fn test_certificate_revocation_requires_quorum() {
        let mut ca = make_ca();
        let csr = ca.create_csr("tss", vec![], node(1));
        let serial = ca.record_issued(&csr, vec![node(1), node(2)], vec![0xAB; 32]);
        assert!(ca.is_valid(serial));
        assert!(!ca.revoke(serial, node(1)));
        assert!(ca.is_valid(serial));
        assert!(ca.revoke(serial, node(2)));
        assert!(!ca.is_valid(serial));
        assert!(!ca.revoke(999, node(1)));
    }

    #[test]
    fn test_validity_checking() {
        let mut ca = make_ca();
        let csr = ca.create_csr("audit", vec![], node(1));
        let serial = ca.record_issued(&csr, vec![node(1), node(2)], vec![0xCD; 32]);

        // Should be valid (just issued, 30 days validity)
        assert!(ca.is_valid(serial));

        // Non-existent serial is not valid
        assert!(!ca.is_valid(42));

        // Revoked cert is not valid (two votes for quorum)
        ca.revoke(serial, node(1));
        ca.revoke(serial, node(2));
        assert!(!ca.is_valid(serial));
    }

    #[test]
    fn test_renewal_detection() {
        let mut ca = make_ca();

        // Issue a cert that will expire far in the future (default 720h)
        let csr = ca.create_csr("gateway", vec![], node(1));
        let serial_far = ca.record_issued(&csr, vec![node(1), node(2)], vec![0x11; 32]);

        // Certs with 720h left should NOT need renewal (threshold is 168h)
        let renewals = ca.needs_renewal();
        assert!(
            !renewals.iter().any(|c| c.serial == serial_far),
            "cert with 720h remaining should not need renewal"
        );

        // Manually create a cert that expires very soon
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let soon_cert = IssuedCert {
            serial: 100,
            module_name: "expiring-soon".into(),
            subject_alt_names: vec![],
            issued_at: now - 3600 * 700,
            expires_at: now + 3600 * 24, // 24h left, below 168h threshold
            issuer_quorum: vec![node(1)],
            fingerprint: vec![0x22; 32],
            revoked: false,
        };
        ca.issued.insert(100, soon_cert);

        let renewals = ca.needs_renewal();
        assert!(renewals.iter().any(|c| c.serial == 100));
    }

    #[test]
    fn test_revocation_list() {
        let mut ca = make_ca();

        let csr1 = ca.create_csr("a", vec![], node(1));
        let s1 = ca.record_issued(&csr1, vec![node(1)], vec![]);

        let csr2 = ca.create_csr("b", vec![], node(1));
        let s2 = ca.record_issued(&csr2, vec![node(1)], vec![]);

        let csr3 = ca.create_csr("c", vec![], node(1));
        let _s3 = ca.record_issued(&csr3, vec![node(1)], vec![]);

        assert!(ca.revocation_list().is_empty());

        ca.revoke(s1, node(1));
        ca.revoke(s1, node(2));
        ca.revoke(s2, node(1));
        ca.revoke(s2, node(2));

        assert_eq!(ca.revocation_list(), &[s1, s2]);
    }

    #[test]
    fn test_ca_fingerprint() {
        let ca = make_ca();
        assert_eq!(ca.ca_fingerprint(), &[0xCA; 64]);
    }

    // ── CA Key Rotation ────────────────────────────────────────────────

    #[test]
    fn test_rotation_requires_quorum() {
        let mut ca = make_ca();
        let mut rq = RotationQuorum::new(2);
        let result = ca.rotate_ca_key(vec![0xBB; 64], vec![0x01; 128], &mut rq, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("quorum"));
    }

    #[test]
    fn test_rotation_rejects_same_key() {
        let mut ca = make_ca();
        let mut rq = RotationQuorum::new(2);
        rq.add_vote(RotationVote { voter_id: node(1), new_key_fingerprint: vec![0xCA; 64], timestamp: 1 });
        rq.add_vote(RotationVote { voter_id: node(2), new_key_fingerprint: vec![0xCA; 64], timestamp: 2 });
        let result = ca.rotate_ca_key(vec![0xCA; 64], vec![0x01; 128], &mut rq, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must differ"));
    }

    #[test]
    fn test_rotation_rejects_empty_cross_cert() {
        let mut ca = make_ca();
        let mut rq = RotationQuorum::new(2);
        rq.add_vote(RotationVote { voter_id: node(1), new_key_fingerprint: vec![0xBB; 64], timestamp: 1 });
        rq.add_vote(RotationVote { voter_id: node(2), new_key_fingerprint: vec![0xBB; 64], timestamp: 2 });
        let result = ca.rotate_ca_key(vec![0xBB; 64], vec![], &mut rq, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotation_succeeds_with_quorum() {
        let mut ca = make_ca();
        let mut rq = RotationQuorum::new(2);
        rq.add_vote(RotationVote { voter_id: node(1), new_key_fingerprint: vec![0xBB; 64], timestamp: 1 });
        rq.add_vote(RotationVote { voter_id: node(2), new_key_fingerprint: vec![0xBB; 64], timestamp: 2 });
        let new_fp = vec![0xBB; 64];
        let cross = vec![0x01; 128];
        let result = ca.rotate_ca_key(new_fp.clone(), cross.clone(), &mut rq, Some(3600));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.new_fingerprint, new_fp);
        assert_eq!(r.event.old_key_fingerprint, vec![0xCA; 64]);
        assert_eq!(r.event.approvers.len(), 2);
        assert_eq!(ca.ca_fingerprint(), &new_fp[..]);
    }

    #[test]
    fn test_rotation_old_key_in_grace_period() {
        let mut ca = make_ca();
        let old_fp = ca.ca_fingerprint().to_vec();
        let mut rq = RotationQuorum::new(2);
        rq.add_vote(RotationVote { voter_id: node(1), new_key_fingerprint: vec![0xBB; 64], timestamp: 1 });
        rq.add_vote(RotationVote { voter_id: node(2), new_key_fingerprint: vec![0xBB; 64], timestamp: 2 });
        ca.rotate_ca_key(vec![0xBB; 64], vec![0x01; 128], &mut rq, Some(86400)).unwrap();

        // Old key still recognized during grace period.
        assert!(ca.is_known_ca_fingerprint(&old_fp));
        // New key recognized.
        assert!(ca.is_known_ca_fingerprint(&[0xBB; 64]));
        // Unknown key not recognized.
        assert!(!ca.is_known_ca_fingerprint(&[0xFF; 64]));
    }

    #[test]
    fn test_rotation_clears_quorum() {
        let mut ca = make_ca();
        let mut rq = RotationQuorum::new(2);
        rq.add_vote(RotationVote { voter_id: node(1), new_key_fingerprint: vec![0xBB; 64], timestamp: 1 });
        rq.add_vote(RotationVote { voter_id: node(2), new_key_fingerprint: vec![0xBB; 64], timestamp: 2 });
        ca.rotate_ca_key(vec![0xBB; 64], vec![0x01; 128], &mut rq, None).unwrap();
        // Quorum should be cleared after rotation.
        assert!(!rq.has_quorum());
    }

    #[test]
    fn test_double_rotation() {
        let mut ca = make_ca();
        let original_fp = ca.ca_fingerprint().to_vec();

        // First rotation.
        let mut rq1 = RotationQuorum::new(2);
        rq1.add_vote(RotationVote { voter_id: node(1), new_key_fingerprint: vec![0xAA; 64], timestamp: 1 });
        rq1.add_vote(RotationVote { voter_id: node(2), new_key_fingerprint: vec![0xAA; 64], timestamp: 2 });
        ca.rotate_ca_key(vec![0xAA; 64], vec![0x01; 128], &mut rq1, Some(86400)).unwrap();

        // Second rotation.
        let mut rq2 = RotationQuorum::new(2);
        rq2.add_vote(RotationVote { voter_id: node(1), new_key_fingerprint: vec![0xBB; 64], timestamp: 3 });
        rq2.add_vote(RotationVote { voter_id: node(2), new_key_fingerprint: vec![0xBB; 64], timestamp: 4 });
        ca.rotate_ca_key(vec![0xBB; 64], vec![0x02; 128], &mut rq2, Some(86400)).unwrap();

        assert_eq!(ca.ca_fingerprint(), &[0xBB; 64]);
        assert!(ca.is_known_ca_fingerprint(&original_fp));
        assert!(ca.is_known_ca_fingerprint(&[0xAA; 64]));
        assert!(ca.is_known_ca_fingerprint(&[0xBB; 64]));
        assert_eq!(ca.active_retired_keys().len(), 2);
    }
}
