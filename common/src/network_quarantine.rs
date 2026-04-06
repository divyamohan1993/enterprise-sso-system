//! Network-level quarantine that severs TLS connections from compromised nodes.
//! Unlike logical quarantine (Raft membership), this operates at the transport
//! layer and does not require cluster consensus.
//!
//! Usage in the TLS acceptor path:
//! 1. Extract client certificate from the TLS handshake
//! 2. Compute SHA-512 fingerprint of the DER-encoded certificate
//! 3. Check `is_cert_blocked()` before processing any application data
//! 4. If blocked, drop the connection immediately (no error response)
//!
//! This provides defense-in-depth: even if a compromised node bypasses Raft
//! membership checks, the TLS layer will refuse its connections.

use crate::siem::{PanelSiemEvent, SiemPanel, SiemSeverity};
use std::collections::HashSet;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// NetworkQuarantine
// ---------------------------------------------------------------------------

/// Transport-layer blocklist for compromised node IDs and certificate fingerprints.
///
/// Thread-safe via `Mutex`. The critical path (`is_blocked` / `is_cert_blocked`)
/// acquires the lock briefly for a HashSet lookup, which is O(1) amortized.
pub struct NetworkQuarantine {
    /// Blocked node identifiers (logical IDs like "node-3" or UUIDs).
    blocked_nodes: Mutex<HashSet<String>>,
    /// Blocked certificate fingerprints (SHA-512 of DER-encoded cert).
    blocked_fingerprints: Mutex<HashSet<[u8; 64]>>,
}

impl NetworkQuarantine {
    /// Create a new empty quarantine.
    pub fn new() -> Self {
        Self {
            blocked_nodes: Mutex::new(HashSet::new()),
            blocked_fingerprints: Mutex::new(HashSet::new()),
        }
    }

    /// Block a node by ID and certificate fingerprint.
    ///
    /// Both the node ID and certificate fingerprint are added to the blocklist.
    /// This ensures the node cannot reconnect even if it obtains a new logical
    /// identity (the cert fingerprint still matches).
    pub fn block_node(&self, node_id: &str, cert_fingerprint: &[u8; 64]) {
        {
            let mut nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
            nodes.insert(node_id.to_string());
        }
        {
            let mut fps = self
                .blocked_fingerprints
                .lock()
                .unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
            fps.insert(*cert_fingerprint);
        }

        PanelSiemEvent::new(
            SiemPanel::NetworkAnomalies,
            SiemSeverity::Critical,
            "network_quarantine_block",
            format!(
                "Node blocked at transport layer: node_id={}, cert_fp={}",
                node_id,
                hex::encode(&cert_fingerprint[..8]), // log first 8 bytes only
            ),
            file!(),
            line!(),
            module_path!(),
        )
        .emit();

        tracing::warn!(
            node_id = %node_id,
            "network quarantine: node blocked at TLS layer"
        );
    }

    /// Check if a node ID is blocked.
    pub fn is_blocked(&self, node_id: &str) -> bool {
        let nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.contains(node_id)
    }

    /// Check if a certificate fingerprint is blocked.
    pub fn is_cert_blocked(&self, fingerprint: &[u8; 64]) -> bool {
        let fps = self
            .blocked_fingerprints
            .lock()
            .unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        fps.contains(fingerprint)
    }

    /// Number of blocked nodes.
    pub fn blocked_count(&self) -> usize {
        let nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.len()
    }

    /// List all blocked node IDs (for admin dashboard).
    pub fn blocked_node_ids(&self) -> Vec<String> {
        let nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.iter().cloned().collect()
    }

    /// Remove a node from the blocklist (after verified remediation).
    ///
    /// Only removes the node ID. The certificate fingerprint stays blocked
    /// permanently, forcing the remediated node to use a new certificate.
    pub fn unblock_node(&self, node_id: &str) {
        let mut nodes = self.blocked_nodes.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in network_quarantine - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        nodes.remove(node_id);

        PanelSiemEvent::new(
            SiemPanel::NetworkAnomalies,
            SiemSeverity::Warning,
            "network_quarantine_unblock",
            format!("Node unblocked at transport layer: node_id={node_id} (cert fingerprint remains blocked)"),
            file!(),
            line!(),
            module_path!(),
        )
        .emit();
    }
}

impl Default for NetworkQuarantine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PersistentNetworkQuarantine -- file-backed quarantine with HMAC integrity
// ---------------------------------------------------------------------------

/// File-backed network quarantine with HMAC-SHA512 integrity verification.
///
/// Persists blocked node IDs and certificate fingerprints to a JSON file
/// with an HMAC-SHA512 tag for tamper detection. This is not database-backed
/// because network quarantine is cluster infrastructure that must function
/// even when the database is unavailable (defense-in-depth).
///
/// On construction, the file is loaded and its HMAC is verified. If the file
/// is missing, the quarantine starts empty. If the HMAC fails verification,
/// a SIEM critical alert is emitted and the file is treated as tampered
/// (quarantine starts empty to avoid trusting attacker-modified data, but
/// the corrupted file is preserved for forensic analysis).
///
/// Writes are append-friendly: the entire state is re-serialized on each
/// block/unblock operation. This is acceptable because quarantine mutations
/// are rare (compromise events) and the dataset is small.
pub struct PersistentNetworkQuarantine {
    inner: NetworkQuarantine,
    file_path: std::path::PathBuf,
    hmac_key: [u8; 64],
}

/// Serializable quarantine state for file persistence.
#[derive(serde::Serialize, serde::Deserialize)]
struct QuarantineFileState {
    blocked_nodes: Vec<String>,
    blocked_fingerprints: Vec<String>, // hex-encoded [u8; 64]
    hmac_hex: String,
}

impl PersistentNetworkQuarantine {
    /// Create a new persistent quarantine, loading state from `file_path` if it exists.
    ///
    /// `hmac_key` should be derived from the master KEK via HKDF for consistency
    /// across restarts.
    pub fn new(file_path: std::path::PathBuf, hmac_key: [u8; 64]) -> Self {
        let mut pq = Self {
            inner: NetworkQuarantine::new(),
            file_path,
            hmac_key,
        };
        if let Err(e) = pq.load_from_file() {
            // Non-fatal: start empty but warn
            PanelSiemEvent::new(
                SiemPanel::NetworkAnomalies,
                SiemSeverity::Critical,
                "quarantine_load_failed",
                format!("Failed to load network quarantine from file: {e}"),
                file!(), line!(), module_path!(),
            ).emit();
        }
        pq
    }

    /// Compute HMAC-SHA512 over the serialized quarantine state (excluding the hmac field).
    fn compute_hmac(&self, nodes: &[String], fingerprints: &[String]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;

        let mut mac = HmacSha512::new_from_slice(&self.hmac_key)
            .expect("HMAC-SHA512 accepts any key length");
        // Canonical serialization: sorted entries, newline-separated
        let mut sorted_nodes = nodes.to_vec();
        sorted_nodes.sort();
        let mut sorted_fps = fingerprints.to_vec();
        sorted_fps.sort();
        for n in &sorted_nodes {
            mac.update(b"node:");
            mac.update(n.as_bytes());
            mac.update(b"\n");
        }
        for f in &sorted_fps {
            mac.update(b"fp:");
            mac.update(f.as_bytes());
            mac.update(b"\n");
        }
        hex::encode(mac.finalize().into_bytes())
    }

    /// Load quarantine state from the file, verifying HMAC integrity.
    fn load_from_file(&mut self) -> Result<(), String> {
        let data = match std::fs::read_to_string(&self.file_path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("read quarantine file: {e}")),
        };

        let state: QuarantineFileState = serde_json::from_str(&data)
            .map_err(|e| format!("parse quarantine file: {e}"))?;

        // Verify HMAC integrity
        let expected_hmac = self.compute_hmac(&state.blocked_nodes, &state.blocked_fingerprints);
        if !crypto::ct::ct_eq(expected_hmac.as_bytes(), state.hmac_hex.as_bytes()) {
            PanelSiemEvent::new(
                SiemPanel::NetworkAnomalies,
                SiemSeverity::Critical,
                "quarantine_tamper_detected",
                "Network quarantine file HMAC verification failed. File may be tampered. \
                 Starting with empty quarantine. Corrupted file preserved for forensics.",
                file!(), line!(), module_path!(),
            ).emit();
            return Err("HMAC verification failed -- possible tampering".to_string());
        }

        // Restore state
        for node_id in &state.blocked_nodes {
            self.inner.blocked_nodes.lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(node_id.clone());
        }
        for fp_hex in &state.blocked_fingerprints {
            if let Ok(fp_bytes) = hex::decode(fp_hex) {
                if fp_bytes.len() == 64 {
                    let mut fp = [0u8; 64];
                    fp.copy_from_slice(&fp_bytes);
                    self.inner.blocked_fingerprints.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(fp);
                }
            }
        }

        Ok(())
    }

    /// Persist the current quarantine state to the file with HMAC integrity.
    fn save_to_file(&self) -> Result<(), String> {
        let nodes: Vec<String> = self.inner.blocked_nodes.lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter().cloned().collect();
        let fingerprints: Vec<String> = self.inner.blocked_fingerprints.lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter().map(hex::encode).collect();

        let hmac_hex = self.compute_hmac(&nodes, &fingerprints);

        let state = QuarantineFileState {
            blocked_nodes: nodes,
            blocked_fingerprints: fingerprints,
            hmac_hex,
        };

        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| format!("serialize quarantine: {e}"))?;

        // Atomic write: write to temp file then rename
        let tmp_path = self.file_path.with_extension("tmp");
        std::fs::write(&tmp_path, &json)
            .map_err(|e| format!("write quarantine temp file: {e}"))?;
        std::fs::rename(&tmp_path, &self.file_path)
            .map_err(|e| format!("rename quarantine file: {e}"))?;

        Ok(())
    }

    /// Block a node by ID and certificate fingerprint, persisting to file.
    pub fn block_node(&self, node_id: &str, cert_fingerprint: &[u8; 64]) {
        self.inner.block_node(node_id, cert_fingerprint);
        if let Err(e) = self.save_to_file() {
            PanelSiemEvent::new(
                SiemPanel::NetworkAnomalies,
                SiemSeverity::Critical,
                "quarantine_persist_failed",
                format!("Failed to persist quarantine after blocking node {node_id}: {e}"),
                file!(), line!(), module_path!(),
            ).emit();
        }
    }

    /// Check if a node ID is blocked.
    pub fn is_blocked(&self, node_id: &str) -> bool {
        self.inner.is_blocked(node_id)
    }

    /// Check if a certificate fingerprint is blocked.
    pub fn is_cert_blocked(&self, fingerprint: &[u8; 64]) -> bool {
        self.inner.is_cert_blocked(fingerprint)
    }

    /// Number of blocked nodes.
    pub fn blocked_count(&self) -> usize {
        self.inner.blocked_count()
    }

    /// List all blocked node IDs.
    pub fn blocked_node_ids(&self) -> Vec<String> {
        self.inner.blocked_node_ids()
    }

    /// Remove a node from the blocklist, persisting to file.
    pub fn unblock_node(&self, node_id: &str) {
        self.inner.unblock_node(node_id);
        if let Err(e) = self.save_to_file() {
            PanelSiemEvent::new(
                SiemPanel::NetworkAnomalies,
                SiemSeverity::Critical,
                "quarantine_persist_failed",
                format!("Failed to persist quarantine after unblocking node {node_id}: {e}"),
                file!(), line!(), module_path!(),
            ).emit();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fingerprint(fill: u8) -> [u8; 64] {
        [fill; 64]
    }

    #[test]
    fn new_quarantine_is_empty() {
        let nq = NetworkQuarantine::new();
        assert_eq!(nq.blocked_count(), 0);
        assert!(!nq.is_blocked("node-1"));
        assert!(!nq.is_cert_blocked(&make_fingerprint(0xAA)));
    }

    #[test]
    fn block_node_adds_to_both_lists() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xBB);
        nq.block_node("node-3", &fp);

        assert!(nq.is_blocked("node-3"));
        assert!(nq.is_cert_blocked(&fp));
        assert_eq!(nq.blocked_count(), 1);
    }

    #[test]
    fn block_multiple_nodes() {
        let nq = NetworkQuarantine::new();
        nq.block_node("node-1", &make_fingerprint(0x01));
        nq.block_node("node-2", &make_fingerprint(0x02));
        nq.block_node("node-3", &make_fingerprint(0x03));

        assert_eq!(nq.blocked_count(), 3);
        assert!(nq.is_blocked("node-1"));
        assert!(nq.is_blocked("node-2"));
        assert!(nq.is_blocked("node-3"));
        assert!(!nq.is_blocked("node-4"));
    }

    #[test]
    fn duplicate_block_is_idempotent() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xCC);
        nq.block_node("node-1", &fp);
        nq.block_node("node-1", &fp);
        assert_eq!(nq.blocked_count(), 1);
    }

    #[test]
    fn cert_fingerprint_matching_exact() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xDD);
        nq.block_node("node-1", &fp);

        // Exact match
        assert!(nq.is_cert_blocked(&fp));
        // Different fingerprint
        assert!(!nq.is_cert_blocked(&make_fingerprint(0xEE)));
        // One byte different
        let mut almost = fp;
        almost[63] = 0x00;
        assert!(!nq.is_cert_blocked(&almost));
    }

    #[test]
    fn unblock_node_removes_id_keeps_cert() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xFF);
        nq.block_node("node-5", &fp);

        assert!(nq.is_blocked("node-5"));
        assert!(nq.is_cert_blocked(&fp));

        nq.unblock_node("node-5");
        assert!(!nq.is_blocked("node-5"));
        // Certificate fingerprint remains blocked (node must get new cert)
        assert!(nq.is_cert_blocked(&fp));
        assert_eq!(nq.blocked_count(), 0);
    }

    #[test]
    fn blocked_node_ids_list() {
        let nq = NetworkQuarantine::new();
        nq.block_node("alpha", &make_fingerprint(0x01));
        nq.block_node("beta", &make_fingerprint(0x02));

        let mut ids = nq.blocked_node_ids();
        ids.sort();
        assert_eq!(ids, vec!["alpha", "beta"]);
    }

    #[test]
    fn unblock_nonexistent_is_noop() {
        let nq = NetworkQuarantine::new();
        nq.unblock_node("ghost");
        assert_eq!(nq.blocked_count(), 0);
    }

    #[test]
    fn default_impl() {
        let nq: NetworkQuarantine = Default::default();
        assert_eq!(nq.blocked_count(), 0);
    }

    #[test]
    fn different_nodes_same_fingerprint() {
        let nq = NetworkQuarantine::new();
        let fp = make_fingerprint(0xAA);
        nq.block_node("node-a", &fp);
        nq.block_node("node-b", &fp);

        assert_eq!(nq.blocked_count(), 2);
        assert!(nq.is_blocked("node-a"));
        assert!(nq.is_blocked("node-b"));
        // Only one fingerprint entry (same fingerprint)
        assert!(nq.is_cert_blocked(&fp));
    }
}
