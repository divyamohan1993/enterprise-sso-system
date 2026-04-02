//! Network quarantine and incident response pipeline.
//!
//! Pipeline: Detect -> Quarantine -> Investigate -> Heal -> Verify -> Rejoin
//!
//! Quarantine actions:
//! 1. Revoke the node's cluster membership (Raft MemberLeave)
//! 2. Rotate all channel keys that the compromised node had access to
//! 3. Block the node's IP in all peer firewall rules
//! 4. Force-close all active connections from the quarantined node
//! 5. Log forensic snapshot (process list, open files, network connections)

use crate::raft::{ClusterCommand, NodeId};
use std::collections::HashMap;
use std::time::Instant;

// ── QuarantineState ───────────────────────────────────────────────────────────

/// Quarantine state for a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineState {
    /// Normal operation.
    Active,
    /// Suspected compromise -- under enhanced monitoring.
    Suspected,
    /// Confirmed compromise -- network isolated.
    Quarantined,
    /// Being healed -- binary replacement in progress.
    Healing,
    /// Healed and verified -- waiting to rejoin.
    PendingRejoin,
}

impl std::fmt::Display for QuarantineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineState::Active => write!(f, "active"),
            QuarantineState::Suspected => write!(f, "suspected"),
            QuarantineState::Quarantined => write!(f, "quarantined"),
            QuarantineState::Healing => write!(f, "healing"),
            QuarantineState::PendingRejoin => write!(f, "pending_rejoin"),
        }
    }
}

// ── QuarantineRecord ──────────────────────────────────────────────────────────

/// Full quarantine record for a single node.
pub struct QuarantineRecord {
    pub node_id: NodeId,
    pub state: QuarantineState,
    pub quarantined_at: Option<Instant>,
    pub reason: String,
    pub forensic_snapshot: Option<ForensicSnapshot>,
    pub channels_rotated: Vec<String>,
    pub heal_attempts: u32,
    pub max_heal_attempts: u32,
}

// ── ForensicSnapshot ──────────────────────────────────────────────────────────

/// Forensic data captured at quarantine time from /proc and environment.
pub struct ForensicSnapshot {
    pub timestamp: i64,
    /// Process status from /proc/self/status.
    pub process_list: String,
    /// Open file descriptors from /proc/self/fd.
    pub open_files: String,
    /// Network connections from /proc/net/tcp.
    pub network_connections: String,
    /// Loaded libraries from /proc/self/maps.
    pub loaded_libraries: String,
    /// Sanitized environment variables (secrets redacted).
    pub environment: String,
}

impl ForensicSnapshot {
    /// Capture a forensic snapshot from the local /proc filesystem.
    pub fn capture() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let process_list = std::fs::read_to_string("/proc/self/status")
            .unwrap_or_else(|e| format!("error reading /proc/self/status: {e}"));

        let open_files = capture_open_fds();

        let network_connections = std::fs::read_to_string("/proc/net/tcp")
            .unwrap_or_else(|e| format!("error reading /proc/net/tcp: {e}"));

        let loaded_libraries = match std::fs::read_to_string("/proc/self/maps") {
            Ok(maps) => redact_aslr_addresses(&maps),
            Err(e) => format!("error reading /proc/self/maps: {e}"),
        };

        let environment = capture_sanitized_env();

        Self {
            timestamp,
            process_list,
            open_files,
            network_connections,
            loaded_libraries,
            environment,
        }
    }
}

impl std::fmt::Debug for ForensicSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForensicSnapshot")
            .field("timestamp", &self.timestamp)
            .field("process_list_len", &self.process_list.len())
            .field("open_files_len", &self.open_files.len())
            .field("network_connections_len", &self.network_connections.len())
            .field("loaded_libraries_len", &self.loaded_libraries.len())
            .field("environment_len", &self.environment.len())
            .finish()
    }
}

// ── QuarantineManager ─────────────────────────────────────────────────────────

/// Manages quarantine state for all nodes in the cluster.
pub struct QuarantineManager {
    records: HashMap<NodeId, QuarantineRecord>,
    /// Maximum healing attempts before permanent exclusion (default: 3).
    max_heal_attempts: u32,
    /// Channels each node had access to (for key rotation on quarantine).
    node_channels: HashMap<NodeId, Vec<String>>,
}

impl QuarantineManager {
    /// Create a new quarantine manager with default settings.
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            max_heal_attempts: 3,
            node_channels: HashMap::new(),
        }
    }

    /// Register channels that a node has access to (call during node join).
    pub fn register_node_channels(&mut self, node_id: NodeId, channels: Vec<String>) {
        self.node_channels.insert(node_id, channels);
    }

    /// Begin quarantine process for a suspected node.
    /// Returns list of ClusterCommands to propose via Raft.
    pub fn quarantine_node(
        &mut self,
        node_id: NodeId,
        reason: String,
    ) -> Vec<ClusterCommand> {
        let now = Instant::now();

        // Capture forensic snapshot before quarantine
        let snapshot = ForensicSnapshot::capture();

        // Determine channels to rotate
        let channels = self
            .node_channels
            .get(&node_id)
            .cloned()
            .unwrap_or_default();

        let record = QuarantineRecord {
            node_id,
            state: QuarantineState::Quarantined,
            quarantined_at: Some(now),
            reason: reason.clone(),
            forensic_snapshot: Some(snapshot),
            channels_rotated: channels.clone(),
            heal_attempts: 0,
            max_heal_attempts: self.max_heal_attempts,
        };

        self.records.insert(node_id, record);

        tracing::warn!(
            node = %node_id,
            reason = %reason,
            channels_to_rotate = channels.len(),
            "quarantine: node quarantined"
        );

        // Build the Raft commands
        let mut commands = Vec::new();

        // 1. Remove from cluster
        commands.push(ClusterCommand::MemberLeave { node_id });

        // 2. Mark unhealthy
        commands.push(ClusterCommand::HealthUpdate {
            node_id,
            healthy: false,
        });

        // 3. Tamper detected (use empty hashes since we may not have them)
        commands.push(ClusterCommand::TamperDetected {
            node_id,
            expected_hash: Vec::new(),
            actual_hash: Vec::new(),
        });

        commands
    }

    /// Capture forensic snapshot from local /proc.
    pub fn capture_forensic_snapshot() -> ForensicSnapshot {
        ForensicSnapshot::capture()
    }

    /// Get channels that need key rotation after quarantine.
    pub fn channels_to_rotate(&self, node_id: &NodeId) -> Vec<String> {
        self.records
            .get(node_id)
            .map(|r| r.channels_rotated.clone())
            .unwrap_or_default()
    }

    /// Advance to healing state.
    pub fn begin_healing(&mut self, node_id: &NodeId) -> Result<(), String> {
        let record = self
            .records
            .get_mut(node_id)
            .ok_or_else(|| format!("no quarantine record for node {node_id}"))?;

        if record.state != QuarantineState::Quarantined {
            return Err(format!(
                "node {node_id} is in state {}, expected Quarantined",
                record.state
            ));
        }

        if record.heal_attempts >= record.max_heal_attempts {
            return Err(format!(
                "node {node_id} has exceeded max heal attempts ({})",
                record.max_heal_attempts
            ));
        }

        record.heal_attempts += 1;
        record.state = QuarantineState::Healing;

        tracing::info!(
            node = %node_id,
            attempt = record.heal_attempts,
            max = record.max_heal_attempts,
            "quarantine: healing started"
        );

        Ok(())
    }

    /// Record successful heal. Advances state to PendingRejoin.
    pub fn healing_complete(&mut self, node_id: &NodeId) -> Result<(), String> {
        let record = self
            .records
            .get_mut(node_id)
            .ok_or_else(|| format!("no quarantine record for node {node_id}"))?;

        if record.state != QuarantineState::Healing {
            return Err(format!(
                "node {node_id} is in state {}, expected Healing",
                record.state
            ));
        }

        record.state = QuarantineState::PendingRejoin;

        tracing::info!(
            node = %node_id,
            "quarantine: healing complete, pending rejoin verification"
        );

        Ok(())
    }

    /// Approve rejoin after verification. Returns Raft commands to re-admit node.
    pub fn approve_rejoin(&mut self, node_id: &NodeId) -> Vec<ClusterCommand> {
        let record = match self.records.get_mut(node_id) {
            Some(r) if r.state == QuarantineState::PendingRejoin => r,
            _ => return Vec::new(),
        };

        record.state = QuarantineState::Active;
        record.quarantined_at = None;
        record.forensic_snapshot = None;

        tracing::info!(
            node = %node_id,
            "quarantine: rejoin approved"
        );

        vec![
            ClusterCommand::TamperHealed { node_id: *node_id },
            ClusterCommand::HealthUpdate {
                node_id: *node_id,
                healthy: true,
            },
        ]
    }

    /// Permanently exclude a node (too many failed heal attempts).
    pub fn permanently_exclude(&mut self, node_id: &NodeId) -> Vec<ClusterCommand> {
        if let Some(record) = self.records.get_mut(node_id) {
            record.state = QuarantineState::Quarantined;
            // Keep the record but mark it as permanently excluded by
            // setting max_heal_attempts to 0 so no further healing is possible.
            record.max_heal_attempts = 0;
        }

        tracing::error!(
            node = %node_id,
            "quarantine: node PERMANENTLY EXCLUDED from cluster"
        );

        vec![ClusterCommand::MemberLeave {
            node_id: *node_id,
        }]
    }

    /// Get current quarantine state.
    pub fn node_state(&self, node_id: &NodeId) -> Option<&QuarantineState> {
        self.records.get(node_id).map(|r| &r.state)
    }

    /// Check if any quarantined nodes have exceeded max heal attempts.
    pub fn check_permanent_exclusions(&mut self) -> Vec<NodeId> {
        let mut excluded = Vec::new();
        for (node_id, record) in &self.records {
            if record.state == QuarantineState::Quarantined
                && record.max_heal_attempts > 0
                && record.heal_attempts >= record.max_heal_attempts
            {
                excluded.push(*node_id);
            }
        }
        excluded
    }

    /// Number of quarantined nodes (in any non-Active state).
    pub fn quarantined_count(&self) -> usize {
        self.records
            .values()
            .filter(|r| r.state != QuarantineState::Active)
            .count()
    }

    /// Is a specific node quarantined?
    pub fn is_quarantined(&self, node_id: &NodeId) -> bool {
        matches!(
            self.records.get(node_id).map(|r| &r.state),
            Some(QuarantineState::Quarantined)
                | Some(QuarantineState::Healing)
                | Some(QuarantineState::Suspected)
        )
    }
}

impl Default for QuarantineManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read open file descriptors from /proc/self/fd.
fn capture_open_fds() -> String {
    match std::fs::read_dir("/proc/self/fd") {
        Ok(entries) => {
            let mut fds = Vec::new();
            for entry in entries.flatten() {
                let fd_name = entry.file_name().to_string_lossy().to_string();
                let target = std::fs::read_link(entry.path())
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".into());
                fds.push(format!("fd {fd_name} -> {target}"));
            }
            fds.sort();
            fds.join("\n")
        }
        Err(e) => format!("error reading /proc/self/fd: {e}"),
    }
}

/// Capture environment variables with sensitive values redacted.
fn capture_sanitized_env() -> String {
    let sensitive_patterns = [
        "KEY", "SECRET", "TOKEN", "PASSWORD", "PASS", "CREDENTIAL",
        "PRIVATE", "KEK", "HMAC", "SEALED", "AUTH",
    ];

    let mut entries: Vec<String> = std::env::vars()
        .map(|(key, value)| {
            let key_upper = key.to_uppercase();
            let is_sensitive = sensitive_patterns
                .iter()
                .any(|pat| key_upper.contains(pat));

            if is_sensitive {
                format!("{key}=[REDACTED]")
            } else {
                format!("{key}={value}")
            }
        })
        .collect();

    entries.sort();
    entries.join("\n")
}

/// Redact ASLR addresses from /proc/self/maps content.
/// Replaces hex address ranges (e.g., "7f1234560000-7f1234570000") with "REDACTED"
/// while preserving the pathname column for library identification.
fn redact_aslr_addresses(maps: &str) -> String {
    maps.lines()
        .map(|line| {
            // /proc/self/maps format:
            // address           perms offset  dev   inode   pathname
            // 7f1234560000-7f1234570000 r-xp 00000000 08:01 12345 /usr/lib/libc.so
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() >= 6 {
                // Keep permissions and pathname, redact addresses and offset
                format!(
                    "REDACTED {} REDACTED {} {} {}",
                    parts.get(1).unwrap_or(&""),
                    parts.get(3).unwrap_or(&""),
                    parts.get(4).unwrap_or(&""),
                    parts.get(5).unwrap_or(&"").trim()
                )
            } else if parts.len() >= 2 {
                // Short line: redact the address portion
                format!("REDACTED {}", parts[1..].join(" "))
            } else {
                "REDACTED".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> NodeId {
        NodeId::random()
    }

    #[test]
    fn test_new_manager() {
        let mgr = QuarantineManager::new();
        assert_eq!(mgr.quarantined_count(), 0);
    }

    #[test]
    fn test_quarantine_node_returns_three_commands() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        let commands = mgr.quarantine_node(node, "test compromise".into());
        assert_eq!(commands.len(), 3);

        // Verify command types
        assert!(matches!(&commands[0], ClusterCommand::MemberLeave { node_id } if *node_id == node));
        assert!(matches!(&commands[1], ClusterCommand::HealthUpdate { node_id, healthy } if *node_id == node && !healthy));
        assert!(matches!(&commands[2], ClusterCommand::TamperDetected { node_id, .. } if *node_id == node));
    }

    #[test]
    fn test_quarantine_sets_state() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        mgr.quarantine_node(node, "test".into());
        assert_eq!(mgr.node_state(&node), Some(&QuarantineState::Quarantined));
        assert!(mgr.is_quarantined(&node));
        assert_eq!(mgr.quarantined_count(), 1);
    }

    #[test]
    fn test_full_lifecycle() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        // Quarantine
        mgr.quarantine_node(node, "test".into());
        assert_eq!(mgr.node_state(&node), Some(&QuarantineState::Quarantined));

        // Begin healing
        mgr.begin_healing(&node).unwrap();
        assert_eq!(mgr.node_state(&node), Some(&QuarantineState::Healing));

        // Complete healing
        mgr.healing_complete(&node).unwrap();
        assert_eq!(mgr.node_state(&node), Some(&QuarantineState::PendingRejoin));

        // Approve rejoin
        let commands = mgr.approve_rejoin(&node);
        assert_eq!(commands.len(), 2);
        assert!(matches!(&commands[0], ClusterCommand::TamperHealed { .. }));
        assert!(matches!(&commands[1], ClusterCommand::HealthUpdate { healthy, .. } if *healthy));
        assert_eq!(mgr.node_state(&node), Some(&QuarantineState::Active));
        assert!(!mgr.is_quarantined(&node));
    }

    #[test]
    fn test_begin_healing_wrong_state() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        // No record at all
        assert!(mgr.begin_healing(&node).is_err());

        // After quarantine + healing, try again without re-quarantining
        mgr.quarantine_node(node, "test".into());
        mgr.begin_healing(&node).unwrap();
        // Now in Healing state, can't begin_healing again
        assert!(mgr.begin_healing(&node).is_err());
    }

    #[test]
    fn test_healing_complete_wrong_state() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        mgr.quarantine_node(node, "test".into());
        // Try completing without starting
        assert!(mgr.healing_complete(&node).is_err());
    }

    #[test]
    fn test_max_heal_attempts() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();
        mgr.quarantine_node(node, "test".into());

        // Heal 3 times (max)
        for i in 0..3 {
            if i > 0 {
                // Re-quarantine for subsequent attempts
                if let Some(r) = mgr.records.get_mut(&node) {
                    r.state = QuarantineState::Quarantined;
                }
            }
            mgr.begin_healing(&node).unwrap();
            mgr.healing_complete(&node).unwrap();
            // Simulate failed verification by going back to quarantined
            if i < 2 {
                if let Some(r) = mgr.records.get_mut(&node) {
                    r.state = QuarantineState::Quarantined;
                }
            }
        }

        // 4th attempt should fail
        if let Some(r) = mgr.records.get_mut(&node) {
            r.state = QuarantineState::Quarantined;
        }
        assert!(mgr.begin_healing(&node).is_err());
    }

    #[test]
    fn test_permanent_exclusion() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        mgr.quarantine_node(node, "test".into());
        let commands = mgr.permanently_exclude(&node);

        assert_eq!(commands.len(), 1);
        assert!(matches!(&commands[0], ClusterCommand::MemberLeave { node_id } if *node_id == node));

        // After permanent exclusion, healing should fail
        if let Some(r) = mgr.records.get_mut(&node) {
            r.state = QuarantineState::Quarantined;
        }
        assert!(mgr.begin_healing(&node).is_err());
    }

    #[test]
    fn test_check_permanent_exclusions() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        mgr.quarantine_node(node, "test".into());

        // Exhaust heal attempts
        for _ in 0..3 {
            if let Some(r) = mgr.records.get_mut(&node) {
                r.state = QuarantineState::Quarantined;
            }
            mgr.begin_healing(&node).unwrap();
        }
        // Set back to quarantined for the check
        if let Some(r) = mgr.records.get_mut(&node) {
            r.state = QuarantineState::Quarantined;
        }

        let exclusions = mgr.check_permanent_exclusions();
        assert!(exclusions.contains(&node));
    }

    #[test]
    fn test_channels_to_rotate() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        mgr.register_node_channels(node, vec!["auth".into(), "session".into()]);
        mgr.quarantine_node(node, "test".into());

        let channels = mgr.channels_to_rotate(&node);
        assert_eq!(channels, vec!["auth", "session"]);
    }

    #[test]
    fn test_channels_to_rotate_unknown_node() {
        let mgr = QuarantineManager::new();
        let node = test_node();
        assert!(mgr.channels_to_rotate(&node).is_empty());
    }

    #[test]
    fn test_approve_rejoin_wrong_state() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        // Not in PendingRejoin state
        mgr.quarantine_node(node, "test".into());
        let commands = mgr.approve_rejoin(&node);
        assert!(commands.is_empty()); // should return empty, not panic
    }

    #[test]
    fn test_is_quarantined_various_states() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        // Not in records
        assert!(!mgr.is_quarantined(&node));

        // Quarantined
        mgr.quarantine_node(node, "test".into());
        assert!(mgr.is_quarantined(&node));

        // Healing
        mgr.begin_healing(&node).unwrap();
        assert!(mgr.is_quarantined(&node));

        // PendingRejoin -- not quarantined (awaiting rejoin)
        mgr.healing_complete(&node).unwrap();
        assert!(!mgr.is_quarantined(&node));

        // Active
        mgr.approve_rejoin(&node);
        assert!(!mgr.is_quarantined(&node));
    }

    #[test]
    fn test_forensic_snapshot_capture() {
        let snapshot = ForensicSnapshot::capture();
        assert!(snapshot.timestamp > 0);
        // On Linux, these should have real content
        assert!(!snapshot.process_list.is_empty());
        assert!(!snapshot.loaded_libraries.is_empty());
    }

    #[test]
    fn test_forensic_snapshot_debug_redacted() {
        let snapshot = ForensicSnapshot::capture();
        let debug = format!("{:?}", snapshot);
        // Should not contain raw process data, just lengths
        assert!(debug.contains("process_list_len"));
        assert!(!debug.contains("TracerPid")); // raw /proc/self/status content
    }

    #[test]
    fn test_capture_sanitized_env_redacts_secrets() {
        // Set a test secret
        std::env::set_var("TEST_SECRET_KEY_QUARANTINE", "super_secret_value");
        let env = capture_sanitized_env();

        // The key should be present but value redacted
        assert!(env.contains("TEST_SECRET_KEY_QUARANTINE=[REDACTED]"));
        assert!(!env.contains("super_secret_value"));

        std::env::remove_var("TEST_SECRET_KEY_QUARANTINE");
    }

    #[test]
    fn test_capture_sanitized_env_allows_normal_vars() {
        std::env::set_var("QUARANTINE_TEST_NORMAL_VAR", "visible_value");
        let env = capture_sanitized_env();

        assert!(env.contains("QUARANTINE_TEST_NORMAL_VAR=visible_value"));

        std::env::remove_var("QUARANTINE_TEST_NORMAL_VAR");
    }

    #[test]
    fn test_quarantine_captures_forensic_snapshot() {
        let mut mgr = QuarantineManager::new();
        let node = test_node();

        mgr.quarantine_node(node, "test".into());
        let record = mgr.records.get(&node).unwrap();
        assert!(record.forensic_snapshot.is_some());
        assert!(record.forensic_snapshot.as_ref().unwrap().timestamp > 0);
    }

    #[test]
    fn test_multiple_nodes_quarantined() {
        let mut mgr = QuarantineManager::new();
        let n1 = test_node();
        let n2 = test_node();
        let n3 = test_node();

        mgr.quarantine_node(n1, "reason1".into());
        mgr.quarantine_node(n2, "reason2".into());

        assert_eq!(mgr.quarantined_count(), 2);
        assert!(mgr.is_quarantined(&n1));
        assert!(mgr.is_quarantined(&n2));
        assert!(!mgr.is_quarantined(&n3));
    }

    #[test]
    fn test_quarantine_state_display() {
        assert_eq!(QuarantineState::Active.to_string(), "active");
        assert_eq!(QuarantineState::Quarantined.to_string(), "quarantined");
        assert_eq!(QuarantineState::Healing.to_string(), "healing");
        assert_eq!(QuarantineState::PendingRejoin.to_string(), "pending_rejoin");
        assert_eq!(QuarantineState::Suspected.to_string(), "suspected");
    }

    #[test]
    fn test_default_impl() {
        let mgr: QuarantineManager = Default::default();
        assert_eq!(mgr.quarantined_count(), 0);
    }
}
