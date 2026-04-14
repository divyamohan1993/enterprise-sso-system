//! Monitors quorum health across all distributed subsystems.
//! Detects when the cluster has fallen below operational thresholds.
//!
//! Tracked subsystems:
//! - **Raft consensus**: needs majority (3 of 5) for leader election
//! - **FROST signing**: needs threshold (3 of 5) for token issuance
//! - **BFT audit**: needs 2f+1 honest nodes (7 of 11) for Byzantine fault tolerance
//! - **Shamir KEK**: needs threshold (3 of 5) for key reconstruction

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// BFT configuration (shared with audit/src/bft.rs)
// ---------------------------------------------------------------------------

/// Configurable BFT parameters. Both quorum_health and audit BFT modules
/// must reference the same configuration to prevent quorum mismatches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BftConfig {
    /// Total number of BFT audit nodes in the cluster.
    pub total_nodes: u32,
    /// Maximum number of Byzantine (faulty) nodes tolerated: f = floor((n-1)/3).
    pub max_byzantine: u32,
    /// Quorum size required for BFT agreement: 2f + 1.
    pub quorum_size: u32,
}

impl BftConfig {
    /// Create a new BFT configuration. Panics if the invariant
    /// `quorum_size == 2 * max_byzantine + 1` is violated.
    pub fn new(total_nodes: u32, max_byzantine: u32, quorum_size: u32) -> Self {
        assert_eq!(
            quorum_size,
            2 * max_byzantine + 1,
            "BFT invariant violated: quorum_size ({}) must equal 2 * max_byzantine ({}) + 1 = {}",
            quorum_size,
            max_byzantine,
            2 * max_byzantine + 1,
        );
        assert!(
            total_nodes >= quorum_size,
            "BFT invariant violated: total_nodes ({}) must be >= quorum_size ({})",
            total_nodes,
            quorum_size,
        );
        Self {
            total_nodes,
            max_byzantine,
            quorum_size,
        }
    }

    /// Load BFT configuration from environment or use the default 11-node cluster.
    pub fn from_env() -> Self {
        let total_nodes: u32 = std::env::var("MILNET_BFT_TOTAL_NODES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(11);
        let max_byzantine: u32 = std::env::var("MILNET_BFT_MAX_BYZANTINE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        let quorum_size = 2 * max_byzantine + 1;
        Self::new(total_nodes, max_byzantine, quorum_size)
    }

    /// Validate that another node's BFT config matches ours.
    pub fn validate_peer_config(&self, peer_config: &BftConfig) -> Result<(), String> {
        if self != peer_config {
            return Err(format!(
                "BFT config mismatch: local(n={},f={},q={}) vs peer(n={},f={},q={})",
                self.total_nodes, self.max_byzantine, self.quorum_size,
                peer_config.total_nodes, peer_config.max_byzantine, peer_config.quorum_size,
            ));
        }
        Ok(())
    }
}

impl Default for BftConfig {
    fn default() -> Self {
        Self::new(11, 3, 7)
    }
}

// ---------------------------------------------------------------------------
// Dynamic quorum configuration
// ---------------------------------------------------------------------------

/// Configuration for Raft, FROST, and KEK cluster sizes.
/// Quorum is computed dynamically as cluster_size / 2 + 1 (majority).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterConfig {
    /// Number of Raft peers in the cluster.
    pub raft_cluster_size: u32,
    /// Number of FROST signers in the cluster.
    pub frost_cluster_size: u32,
    /// Number of KEK share holders in the cluster.
    pub kek_cluster_size: u32,
}

impl ClusterConfig {
    /// Compute majority quorum: cluster_size / 2 + 1.
    pub fn majority_quorum(cluster_size: u32) -> u32 {
        if cluster_size == 0 { return 1; }
        cluster_size / 2 + 1
    }

    pub fn raft_quorum(&self) -> u32 {
        Self::majority_quorum(self.raft_cluster_size)
    }

    pub fn frost_threshold(&self) -> u32 {
        Self::majority_quorum(self.frost_cluster_size)
    }

    pub fn kek_threshold(&self) -> u32 {
        Self::majority_quorum(self.kek_cluster_size)
    }

    /// Load from environment or use defaults (5-node clusters).
    pub fn from_env() -> Self {
        let raft = std::env::var("MILNET_RAFT_CLUSTER_SIZE")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(5);
        let frost = std::env::var("MILNET_FROST_CLUSTER_SIZE")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(5);
        let kek = std::env::var("MILNET_KEK_CLUSTER_SIZE")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(5);
        Self { raft_cluster_size: raft, frost_cluster_size: frost, kek_cluster_size: kek }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self { raft_cluster_size: 5, frost_cluster_size: 5, kek_cluster_size: 5 }
    }
}

// ---------------------------------------------------------------------------
// QuorumStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumStatus {
    Healthy,
    Degraded { systems: Vec<&'static str> },
    Critical,
    QuorumLost,
}

// ---------------------------------------------------------------------------
// QuorumHealth
// ---------------------------------------------------------------------------

pub struct QuorumHealth {
    pub raft_healthy_peers: AtomicU32,
    pub frost_available_signers: AtomicU32,
    pub bft_honest_nodes: AtomicU32,
    pub kek_available_shares: AtomicU32,
    bft_config: BftConfig,
    cluster_config: ClusterConfig,
}

impl QuorumHealth {
    pub fn new() -> Self {
        Self::with_bft_config(BftConfig::default())
    }

    pub fn with_bft_config(bft_config: BftConfig) -> Self {
        Self::with_full_config(bft_config, ClusterConfig::default())
    }

    pub fn with_full_config(bft_config: BftConfig, cluster_config: ClusterConfig) -> Self {
        Self {
            raft_healthy_peers: AtomicU32::new(0),
            frost_available_signers: AtomicU32::new(0),
            bft_honest_nodes: AtomicU32::new(0),
            kek_available_shares: AtomicU32::new(0),
            bft_config,
            cluster_config,
        }
    }

    pub fn new_healthy() -> Self {
        let bft_config = BftConfig::default();
        let cluster_config = ClusterConfig::default();
        let total = bft_config.total_nodes;
        Self {
            raft_healthy_peers: AtomicU32::new(cluster_config.raft_cluster_size),
            frost_available_signers: AtomicU32::new(cluster_config.frost_cluster_size),
            bft_honest_nodes: AtomicU32::new(total),
            kek_available_shares: AtomicU32::new(cluster_config.kek_cluster_size),
            bft_config,
            cluster_config,
        }
    }

    pub fn bft_config(&self) -> &BftConfig {
        &self.bft_config
    }

    pub fn cluster_config(&self) -> &ClusterConfig {
        &self.cluster_config
    }

    pub fn update_raft_peers(&self, count: u32) {
        self.raft_healthy_peers.store(count, Ordering::SeqCst);
    }

    pub fn update_frost_signers(&self, count: u32) {
        self.frost_available_signers.store(count, Ordering::SeqCst);
    }

    pub fn update_bft_nodes(&self, count: u32) {
        self.bft_honest_nodes.store(count, Ordering::SeqCst);
    }

    pub fn update_kek_shares(&self, count: u32) {
        self.kek_available_shares.store(count, Ordering::SeqCst);
    }

    pub fn assess(&self) -> QuorumStatus {
        let raft = self.raft_healthy_peers.load(Ordering::SeqCst);
        let frost = self.frost_available_signers.load(Ordering::SeqCst);
        let bft = self.bft_honest_nodes.load(Ordering::SeqCst);
        let kek = self.kek_available_shares.load(Ordering::SeqCst);

        let raft_quorum = self.cluster_config.raft_quorum();
        let frost_threshold = self.cluster_config.frost_threshold();
        let kek_threshold = self.cluster_config.kek_threshold();

        let raft_ok = raft >= raft_quorum;
        let frost_ok = frost >= frost_threshold;
        let bft_ok = bft >= self.bft_config.quorum_size;
        let kek_ok = kek >= kek_threshold;

        let all_ok = raft_ok && frost_ok && bft_ok && kek_ok;
        let none_ok = !raft_ok && !frost_ok && !bft_ok && !kek_ok;

        if all_ok {
            return QuorumStatus::Healthy;
        }
        if none_ok {
            return QuorumStatus::QuorumLost;
        }

        let mut degraded = Vec::new();
        if !raft_ok { degraded.push("raft"); }
        if !frost_ok { degraded.push("frost"); }
        if !bft_ok { degraded.push("bft"); }
        if !kek_ok { degraded.push("kek"); }

        if degraded.len() >= 3 || (!raft_ok && !frost_ok) {
            QuorumStatus::Critical
        } else {
            QuorumStatus::Degraded { systems: degraded }
        }
    }

    pub fn health_endpoint_status(&self) -> (u16, &'static str) {
        match self.assess() {
            QuorumStatus::Healthy => (200, "OK"),
            QuorumStatus::Degraded { .. } => (200, "DEGRADED"),
            QuorumStatus::Critical => (503, "CRITICAL_DEGRADATION"),
            QuorumStatus::QuorumLost => (503, "QUORUM_LOST"),
        }
    }
}

impl Default for QuorumHealth {
    fn default() -> Self {
        Self::new()
    }
}

pub fn bft_quorum() -> u32 {
    BftConfig::default().quorum_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_starts_quorum_lost() {
        let qh = QuorumHealth::new();
        assert_eq!(qh.assess(), QuorumStatus::QuorumLost);
    }

    #[test]
    fn all_healthy() {
        let qh = QuorumHealth::new_healthy();
        assert_eq!(qh.assess(), QuorumStatus::Healthy);
        assert_eq!(qh.health_endpoint_status(), (200, "OK"));
    }

    #[test]
    fn single_subsystem_degraded_bft() {
        let qh = QuorumHealth::new_healthy();
        qh.update_bft_nodes(6);
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems == &["bft"]));
        assert_eq!(qh.health_endpoint_status(), (200, "DEGRADED"));
    }

    #[test]
    fn single_subsystem_degraded_kek() {
        let qh = QuorumHealth::new_healthy();
        qh.update_kek_shares(2);
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems == &["kek"]));
    }

    #[test]
    fn raft_and_frost_down_is_critical() {
        let qh = QuorumHealth::new_healthy();
        qh.update_raft_peers(2);
        qh.update_frost_signers(2);
        assert_eq!(qh.assess(), QuorumStatus::Critical);
        assert_eq!(qh.health_endpoint_status(), (503, "CRITICAL_DEGRADATION"));
    }

    #[test]
    fn three_subsystems_down_is_critical() {
        let qh = QuorumHealth::new_healthy();
        qh.update_bft_nodes(3);
        qh.update_kek_shares(1);
        qh.update_frost_signers(1);
        assert_eq!(qh.assess(), QuorumStatus::Critical);
    }

    #[test]
    fn all_subsystems_down_is_quorum_lost() {
        let qh = QuorumHealth::new_healthy();
        qh.update_raft_peers(1);
        qh.update_frost_signers(0);
        qh.update_bft_nodes(2);
        qh.update_kek_shares(0);
        assert_eq!(qh.assess(), QuorumStatus::QuorumLost);
        assert_eq!(qh.health_endpoint_status(), (503, "QUORUM_LOST"));
    }

    #[test]
    fn boundary_exactly_at_threshold() {
        let bft_q = bft_quorum();
        let cc = ClusterConfig::default();
        let qh = QuorumHealth::new();
        qh.update_raft_peers(cc.raft_quorum());
        qh.update_frost_signers(cc.frost_threshold());
        qh.update_bft_nodes(bft_q);
        qh.update_kek_shares(cc.kek_threshold());
        assert_eq!(qh.assess(), QuorumStatus::Healthy);
    }

    #[test]
    fn boundary_one_below_threshold() {
        let bft_q = bft_quorum();
        let cc = ClusterConfig::default();
        let qh = QuorumHealth::new();
        qh.update_raft_peers(cc.raft_quorum() - 1);
        qh.update_frost_signers(cc.frost_threshold());
        qh.update_bft_nodes(bft_q);
        qh.update_kek_shares(cc.kek_threshold());
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems == &["raft"]));
    }

    #[test]
    fn degraded_two_non_critical_subsystems() {
        let bft_q = bft_quorum();
        let cc = ClusterConfig::default();
        let qh = QuorumHealth::new();
        qh.update_raft_peers(cc.raft_quorum());
        qh.update_frost_signers(cc.frost_threshold());
        qh.update_bft_nodes(bft_q - 1);
        qh.update_kek_shares(cc.kek_threshold() - 1);
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems.len() == 2));
    }

    #[test]
    fn dynamic_quorum_from_cluster_size() {
        // majority_quorum(5) = 3, majority_quorum(7) = 4, majority_quorum(3) = 2
        assert_eq!(ClusterConfig::majority_quorum(5), 3);
        assert_eq!(ClusterConfig::majority_quorum(7), 4);
        assert_eq!(ClusterConfig::majority_quorum(3), 2);
        assert_eq!(ClusterConfig::majority_quorum(1), 1);
        assert_eq!(ClusterConfig::majority_quorum(0), 1);
    }

    #[test]
    fn custom_cluster_sizes() {
        let cc = ClusterConfig { raft_cluster_size: 7, frost_cluster_size: 7, kek_cluster_size: 7 };
        let qh = QuorumHealth::with_full_config(BftConfig::default(), cc);
        // 7-node cluster needs quorum of 4
        qh.update_raft_peers(3);
        qh.update_frost_signers(4);
        qh.update_bft_nodes(7);
        qh.update_kek_shares(4);
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems == &["raft"]));
    }

    #[test]
    fn health_endpoint_degraded_returns_200() {
        let qh = QuorumHealth::new_healthy();
        qh.update_kek_shares(1);
        let (code, _) = qh.health_endpoint_status();
        assert_eq!(code, 200);
    }

    #[test]
    fn default_impl() {
        let qh: QuorumHealth = Default::default();
        assert_eq!(qh.assess(), QuorumStatus::QuorumLost);
    }

    #[test]
    fn update_methods_work() {
        let qh = QuorumHealth::new();
        qh.update_raft_peers(5);
        assert_eq!(qh.raft_healthy_peers.load(Ordering::SeqCst), 5);
        qh.update_frost_signers(4);
        assert_eq!(qh.frost_available_signers.load(Ordering::SeqCst), 4);
        qh.update_bft_nodes(11);
        assert_eq!(qh.bft_honest_nodes.load(Ordering::SeqCst), 11);
        qh.update_kek_shares(3);
        assert_eq!(qh.kek_available_shares.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn transition_healthy_to_degraded_to_critical_to_lost() {
        let qh = QuorumHealth::new_healthy();
        assert_eq!(qh.assess(), QuorumStatus::Healthy);
        qh.update_bft_nodes(3);
        assert!(matches!(qh.assess(), QuorumStatus::Degraded { .. }));
        qh.update_raft_peers(1);
        qh.update_frost_signers(1);
        assert_eq!(qh.assess(), QuorumStatus::Critical);
        qh.update_kek_shares(0);
        assert_eq!(qh.assess(), QuorumStatus::QuorumLost);
    }

    #[test]
    fn bft_config_invariant_holds() {
        let cfg = BftConfig::default();
        assert_eq!(cfg.total_nodes, 11);
        assert_eq!(cfg.max_byzantine, 3);
        assert_eq!(cfg.quorum_size, 7);
        assert_eq!(cfg.quorum_size, 2 * cfg.max_byzantine + 1);
    }

    #[test]
    #[should_panic(expected = "BFT invariant violated")]
    fn bft_config_rejects_bad_quorum() {
        BftConfig::new(11, 3, 5);
    }

    #[test]
    fn bft_config_peer_validation() {
        let local = BftConfig::default();
        let same = BftConfig::default();
        assert!(local.validate_peer_config(&same).is_ok());
        let different = BftConfig::new(7, 2, 5);
        assert!(local.validate_peer_config(&different).is_err());
    }
}
