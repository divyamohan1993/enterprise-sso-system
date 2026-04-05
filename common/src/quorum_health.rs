//! Monitors quorum health across all distributed subsystems.
//! Detects when the cluster has fallen below operational thresholds.
//!
//! Tracked subsystems:
//! - **Raft consensus**: needs majority (3 of 5) for leader election
//! - **FROST signing**: needs threshold (3 of 5) for token issuance
//! - **BFT audit**: needs 2f+1 honest nodes (5 of 7) for Byzantine fault tolerance
//! - **Shamir KEK**: needs threshold (3 of 5) for key reconstruction

use std::sync::atomic::{AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// Thresholds (matching system architecture: 5-node Raft, 3-of-5 FROST/KEK, 7-node BFT)
// ---------------------------------------------------------------------------

/// Raft requires strict majority: ceil(5/2)+1 = 3.
const RAFT_QUORUM: u32 = 3;
/// FROST threshold for signing.
const FROST_THRESHOLD: u32 = 3;
/// BFT requires 2f+1 honest nodes. With f=2 (7-node cluster), need 5.
const BFT_QUORUM: u32 = 5;
/// Shamir KEK reconstruction threshold.
const KEK_THRESHOLD: u32 = 3;

// ---------------------------------------------------------------------------
// QuorumStatus
// ---------------------------------------------------------------------------

/// Overall cluster quorum status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumStatus {
    /// All subsystems at or above quorum.
    Healthy,
    /// Some subsystems below quorum but at least one distributed protocol still works.
    Degraded { systems: Vec<&'static str> },
    /// Multiple subsystems below quorum. Cluster barely operational.
    Critical,
    /// Cannot operate any distributed protocol. Node must enter emergency mode.
    QuorumLost,
}

// ---------------------------------------------------------------------------
// QuorumHealth
// ---------------------------------------------------------------------------

/// Tracks live peer counts for each distributed subsystem.
///
/// All fields are atomic so any thread (heartbeat receiver, health checker,
/// API handler) can update or read without locks.
pub struct QuorumHealth {
    /// Number of Raft peers responding (including self).
    pub raft_healthy_peers: AtomicU32,
    /// Number of FROST signers available for threshold signing.
    pub frost_available_signers: AtomicU32,
    /// Number of BFT nodes believed honest.
    pub bft_honest_nodes: AtomicU32,
    /// Number of KEK share holders reachable.
    pub kek_available_shares: AtomicU32,
}

impl QuorumHealth {
    /// Create a new health tracker. Starts with zero across the board
    /// (conservative: assume nothing until proven healthy).
    pub fn new() -> Self {
        Self {
            raft_healthy_peers: AtomicU32::new(0),
            frost_available_signers: AtomicU32::new(0),
            bft_honest_nodes: AtomicU32::new(0),
            kek_available_shares: AtomicU32::new(0),
        }
    }

    /// Create a tracker initialized to healthy values (useful for tests).
    pub fn new_healthy() -> Self {
        Self {
            raft_healthy_peers: AtomicU32::new(5),
            frost_available_signers: AtomicU32::new(5),
            bft_honest_nodes: AtomicU32::new(7),
            kek_available_shares: AtomicU32::new(5),
        }
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

    /// Assess overall quorum status across all subsystems.
    pub fn assess(&self) -> QuorumStatus {
        let raft = self.raft_healthy_peers.load(Ordering::SeqCst);
        let frost = self.frost_available_signers.load(Ordering::SeqCst);
        let bft = self.bft_honest_nodes.load(Ordering::SeqCst);
        let kek = self.kek_available_shares.load(Ordering::SeqCst);

        let raft_ok = raft >= RAFT_QUORUM;
        let frost_ok = frost >= FROST_THRESHOLD;
        let bft_ok = bft >= BFT_QUORUM;
        let kek_ok = kek >= KEK_THRESHOLD;

        let all_ok = raft_ok && frost_ok && bft_ok && kek_ok;
        let none_ok = !raft_ok && !frost_ok && !bft_ok && !kek_ok;

        if all_ok {
            return QuorumStatus::Healthy;
        }

        if none_ok {
            return QuorumStatus::QuorumLost;
        }

        // Collect degraded subsystems
        let mut degraded = Vec::new();
        if !raft_ok {
            degraded.push("raft");
        }
        if !frost_ok {
            degraded.push("frost");
        }
        if !bft_ok {
            degraded.push("bft");
        }
        if !kek_ok {
            degraded.push("kek");
        }

        // Critical: 3+ subsystems down, or both consensus and signing down
        if degraded.len() >= 3 || (!raft_ok && !frost_ok) {
            QuorumStatus::Critical
        } else {
            QuorumStatus::Degraded { systems: degraded }
        }
    }

    /// Return HTTP-style status for the `/health` endpoint.
    ///
    /// - `200 OK` when healthy
    /// - `200 DEGRADED` when degraded (still serving reads)
    /// - `503 CRITICAL_DEGRADATION` when critical
    /// - `503 QUORUM_LOST` when all quorums lost
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        qh.update_bft_nodes(4); // below 5
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems == &["bft"]));
        assert_eq!(qh.health_endpoint_status(), (200, "DEGRADED"));
    }

    #[test]
    fn single_subsystem_degraded_kek() {
        let qh = QuorumHealth::new_healthy();
        qh.update_kek_shares(2); // below 3
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
        let qh = QuorumHealth::new();
        qh.update_raft_peers(RAFT_QUORUM);
        qh.update_frost_signers(FROST_THRESHOLD);
        qh.update_bft_nodes(BFT_QUORUM);
        qh.update_kek_shares(KEK_THRESHOLD);
        assert_eq!(qh.assess(), QuorumStatus::Healthy);
    }

    #[test]
    fn boundary_one_below_threshold() {
        let qh = QuorumHealth::new();
        qh.update_raft_peers(RAFT_QUORUM - 1);
        qh.update_frost_signers(FROST_THRESHOLD);
        qh.update_bft_nodes(BFT_QUORUM);
        qh.update_kek_shares(KEK_THRESHOLD);
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems == &["raft"]));
    }

    #[test]
    fn degraded_two_non_critical_subsystems() {
        let qh = QuorumHealth::new();
        qh.update_raft_peers(RAFT_QUORUM);
        qh.update_frost_signers(FROST_THRESHOLD);
        qh.update_bft_nodes(BFT_QUORUM - 1);
        qh.update_kek_shares(KEK_THRESHOLD - 1);
        let status = qh.assess();
        assert!(matches!(status, QuorumStatus::Degraded { ref systems } if systems.len() == 2));
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
        qh.update_bft_nodes(7);
        assert_eq!(qh.bft_honest_nodes.load(Ordering::SeqCst), 7);
        qh.update_kek_shares(3);
        assert_eq!(qh.kek_available_shares.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn transition_healthy_to_degraded_to_critical_to_lost() {
        let qh = QuorumHealth::new_healthy();
        assert_eq!(qh.assess(), QuorumStatus::Healthy);

        // Degrade one
        qh.update_bft_nodes(3);
        assert!(matches!(qh.assess(), QuorumStatus::Degraded { .. }));

        // Lose consensus + signing
        qh.update_raft_peers(1);
        qh.update_frost_signers(1);
        assert_eq!(qh.assess(), QuorumStatus::Critical);

        // Lose everything
        qh.update_kek_shares(0);
        assert_eq!(qh.assess(), QuorumStatus::QuorumLost);
    }
}
