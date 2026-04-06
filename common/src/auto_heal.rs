//! Auto-healing and failure detection for distributed cluster.
//!
//! Monitors peer health, detects failures, and triggers recovery actions.
//! Leader-only decisions: mark dead nodes, propose membership changes.
//! Follower recovery: auto-rejoin on restart, Raft log sync.

use crate::raft::{ClusterCommand, NodeId};
use crate::siem::SecurityEvent;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Number of consecutive quorum failures before escalating to incident response.
const QUORUM_LOSS_ESCALATION_THRESHOLD: u32 = 3;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Auto-healer configuration.
#[derive(Debug, Clone)]
pub struct AutoHealConfig {
    /// How often to probe peers (default: 5s).
    pub probe_interval: Duration,
    /// Consecutive probe failures before marking degraded (default: 3).
    pub degraded_threshold: u32,
    /// Consecutive probe failures before marking dead (default: 6).
    pub dead_threshold: u32,
    /// How long a dead node must stay dead before proposing MemberLeave (default: 60s).
    pub eviction_grace_period: Duration,
    /// Maximum time to wait for a rejoining node to sync (default: 30s).
    pub rejoin_sync_timeout: Duration,
}

impl Default for AutoHealConfig {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            degraded_threshold: 3,
            dead_threshold: 6,
            eviction_grace_period: Duration::from_secs(60),
            rejoin_sync_timeout: Duration::from_secs(30),
        }
    }
}

// ---------------------------------------------------------------------------
// Peer health state
// ---------------------------------------------------------------------------

/// Health status of a peer node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerHealth {
    /// Responding normally.
    Healthy,
    /// Missed some probes but not yet dead.
    Degraded,
    /// Unresponsive beyond dead threshold.
    Dead,
    /// Recently rejoined, syncing state.
    Recovering,
}

impl std::fmt::Display for PeerHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Dead => write!(f, "dead"),
            Self::Recovering => write!(f, "recovering"),
        }
    }
}

/// Tracked state for one peer.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub node_id: NodeId,
    pub health_addr: String,
    pub health: PeerHealth,
    pub consecutive_failures: u32,
    pub last_seen: Instant,
    pub dead_since: Option<Instant>,
    /// True if we've already proposed a MemberLeave for this peer.
    pub eviction_proposed: bool,
}

impl PeerState {
    pub fn new(node_id: NodeId, health_addr: String) -> Self {
        Self {
            node_id,
            health_addr,
            health: PeerHealth::Healthy,
            consecutive_failures: 0,
            last_seen: Instant::now(),
            dead_since: None,
            eviction_proposed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Auto-healer engine
// ---------------------------------------------------------------------------

/// The auto-healer tracks peer health and generates cluster commands
/// when peers fail or recover.
pub struct AutoHealer {
    config: AutoHealConfig,
    peers: HashMap<NodeId, PeerState>,
    /// Consecutive quorum check failures (resets on quorum recovery).
    consecutive_quorum_failures: u32,
}

impl AutoHealer {
    pub fn new(config: AutoHealConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            consecutive_quorum_failures: 0,
        }
    }

    /// Register a peer to monitor.
    pub fn add_peer(&mut self, node_id: NodeId, health_addr: String) {
        self.peers
            .entry(node_id)
            .or_insert_with(|| PeerState::new(node_id, health_addr));
    }

    /// Remove a peer from monitoring.
    pub fn remove_peer(&mut self, node_id: &NodeId) {
        self.peers.remove(node_id);
    }

    /// Record a successful probe for a peer.
    pub fn record_success(&mut self, node_id: &NodeId) -> Option<ClusterCommand> {
        let peer = self.peers.get_mut(node_id)?;
        let was_dead = peer.health == PeerHealth::Dead;

        peer.consecutive_failures = 0;
        peer.last_seen = Instant::now();
        peer.dead_since = None;
        peer.eviction_proposed = false;

        if was_dead {
            peer.health = PeerHealth::Recovering;
            tracing::info!(
                node_id = %node_id,
                "peer recovered from dead state — entering recovery"
            );
            // Propose a health update so the cluster knows this node is back
            return Some(ClusterCommand::HealthUpdate {
                node_id: *node_id,
                healthy: true,
            });
        }

        if peer.health == PeerHealth::Recovering || peer.health == PeerHealth::Degraded {
            peer.health = PeerHealth::Healthy;
            tracing::info!(node_id = %node_id, "peer health restored to healthy");
        }

        None
    }

    /// Record a failed probe for a peer. Returns a ClusterCommand to propose
    /// if the peer should be evicted (leader-only action).
    pub fn record_failure(&mut self, node_id: &NodeId) -> Option<ClusterCommand> {
        let peer = self.peers.get_mut(node_id)?;
        peer.consecutive_failures += 1;

        let old_health = peer.health;

        // Update health tier
        if peer.consecutive_failures >= self.config.dead_threshold {
            if peer.health != PeerHealth::Dead {
                peer.health = PeerHealth::Dead;
                peer.dead_since = Some(Instant::now());
                tracing::error!(
                    node_id = %node_id,
                    failures = peer.consecutive_failures,
                    "peer marked DEAD after {} consecutive failures",
                    peer.consecutive_failures
                );
            }

            // Check eviction grace period
            if let Some(dead_since) = peer.dead_since {
                if dead_since.elapsed() >= self.config.eviction_grace_period
                    && !peer.eviction_proposed
                {
                    peer.eviction_proposed = true;
                    tracing::warn!(
                        node_id = %node_id,
                        grace_secs = self.config.eviction_grace_period.as_secs(),
                        "proposing MemberLeave for dead peer after grace period"
                    );
                    return Some(ClusterCommand::MemberLeave {
                        node_id: *node_id,
                    });
                }
            }
        } else if peer.consecutive_failures >= self.config.degraded_threshold {
            if peer.health != PeerHealth::Degraded {
                peer.health = PeerHealth::Degraded;
                tracing::warn!(
                    node_id = %node_id,
                    failures = peer.consecutive_failures,
                    "peer marked DEGRADED"
                );
                return Some(ClusterCommand::HealthUpdate {
                    node_id: *node_id,
                    healthy: false,
                });
            }
        }

        if old_health != peer.health {
            tracing::info!(
                node_id = %node_id,
                old = %old_health,
                new = %peer.health,
                "peer health state transition"
            );
        }

        None
    }

    /// Get the health status of a specific peer.
    pub fn peer_health(&self, node_id: &NodeId) -> Option<PeerHealth> {
        self.peers.get(node_id).map(|p| p.health)
    }

    /// Get all peers and their current health.
    pub fn all_peer_health(&self) -> Vec<(NodeId, PeerHealth)> {
        self.peers
            .values()
            .map(|p| (p.node_id, p.health))
            .collect()
    }

    /// Count of healthy peers (excludes dead/degraded).
    pub fn healthy_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.health == PeerHealth::Healthy)
            .count()
    }

    /// Count of dead peers.
    pub fn dead_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.health == PeerHealth::Dead)
            .count()
    }

    /// Check if we have quorum (majority of total peers + self are reachable).
    ///
    /// When quorum is lost, emits a CRITICAL SIEM event and increments the
    /// consecutive-failure counter.  After [`QUORUM_LOSS_ESCALATION_THRESHOLD`]
    /// consecutive failures, triggers incident-response escalation.
    pub fn has_quorum(&mut self, total_including_self: usize) -> bool {
        let reachable = self.healthy_count() + 1; // +1 for self
        let quorum_ok = reachable > total_including_self / 2;

        if quorum_ok {
            if self.consecutive_quorum_failures > 0 {
                tracing::info!(
                    consecutive_failures = self.consecutive_quorum_failures,
                    "quorum restored after {} consecutive failures",
                    self.consecutive_quorum_failures
                );
            }
            self.consecutive_quorum_failures = 0;
        } else {
            self.consecutive_quorum_failures += 1;

            tracing::error!(
                reachable = reachable,
                total = total_including_self,
                consecutive_failures = self.consecutive_quorum_failures,
                "QUORUM LOST — cluster cannot reach majority"
            );

            // Emit CRITICAL SIEM event on every quorum loss.
            let event = SecurityEvent {
                timestamp: SecurityEvent::now_iso8601(),
                category: "cluster",
                action: "quorum_lost",
                severity: crate::siem::Severity::Critical,
                outcome: "failure",
                user_id: None,
                source_ip: None,
                detail: Some(format!(
                    "reachable={}/{} consecutive_failures={}",
                    reachable, total_including_self, self.consecutive_quorum_failures
                )),
            };
            event.emit();

            // Escalate to incident response after threshold consecutive failures.
            if self.consecutive_quorum_failures >= QUORUM_LOSS_ESCALATION_THRESHOLD {
                tracing::error!(
                    threshold = QUORUM_LOSS_ESCALATION_THRESHOLD,
                    consecutive_failures = self.consecutive_quorum_failures,
                    "INCIDENT RESPONSE ESCALATION — quorum lost for {} consecutive checks",
                    self.consecutive_quorum_failures
                );
                let escalation = SecurityEvent {
                    timestamp: SecurityEvent::now_iso8601(),
                    category: "cluster",
                    action: "quorum_loss_escalation",
                    severity: crate::siem::Severity::Critical,
                    outcome: "failure",
                    user_id: None,
                    source_ip: None,
                    detail: Some(format!(
                        "incident_response_triggered after {} consecutive quorum failures",
                        self.consecutive_quorum_failures
                    )),
                };
                escalation.emit();
            }
        }

        quorum_ok
    }

    /// Get health addresses for all peers that need probing.
    pub fn peers_to_probe(&self) -> Vec<(NodeId, String)> {
        self.peers
            .values()
            .map(|p| (p.node_id, p.health_addr.clone()))
            .collect()
    }

    /// Total monitored peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

// ---------------------------------------------------------------------------
// Health probe (async TCP check)
// ---------------------------------------------------------------------------

/// Probe a peer's health endpoint with challenge-response authentication.
///
/// After TCP connect succeeds, sends a 32-byte random nonce and expects
/// back HMAC-SHA512(health_key, nonce). If `MILNET_HEALTH_HMAC_KEY` is
/// not set, falls back to TCP-only connectivity check.
pub async fn probe_peer_health(addr: &str) -> bool {
    let timeout = Duration::from_secs(5);
    let stream = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::trace!(addr = addr, error = %e, "health probe connection failed");
            return false;
        }
        Err(_) => {
            tracing::trace!(addr = addr, "health probe timed out");
            return false;
        }
    };

    // If HMAC key is configured, perform challenge-response verification.
    let health_key = match std::env::var("MILNET_HEALTH_HMAC_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => return true, // No HMAC key: TCP connect is sufficient.
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Generate 32-byte random nonce.
    let mut nonce = [0u8; 32];
    if getrandom::getrandom(&mut nonce).is_err() {
        tracing::warn!(addr = addr, "health probe: failed to generate nonce");
        return false;
    }

    let mut stream = stream;

    // Send nonce to peer.
    if stream.write_all(&nonce).await.is_err() {
        tracing::trace!(addr = addr, "health probe: failed to send nonce");
        return false;
    }

    // Read HMAC-SHA512 response (64 bytes) within timeout.
    let mut response = [0u8; 64];
    let read_result = tokio::time::timeout(
        Duration::from_secs(5),
        stream.read_exact(&mut response),
    )
    .await;

    match read_result {
        Ok(Ok(_n)) => {}
        _ => {
            tracing::trace!(addr = addr, "health probe: HMAC response timeout or read error");
            return false;
        }
    }

    // Compute expected HMAC-SHA512(key, nonce) and verify (constant-time).
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let mut mac = match HmacSha512::new_from_slice(health_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            tracing::warn!(addr = addr, "health probe: invalid HMAC key length");
            return false;
        }
    };
    mac.update(&nonce);

    match mac.verify_slice(&response) {
        Ok(()) => true,
        Err(_) => {
            tracing::warn!(addr = addr, "health probe: HMAC verification failed");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Auto-heal background task
// ---------------------------------------------------------------------------

/// Spawn the auto-healing background loop.
///
/// This runs on every node but only the leader proposes cluster commands.
/// Followers still track peer health locally for faster failover decisions.
pub async fn run_auto_heal_loop(
    healer: std::sync::Arc<std::sync::Mutex<AutoHealer>>,
    propose_fn: impl Fn(ClusterCommand) + Send + Sync + 'static,
    is_leader_fn: impl Fn() -> bool + Send + Sync + 'static,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let probe_interval = {
        let h = healer.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in auto_heal - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        h.config.probe_interval
    };

    let mut interval = tokio::time::interval(probe_interval);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Collect peers to probe
                let peers_to_probe = {
                    let h = healer.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in auto_heal - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
                    h.peers_to_probe()
                };

                // Probe all peers concurrently
                let mut handles = Vec::new();
                for (node_id, addr) in peers_to_probe {
                    handles.push(tokio::spawn(async move {
                        let ok = probe_peer_health(&addr).await;
                        (node_id, ok)
                    }));
                }

                // Collect results and update healer
                for handle in handles {
                    if let Ok((node_id, ok)) = handle.await {
                        let cmd = {
                            let mut h = healer.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in auto_heal - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
                            if ok {
                                h.record_success(&node_id)
                            } else {
                                h.record_failure(&node_id)
                            }
                        };

                        // Only leader proposes cluster commands
                        if let Some(cmd) = cmd {
                            if is_leader_fn() {
                                propose_fn(cmd);
                            }
                        }
                    }
                }
            }
            _ = shutdown.changed() => {
                tracing::info!("auto-heal loop shutting down");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(n: u8) -> NodeId {
        NodeId(uuid::Uuid::from_bytes([n; 16]))
    }

    #[test]
    fn healthy_after_construction() {
        let mut healer = AutoHealer::new(AutoHealConfig::default());
        healer.add_peer(nid(1), "10.0.0.1:10101".into());
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Healthy));
        assert_eq!(healer.healthy_count(), 1);
    }

    #[test]
    fn degraded_after_threshold_failures() {
        let mut healer = AutoHealer::new(AutoHealConfig::default());
        healer.add_peer(nid(1), "10.0.0.1:10101".into());

        // 2 failures: still healthy
        for _ in 0..2 {
            healer.record_failure(&nid(1));
        }
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Healthy));

        // 3rd failure: degraded
        let cmd = healer.record_failure(&nid(1));
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Degraded));
        assert!(matches!(cmd, Some(ClusterCommand::HealthUpdate { healthy: false, .. })));
    }

    #[test]
    fn dead_after_threshold_failures() {
        let mut healer = AutoHealer::new(AutoHealConfig::default());
        healer.add_peer(nid(1), "10.0.0.1:10101".into());

        for _ in 0..6 {
            healer.record_failure(&nid(1));
        }
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Dead));
        assert_eq!(healer.dead_count(), 1);
    }

    #[test]
    fn recovery_after_success() {
        let mut healer = AutoHealer::new(AutoHealConfig::default());
        healer.add_peer(nid(1), "10.0.0.1:10101".into());

        // Make dead
        for _ in 0..6 {
            healer.record_failure(&nid(1));
        }
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Dead));

        // Recover
        let cmd = healer.record_success(&nid(1));
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Recovering));
        assert!(matches!(cmd, Some(ClusterCommand::HealthUpdate { healthy: true, .. })));

        // Second success -> healthy
        healer.record_success(&nid(1));
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Healthy));
    }

    #[test]
    fn quorum_check() {
        let mut healer = AutoHealer::new(AutoHealConfig::default());
        healer.add_peer(nid(1), "10.0.0.1:10101".into());
        healer.add_peer(nid(2), "10.0.0.2:10101".into());

        // 3-node cluster (2 peers + self): need 2 for quorum
        assert!(healer.has_quorum(3), "2 healthy peers + self = 3 >= 2");

        // Kill one peer
        for _ in 0..6 {
            healer.record_failure(&nid(1));
        }
        // 1 healthy peer + self = 2 >= 2
        assert!(healer.has_quorum(3));

        // Kill second peer
        for _ in 0..6 {
            healer.record_failure(&nid(2));
        }
        // 0 healthy peers + self = 1 < 2
        assert!(!healer.has_quorum(3));
    }

    #[test]
    fn eviction_not_proposed_during_grace_period() {
        let config = AutoHealConfig {
            eviction_grace_period: Duration::from_secs(3600), // 1 hour
            ..Default::default()
        };
        let mut healer = AutoHealer::new(config);
        healer.add_peer(nid(1), "10.0.0.1:10101".into());

        // Make dead
        for _ in 0..6 {
            healer.record_failure(&nid(1));
        }
        assert_eq!(healer.peer_health(&nid(1)), Some(PeerHealth::Dead));

        // Another failure — still within grace period, no eviction
        let cmd = healer.record_failure(&nid(1));
        assert!(cmd.is_none(), "eviction should not be proposed during grace period");
    }

    #[test]
    fn eviction_proposed_after_grace_period() {
        let config = AutoHealConfig {
            eviction_grace_period: Duration::from_millis(0), // immediate
            ..Default::default()
        };
        let mut healer = AutoHealer::new(config);
        healer.add_peer(nid(1), "10.0.0.1:10101".into());

        // Accumulate failures. With grace_period=0, eviction is proposed
        // on the same call that transitions to Dead (the 6th failure).
        let mut eviction_cmd = None;
        for _ in 0..7 {
            if let Some(cmd) = healer.record_failure(&nid(1)) {
                if matches!(cmd, ClusterCommand::MemberLeave { .. }) {
                    eviction_cmd = Some(cmd);
                }
            }
        }
        assert!(
            eviction_cmd.is_some(),
            "eviction must be proposed when grace period is 0"
        );
    }

    #[test]
    fn eviction_proposed_only_once() {
        let config = AutoHealConfig {
            eviction_grace_period: Duration::from_millis(0),
            ..Default::default()
        };
        let mut healer = AutoHealer::new(config);
        healer.add_peer(nid(1), "10.0.0.1:10101".into());

        // Drive to dead + eviction
        let mut eviction_count = 0;
        for _ in 0..10 {
            if let Some(cmd) = healer.record_failure(&nid(1)) {
                if matches!(cmd, ClusterCommand::MemberLeave { .. }) {
                    eviction_count += 1;
                }
            }
        }
        assert_eq!(eviction_count, 1, "eviction must be proposed exactly once");
    }

    #[test]
    fn remove_peer_stops_tracking() {
        let mut healer = AutoHealer::new(AutoHealConfig::default());
        healer.add_peer(nid(1), "10.0.0.1:10101".into());
        assert_eq!(healer.peer_count(), 1);

        healer.remove_peer(&nid(1));
        assert_eq!(healer.peer_count(), 0);
        assert_eq!(healer.peer_health(&nid(1)), None);
    }
}
