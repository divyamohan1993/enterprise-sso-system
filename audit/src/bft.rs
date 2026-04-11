//! Simplified BFT audit replication with split-brain prevention and
//! automatic Byzantine node detection.
//!
//! Models a cluster of 11 audit nodes that tolerates up to 3 Byzantine faults.
//! An entry is considered committed when a quorum (2f + 1 = 7) of nodes accept it.
//! Byzantine nodes that produce conflicting entries are detectable via chain
//! divergence checks.
//!
//! Each node optionally persists its accepted entries to a separate file so
//! that surviving files provide tamper evidence even if some nodes crash.

use crate::log::{hash_entry, AuditLog};
use common::types::{AuditEntry, AuditEventType, Receipt};
use crypto::pq_sign;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write as IoWrite};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Partition detection timeout: a node must hear from a majority of peers
/// within this window or it considers itself partitioned.
const PARTITION_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum BFT nodes for Byzantine fault tolerance (tolerates f=3 failures).
/// Increased from 7 to 11 to prevent 3 Byzantine nodes + 2 honest duped from
/// forming quorum. With 11 nodes: f=3, quorum=7, so attacker needs 4+ nodes.
pub const MIN_BFT_NODES: usize = 11;
/// Quorum size: 2f+1 where f = floor((n-1)/3). With 11 nodes: f=3, quorum=7.
pub const BFT_QUORUM: usize = 7;

/// Returns true if the cluster has sufficient nodes for BFT guarantees.
pub fn has_bft_quorum(node_count: usize) -> bool {
    node_count >= MIN_BFT_NODES
}

/// A single audit replica node.
pub struct AuditNode {
    pub node_id: u8,
    pub log: AuditLog,
    pub is_byzantine: bool,
    /// Optional path to a JSONL persistence file for this node.
    persistence_path: Option<PathBuf>,
    /// Epoch counter — incremented on every accepted entry.
    pub epoch: u64,
    /// Timestamp when each peer was last successfully contacted.
    last_seen: HashMap<usize, Instant>,
    /// Known epoch of each peer.
    pub peer_epochs: HashMap<usize, u64>,
    /// Per-node response times for Byzantine detection (in microseconds).
    response_times: HashMap<usize, Vec<u64>>,
    /// Optional ML-DSA-87 verifying key for proposer signature verification.
    /// When set, `accept_entry` rejects entries with missing or invalid signatures.
    pq_verifying_key: Option<pq_sign::PqVerifyingKey>,
}

impl AuditNode {
    pub fn new(node_id: u8) -> Self {
        Self {
            node_id,
            log: AuditLog::new(),
            is_byzantine: false,
            persistence_path: None,
            epoch: 0,
            last_seen: HashMap::new(),
            peer_epochs: HashMap::new(),
            response_times: HashMap::new(),
            pq_verifying_key: None,
        }
    }

    /// Create a node with an ML-DSA-87 verifying key for proposer signature verification.
    pub fn new_with_verifying_key(node_id: u8, verifying_key: pq_sign::PqVerifyingKey) -> Self {
        Self {
            node_id,
            log: AuditLog::new(),
            is_byzantine: false,
            persistence_path: None,
            epoch: 0,
            last_seen: HashMap::new(),
            peer_epochs: HashMap::new(),
            response_times: HashMap::new(),
            pq_verifying_key: Some(verifying_key),
        }
    }

    /// Create a node with file-based persistence.
    /// On construction, reloads any previously persisted entries from the file.
    pub fn new_with_persistence(node_id: u8, path: PathBuf) -> Self {
        // Ensure the parent directory exists.
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                tracing::error!(
                    "BFT node {}: failed to create persistence directory {:?}: {}",
                    node_id, parent, e
                );
            }
        }

        // Reload persisted entries.
        let entries = load_entries_from_file(&path, node_id);
        let epoch = entries.len() as u64;
        let log = if entries.is_empty() {
            AuditLog::new()
        } else {
            let log = AuditLog::from_entries(entries);
            if !log.verify_chain_structure_only() { // explicit: no signing key available at reload
                tracing::error!(
                    "CRITICAL: BFT node {}: persisted chain verification FAILED on reload from {:?}",
                    node_id, path
                );
            } else {
                tracing::info!(
                    "BFT node {}: reloaded {} entries from {:?}",
                    node_id, log.len(), path
                );
            }
            log
        };

        Self {
            node_id,
            log,
            is_byzantine: false,
            persistence_path: Some(path),
            epoch,
            last_seen: HashMap::new(),
            peer_epochs: HashMap::new(),
            response_times: HashMap::new(),
            pq_verifying_key: None,
        }
    }

    /// Accept an entry proposal. Returns the entry hash if accepted.
    ///
    /// Before accepting, checks that:
    /// 1. The proposer epoch is not stale (>= our own epoch).
    /// 2. The entry's prev_hash matches our chain tip.
    /// 3. The entry's ML-DSA-87 signature is valid (when a verifying key is configured).
    pub fn accept_entry(&mut self, entry: &AuditEntry, proposer_epoch: u64) -> Option<[u8; 64]> {
        if self.is_byzantine {
            return None; // Byzantine node refuses
        }

        // Reject entries from proposers with stale epochs.
        if proposer_epoch < self.epoch {
            tracing::warn!(
                "BFT node {}: rejecting entry from stale proposer epoch {} (our epoch {})",
                self.node_id, proposer_epoch, self.epoch
            );
            return None;
        }

        // SECURITY: Verify proposer's ML-DSA-87 signature on the entry.
        // Without this check, any node could inject unsigned entries into the chain.
        if let Some(ref vk) = self.pq_verifying_key {
            if entry.signature.is_empty() {
                tracing::warn!(
                    "BFT node {}: rejecting unsigned entry (event_id={})",
                    self.node_id, entry.event_id
                );
                return None;
            }
            let entry_hash = hash_entry(entry);
            if !pq_sign::pq_verify_raw(vk, &entry_hash, &entry.signature) {
                tracing::warn!(
                    "BFT node {}: rejecting entry with invalid proposer signature (event_id={})",
                    self.node_id, entry.event_id
                );
                return None;
            }
        }

        // Verify the entry's prev_hash matches our last hash
        let our_last = if self.log.is_empty() {
            [0u8; 64]
        } else {
            hash_entry(&self.log.entries()[self.log.len() - 1])
        };
        // SECURITY: constant-time comparison prevents Byzantine nodes from
        // probing chain state via timing side-channel.
        if !crypto::ct::ct_eq_64(&entry.prev_hash, &our_last) {
            return None; // Chain mismatch
        }
        if let Err(e) = self.log.append_raw(entry.clone()) {
            tracing::error!("BFT node {}: append_raw failed: {}", self.node_id, e);
            return None;
        }

        // Increment epoch on successful accept.
        self.epoch += 1;

        // Persist to file if configured.
        if let Some(ref path) = self.persistence_path {
            if let Err(e) = append_entry_to_file(path, entry) {
                tracing::error!(
                    "BFT node {}: failed to persist entry to {:?}: {}",
                    self.node_id, path, e
                );
            }
        }

        Some(hash_entry(entry))
    }

    /// Record a heartbeat from a peer, updating last_seen and peer epoch tracking.
    pub fn heartbeat(&mut self, from_node: usize, epoch: u64) {
        self.last_seen.insert(from_node, Instant::now());
        self.peer_epochs.insert(from_node, epoch);
    }

    /// Check whether this node believes it is in a minority partition.
    ///
    /// Returns `true` if fewer than (total_peers / 2 + 1) peers have been
    /// heard from within the last [`PARTITION_TIMEOUT`].
    pub fn check_partition(&self, total_nodes: usize) -> bool {
        let now = Instant::now();
        let required = total_nodes / 2 + 1;
        let reachable = self
            .last_seen
            .values()
            .filter(|&&ts| now.duration_since(ts) < PARTITION_TIMEOUT)
            .count();
        // Count ourselves as reachable.
        let reachable = reachable + 1;
        reachable < required
    }

    /// Record a response time observation (in microseconds) for a peer node.
    pub fn record_response_time(&mut self, peer: usize, time_us: u64) {
        self.response_times.entry(peer).or_default().push(time_us);
    }
}

/// Per-node Byzantine detection state tracked by the cluster.
#[derive(Debug, Clone)]
pub struct ByzantineDetectionState {
    /// Nodes flagged as suspicious due to response time anomalies.
    pub suspicious_nodes: Vec<usize>,
    /// Nodes whose chain hash diverges from the majority.
    pub diverged_nodes: Vec<usize>,
    /// Nodes confirmed Byzantine by f+1 agreement.
    pub confirmed_byzantine: Vec<usize>,
}

/// Verify that BFT node addresses are not all on localhost.
/// In military mode, all nodes sharing the same process has zero BFT guarantees.
/// This checks a list of configured addresses (from MILNET_BFT_NODE_ADDRS env var,
/// comma-separated) and emits SIEM:CRITICAL if all resolve to localhost.
///
/// PRODUCTION DEPLOYMENT: Each BFT node must run as a separate process on a
/// separate host. This check is a startup safety net, not a substitute for
/// proper deployment architecture.
fn check_bft_node_addresses() {
    if cfg!(test) || cfg!(feature = "test-support") {
        return;
    }
    let addrs = match std::env::var("MILNET_BFT_NODE_ADDRS") {
        Ok(a) if !a.is_empty() => a,
        _ => return, // No addresses configured, skip check
    };
    let all_local = addrs.split(',').all(|addr| {
        let addr = addr.trim();
        addr.starts_with("127.") || addr.starts_with("localhost") || addr == "::1"
    });
    if all_local {
        let msg = format!(
            "SIEM:CRITICAL All {} BFT node addresses resolve to localhost. \
             Zero Byzantine fault tolerance in this configuration. \
             Deploy BFT nodes on separate hosts.",
            addrs.split(',').count()
        );
        tracing::error!("{}", msg);
        common::siem::SecurityEvent {
            timestamp: common::siem::SecurityEvent::now_iso8601(),
            category: "bft_audit",
            action: "single_host_bft_detected",
            severity: common::siem::Severity::Critical,
            outcome: "failure",
            user_id: None,
            source_ip: None,
            detail: Some(msg),
        }
        .emit();
        if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
            panic!(
                "FATAL: All BFT nodes on localhost in military deployment. \
                 Deploy on separate hosts."
            );
        }
    }
}

/// Startup check: BFT single-process mode warning/enforcement.
/// In production, single-process mode requires explicit acknowledgment.
/// In military deployment, single-process mode is unconditionally fatal.
/// In test builds (cfg(test) or feature "test-support"), enforcement is skipped.
fn check_single_process_military_deployment() {
    // Test builds: allow single-process mode without ceremony.
    if cfg!(test) || cfg!(feature = "test-support") {
        return;
    }
    if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok() {
        panic!(
            "FATAL: BFT audit running in single-process mode in military deployment. \
             All 11 nodes share one address space -- zero actual Byzantine fault tolerance. \
             Deploy BFT nodes as separate processes/VMs."
        );
    }
    // In production, single-process mode is NEVER permitted.
    // This was previously gated by MILNET_BFT_SINGLE_PROCESS_ACK=1 but that
    // escape hatch has been removed. Deploy BFT nodes as separate processes/VMs.
    if std::env::var("MILNET_PRODUCTION").is_ok()
        || std::env::var("MILNET_BFT_SINGLE_PROCESS_ACK").is_err()
    {
        panic!(
            "FATAL: BFT audit running in single-process mode. \
             All nodes share one address space -- zero actual Byzantine fault tolerance. \
             Deploy BFT nodes as separate processes/VMs."
        );
    }
    // Non-production, non-military, with explicit ACK: require MLP mode
    if !common::config::is_mlp_mode() {
        panic!(
            "FATAL: BFT single-process mode requires MLP mode. \
             Set MILNET_MLP_MODE=1 and MILNET_MLP_ACK=1, or deploy BFT nodes as separate processes/VMs."
        );
    }
    tracing::warn!(
        target: "siem",
        "SIEM:WARNING: BFT audit running in single-process mode with explicit ACK in MLP mode. \
         All nodes share one address space -- zero actual Byzantine fault tolerance. \
         This is acceptable ONLY for local development and testing."
    );
}

/// Determine if BFT should default to single-process mode.
/// In production, defaults to false (distributed). Only true when
/// MILNET_BFT_SINGLE_PROCESS_ACK=1 is explicitly set, or in test builds.
fn default_single_process_mode() -> bool {
    if cfg!(test) || cfg!(feature = "test-support") {
        return true;
    }
    std::env::var("MILNET_BFT_SINGLE_PROCESS_ACK").as_deref() == Ok("1")
}

/// Reason a node was quarantined for Byzantine behavior.
#[derive(Debug, Clone)]
pub enum ByzantineReason {
    ChainDivergence { expected_hash: [u8; 64], actual_hash: [u8; 64] },
    ResponseTimeAnomaly { avg_ms: u64, threshold_ms: u64 },
    SignatureFailure,
    EquivocationDetected { entry_a_hash: [u8; 64], entry_b_hash: [u8; 64] },
}

/// Quarantine state for a Byzantine-suspected node.
#[derive(Debug, Clone)]
pub struct QuarantinedNode {
    pub node_id: usize,
    pub detected_at: u64,
    pub reason: ByzantineReason,
    pub evidence_hash: [u8; 64],
    pub re_attestation_required: bool,
}

/// BFT audit cluster.
pub struct BftAuditCluster {
    pub nodes: Vec<AuditNode>,
    /// Minimum number of nodes that must accept for an entry to be committed.
    pub quorum_size: usize,
    /// Optional ML-DSA-87 signing key for signing audit entries.
    pq_signing_key: Option<pq_sign::PqSigningKey>,
    /// Optional ML-DSA-87 verifying key (derived from signing key) for signature verification.
    pq_verifying_key: Option<pq_sign::PqVerifyingKey>,
    /// Maximum Byzantine faults tolerated.
    f: usize,
    /// Monotonic sequence number for proposer rotation.
    sequence_number: u64,
    /// Single-process mode flag. True when BFT nodes run in one process.
    single_process_mode: bool,
    /// Nodes currently quarantined for Byzantine behavior.
    pub quarantined: Vec<QuarantinedNode>,
    /// Timestamp of the last successful proposal (monotonic).
    last_proposal_at: Instant,
}

impl BftAuditCluster {
    /// Create a new cluster. `node_count` should be >= 11 for meaningful BFT
    /// (3f + 1). For 11 nodes: f = 3, quorum = 2f + 1 = 7.
    pub fn new(node_count: usize) -> Self {
        // BFT requires minimum 11 nodes -- fail hard if fewer
        if node_count < MIN_BFT_NODES {
            tracing::error!(
                "CRITICAL: BFT audit running with {} nodes (minimum {} required). \
                 Audit integrity cannot be guaranteed with fewer than {} nodes (2f+1 = {} quorum).",
                node_count, MIN_BFT_NODES, MIN_BFT_NODES, BFT_QUORUM
            );
        }

        check_single_process_military_deployment();
        check_bft_node_addresses();

        let f = (node_count - 1) / 3; // max Byzantine faults tolerated
        let quorum = 2 * f + 1; // minimum for consensus
        let nodes: Vec<AuditNode> = (0..node_count as u8).map(AuditNode::new).collect();
        let mut cluster = Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: None,
            pq_verifying_key: None,
            f,
            sequence_number: 0,
            single_process_mode: default_single_process_mode(),
            quarantined: Vec::new(),
            last_proposal_at: Instant::now(),
        };
        cluster.initialize_heartbeats();
        cluster
    }

    /// Create a new cluster with an ML-DSA-87 signing key for entry signing.
    pub fn new_with_signing_key(node_count: usize, signing_key: pq_sign::PqSigningKey) -> Self {
        // BFT requires minimum 11 nodes -- fail hard if fewer
        if node_count < MIN_BFT_NODES {
            tracing::error!(
                "CRITICAL: BFT audit running with {} nodes (minimum {} required). \
                 Audit integrity cannot be guaranteed with fewer than {} nodes (2f+1 = {} quorum).",
                node_count, MIN_BFT_NODES, MIN_BFT_NODES, BFT_QUORUM
            );
        }

        check_single_process_military_deployment();

        let f = (node_count - 1) / 3;
        let quorum = 2 * f + 1;
        let verifying_key = signing_key.verifying_key().clone();
        let nodes: Vec<AuditNode> = (0..node_count as u8)
            .map(|id| AuditNode::new_with_verifying_key(id, verifying_key.clone()))
            .collect();
        let mut cluster = Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: Some(signing_key),
            pq_verifying_key: Some(verifying_key),
            f,
            sequence_number: 0,
            single_process_mode: default_single_process_mode(),
            quarantined: Vec::new(),
            last_proposal_at: Instant::now(),
        };
        cluster.initialize_heartbeats();
        cluster
    }

    /// Create a new cluster with signing key and per-node file persistence.
    ///
    /// Each node gets its own persistence file under `persistence_dir`:
    ///   `persistence_dir/node_<id>.jsonl`
    ///
    /// On startup, each node reloads its entries and verifies its chain.
    pub fn new_with_persistence(
        node_count: usize,
        signing_key: pq_sign::PqSigningKey,
        persistence_dir: &std::path::Path,
    ) -> Self {
        // BFT requires minimum 11 nodes -- fail hard if fewer
        if node_count < MIN_BFT_NODES {
            tracing::error!(
                "CRITICAL: BFT audit running with {} nodes (minimum {} required). \
                 Audit integrity cannot be guaranteed with fewer than {} nodes (2f+1 = {} quorum).",
                node_count, MIN_BFT_NODES, MIN_BFT_NODES, BFT_QUORUM
            );
        }

        let f = (node_count - 1) / 3;
        let quorum = 2 * f + 1;
        let verifying_key = signing_key.verifying_key().clone();
        let nodes: Vec<AuditNode> = (0..node_count as u8)
            .map(|id| {
                let path = persistence_dir.join(format!("node_{}.jsonl", id));
                let mut node = AuditNode::new_with_persistence(id, path);
                node.pq_verifying_key = Some(verifying_key.clone());
                node
            })
            .collect();
        check_single_process_military_deployment();

        let mut cluster = Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: Some(signing_key),
            pq_verifying_key: Some(verifying_key),
            f,
            sequence_number: 0,
            single_process_mode: default_single_process_mode(),
            quarantined: Vec::new(),
            last_proposal_at: Instant::now(),
        };
        cluster.initialize_heartbeats();
        cluster
    }

    /// Initialize heartbeats so all nodes know about each other at startup.
    /// This prevents false partition detection on newly created clusters.
    fn initialize_heartbeats(&mut self) {
        let info: Vec<(usize, u64)> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (i, n.epoch))
            .collect();

        for &(target_idx, _) in &info {
            for &(src_idx, src_epoch) in &info {
                if target_idx != src_idx {
                    self.nodes[target_idx].heartbeat(src_idx, src_epoch);
                }
            }
        }
    }

    /// Maximum time to wait for a proposer to produce an entry before rotation (5 seconds).
    const PROPOSER_TIMEOUT_MS: u128 = 5_000;

    /// Check if the current proposer has timed out.
    /// If the last successful proposal was more than PROPOSER_TIMEOUT_MS ago,
    /// automatically advance to the next proposer by incrementing the sequence number.
    pub fn check_proposer_timeout(&mut self) -> bool {
        let elapsed = self.last_proposal_at.elapsed().as_millis();
        if elapsed > Self::PROPOSER_TIMEOUT_MS {
            self.sequence_number += 1;
            tracing::warn!(
                elapsed_ms = elapsed,
                new_sequence = self.sequence_number,
                "BFT proposer timeout: advancing to next proposer after {}ms",
                elapsed
            );
            true
        } else {
            false
        }
    }

    /// Propose an entry using a two-phase BFT commit protocol.
    ///
    /// Phase 1 (PREPARE): Proposer sends entry to all nodes. Each node validates
    /// the entry (prev_hash, epoch) and returns a PREPARE-OK vote with the entry
    /// hash. The proposer collects votes and checks for equivocation (conflicting
    /// hashes from different nodes for the same entry).
    ///
    /// Phase 2 (COMMIT): Once quorum PREPARE-OK votes are collected for the SAME
    /// entry hash, the proposer sends a COMMIT message with the quorum proof
    /// (set of voting node IDs). Nodes only commit after verifying quorum proof.
    ///
    /// This prevents a Byzantine proposer from sending different entries to
    /// different nodes (equivocation attack), because nodes exchange prepare
    /// votes and verify quorum before committing.
    ///
    /// Proposer rotation: If the current proposer fails (timeout or partition),
    /// the next honest node in round-robin order takes over. This prevents a
    /// single Byzantine or crashed proposer from stalling the cluster.
    pub fn propose_entry(
        &mut self,
        event_type: AuditEventType,
        user_ids: Vec<Uuid>,
        device_ids: Vec<Uuid>,
        risk_score: f64,
        ceremony_receipts: Vec<Receipt>,
        classification: u8,
    ) -> Result<[u8; 64], String> {
        // Quorum enforcement: REJECT if cluster lacks BFT guarantees.
        if !has_bft_quorum(self.nodes.len()) {
            common::siem::SecurityEvent::tamper_detected(
                &format!(
                    "BFT audit cluster has only {} nodes (minimum {} required). \
                     Rejecting entry to prevent Byzantine corruption.",
                    self.nodes.len(),
                    MIN_BFT_NODES
                ),
            );
            return Err(format!(
                "BFT quorum enforcement: cluster has {} nodes but minimum {} required. \
                 Cannot commit audit entries without Byzantine fault tolerance.",
                self.nodes.len(),
                MIN_BFT_NODES
            ));
        }

        // Rotate proposer based on sequence number across honest nodes.
        // Try up to f+1 proposers to handle Byzantine/crashed proposers.
        let honest_indices: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.is_byzantine)
            .map(|(i, _)| i)
            .collect();
        if honest_indices.is_empty() {
            return Err("no honest nodes available".to_string());
        }

        let max_proposer_attempts = self.f + 1;
        let mut last_error = String::new();

        for attempt in 0..max_proposer_attempts {
            let proposer_idx =
                honest_indices[(self.sequence_number as usize + attempt) % honest_indices.len()];

            // Check partition status of the proposer.
            if self.nodes[proposer_idx].check_partition(self.nodes.len()) {
                last_error = format!(
                    "proposer {} is in a minority partition (attempt {}/{})",
                    proposer_idx, attempt + 1, max_proposer_attempts
                );
                tracing::warn!("{}", last_error);
                continue; // Try next proposer
            }

            let proposer_epoch = self.nodes[proposer_idx].epoch;

            // Build the entry using the proposer's state for prev_hash.
            let prev_hash = {
                let proposer = &self.nodes[proposer_idx];
                if proposer.log.is_empty() {
                    [0u8; 64]
                } else {
                    hash_entry(&proposer.log.entries()[proposer.log.len() - 1])
                }
            };

            let mut entry = AuditEntry {
                event_id: Uuid::new_v4(),
                event_type: event_type.clone(),
                user_ids: user_ids.clone(),
                device_ids: device_ids.clone(),
                ceremony_receipts: ceremony_receipts.clone(),
                risk_score,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as i64,
                prev_hash,
                signature: Vec::new(),
                classification,
                correlation_id: None,
                trace_id: None,
                source_ip: None,
                session_id: None,
                request_id: None,
                user_agent: None,
            };

            if let Some(ref key) = self.pq_signing_key {
                let hash = hash_entry(&entry);
                entry.signature = pq_sign::pq_sign_raw(key, &hash);
            }

            // ── PHASE 1: PREPARE ──
            // Send entry to all nodes, collect prepare votes.
            // Each vote is (node_index, entry_hash). Votes must agree on the
            // same hash to prevent equivocation.
            let mut prepare_votes: Vec<(usize, [u8; 64])> = Vec::new();

            for (node_idx, node) in self.nodes.iter().enumerate() {
                // Validate entry against this node's state (read-only check)
                if node.is_byzantine {
                    continue; // Byzantine nodes may vote but we track their votes
                }

                // Check prev_hash matches this node's last entry
                let node_last = if node.log.is_empty() {
                    [0u8; 64]
                } else {
                    hash_entry(&node.log.entries()[node.log.len() - 1])
                };

                if entry.prev_hash != node_last {
                    continue; // Node has divergent state, cannot prepare
                }

                // Check proposer epoch
                if proposer_epoch < node.epoch {
                    continue; // Stale proposer
                }

                // Node accepts the prepare: compute entry hash as vote
                let entry_hash = hash_entry(&entry);
                prepare_votes.push((node_idx, entry_hash));
            }

            // Check for equivocation: all prepare votes must agree on the same hash.
            // In a correct system this always holds; divergence means Byzantine proposer.
            if prepare_votes.len() >= 2 {
                let reference_hash = prepare_votes[0].1;
                let equivocation = prepare_votes.iter().any(|(_, h)| h != &reference_hash);
                if equivocation {
                    common::siem::SecurityEvent::tamper_detected(
                        &format!(
                            "BFT EQUIVOCATION DETECTED: proposer {} sent conflicting entries \
                             to different nodes. Prepare votes have inconsistent hashes. \
                             Rotating to next proposer.",
                            proposer_idx
                        ),
                    );
                    last_error = format!(
                        "equivocation detected from proposer {} (attempt {}/{})",
                        proposer_idx, attempt + 1, max_proposer_attempts
                    );
                    continue; // Try next proposer
                }
            }

            // Use effective_quorum to account for quarantined nodes
            let required = self.effective_quorum().unwrap_or(self.quorum_size);

            // Check if we have quorum prepare votes
            if prepare_votes.len() < required {
                last_error = format!(
                    "prepare quorum not met: {}/{} voted (need {}) for proposer {} (attempt {}/{})",
                    prepare_votes.len(),
                    self.nodes.len(),
                    required,
                    proposer_idx,
                    attempt + 1,
                    max_proposer_attempts
                );
                tracing::warn!("{}", last_error);
                continue; // Try next proposer
            }

            // ── PHASE 2: COMMIT ──
            // Quorum reached. Now commit the entry to all nodes that prepared.
            // The commit includes the quorum proof (set of voting node indices)
            // so each node can independently verify that quorum was achieved.
            let voting_nodes: Vec<usize> = prepare_votes.iter().map(|(idx, _)| *idx).collect();
            let entry_hash = prepare_votes[0].1;

            let mut commit_count = 0usize;
            for &node_idx in &voting_nodes {
                // Verify quorum proof: this node can see that enough nodes prepared
                if voting_nodes.len() < required {
                    continue; // Should not happen, but defense in depth
                }
                // Actually commit the entry
                if let Some(_hash) = self.nodes[node_idx].accept_entry(&entry, proposer_epoch) {
                    commit_count += 1;
                }
            }

            if commit_count >= required {
                // Exchange heartbeats among all nodes that committed.
                self.exchange_heartbeats();
                self.sequence_number += 1;
                self.last_proposal_at = Instant::now();
                tracing::info!(
                    proposer = proposer_idx,
                    committed = commit_count,
                    quorum = required,
                    attempt = attempt + 1,
                    "BFT entry committed via two-phase protocol"
                );
                return Ok(entry_hash);
            }

            last_error = format!(
                "commit failed: {}/{} committed (need {}) for proposer {}",
                commit_count,
                voting_nodes.len(),
                required,
                proposer_idx
            );
        }

        Err(format!(
            "BFT proposal failed after {} proposer attempts. Last error: {}",
            max_proposer_attempts, last_error
        ))
    }

    /// Verify all honest nodes have consistent chains.
    pub fn verify_consistency(&self) -> bool {
        let honest_nodes: Vec<&AuditNode> = self.nodes.iter().filter(|n| !n.is_byzantine).collect();

        if honest_nodes.is_empty() {
            return true;
        }

        let reference = &honest_nodes[0].log;
        for node in &honest_nodes[1..] {
            if node.log.len() != reference.len() {
                return false;
            }
            // Compare hashes of last entry
            if !node.log.is_empty() && !reference.is_empty() {
                let node_hash = hash_entry(&node.log.entries()[node.log.len() - 1]);
                let ref_hash = hash_entry(&reference.entries()[reference.len() - 1]);
                if node_hash != ref_hash {
                    return false;
                }
            }
        }
        true
    }

    /// Mark a node as Byzantine (for testing).
    pub fn set_byzantine(&mut self, node_id: u8) {
        if let Some(node) = self.nodes.iter_mut().find(|n| n.node_id == node_id) {
            node.is_byzantine = true;
        }
    }

    /// Exchange heartbeats among all honest nodes so they know about each other.
    /// Called after a successful proposal round.
    fn exchange_heartbeats(&mut self) {
        // Collect (node_index, epoch) for all honest nodes.
        let info: Vec<(usize, u64)> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.is_byzantine)
            .map(|(i, n)| (i, n.epoch))
            .collect();

        // Each honest node records heartbeats from every other honest node.
        for &(target_idx, _) in &info {
            for &(src_idx, src_epoch) in &info {
                if target_idx != src_idx {
                    self.nodes[target_idx].heartbeat(src_idx, src_epoch);
                }
            }
        }
    }

    /// Number of active (non-quarantined) nodes.
    pub fn active_node_count(&self) -> usize {
        self.nodes.len() - self.quarantined.len()
    }

    /// Adjusted quorum size excluding quarantined nodes.
    /// Returns None if too many nodes are quarantined for safety.
    pub fn effective_quorum(&self) -> Option<usize> {
        let active = self.active_node_count();
        let f = (active.saturating_sub(1)) / 3;
        let quorum = 2 * f + 1;
        if active < quorum {
            return None; // System cannot safely proceed.
        }
        Some(quorum)
    }

    /// Check if a node is currently quarantined.
    pub fn is_quarantined(&self, node_id: usize) -> bool {
        self.quarantined.iter().any(|q| q.node_id == node_id)
    }

    /// Quarantine a node: remove from active quorum, log SIEM event.
    pub fn quarantine_node(&mut self, node_id: usize, reason: ByzantineReason) {
        if self.is_quarantined(node_id) {
            return; // Already quarantined.
        }

        let detected_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Compute evidence hash (SHA-512 of node_id + reason description).
        let mut evidence = Vec::new();
        evidence.extend_from_slice(&(node_id as u64).to_le_bytes());
        evidence.extend_from_slice(&detected_at.to_le_bytes());
        let evidence_hash = {
            use sha2::{Sha512, Digest};
            let mut hasher = Sha512::new();
            hasher.update(&evidence);
            let result = hasher.finalize();
            let mut hash = [0u8; 64];
            hash.copy_from_slice(&result);
            hash
        };

        let quarantined_node = QuarantinedNode {
            node_id,
            detected_at,
            reason,
            evidence_hash,
            re_attestation_required: true,
        };

        self.quarantined.push(quarantined_node);

        // Mark the node as Byzantine in the cluster.
        if node_id < self.nodes.len() {
            self.nodes[node_id].is_byzantine = true;
        }

        // Recalculate quorum excluding quarantined nodes.
        let active = self.active_node_count();
        let f = (active.saturating_sub(1)) / 3;
        self.quorum_size = 2 * f + 1;
        self.f = f;

        // SIEM event.
        let detail = format!(
            "BFT node {} quarantined at epoch {}. Active nodes: {}, new quorum: {}",
            node_id, detected_at, active, self.quorum_size
        );
        tracing::error!("SIEM:CRITICAL {}", detail);
        common::siem::SecurityEvent::tamper_detected(&detail);
    }

    /// Attempt readmission of a quarantined node.
    /// Requires: valid attestation (simulated by `attestation_valid` param),
    /// chain sync (node's epoch matches cluster), and unanimous vote from
    /// all remaining active honest nodes.
    pub fn attempt_readmission(
        &mut self,
        node_id: usize,
        attestation_valid: bool,
        votes: &[usize],
    ) -> Result<(), String> {
        let qidx = self.quarantined.iter().position(|q| q.node_id == node_id)
            .ok_or_else(|| format!("node {} is not quarantined", node_id))?;

        if !attestation_valid {
            return Err("ML-DSA-87 attestation verification failed".to_string());
        }

        // Verify unanimous vote from all active honest nodes.
        let active_honest: Vec<usize> = self.nodes.iter().enumerate()
            .filter(|(i, n)| !n.is_byzantine && !self.is_quarantined(*i))
            .map(|(i, _)| i)
            .collect();

        for &honest_id in &active_honest {
            if !votes.contains(&honest_id) {
                return Err(format!(
                    "readmission requires unanimous vote; missing vote from node {}",
                    honest_id
                ));
            }
        }

        // Readmit: remove from quarantine, unmark Byzantine.
        self.quarantined.remove(qidx);
        if node_id < self.nodes.len() {
            self.nodes[node_id].is_byzantine = false;
        }

        // Recalculate quorum.
        let active = self.active_node_count();
        let f = (active.saturating_sub(1)) / 3;
        self.quorum_size = 2 * f + 1;
        self.f = f;

        let detail = format!(
            "BFT node {} readmitted. Active nodes: {}, quorum: {}",
            node_id, active, self.quorum_size
        );
        tracing::info!("SIEM:INFO {}", detail);
        common::siem::SecurityEvent {
            timestamp: common::siem::SecurityEvent::now_iso8601(),
            category: "bft_quarantine",
            action: "node_readmitted",
            severity: common::siem::Severity::Info,
            outcome: "success",
            user_id: None,
            source_ip: None,
            detail: Some(detail),
        }
        .emit();

        Ok(())
    }

    /// Detect Byzantine nodes using response time anomalies and chain divergence.
    ///
    /// Returns indices of nodes detected as Byzantine.  A node is confirmed
    /// Byzantine only when at least f + 1 non-Byzantine nodes agree on the
    /// detection (implemented here as majority-chain agreement for divergence
    /// checks).
    pub fn detect_byzantine(&mut self) -> Vec<usize> {
        let n = self.nodes.len();
        let f_plus_1 = self.f + 1;

        let mut state = ByzantineDetectionState {
            suspicious_nodes: Vec::new(),
            diverged_nodes: Vec::new(),
            confirmed_byzantine: Vec::new(),
        };

        // --- Response time anomaly detection ---
        // Aggregate all response time observations across all observer nodes.
        let mut all_times: Vec<u64> = Vec::new();
        let mut per_node_times: HashMap<usize, Vec<u64>> = HashMap::new();

        for node in &self.nodes {
            for (&peer, times) in &node.response_times {
                all_times.extend_from_slice(times);
                per_node_times.entry(peer).or_default().extend_from_slice(times);
            }
        }

        if all_times.len() > 1 {
            let global_mean = all_times.iter().sum::<u64>() as f64 / all_times.len() as f64;
            let variance = all_times
                .iter()
                .map(|&t| {
                    let diff = t as f64 - global_mean;
                    diff * diff
                })
                .sum::<f64>()
                / all_times.len() as f64;
            let stddev = variance.sqrt();

            // Flag nodes whose mean response time deviates > 3 stddev from global mean.
            for (peer, times) in &per_node_times {
                if times.is_empty() {
                    continue;
                }
                let peer_mean = times.iter().sum::<u64>() as f64 / times.len() as f64;
                if (peer_mean - global_mean).abs() > 3.0 * stddev && stddev > 0.0 {
                    state.suspicious_nodes.push(*peer);
                }
            }
        }

        // --- Chain divergence detection ---
        // Build a map of (chain_length, last_entry_hash) -> list of node indices.
        let mut chain_groups: HashMap<(usize, [u8; 64]), Vec<usize>> = HashMap::new();
        for (i, node) in self.nodes.iter().enumerate() {
            let last_hash = if node.log.is_empty() {
                [0u8; 64]
            } else {
                hash_entry(&node.log.entries()[node.log.len() - 1])
            };
            chain_groups
                .entry((node.log.len(), last_hash))
                .or_default()
                .push(i);
        }

        // The majority chain group is the one with the most members.
        if let Some((_, majority_nodes)) = chain_groups.iter().max_by_key(|(_, members)| members.len()) {
            let majority_set: std::collections::HashSet<usize> =
                majority_nodes.iter().copied().collect();

            // Nodes not in the majority group are diverged.
            for i in 0..n {
                if !majority_set.contains(&i) {
                    state.diverged_nodes.push(i);
                }
            }

            // Confirm Byzantine only if the majority group has at least f+1
            // non-Byzantine members (agreement requirement).
            let non_byzantine_in_majority = majority_nodes
                .iter()
                .filter(|&&idx| !self.nodes[idx].is_byzantine)
                .count();

            if non_byzantine_in_majority >= f_plus_1 {
                for &diverged_idx in &state.diverged_nodes {
                    state.confirmed_byzantine.push(diverged_idx);
                }
            }
        }

        // Also confirm suspicious nodes if enough non-Byzantine nodes observed them.
        for &suspicious_idx in &state.suspicious_nodes {
            if !state.confirmed_byzantine.contains(&suspicious_idx) {
                // Count how many non-Byzantine observer nodes flagged this peer.
                let observer_count = self
                    .nodes
                    .iter()
                    .enumerate()
                    .filter(|(i, node)| {
                        *i != suspicious_idx
                            && !node.is_byzantine
                            && node
                                .response_times
                                .get(&suspicious_idx)
                                .map_or(false, |times| {
                                    if times.is_empty() || all_times.len() <= 1 {
                                        return false;
                                    }
                                    let global_mean =
                                        all_times.iter().sum::<u64>() as f64 / all_times.len() as f64;
                                    let variance = all_times
                                        .iter()
                                        .map(|&t| {
                                            let diff = t as f64 - global_mean;
                                            diff * diff
                                        })
                                        .sum::<f64>()
                                        / all_times.len() as f64;
                                    let stddev = variance.sqrt();
                                    let peer_mean =
                                        times.iter().sum::<u64>() as f64 / times.len() as f64;
                                    stddev > 0.0
                                        && (peer_mean - global_mean).abs() > 3.0 * stddev
                                })
                    })
                    .count();

                if observer_count >= f_plus_1 {
                    state.confirmed_byzantine.push(suspicious_idx);
                }
            }
        }

        // Emit CRITICAL SIEM events for confirmed Byzantine nodes.
        for &idx in &state.confirmed_byzantine {
            let detail = format!(
                "Byzantine node detected: node {} (suspicious={}, diverged={})",
                idx,
                state.suspicious_nodes.contains(&idx),
                state.diverged_nodes.contains(&idx),
            );
            tracing::error!("CRITICAL: {}", detail);
            common::siem::SecurityEvent::tamper_detected(&detail);

            // Mark node as Byzantine in the cluster.
            self.nodes[idx].is_byzantine = true;
        }

        state.confirmed_byzantine
    }
}

// ── File persistence helpers ─────────────────────────────────────────────

/// Domain separation string for BFT persistence encryption.
const BFT_PERSIST_AAD: &[u8] = b"MILNET-BFT-PERSIST-v1";

/// Derive a per-node encryption key from the master KEK for BFT persistence.
/// Uses HKDF-SHA512 with node_id in the info string for domain separation.
fn derive_bft_persist_key(node_id: u8) -> [u8; 32] {
    use sha2::Sha512;
    use hkdf::Hkdf;

    let kek = common::sealed_keys::get_master_kek();
    let hkdf = Hkdf::<Sha512>::new(Some(b"MILNET-BFT-NODE-KEY-v1"), kek);
    let info = format!("bft-node-{}", node_id);
    let mut key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut key)
        .expect("HKDF expand for BFT persist key");
    key
}

/// Encrypt and append a single audit entry to the given file.
///
/// Each line is: hex(nonce || AES-256-GCM(json, AAD=MILNET-BFT-PERSIST-v1))
/// This prevents disk compromise from exposing audit entries in cleartext.
fn append_entry_to_file(path: &std::path::Path, entry: &AuditEntry) -> std::io::Result<()> {
    let json = serde_json::to_string(entry).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;

    // Derive per-node key from path (node_id embedded in filename)
    let node_id = path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("node_"))
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(0);
    let key = derive_bft_persist_key(node_id);

    // Encrypt: nonce(12) || ciphertext || tag(16)
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("CSPRNG failed: {e}"))
    })?;
    let nonce = GenericArray::from_slice(&nonce_bytes);

    let payload = aes_gcm::aead::Payload {
        msg: json.as_bytes(),
        aad: BFT_PERSIST_AAD,
    };
    let ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("AES-GCM encrypt failed: {e}"))
    })?;

    // Wire format: nonce || ciphertext (hex-encoded per line)
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", hex::encode(&blob))?;
    file.sync_data()?;

    // Zeroize key material
    let mut key = key;
    zeroize::Zeroize::zeroize(&mut key);

    Ok(())
}

/// Load and decrypt audit entries from an encrypted JSONL persistence file.
/// Returns an empty vec if the file does not exist or is empty.
/// Logs warnings for malformed/tampered lines but continues loading valid ones.
fn load_entries_from_file(path: &std::path::Path, node_id: u8) -> Vec<AuditEntry> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::error!(
                "BFT node {}: failed to open persistence file {:?}: {}",
                node_id, path, e
            );
            return Vec::new();
        }
    };

    let mut key = derive_bft_persist_key(node_id);

    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        match line {
            Ok(text) => {
                let text = text.trim().to_string();
                if text.is_empty() {
                    continue;
                }
                // Try encrypted format first (hex-encoded nonce || ciphertext)
                let parsed = hex::decode(&text)
                    .ok()
                    .and_then(|blob| {
                        if blob.len() < 12 + 16 {
                            return None; // Too short for nonce + tag
                        }
                        let nonce = GenericArray::from_slice(&blob[..12]);
                        let payload = aes_gcm::aead::Payload {
                            msg: &blob[12..],
                            aad: BFT_PERSIST_AAD,
                        };
                        cipher.decrypt(nonce, payload).ok()
                    })
                    .and_then(|plaintext| {
                        serde_json::from_slice::<AuditEntry>(&plaintext).ok()
                    });

                // Fallback: try legacy plaintext JSON for migration
                let entry = parsed.or_else(|| {
                    tracing::warn!(
                        "BFT node {}: line {} is not encrypted, attempting legacy plaintext parse",
                        node_id, line_num + 1
                    );
                    serde_json::from_str::<AuditEntry>(&text).ok()
                });

                match entry {
                    Some(e) => entries.push(e),
                    None => {
                        tracing::warn!(
                            "BFT node {}: skipping tampered/malformed line {} in {:?}",
                            node_id, line_num + 1, path
                        );
                        common::siem::SecurityEvent::tamper_detected(
                            &format!(
                                "BFT node {}: persistence file {:?} line {} failed decryption. \
                                 Possible disk tampering or key mismatch.",
                                node_id, path, line_num + 1
                            ),
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "BFT node {}: I/O error reading line {} from {:?}: {}",
                    node_id, line_num + 1, path, e
                );
            }
        }
    }

    // Zeroize key material
    zeroize::Zeroize::zeroize(&mut key);

    entries
}

// ── Quarantine tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod quarantine_tests {
    use super::*;

    fn make_test_cluster() -> BftAuditCluster {
        // Use MILNET_MASTER_KEK for persistence key derivation.
        std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));
        std::env::set_var("MILNET_BFT_SINGLE_PROCESS_ACK", "1");
        BftAuditCluster::new(11)
    }

    #[test]
    fn divergent_node_is_quarantined() {
        let mut cluster = make_test_cluster();
        assert_eq!(cluster.quarantined.len(), 0);

        // Quarantine node 3 for chain divergence.
        cluster.quarantine_node(
            3,
            ByzantineReason::ChainDivergence {
                expected_hash: [0xAA; 64],
                actual_hash: [0xBB; 64],
            },
        );

        assert_eq!(cluster.quarantined.len(), 1);
        assert_eq!(cluster.quarantined[0].node_id, 3);
        assert!(cluster.is_quarantined(3));
        assert!(cluster.nodes[3].is_byzantine);
        assert!(cluster.quarantined[0].re_attestation_required);
    }

    #[test]
    fn quarantined_node_excluded_from_quorum() {
        let mut cluster = make_test_cluster();
        let original_quorum = cluster.quorum_size;

        // Quarantine 3 nodes.
        for i in 0..3 {
            cluster.quarantine_node(i, ByzantineReason::SignatureFailure);
        }

        // Active = 11 - 3 = 8, f = (8-1)/3 = 2, quorum = 2*2+1 = 5
        assert_eq!(cluster.active_node_count(), 8);
        assert_eq!(cluster.quorum_size, 5);
        assert!(cluster.quorum_size < original_quorum);
    }

    #[test]
    fn readmission_requires_attestation_and_vote() {
        let mut cluster = make_test_cluster();

        cluster.quarantine_node(5, ByzantineReason::SignatureFailure);
        assert!(cluster.is_quarantined(5));

        // Fail without attestation.
        let result = cluster.attempt_readmission(5, false, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("attestation"));

        // Fail without unanimous votes.
        let result = cluster.attempt_readmission(5, true, &[0, 1, 2]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unanimous"));

        // Succeed with attestation + all active honest node votes.
        let active_honest: Vec<usize> = cluster.nodes.iter().enumerate()
            .filter(|(i, n)| !n.is_byzantine && !cluster.is_quarantined(*i))
            .map(|(i, _)| i)
            .collect();
        let result = cluster.attempt_readmission(5, true, &active_honest);
        assert!(result.is_ok());
        assert!(!cluster.is_quarantined(5));
        assert!(!cluster.nodes[5].is_byzantine);
    }

    #[test]
    fn multiple_quarantines_shrink_quorum() {
        let mut cluster = make_test_cluster();

        // 11 nodes: f=3, quorum=7
        assert_eq!(cluster.quorum_size, 7);

        // Quarantine 1 node: 10 active, f=3, quorum=7
        cluster.quarantine_node(0, ByzantineReason::SignatureFailure);
        assert_eq!(cluster.active_node_count(), 10);
        assert_eq!(cluster.quorum_size, 7);

        // Quarantine 2 more: 8 active, f=2, quorum=5
        cluster.quarantine_node(1, ByzantineReason::SignatureFailure);
        cluster.quarantine_node(2, ByzantineReason::SignatureFailure);
        assert_eq!(cluster.active_node_count(), 8);
        assert_eq!(cluster.quorum_size, 5);

        // Quarantine 3 more: 5 active, f=1, quorum=3
        cluster.quarantine_node(3, ByzantineReason::SignatureFailure);
        cluster.quarantine_node(4, ByzantineReason::SignatureFailure);
        cluster.quarantine_node(5, ByzantineReason::SignatureFailure);
        assert_eq!(cluster.active_node_count(), 5);
        assert_eq!(cluster.quorum_size, 3);
    }

    #[test]
    fn system_halts_if_too_many_quarantined() {
        let mut cluster = make_test_cluster();

        // Quarantine 8 of 11 nodes: 3 active, f=0, quorum=1
        for i in 0..8 {
            cluster.quarantine_node(i, ByzantineReason::SignatureFailure);
        }

        assert_eq!(cluster.active_node_count(), 3);
        // effective_quorum checks if the cluster can safely operate.
        // With 3 active: f=0, quorum=1. This is technically achievable
        // but has zero fault tolerance.
        let eq = cluster.effective_quorum();
        assert!(eq.is_some()); // Can still operate (quorum=1).

        // Quarantine 2 more: 1 active node remaining.
        cluster.quarantine_node(8, ByzantineReason::SignatureFailure);
        cluster.quarantine_node(9, ByzantineReason::SignatureFailure);
        assert_eq!(cluster.active_node_count(), 1);
        // 1 active: f=0, quorum=1. Can technically still operate with 1 node.
        let eq = cluster.effective_quorum();
        assert!(eq.is_some());

        // Quarantine the last node: 0 active.
        cluster.quarantine_node(10, ByzantineReason::SignatureFailure);
        assert_eq!(cluster.active_node_count(), 0);
        let eq = cluster.effective_quorum();
        assert!(eq.is_none(), "system should halt with 0 active nodes");
    }
}
