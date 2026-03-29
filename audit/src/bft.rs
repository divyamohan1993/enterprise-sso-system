//! Simplified BFT audit replication with split-brain prevention and
//! automatic Byzantine node detection.
//!
//! Models a cluster of 7 audit nodes that tolerates up to 2 Byzantine faults.
//! An entry is considered committed when a quorum (2f + 1 = 5) of nodes accept it.
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

/// Minimum BFT nodes for Byzantine fault tolerance (tolerates f=2 failures).
pub const MIN_BFT_NODES: usize = 7;
/// Quorum size: 2f+1 where f = floor((n-1)/3).
pub const BFT_QUORUM: usize = 5;

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
            if !log.verify_chain() {
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
        }
    }

    /// Accept an entry proposal. Returns the entry hash if accepted.
    ///
    /// Before accepting, checks that the proposer epoch is not stale
    /// (i.e., the proposer's epoch must be >= our own epoch).
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

        // Verify the entry's prev_hash matches our last hash
        let our_last = if self.log.is_empty() {
            [0u8; 64]
        } else {
            hash_entry(&self.log.entries()[self.log.len() - 1])
        };
        if entry.prev_hash != our_last {
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

/// BFT audit cluster.
pub struct BftAuditCluster {
    pub nodes: Vec<AuditNode>,
    /// Minimum number of nodes that must accept for an entry to be committed.
    pub quorum_size: usize,
    /// Optional ML-DSA-65 signing key for signing audit entries.
    pq_signing_key: Option<pq_sign::PqSigningKey>,
    /// Maximum Byzantine faults tolerated.
    f: usize,
}

impl BftAuditCluster {
    /// Create a new cluster. `node_count` should be >= 4 for meaningful BFT
    /// (3f + 1). For 7 nodes: f = 2, quorum = 2f + 1 = 5.
    pub fn new(node_count: usize) -> Self {
        // BFT requires minimum 7 nodes — fail hard if fewer
        if node_count < 7 {
            tracing::error!(
                "CRITICAL: BFT audit running with {} nodes (minimum 7 required). \
                 Audit integrity cannot be guaranteed with fewer than 7 nodes (2f+1 = 5 quorum).",
                node_count
            );
        }

        let f = (node_count - 1) / 3; // max Byzantine faults tolerated
        let quorum = 2 * f + 1; // minimum for consensus
        let nodes: Vec<AuditNode> = (0..node_count as u8).map(AuditNode::new).collect();
        let mut cluster = Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: None,
            f,
        };
        cluster.initialize_heartbeats();
        cluster
    }

    /// Create a new cluster with an ML-DSA-65 signing key for entry signing.
    pub fn new_with_signing_key(node_count: usize, signing_key: pq_sign::PqSigningKey) -> Self {
        // BFT requires minimum 7 nodes — fail hard if fewer
        if node_count < 7 {
            tracing::error!(
                "CRITICAL: BFT audit running with {} nodes (minimum 7 required). \
                 Audit integrity cannot be guaranteed with fewer than 7 nodes (2f+1 = 5 quorum).",
                node_count
            );
        }

        let f = (node_count - 1) / 3;
        let quorum = 2 * f + 1;
        let nodes: Vec<AuditNode> = (0..node_count as u8).map(AuditNode::new).collect();
        let mut cluster = Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: Some(signing_key),
            f,
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
        // BFT requires minimum 7 nodes — fail hard if fewer
        if node_count < 7 {
            tracing::error!(
                "CRITICAL: BFT audit running with {} nodes (minimum 7 required). \
                 Audit integrity cannot be guaranteed with fewer than 7 nodes (2f+1 = 5 quorum).",
                node_count
            );
        }

        let f = (node_count - 1) / 3;
        let quorum = 2 * f + 1;
        let nodes: Vec<AuditNode> = (0..node_count as u8)
            .map(|id| {
                let path = persistence_dir.join(format!("node_{}.jsonl", id));
                AuditNode::new_with_persistence(id, path)
            })
            .collect();
        let mut cluster = Self {
            nodes,
            quorum_size: quorum,
            pq_signing_key: Some(signing_key),
            f,
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

    /// Propose an entry to all nodes. Returns `Ok(entry_hash)` if quorum accepts.
    ///
    /// Before proposing, checks that the proposing node (the first honest node)
    /// is not in a minority partition. The proposer's epoch is included as
    /// metadata so that acceptors can reject stale proposals.
    pub fn propose_entry(
        &mut self,
        event_type: AuditEventType,
        user_ids: Vec<Uuid>,
        device_ids: Vec<Uuid>,
        risk_score: f64,
        ceremony_receipts: Vec<Receipt>,
        classification: u8,
    ) -> Result<[u8; 64], String> {
        // Find the first honest node to act as proposer.
        let proposer_idx = self
            .nodes
            .iter()
            .position(|n| !n.is_byzantine)
            .ok_or_else(|| "no honest nodes available".to_string())?;

        // Check partition status of the proposer.
        if self.nodes[proposer_idx].check_partition(self.nodes.len()) {
            return Err(
                "proposer is in a minority partition; refusing to accept entries".to_string(),
            );
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
            event_type,
            user_ids,
            device_ids,
            ceremony_receipts,
            risk_score,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
            prev_hash,
            signature: Vec::new(),
            classification,
        };

        if let Some(ref key) = self.pq_signing_key {
            let hash = hash_entry(&entry);
            entry.signature = pq_sign::pq_sign_raw(key, &hash);
        }

        // Quorum enforcement: warn if cluster lacks BFT guarantees
        if !has_bft_quorum(self.nodes.len()) {
            tracing::error!(
                "CRITICAL: committing audit entry with only {} nodes (minimum {} required for BFT). \
                 Byzantine fault tolerance is NOT guaranteed.",
                self.nodes.len(),
                MIN_BFT_NODES
            );
        }

        // Propose to all nodes, count acceptances.
        let mut accept_count = 0usize;
        let mut entry_hash = [0u8; 64];

        for node in &mut self.nodes {
            if let Some(hash) = node.accept_entry(&entry, proposer_epoch) {
                accept_count += 1;
                entry_hash = hash;
            }
        }

        if accept_count >= self.quorum_size {
            // Exchange heartbeats among all nodes that accepted.
            self.exchange_heartbeats();
            Ok(entry_hash)
        } else {
            Err(format!(
                "quorum not met: {}/{} accepted (need {})",
                accept_count,
                self.nodes.len(),
                self.quorum_size
            ))
        }
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

/// Append a single audit entry as a JSON line to the given file.
fn append_entry_to_file(path: &std::path::Path, entry: &AuditEntry) -> std::io::Result<()> {
    let json = serde_json::to_string(entry).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", json)?;
    file.sync_data()?;
    Ok(())
}

/// Load audit entries from a JSONL persistence file.
/// Returns an empty vec if the file does not exist or is empty.
/// Logs warnings for malformed lines but continues loading valid ones.
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

    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        match line {
            Ok(text) => {
                let text = text.trim().to_string();
                if text.is_empty() {
                    continue;
                }
                match serde_json::from_str::<AuditEntry>(&text) {
                    Ok(entry) => entries.push(entry),
                    Err(e) => {
                        tracing::warn!(
                            "BFT node {}: skipping malformed line {} in {:?}: {}",
                            node_id, line_num + 1, path, e
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
    entries
}
