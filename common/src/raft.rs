//! Raft consensus engine for distributed leader election.
//!
//! Minimal implementation focused on leader election and cluster state
//! replication. Log entries are cluster commands only (membership changes,
//! role assignments). NOT a general-purpose replicated state machine.
//!
//! Timing:
//! - Heartbeat interval: 500ms
//! - Election timeout: 1500-3000ms (randomized)
//! - Leader commits carry monotonic fencing tokens
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

// ── Core newtypes ──────────────────────────────────────────────────────────────

/// Unique identifier for a Raft node, wrapping a UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub Uuid);

impl NodeId {
    /// Create a new random node ID.
    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::LowerHex for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0.as_bytes();
        for b in bytes {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// Monotonically increasing term number used for leader elections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Term(pub u64);

impl Term {
    pub fn zero() -> Self {
        Self(0)
    }
}

impl std::fmt::Display for Term {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "T{}", self.0)
    }
}

/// Zero-based log index. Index 0 is a sentinel (no entry exists at index 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LogIndex(pub u64);

impl LogIndex {
    pub fn zero() -> Self {
        Self(0)
    }
}

impl std::fmt::Display for LogIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

// ── Role ───────────────────────────────────────────────────────────────────────

/// The current role of a Raft node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

// ── Cluster commands ───────────────────────────────────────────────────────────

/// Commands that can be replicated through the Raft log.
///
/// These are cluster-management commands only, not general data. Each command
/// describes a state transition in the cluster membership or health model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterCommand {
    /// A new node joins the cluster.
    MemberJoin {
        node_id: NodeId,
        addr: String,
        service_type: String,
    },
    /// A node leaves the cluster.
    MemberLeave { node_id: NodeId },
    /// Assign a role to a node (e.g., "auth-primary", "session-replica").
    RoleAssignment { node_id: NodeId, role: String },
    /// Health status update for a node.
    HealthUpdate { node_id: NodeId, healthy: bool },
    /// No-op entry committed by a new leader to establish its authority.
    Noop,
    /// Binary tampering detected on a node. The tampered node is stripped
    /// of leader role and flagged for healing. Other nodes will refuse to
    /// accept it as leader until the binary hash matches the golden hash.
    /// Hashes stored as Vec<u8> because serde doesn't support [u8; 64].
    TamperDetected {
        node_id: NodeId,
        expected_hash: Vec<u8>,
        actual_hash: Vec<u8>,
    },
    /// Node has been healed (binary replaced and verified). It can rejoin
    /// the cluster and be eligible for leader election again.
    TamperHealed { node_id: NodeId },
}

// ── Log entry ──────────────────────────────────────────────────────────────────

/// A single entry in the replicated log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: Term,
    pub index: LogIndex,
    pub command: ClusterCommand,
}

// ── Messages ───────────────────────────────────────────────────────────────────

/// Messages exchanged between Raft nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftMessage {
    /// Sent by a candidate to request votes during an election.
    RequestVote {
        term: Term,
        candidate_id: NodeId,
        last_log_index: LogIndex,
        last_log_term: Term,
    },
    /// Response to a vote request.
    RequestVoteResponse {
        term: Term,
        vote_granted: bool,
    },
    /// Sent by the leader to replicate entries and as heartbeats.
    AppendEntries {
        term: Term,
        leader_id: NodeId,
        prev_log_index: LogIndex,
        prev_log_term: Term,
        entries: Vec<LogEntry>,
        leader_commit: LogIndex,
    },
    /// Response to an AppendEntries RPC.
    AppendEntriesResponse {
        term: Term,
        success: bool,
        match_index: LogIndex,
    },
}

impl RaftMessage {
    /// Extract the term from any message variant.
    pub fn term(&self) -> Term {
        match self {
            Self::RequestVote { term, .. }
            | Self::RequestVoteResponse { term, .. }
            | Self::AppendEntries { term, .. }
            | Self::AppendEntriesResponse { term, .. } => *term,
        }
    }
}

// ── Configuration ──────────────────────────────────────────────────────────────

/// Configuration for a Raft node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    /// Heartbeat interval in milliseconds (default: 500).
    pub heartbeat_ms: u64,
    /// Minimum election timeout in milliseconds (default: 1500).
    pub election_timeout_min_ms: u64,
    /// Maximum election timeout in milliseconds (default: 3000).
    pub election_timeout_max_ms: u64,
    /// Peers in the cluster: (node_id, address) pairs.
    pub peers: Vec<(NodeId, String)>,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            heartbeat_ms: 500,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
            peers: Vec::new(),
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Generate a random election timeout duration using `getrandom`.
fn random_election_timeout(min_ms: u64, max_ms: u64) -> Duration {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).unwrap_or_else(|_| {
        buf = [42; 8];
    });
    let range = max_ms - min_ms;
    let random = u64::from_le_bytes(buf) % range;
    Duration::from_millis(min_ms + random)
}

// ── Raft state machine ────────────────────────────────────────────────────────

/// Core Raft state machine.
///
/// Implements leader election, log replication, and commit tracking.
/// Purely deterministic aside from timer reads: call [`RaftState::tick`] on
/// timer events and [`RaftState::handle_message`] on incoming RPCs. Both
/// return a list of `(NodeId, RaftMessage)` pairs to send over the network.
pub struct RaftState {
    /// This node's identity.
    node_id: NodeId,
    /// Latest term this node has seen.
    current_term: Term,
    /// Candidate that received our vote in the current term, if any.
    voted_for: Option<NodeId>,
    /// The replicated log (1-indexed; vec index 0 = log index 1).
    log: Vec<LogEntry>,
    /// Highest log index known to be committed.
    commit_index: LogIndex,
    /// Highest log index applied to the state machine.
    last_applied: LogIndex,
    /// Current role.
    role: RaftRole,
    /// Current leader (if known).
    leader_id: Option<NodeId>,
    /// Monotonic fencing token, incremented each time this node becomes leader.
    fencing_token: u64,
    /// Votes received during an election (Candidate state only).
    votes_received: HashSet<NodeId>,
    /// For each peer, index of the next log entry to send (Leader state only).
    next_index: HashMap<NodeId, LogIndex>,
    /// For each peer, highest log index known to be replicated (Leader only).
    match_index: HashMap<NodeId, LogIndex>,
    /// Deadline for the next election timeout.
    election_deadline: Instant,
    /// Node configuration.
    config: RaftConfig,
}

impl RaftState {
    /// Create a new Raft node in the Follower state.
    pub fn new(node_id: NodeId, config: RaftConfig) -> Self {
        let timeout = random_election_timeout(
            config.election_timeout_min_ms,
            config.election_timeout_max_ms,
        );
        tracing::info!(
            node = %node_id,
            peers = config.peers.len(),
            "initialising raft node"
        );
        Self {
            node_id,
            current_term: Term::zero(),
            voted_for: None,
            log: Vec::new(),
            commit_index: LogIndex::zero(),
            last_applied: LogIndex::zero(),
            role: RaftRole::Follower,
            leader_id: None,
            fencing_token: 0,
            votes_received: HashSet::new(),
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            election_deadline: Instant::now() + timeout,
            config,
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────

    /// Handle a received message from `from`. Returns messages to send.
    pub fn handle_message(
        &mut self,
        from: NodeId,
        msg: RaftMessage,
    ) -> Vec<(NodeId, RaftMessage)> {
        // Rule: if any RPC contains a term > currentTerm, step down.
        let msg_term = msg.term();
        if msg_term > self.current_term {
            tracing::debug!(
                node = %self.node_id,
                msg_term = msg_term.0,
                current_term = self.current_term.0,
                "received higher term, stepping down"
            );
            self.become_follower(msg_term, None);
        }

        match msg {
            RaftMessage::RequestVote {
                term,
                candidate_id,
                last_log_index,
                last_log_term,
            } => self.handle_request_vote(from, term, candidate_id, last_log_index, last_log_term),
            RaftMessage::RequestVoteResponse { term, vote_granted } => {
                self.handle_vote_response(from, term, vote_granted)
            }
            RaftMessage::AppendEntries {
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => self.handle_append_entries(
                from,
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            ),
            RaftMessage::AppendEntriesResponse {
                term,
                success,
                match_index,
            } => self.handle_append_entries_response(from, term, success, match_index),
        }
    }

    /// Called on timer tick. Returns heartbeats (if leader) or starts an
    /// election (if follower/candidate and the election timer has expired).
    pub fn tick(&mut self) -> Vec<(NodeId, RaftMessage)> {
        match self.role {
            RaftRole::Leader => self.send_heartbeats(),
            RaftRole::Follower | RaftRole::Candidate => {
                if Instant::now() >= self.election_deadline {
                    tracing::info!(
                        node = %self.node_id,
                        term = self.current_term.0,
                        "election timeout, starting election"
                    );
                    self.start_election()
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Propose a new cluster command. Only succeeds if this node is the leader.
    pub fn propose(&mut self, command: ClusterCommand) -> Result<LogIndex, String> {
        if self.role != RaftRole::Leader {
            return Err("not the leader".into());
        }
        let index = LogIndex(self.last_log_index().0 + 1);
        let entry = LogEntry {
            term: self.current_term,
            index,
            command,
        };
        tracing::debug!(
            node = %self.node_id,
            index = index.0,
            "appending proposed entry to log"
        );
        self.log.push(entry);

        // Update our own match index.
        self.match_index.insert(self.node_id, index);

        // If single-node cluster, commit immediately.
        self.advance_commit_index();

        Ok(index)
    }

    /// Get current role.
    pub fn role(&self) -> &RaftRole {
        &self.role
    }

    /// Is this node the leader?
    pub fn is_leader(&self) -> bool {
        self.role == RaftRole::Leader
    }

    /// Current leader (if known).
    pub fn leader_id(&self) -> Option<&NodeId> {
        self.leader_id.as_ref()
    }

    /// Current fencing token.
    pub fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Drain committed but unapplied entries.
    pub fn take_committed(&mut self) -> Vec<LogEntry> {
        let mut entries = Vec::new();
        while self.last_applied < self.commit_index {
            self.last_applied = LogIndex(self.last_applied.0 + 1);
            if let Some(entry) = self.log_entry_at(self.last_applied) {
                entries.push(entry.clone());
            }
        }
        entries
    }

    /// All peer node IDs.
    pub fn peers(&self) -> Vec<NodeId> {
        self.config.peers.iter().map(|(id, _)| *id).collect()
    }

    /// Cluster size (including self).
    pub fn cluster_size(&self) -> usize {
        self.config.peers.len() + 1
    }

    /// Required quorum size (majority).
    pub fn quorum_size(&self) -> usize {
        self.cluster_size() / 2 + 1
    }

    /// Access the node ID.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Current term.
    pub fn current_term(&self) -> Term {
        self.current_term
    }

    /// Immediately promote this node to leader without an election.
    ///
    /// Only valid for single-node clusters (no peers). Panics if peers are
    /// configured — use the normal election path for multi-node clusters.
    pub fn become_leader_standalone(&mut self) {
        assert!(
            self.config.peers.is_empty(),
            "become_leader_standalone must only be called on a single-node cluster"
        );
        self.current_term = Term(self.current_term.0 + 1);
        self.voted_for = Some(self.node_id);
        self.votes_received.clear();
        self.votes_received.insert(self.node_id);
        self.become_leader();
    }

    /// Force this node to step down from leader if its binary is tampered.
    /// Called by the attestation mesh when local binary hash doesn't match
    /// the golden hash. The node becomes a follower and is ineligible for
    /// leader election until healed.
    pub fn step_down_tampered(&mut self) {
        if self.role == RaftRole::Leader {
            tracing::error!(
                node_id = %self.node_id,
                term = self.current_term.0,
                "TAMPER DETECTED: stepping down from leader role"
            );
        }
        self.role = RaftRole::Follower;
        self.leader_id = None;
        // Set voted_for to self to prevent voting in the current term
        // (tampered node should not participate in elections)
        self.voted_for = Some(self.node_id);
        self.reset_election_timer();
    }

    /// Check if this node is marked as tampered (ineligible for election).
    /// A tampered node has voted_for=self but is a follower, which prevents
    /// it from starting elections or granting votes.
    pub fn is_tampered_standby(&self) -> bool {
        self.role == RaftRole::Follower
            && self.voted_for == Some(self.node_id)
            && self.leader_id.is_none()
    }

    // ── Private: election ──────────────────────────────────────────────────

    /// Reset election timer to a new random deadline.
    fn reset_election_timer(&mut self) {
        let timeout = random_election_timeout(
            self.config.election_timeout_min_ms,
            self.config.election_timeout_max_ms,
        );
        self.election_deadline = Instant::now() + timeout;
    }

    /// Start a new election: increment term, vote for self, solicit votes.
    fn start_election(&mut self) -> Vec<(NodeId, RaftMessage)> {
        self.current_term = Term(self.current_term.0 + 1);
        self.role = RaftRole::Candidate;
        self.voted_for = Some(self.node_id);
        self.leader_id = None;
        self.votes_received.clear();
        self.votes_received.insert(self.node_id);
        self.reset_election_timer();

        tracing::info!(
            node = %self.node_id,
            term = self.current_term.0,
            "started election"
        );

        // If single-node cluster, we already have a majority.
        if self.votes_received.len() >= self.quorum_size() {
            return self.become_leader();
        }

        let msg = RaftMessage::RequestVote {
            term: self.current_term,
            candidate_id: self.node_id,
            last_log_index: self.last_log_index(),
            last_log_term: self.last_log_term(),
        };

        self.config
            .peers
            .iter()
            .map(|(id, _)| (*id, msg.clone()))
            .collect()
    }

    /// Transition to leader: initialise volatile leader state, commit a Noop.
    fn become_leader(&mut self) -> Vec<(NodeId, RaftMessage)> {
        self.role = RaftRole::Leader;
        self.leader_id = Some(self.node_id);
        self.fencing_token += 1;

        tracing::info!(
            node = %self.node_id,
            term = self.current_term.0,
            fencing_token = self.fencing_token,
            "became leader"
        );

        // Initialise next_index and match_index for all peers.
        let next = LogIndex(self.last_log_index().0 + 1);
        self.next_index.clear();
        self.match_index.clear();
        for (peer_id, _) in &self.config.peers {
            self.next_index.insert(*peer_id, next);
            self.match_index.insert(*peer_id, LogIndex::zero());
        }
        // Track our own match index.
        self.match_index.insert(self.node_id, self.last_log_index());

        // Append a Noop entry to commit entries from the current term.
        let noop_index = LogIndex(self.last_log_index().0 + 1);
        self.log.push(LogEntry {
            term: self.current_term,
            index: noop_index,
            command: ClusterCommand::Noop,
        });
        self.match_index.insert(self.node_id, noop_index);

        // For single-node cluster, commit immediately.
        self.advance_commit_index();

        // Send initial heartbeats (which include the Noop).
        self.send_heartbeats()
    }

    /// Step down to follower.
    fn become_follower(&mut self, term: Term, leader: Option<NodeId>) {
        self.current_term = term;
        self.role = RaftRole::Follower;
        self.voted_for = None;
        self.leader_id = leader;
        self.votes_received.clear();
        self.next_index.clear();
        self.match_index.clear();
        self.reset_election_timer();
    }

    // ── Private: message handlers ──────────────────────────────────────────

    fn handle_request_vote(
        &mut self,
        from: NodeId,
        term: Term,
        candidate_id: NodeId,
        last_log_index: LogIndex,
        last_log_term: Term,
    ) -> Vec<(NodeId, RaftMessage)> {
        let grant = term >= self.current_term
            && (self.voted_for.is_none() || self.voted_for == Some(candidate_id))
            && self.candidate_log_is_up_to_date(last_log_term, last_log_index);

        if grant {
            self.voted_for = Some(candidate_id);
            self.reset_election_timer();
            tracing::debug!(
                node = %self.node_id,
                candidate = %candidate_id,
                term = term.0,
                "granted vote"
            );
        }

        vec![(
            from,
            RaftMessage::RequestVoteResponse {
                term: self.current_term,
                vote_granted: grant,
            },
        )]
    }

    fn handle_vote_response(
        &mut self,
        from: NodeId,
        _term: Term,
        vote_granted: bool,
    ) -> Vec<(NodeId, RaftMessage)> {
        if self.role != RaftRole::Candidate {
            return Vec::new();
        }

        if vote_granted {
            self.votes_received.insert(from);
            tracing::debug!(
                node = %self.node_id,
                from = %from,
                votes = self.votes_received.len(),
                quorum = self.quorum_size(),
                "received vote"
            );
            if self.votes_received.len() >= self.quorum_size() {
                return self.become_leader();
            }
        }

        Vec::new()
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_append_entries(
        &mut self,
        from: NodeId,
        term: Term,
        leader_id: NodeId,
        prev_log_index: LogIndex,
        prev_log_term: Term,
        entries: Vec<LogEntry>,
        leader_commit: LogIndex,
    ) -> Vec<(NodeId, RaftMessage)> {
        // Reject if term < currentTerm.
        if term < self.current_term {
            return vec![(
                from,
                RaftMessage::AppendEntriesResponse {
                    term: self.current_term,
                    success: false,
                    match_index: LogIndex::zero(),
                },
            )];
        }

        // Valid AppendEntries from the leader: reset timer, update leader.
        self.leader_id = Some(leader_id);
        if self.role != RaftRole::Follower {
            self.become_follower(term, Some(leader_id));
        }
        self.reset_election_timer();

        // Check log consistency at prev_log_index.
        if prev_log_index.0 > 0 {
            match self.log_entry_at(prev_log_index) {
                Some(entry) if entry.term == prev_log_term => {
                    // OK, consistent.
                }
                _ => {
                    // Inconsistency: log does not contain an entry at
                    // prev_log_index with the expected term.
                    return vec![(
                        from,
                        RaftMessage::AppendEntriesResponse {
                            term: self.current_term,
                            success: false,
                            match_index: LogIndex::zero(),
                        },
                    )];
                }
            }
        }

        // Append new entries, handling conflicts.
        for entry in &entries {
            let vec_idx = (entry.index.0 as usize).saturating_sub(1);
            if vec_idx < self.log.len() {
                if self.log[vec_idx].term != entry.term {
                    // Conflict: delete this and all following entries.
                    self.log.truncate(vec_idx);
                    self.log.push(entry.clone());
                }
                // Otherwise entry already matches, skip.
            } else {
                self.log.push(entry.clone());
            }
        }

        // Advance commit index.
        if leader_commit > self.commit_index {
            let last = self.last_log_index();
            self.commit_index = if leader_commit < last {
                leader_commit
            } else {
                last
            };
        }

        let current_match = self.last_log_index();
        vec![(
            from,
            RaftMessage::AppendEntriesResponse {
                term: self.current_term,
                success: true,
                match_index: current_match,
            },
        )]
    }

    fn handle_append_entries_response(
        &mut self,
        from: NodeId,
        _term: Term,
        success: bool,
        peer_match_index: LogIndex,
    ) -> Vec<(NodeId, RaftMessage)> {
        if self.role != RaftRole::Leader {
            return Vec::new();
        }

        if success {
            self.match_index.insert(from, peer_match_index);
            self.next_index
                .insert(from, LogIndex(peer_match_index.0 + 1));
            self.advance_commit_index();
        } else {
            // Decrement next_index and retry on next heartbeat.
            let current = self.next_index.get(&from).copied().unwrap_or(LogIndex(1));
            if current.0 > 1 {
                self.next_index.insert(from, LogIndex(current.0 - 1));
            }
        }

        Vec::new()
    }

    // ── Private: log helpers ───────────────────────────────────────────────

    /// Get the log entry at the given 1-based index.
    fn log_entry_at(&self, index: LogIndex) -> Option<&LogEntry> {
        if index.0 == 0 {
            return None;
        }
        self.log.get((index.0 - 1) as usize)
    }

    /// Index of the last log entry, or 0 if empty.
    fn last_log_index(&self) -> LogIndex {
        LogIndex(self.log.len() as u64)
    }

    /// Term of the last log entry, or Term(0) if empty.
    fn last_log_term(&self) -> Term {
        self.log.last().map(|e| e.term).unwrap_or(Term::zero())
    }

    /// Check if a candidate's log is at least as up-to-date as ours.
    ///
    /// Per Raft paper section 5.4.1: compare last log term first, then index.
    fn candidate_log_is_up_to_date(
        &self,
        candidate_last_term: Term,
        candidate_last_index: LogIndex,
    ) -> bool {
        let my_last_term = self.last_log_term();
        let my_last_index = self.last_log_index();
        if candidate_last_term != my_last_term {
            candidate_last_term > my_last_term
        } else {
            candidate_last_index >= my_last_index
        }
    }

    // ── Private: heartbeats & commit ───────────────────────────────────────

    /// Send AppendEntries (heartbeats / replication) to all peers.
    fn send_heartbeats(&self) -> Vec<(NodeId, RaftMessage)> {
        let mut msgs = Vec::new();
        for (peer_id, _) in &self.config.peers {
            let next = self.next_index.get(peer_id).copied().unwrap_or(LogIndex(1));
            let prev_log_index = LogIndex(next.0.saturating_sub(1));
            let prev_log_term = if prev_log_index.0 > 0 {
                self.log_entry_at(prev_log_index)
                    .map(|e| e.term)
                    .unwrap_or(Term::zero())
            } else {
                Term::zero()
            };

            // Collect entries from next_index onwards.
            let entries: Vec<LogEntry> = self
                .log
                .iter()
                .filter(|e| e.index >= next)
                .cloned()
                .collect();

            msgs.push((
                *peer_id,
                RaftMessage::AppendEntries {
                    term: self.current_term,
                    leader_id: self.node_id,
                    prev_log_index,
                    prev_log_term,
                    entries,
                    leader_commit: self.commit_index,
                },
            ));
        }
        msgs
    }

    /// Advance commit_index based on majority replication.
    ///
    /// A log entry is committed when a majority of nodes (tracked via
    /// match_index) have replicated it AND the entry was written in the
    /// current term (Raft safety property).
    fn advance_commit_index(&mut self) {
        let quorum = self.quorum_size();

        // Walk backwards from the last log entry to find the highest N where
        // a majority of match_index[i] >= N and log[N].term == currentTerm.
        for i in (self.commit_index.0 + 1..=self.last_log_index().0).rev() {
            let idx = LogIndex(i);

            // Only commit entries from the current term.
            if let Some(entry) = self.log_entry_at(idx) {
                if entry.term != self.current_term {
                    continue;
                }
            } else {
                continue;
            }

            // Count how many nodes (including self) have replicated this index.
            let count = self
                .match_index
                .values()
                .filter(|mi| **mi >= idx)
                .count();

            if count >= quorum {
                self.commit_index = idx;
                tracing::debug!(
                    node = %self.node_id,
                    commit_index = idx.0,
                    "advanced commit index"
                );
                break;
            }
        }
    }
}

// ── Postcard serialization helpers ─────────────────────────────────────────────

/// Serialize a [`RaftMessage`] to bytes using postcard.
pub fn serialize_message(msg: &RaftMessage) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_allocvec(msg)
}

/// Deserialize a [`RaftMessage`] from bytes using postcard.
pub fn deserialize_message(bytes: &[u8]) -> Result<RaftMessage, postcard::Error> {
    postcard::from_bytes(bytes)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(peers: Vec<(NodeId, String)>) -> RaftState {
        let id = NodeId::random();
        let config = RaftConfig {
            heartbeat_ms: 500,
            election_timeout_min_ms: 1500,
            election_timeout_max_ms: 3000,
            peers,
        };
        RaftState::new(id, config)
    }

    /// Helper: build a 3-node cluster, returning (node1, node2, node3).
    fn make_three_nodes() -> (RaftState, RaftState, RaftState) {
        let id1 = NodeId::random();
        let id2 = NodeId::random();
        let id3 = NodeId::random();

        let addr = "127.0.0.1:0".to_string();
        let make = |me: NodeId, peers: Vec<(NodeId, String)>| {
            RaftState::new(
                me,
                RaftConfig {
                    heartbeat_ms: 500,
                    election_timeout_min_ms: 1500,
                    election_timeout_max_ms: 3000,
                    peers,
                },
            )
        };

        let n1 = make(id1, vec![(id2, addr.clone()), (id3, addr.clone())]);
        let n2 = make(id2, vec![(id1, addr.clone()), (id3, addr.clone())]);
        let n3 = make(id3, vec![(id1, addr.clone()), (id2, addr)]);
        (n1, n2, n3)
    }

    /// Elect n1 as leader in a three-node cluster by driving the election
    /// protocol to completion. Returns the heartbeats sent after becoming leader.
    fn elect_leader(
        n1: &mut RaftState,
        n2: &mut RaftState,
        _n3: &mut RaftState,
    ) -> Vec<(NodeId, RaftMessage)> {
        let id1 = n1.node_id();
        let id2 = n2.node_id();

        n1.election_deadline = Instant::now() - Duration::from_secs(1);
        let vote_reqs = n1.tick();
        let req_for_n2 = vote_reqs
            .iter()
            .find(|(id, _)| *id == id2)
            .unwrap()
            .1
            .clone();
        let resp = n2.handle_message(id1, req_for_n2);
        n1.handle_message(id2, resp[0].1.clone())
    }

    // ── 1. Single node becomes leader immediately ──────────────────────────

    #[test]
    fn single_node_becomes_leader() {
        let mut node = make_node(vec![]);
        assert_eq!(node.cluster_size(), 1);
        assert_eq!(node.quorum_size(), 1);

        // Force election timeout.
        node.election_deadline = Instant::now() - Duration::from_secs(1);
        let msgs = node.tick();
        // No peers to send messages to.
        assert!(msgs.is_empty());
        assert!(node.is_leader());
        assert_eq!(node.fencing_token(), 1);
        assert_eq!(node.current_term(), Term(1));

        // Noop should be committed immediately.
        let committed = node.take_committed();
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].command, ClusterCommand::Noop);
    }

    // ── 2. Three-node election ─────────────────────────────────────────────

    #[test]
    fn three_node_election() {
        let (mut n1, mut n2, mut n3) = make_three_nodes();
        let id1 = n1.node_id();
        let id2 = n2.node_id();
        let id3 = n3.node_id();

        // Node 1 starts election.
        n1.election_deadline = Instant::now() - Duration::from_secs(1);
        let vote_requests = n1.tick();
        assert_eq!(*n1.role(), RaftRole::Candidate);
        assert_eq!(vote_requests.len(), 2);

        // Deliver vote request to node 2.
        let req_for_n2 = vote_requests
            .iter()
            .find(|(id, _)| *id == id2)
            .unwrap()
            .1
            .clone();
        let responses = n2.handle_message(id1, req_for_n2);
        assert_eq!(responses.len(), 1);
        match &responses[0].1 {
            RaftMessage::RequestVoteResponse { vote_granted, .. } => assert!(vote_granted),
            _ => panic!("expected RequestVoteResponse"),
        }

        // Deliver the positive vote back: n1 has 2/3 => becomes leader.
        let become_leader_msgs = n1.handle_message(id2, responses[0].1.clone());
        assert!(n1.is_leader());
        assert_eq!(n1.fencing_token(), 1);
        // Leader sends heartbeats to both peers.
        assert_eq!(become_leader_msgs.len(), 2);

        // Node 3 also grants vote (already decided but still valid).
        let req_for_n3 = vote_requests
            .iter()
            .find(|(id, _)| *id == id3)
            .unwrap()
            .1
            .clone();
        let responses3 = n3.handle_message(id1, req_for_n3);
        match &responses3[0].1 {
            RaftMessage::RequestVoteResponse { vote_granted, .. } => assert!(vote_granted),
            _ => panic!("expected RequestVoteResponse"),
        }
    }

    // ── 3. Leader heartbeats reset follower timers ─────────────────────────

    #[test]
    fn leader_heartbeats_reset_follower_timer() {
        let (mut n1, mut n2, mut n3) = make_three_nodes();
        let id1 = n1.node_id();
        let id2 = n2.node_id();

        let _ = elect_leader(&mut n1, &mut n2, &mut n3);
        assert!(n1.is_leader());

        // Set n2's election deadline to the near past so we can detect a reset.
        n2.election_deadline = Instant::now() - Duration::from_secs(1);

        // Leader sends heartbeats.
        let now_before = Instant::now();
        let heartbeats = n1.tick();
        let hb_for_n2 = heartbeats
            .iter()
            .find(|(id, _)| *id == id2)
            .unwrap()
            .1
            .clone();
        let _ = n2.handle_message(id1, hb_for_n2);

        // Follower's election deadline should now be in the future (reset by heartbeat).
        assert!(
            n2.election_deadline > now_before,
            "heartbeat should reset the follower's election deadline into the future"
        );
    }

    // ── 4. Higher term causes step-down ────────────────────────────────────

    #[test]
    fn higher_term_causes_step_down() {
        let (mut n1, mut n2, mut n3) = make_three_nodes();
        let id2 = n2.node_id();

        let _ = elect_leader(&mut n1, &mut n2, &mut n3);
        assert!(n1.is_leader());
        assert_eq!(n1.current_term(), Term(1));

        // n2 sends a message with a much higher term.
        let higher_term_msg = RaftMessage::RequestVote {
            term: Term(5),
            candidate_id: id2,
            last_log_index: LogIndex(10),
            last_log_term: Term(5),
        };
        let _ = n1.handle_message(id2, higher_term_msg);
        assert_eq!(*n1.role(), RaftRole::Follower);
        assert_eq!(n1.current_term(), Term(5));
    }

    // ── 5. Log replication and commit ──────────────────────────────────────

    #[test]
    fn log_replication_and_commit() {
        let (mut n1, mut n2, mut n3) = make_three_nodes();
        let id1 = n1.node_id();
        let id2 = n2.node_id();
        let id3 = n3.node_id();

        // Elect n1 as leader (go through all peers to get full replication).
        n1.election_deadline = Instant::now() - Duration::from_secs(1);
        let vote_reqs = n1.tick();
        for (peer_id, msg) in &vote_reqs {
            let responses = if *peer_id == id2 {
                n2.handle_message(id1, msg.clone())
            } else {
                n3.handle_message(id1, msg.clone())
            };
            let _ = n1.handle_message(*peer_id, responses[0].1.clone());
        }
        assert!(n1.is_leader());

        // Leader proposes a command.
        let cmd = ClusterCommand::MemberJoin {
            node_id: NodeId::random(),
            addr: "10.0.0.5:443".into(),
            service_type: "auth".into(),
        };
        let idx = n1.propose(cmd).unwrap();
        assert!(idx.0 > 0);

        // Send heartbeats carrying the entries.
        let heartbeats = n1.tick();
        for (peer_id, msg) in &heartbeats {
            let responses = if *peer_id == id2 {
                n2.handle_message(id1, msg.clone())
            } else {
                n3.handle_message(id1, msg.clone())
            };
            // Feed response back to the leader.
            let _ = n1.handle_message(*peer_id, responses[0].1.clone());
        }

        // After replication to majority, entries should be committed.
        let committed = n1.take_committed();
        assert!(committed.len() >= 2, "expected Noop + MemberJoin, got {}", committed.len());
        assert!(committed
            .iter()
            .any(|e| matches!(e.command, ClusterCommand::Noop)));
        assert!(committed
            .iter()
            .any(|e| matches!(e.command, ClusterCommand::MemberJoin { .. })));
    }

    // ── 6. Fencing token increments on each leader election ────────────────

    #[test]
    fn fencing_token_increments() {
        let mut node = make_node(vec![]);
        assert_eq!(node.fencing_token(), 0);

        // First election.
        node.election_deadline = Instant::now() - Duration::from_secs(1);
        let _ = node.tick();
        assert!(node.is_leader());
        assert_eq!(node.fencing_token(), 1);

        // Step down and re-elect.
        node.become_follower(Term(5), None);
        assert_eq!(*node.role(), RaftRole::Follower);
        node.election_deadline = Instant::now() - Duration::from_secs(1);
        let _ = node.tick();
        assert!(node.is_leader());
        assert_eq!(node.fencing_token(), 2);
        assert_eq!(node.current_term(), Term(6));

        // Third election.
        node.become_follower(Term(10), None);
        node.election_deadline = Instant::now() - Duration::from_secs(1);
        let _ = node.tick();
        assert!(node.is_leader());
        assert_eq!(node.fencing_token(), 3);
    }

    // ── 7. Split vote leads to new election ────────────────────────────────

    #[test]
    fn split_vote_leads_to_new_election() {
        let (mut n1, mut n2, mut n3) = make_three_nodes();
        let id1 = n1.node_id();
        let id2 = n2.node_id();
        let id3 = n3.node_id();

        // Both n1 and n2 start elections simultaneously.
        n1.election_deadline = Instant::now() - Duration::from_secs(1);
        n2.election_deadline = Instant::now() - Duration::from_secs(1);
        let msgs1 = n1.tick();
        let msgs2 = n2.tick();
        assert_eq!(*n1.role(), RaftRole::Candidate);
        assert_eq!(*n2.role(), RaftRole::Candidate);
        assert_eq!(n1.current_term(), n2.current_term());

        // n3 receives n1's request first and votes for n1.
        let req1_for_n3 = msgs1
            .iter()
            .find(|(id, _)| *id == id3)
            .unwrap()
            .1
            .clone();
        let resp3 = n3.handle_message(id1, req1_for_n3);
        match &resp3[0].1 {
            RaftMessage::RequestVoteResponse { vote_granted, .. } => assert!(vote_granted),
            _ => panic!("expected vote response"),
        }

        // n3 rejects n2's request (already voted for n1 this term).
        let req2_for_n3 = msgs2
            .iter()
            .find(|(id, _)| *id == id3)
            .unwrap()
            .1
            .clone();
        let resp3_to_n2 = n3.handle_message(id2, req2_for_n3);
        match &resp3_to_n2[0].1 {
            RaftMessage::RequestVoteResponse { vote_granted, .. } => assert!(!vote_granted),
            _ => panic!("expected vote response"),
        }

        // n2 rejects n1's request (voted for itself).
        let req1_for_n2 = msgs1
            .iter()
            .find(|(id, _)| *id == id2)
            .unwrap()
            .1
            .clone();
        let resp2 = n2.handle_message(id1, req1_for_n2);
        match &resp2[0].1 {
            RaftMessage::RequestVoteResponse { vote_granted, .. } => assert!(!vote_granted),
            _ => panic!("expected vote response"),
        }

        // Deliver n3's vote to n1 => 2 votes (self + n3) => becomes leader.
        let _ = n1.handle_message(id3, resp3[0].1.clone());
        assert!(n1.is_leader());

        // n2 still only has 1 vote (self), remains candidate.
        let _ = n2.handle_message(id3, resp3_to_n2[0].1.clone());
        assert_eq!(*n2.role(), RaftRole::Candidate);

        // n2 must start a new election at a higher term.
        n2.election_deadline = Instant::now() - Duration::from_secs(1);
        let msgs2_retry = n2.tick();
        assert_eq!(*n2.role(), RaftRole::Candidate);
        assert_eq!(n2.current_term(), Term(2));
        assert_eq!(msgs2_retry.len(), 2);
    }

    // ── Additional: propose fails when not leader ──────────────────────────

    #[test]
    fn propose_fails_when_not_leader() {
        let mut node = make_node(vec![]);
        let result = node.propose(ClusterCommand::Noop);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "not the leader");
    }

    // ── Additional: postcard serialization round-trip ──────────────────────

    #[test]
    fn message_serialization_roundtrip() {
        let msg = RaftMessage::RequestVote {
            term: Term(42),
            candidate_id: NodeId::random(),
            last_log_index: LogIndex(10),
            last_log_term: Term(41),
        };
        let bytes = serialize_message(&msg).unwrap();
        let decoded = deserialize_message(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }
}
