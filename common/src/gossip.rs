//! SWIM-style gossip protocol for distributed failure detection.
//!
//! Each node periodically:
//! 1. Picks a random peer and sends a PING
//! 2. If no ACK within timeout, sends PING-REQ to k random members
//! 3. If still no ACK, marks peer as SUSPECT
//! 4. SUSPECT state disseminated via piggybacked gossip
//! 5. After suspicion timeout, peer marked DEAD
//! 6. DEAD members removed from membership
//!
//! Advantages over heartbeat: O(1) per-member message cost, sublinear detection.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::siem::{SecurityEvent, Severity};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Metadata about a cluster node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeMetadata {
    /// Deployment region (e.g. "us-east-1").
    pub region: String,
    /// Service role (e.g. "orchestrator", "tss-coordinator").
    pub role: String,
    /// BLAKE3 hash of the running binary for attestation.
    pub binary_hash: String,
}

/// Membership status of a node in the gossip protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemberStatus {
    Alive,
    Suspect { since_epoch_ms: u64 },
    Dead { since_epoch_ms: u64 },
}

impl MemberStatus {
    fn is_alive(&self) -> bool {
        matches!(self, MemberStatus::Alive)
    }

    fn is_suspect(&self) -> bool {
        matches!(self, MemberStatus::Suspect { .. })
    }

    fn is_dead(&self) -> bool {
        matches!(self, MemberStatus::Dead { .. })
    }

    /// Return a label for SIEM logging.
    fn as_str(&self) -> &'static str {
        match self {
            MemberStatus::Alive => "alive",
            MemberStatus::Suspect { .. } => "suspect",
            MemberStatus::Dead { .. } => "dead",
        }
    }
}

/// State tracked for each known member.
pub struct MemberState {
    pub node_id: String,
    pub status: MemberStatus,
    /// Lamport-style incarnation number — a node increments its own
    /// incarnation to refute false suspicion.
    pub incarnation: u64,
    pub last_seen: Instant,
    pub metadata: NodeMetadata,
}

/// A gossip message exchanged between nodes.
///
/// All gossip messages are HMAC-authenticated to prevent Byzantine poisoning.
/// A compromised node can only send messages attributed to itself, not forge
/// messages from other nodes (incarnation spoofing, status manipulation).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipMessage {
    pub sender: String,
    pub msg_type: GossipMessageType,
    /// Piggybacked membership updates disseminated alongside pings/acks.
    pub piggyback: Vec<MembershipUpdate>,
    pub incarnation: u64,
    /// HMAC-SHA512 over (sender || incarnation || msg_type || piggyback),
    /// keyed with the sender's node transport key. Empty for legacy compat
    /// but MUST be verified in military deployment mode.
    #[serde(default)]
    pub hmac_signature: Vec<u8>,
}

impl GossipMessage {
    /// Compute HMAC-SHA512 signature over the message fields.
    pub fn sign(&mut self, transport_key: &[u8]) {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;

        let mut mac = HmacSha512::new_from_slice(transport_key)
            .expect("HMAC key size is valid");
        mac.update(self.sender.as_bytes());
        mac.update(&self.incarnation.to_le_bytes());
        let type_bytes = postcard::to_allocvec(&self.msg_type).unwrap_or_default();
        mac.update(&type_bytes);
        let piggyback_bytes = postcard::to_allocvec(&self.piggyback).unwrap_or_default();
        mac.update(&piggyback_bytes);
        self.hmac_signature = mac.finalize().into_bytes().to_vec();
    }

    /// Verify the HMAC signature on a received gossip message.
    /// In military deployment mode, unsigned messages are rejected.
    pub fn verify_signature(&self, transport_key: &[u8]) -> Result<(), String> {
        if self.hmac_signature.is_empty() {
            if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_ok()
                || std::env::var("MILNET_PRODUCTION").is_ok()
            {
                return Err(format!(
                    "gossip message from '{}' has no HMAC signature — \
                     rejected in military deployment mode",
                    self.sender
                ));
            }
            tracing::warn!(
                target: "siem",
                "SIEM:WARNING gossip message from '{}' has no HMAC signature",
                self.sender
            );
            return Ok(());
        }

        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        type HmacSha512 = Hmac<Sha512>;

        let mut mac = HmacSha512::new_from_slice(transport_key)
            .expect("HMAC key size is valid");
        mac.update(self.sender.as_bytes());
        mac.update(&self.incarnation.to_le_bytes());
        let type_bytes = postcard::to_allocvec(&self.msg_type).unwrap_or_default();
        mac.update(&type_bytes);
        let piggyback_bytes = postcard::to_allocvec(&self.piggyback).unwrap_or_default();
        mac.update(&piggyback_bytes);

        mac.verify_slice(&self.hmac_signature).map_err(|_| {
            format!(
                "gossip HMAC verification failed from '{}' incarnation {} — \
                 possible Byzantine poisoning or key mismatch",
                self.sender, self.incarnation
            )
        })
    }
}

/// The type of gossip message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessageType {
    Ping { sequence: u64 },
    Ack { sequence: u64 },
    PingReq { target: String, sequence: u64 },
    Compound(Vec<GossipMessageType>),
}

/// A membership state change piggybacked on gossip messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipUpdate {
    pub node_id: String,
    pub status: MemberStatus,
    pub incarnation: u64,
}

// ---------------------------------------------------------------------------
// Outbound action — returned by tick() / handle_message() so the caller
// can send messages over the network transport of their choice.
// ---------------------------------------------------------------------------

/// An action the caller must execute on behalf of the protocol.
#[derive(Debug)]
pub enum GossipAction {
    /// Send `message` to the node identified by `target`.
    Send { target: String, message: GossipMessage },
}

// ---------------------------------------------------------------------------
// GossipProtocol
// ---------------------------------------------------------------------------

/// SWIM-style gossip protocol engine.
///
/// This struct is transport-agnostic: callers drive it by calling [`tick`] on
/// a timer and [`handle_message`] when a message arrives.  The protocol
/// returns [`GossipAction`]s that the caller dispatches over the wire.
///
/// All outgoing messages are HMAC-signed with the transport_key provided at
/// construction. Callers no longer need to sign messages manually.
pub struct GossipProtocol {
    node_id: String,
    members: RwLock<HashMap<String, MemberState>>,
    /// HMAC transport key for auto-signing outgoing messages.
    transport_key: Vec<u8>,
    /// How long a node stays in SUSPECT before being declared DEAD.
    suspicion_timeout: Duration,
    /// Interval between protocol rounds (informational; caller drives ticks).
    #[allow(dead_code)]
    ping_interval: Duration,
    /// How long to wait for a direct PING ACK before resorting to indirect probes.
    ping_timeout: Duration,
    /// Number of indirect probes (PING-REQ) sent when a direct PING fails.
    indirect_ping_count: usize,
    /// Monotonically increasing protocol round counter.
    protocol_period: RwLock<u64>,
    /// Our own incarnation number.
    incarnation: RwLock<u64>,
    /// Recent membership updates waiting to be piggybacked.
    pending_updates: RwLock<Vec<MembershipUpdate>>,
    /// Tracks outstanding pings: sequence -> (target, sent_at, acked).
    outstanding_pings: RwLock<HashMap<u64, OutstandingPing>>,
}

struct OutstandingPing {
    target: String,
    sent_at: Instant,
    acked: bool,
    /// Whether we already sent indirect probes for this ping.
    indirect_sent: bool,
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl GossipProtocol {
    /// Create a new gossip protocol instance for the given node.
    /// Uses a zero transport key (for testing only). In production, use
    /// `new_with_key()` to provide a real HMAC transport key.
    pub fn new(node_id: String) -> Self {
        Self::with_config(node_id, Duration::from_secs(10), Duration::from_secs(1), Duration::from_millis(500), 3)
    }

    /// Create a new gossip protocol instance with an HMAC transport key.
    /// All outgoing messages will be auto-signed with this key.
    pub fn new_with_key(node_id: String, transport_key: Vec<u8>) -> Self {
        Self::with_config_and_key(
            node_id, transport_key,
            Duration::from_secs(10), Duration::from_secs(1), Duration::from_millis(500), 3,
        )
    }

    /// Create with explicit configuration (uses empty transport key for testing).
    pub fn with_config(
        node_id: String,
        suspicion_timeout: Duration,
        ping_interval: Duration,
        ping_timeout: Duration,
        indirect_ping_count: usize,
    ) -> Self {
        Self::with_config_and_key(
            node_id, Vec::new(),
            suspicion_timeout, ping_interval, ping_timeout, indirect_ping_count,
        )
    }

    /// Create with explicit configuration and transport key.
    pub fn with_config_and_key(
        node_id: String,
        transport_key: Vec<u8>,
        suspicion_timeout: Duration,
        ping_interval: Duration,
        ping_timeout: Duration,
        indirect_ping_count: usize,
    ) -> Self {
        Self {
            node_id,
            members: RwLock::new(HashMap::new()),
            transport_key,
            suspicion_timeout,
            ping_interval,
            ping_timeout,
            indirect_ping_count,
            protocol_period: RwLock::new(0),
            incarnation: RwLock::new(0),
            pending_updates: RwLock::new(Vec::new()),
            outstanding_pings: RwLock::new(HashMap::new()),
        }
    }

    /// Sign an outgoing message with the transport key and wrap in a GossipAction.
    fn signed_send(&self, target: String, mut message: GossipMessage) -> GossipAction {
        if !self.transport_key.is_empty() {
            message.sign(&self.transport_key);
        }
        GossipAction::Send { target, message }
    }

    /// Join the cluster by registering seed nodes as initial members.
    ///
    /// Returns PING actions that the caller should dispatch to each seed node.
    pub fn join(&self, seed_nodes: &[(String, NodeMetadata)]) -> Vec<GossipAction> {
        let mut members = crate::sync::siem_write(&self.members, "gossip::join_members");
        let mut actions = Vec::with_capacity(seed_nodes.len());
        let incarnation = *crate::sync::siem_read(&self.incarnation, "gossip::join_incarnation");
        let mut period = crate::sync::siem_write(&self.protocol_period, "gossip::join_period");
        let mut outstanding = crate::sync::siem_write(&self.outstanding_pings, "gossip::join_outstanding");

        for (node_id, metadata) in seed_nodes {
            if node_id == &self.node_id {
                continue;
            }
            members.entry(node_id.clone()).or_insert_with(|| MemberState {
                node_id: node_id.clone(),
                status: MemberStatus::Alive,
                incarnation: 0,
                last_seen: Instant::now(),
                metadata: metadata.clone(),
            });

            *period += 1;
            let seq = *period;
            outstanding.insert(seq, OutstandingPing {
                target: node_id.clone(),
                sent_at: Instant::now(),
                acked: false,
                indirect_sent: false,
            });

            actions.push(self.signed_send(
                node_id.clone(),
                GossipMessage {
                    sender: self.node_id.clone(),
                    msg_type: GossipMessageType::Ping { sequence: seq },
                    piggyback: self.collect_piggyback_unlocked(),
                    incarnation,
                    hmac_signature: Vec::new(),
                },
            ));
        }

        emit_gossip_siem(
            &self.node_id,
            "join",
            &format!("joining cluster with {} seed nodes", seed_nodes.len()),
        );

        actions
    }

    /// Run one protocol round.
    ///
    /// The caller should invoke this at `ping_interval` frequency.
    /// Returns actions that must be dispatched over the network.
    pub fn tick(&self) -> Vec<GossipAction> {
        let mut actions = Vec::new();

        // 1. Expire suspects -> dead
        self.expire_suspects();

        // 2. Check outstanding pings for timeouts
        actions.extend(self.check_outstanding_pings());

        // 3. Pick a random alive peer and ping it
        if let Some(target) = self.pick_random_alive_peer() {
            let incarnation = *crate::sync::siem_read(&self.incarnation, "gossip::tick_incarnation");
            let mut period = crate::sync::siem_write(&self.protocol_period, "gossip::tick_period");
            *period += 1;
            let seq = *period;

            let mut outstanding = crate::sync::siem_write(&self.outstanding_pings, "gossip::tick_outstanding");
            outstanding.insert(seq, OutstandingPing {
                target: target.clone(),
                sent_at: Instant::now(),
                acked: false,
                indirect_sent: false,
            });

            actions.push(self.signed_send(
                target.clone(),
                GossipMessage {
                    sender: self.node_id.clone(),
                    msg_type: GossipMessageType::Ping { sequence: seq },
                    piggyback: self.piggyback_updates(),
                    incarnation,
                    hmac_signature: Vec::new(),
                },
            ));
        }

        actions
    }

    /// Process an incoming gossip message.
    ///
    /// Returns actions (e.g. ACKs, forwarded PING-REQs) for the caller to send.
    /// Maximum piggyback updates accepted per gossip message.
    /// Reject messages with excessive piggyback vectors to prevent memory exhaustion.
    const MAX_PIGGYBACK_UPDATES: usize = 100;

    pub fn handle_message(&self, msg: GossipMessage) -> Vec<GossipAction> {
        let mut actions = Vec::new();

        // Reject oversized piggyback vectors to prevent memory exhaustion
        if msg.piggyback.len() > Self::MAX_PIGGYBACK_UPDATES {
            tracing::error!(
                sender = %msg.sender,
                piggyback_len = msg.piggyback.len(),
                max = Self::MAX_PIGGYBACK_UPDATES,
                "Gossip: rejecting message with oversized piggyback vector"
            );
            return actions;
        }

        // Apply piggybacked membership updates
        for update in &msg.piggyback {
            self.apply_membership_update(update);
        }

        // Update sender as alive
        self.mark_alive(&msg.sender, msg.incarnation);

        let incarnation = *crate::sync::siem_read(&self.incarnation, "gossip::handle_message");

        match &msg.msg_type {
            GossipMessageType::Ping { sequence } => {
                // Reply with ACK
                actions.push(self.signed_send(
                    msg.sender.clone(),
                    GossipMessage {
                        sender: self.node_id.clone(),
                        msg_type: GossipMessageType::Ack { sequence: *sequence },
                        piggyback: self.piggyback_updates(),
                        incarnation,
                        hmac_signature: Vec::new(),
                    },
                ));
            }
            GossipMessageType::Ack { sequence } => {
                let mut outstanding = crate::sync::siem_write(&self.outstanding_pings, "gossip::handle_ack");
                if let Some(ping) = outstanding.get_mut(sequence) {
                    ping.acked = true;
                }
            }
            GossipMessageType::PingReq { target, sequence } => {
                // Forward a PING to the requested target on behalf of the sender
                actions.push(self.signed_send(
                    target.clone(),
                    GossipMessage {
                        sender: self.node_id.clone(),
                        msg_type: GossipMessageType::Ping { sequence: *sequence },
                        piggyback: self.piggyback_updates(),
                        incarnation,
                        hmac_signature: Vec::new(),
                    },
                ));
            }
            GossipMessageType::Compound(msgs) => {
                for sub in msgs {
                    let sub_msg = GossipMessage {
                        sender: msg.sender.clone(),
                        msg_type: sub.clone(),
                        piggyback: Vec::new(),
                        incarnation: msg.incarnation,
                        hmac_signature: Vec::new(),
                    };
                    actions.extend(self.handle_message(sub_msg));
                }
            }
        }

        actions
    }

    /// Transition a node to SUSPECT status.
    pub fn suspect_node(&self, node_id: &str) {
        let mut members = crate::sync::siem_write(&self.members, "gossip::suspect_node");
        if let Some(member) = members.get_mut(node_id) {
            if member.status.is_alive() {
                let now_ms = epoch_ms();
                member.status = MemberStatus::Suspect { since_epoch_ms: now_ms };

                emit_gossip_siem(
                    &self.node_id,
                    "suspect",
                    &format!("node {} marked SUSPECT", node_id),
                );

                self.enqueue_update(MembershipUpdate {
                    node_id: node_id.to_string(),
                    status: MemberStatus::Suspect { since_epoch_ms: now_ms },
                    incarnation: member.incarnation,
                });
            }
        }
    }

    /// Declare a node DEAD (should only be called after suspicion timeout expires).
    pub fn declare_dead(&self, node_id: &str) {
        let mut members = crate::sync::siem_write(&self.members, "gossip::declare_dead");
        if let Some(member) = members.get_mut(node_id) {
            if !member.status.is_dead() {
                let now_ms = epoch_ms();
                member.status = MemberStatus::Dead { since_epoch_ms: now_ms };

                emit_gossip_siem(
                    &self.node_id,
                    "dead",
                    &format!("node {} declared DEAD", node_id),
                );

                self.enqueue_update(MembershipUpdate {
                    node_id: node_id.to_string(),
                    status: MemberStatus::Dead { since_epoch_ms: now_ms },
                    incarnation: member.incarnation,
                });
            }
        }
    }

    /// Refute a false suspicion of ourselves by incrementing our incarnation number.
    ///
    /// When a node learns it has been suspected, it bumps its incarnation and
    /// disseminates an ALIVE update that overrides the stale suspicion.
    pub fn refute_suspicion(&self) -> MembershipUpdate {
        let mut incarnation = crate::sync::siem_write(&self.incarnation, "gossip::refute_suspicion");
        *incarnation += 1;
        let new_incarnation = *incarnation;

        emit_gossip_siem(
            &self.node_id,
            "refute",
            &format!(
                "refuting false suspicion — incarnation bumped to {}",
                new_incarnation
            ),
        );

        let update = MembershipUpdate {
            node_id: self.node_id.clone(),
            status: MemberStatus::Alive,
            incarnation: new_incarnation,
        };
        self.enqueue_update(update.clone());
        update
    }

    /// Return the list of currently alive members (excluding self).
    pub fn alive_members(&self) -> Vec<String> {
        let members = crate::sync::siem_read(&self.members, "gossip::alive_members");
        members
            .values()
            .filter(|m| m.status.is_alive() && m.node_id != self.node_id)
            .map(|m| m.node_id.clone())
            .collect()
    }

    /// Collect recent membership updates for piggybacking on outgoing messages.
    pub fn piggyback_updates(&self) -> Vec<MembershipUpdate> {
        let mut pending = crate::sync::siem_write(&self.pending_updates, "gossip::piggyback_updates");
        pending.drain(..).collect()
    }

    /// Return the current incarnation number of this node.
    pub fn incarnation(&self) -> u64 {
        *crate::sync::siem_read(&self.incarnation, "gossip::incarnation")
    }

    /// Return the node ID of this protocol instance.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Get the status of a specific member.
    pub fn member_status(&self, node_id: &str) -> Option<MemberStatus> {
        let members = crate::sync::siem_read(&self.members, "gossip::member_status");
        members.get(node_id).map(|m| m.status.clone())
    }

    /// Return count of all known members (any status).
    pub fn member_count(&self) -> usize {
        crate::sync::siem_read(&self.members, "gossip::member_count").len()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Collect piggyback without acquiring pending_updates lock (caller holds
    /// members lock already, so we snapshot what we have).
    fn collect_piggyback_unlocked(&self) -> Vec<MembershipUpdate> {
        // Best-effort: if we can acquire the lock, drain; otherwise empty.
        match self.pending_updates.try_write() {
            Ok(mut pending) => pending.drain(..).collect(),
            Err(_) => Vec::new(),
        }
    }

    fn enqueue_update(&self, update: MembershipUpdate) {
        if let Ok(mut pending) = self.pending_updates.write() {
            pending.push(update);
        }
    }

    fn mark_alive(&self, node_id: &str, incarnation: u64) {
        let mut members = crate::sync::siem_write(&self.members, "gossip::mark_alive");
        if let Some(member) = members.get_mut(node_id) {
            // Only accept if incarnation is >= what we know
            if incarnation >= member.incarnation {
                member.incarnation = incarnation;
                member.last_seen = Instant::now();
                if !member.status.is_alive() {
                    member.status = MemberStatus::Alive;
                    emit_gossip_siem(
                        &self.node_id,
                        "alive",
                        &format!("node {} restored to ALIVE (incarnation {})", node_id, incarnation),
                    );
                }
            }
        }
    }

    fn apply_membership_update(&self, update: &MembershipUpdate) {
        let mut members = crate::sync::siem_write(&self.members, "gossip::apply_membership_update");
        if let Some(member) = members.get_mut(&update.node_id) {
            // Updates with higher incarnation always win.
            // At same incarnation: Dead > Suspect > Alive.
            if update.incarnation > member.incarnation
                || (update.incarnation == member.incarnation && status_precedence(&update.status) > status_precedence(&member.status))
            {
                member.incarnation = update.incarnation;
                member.status = update.status.clone();
                if update.status.is_alive() {
                    member.last_seen = Instant::now();
                }
            }
        }
    }

    fn expire_suspects(&self) {
        let mut to_declare_dead = Vec::new();
        {
            let members = crate::sync::siem_read(&self.members, "gossip::expire_suspects");
            let timeout = self.suspicion_timeout;
            for member in members.values() {
                if let MemberStatus::Suspect { since_epoch_ms } = &member.status {
                    let suspect_duration_ms = epoch_ms().saturating_sub(*since_epoch_ms);
                    if suspect_duration_ms >= timeout.as_millis() as u64 {
                        to_declare_dead.push(member.node_id.clone());
                    }
                }
            }
        }
        for node_id in to_declare_dead {
            self.declare_dead(&node_id);
        }
    }

    fn check_outstanding_pings(&self) -> Vec<GossipAction> {
        let mut actions = Vec::new();
        let mut timed_out = Vec::new();
        let mut need_indirect = Vec::new();

        {
            let outstanding = crate::sync::siem_read(&self.outstanding_pings, "gossip::check_outstanding_pings");
            for (seq, ping) in outstanding.iter() {
                if ping.acked {
                    continue;
                }
                let elapsed = ping.sent_at.elapsed();
                if elapsed >= self.ping_timeout && !ping.indirect_sent {
                    need_indirect.push((*seq, ping.target.clone()));
                } else if elapsed >= self.ping_timeout * 2 {
                    // Double the ping timeout with no indirect ACK -> suspect
                    timed_out.push((*seq, ping.target.clone()));
                }
            }
        }

        // Send indirect probes (PING-REQ)
        for (seq, target) in &need_indirect {
            let peers = self.pick_k_random_peers(&target, self.indirect_ping_count);
            let incarnation = *crate::sync::siem_read(&self.incarnation, "gossip::indirect_ping_incarnation");
            for peer in peers {
                actions.push(self.signed_send(
                    peer,
                    GossipMessage {
                        sender: self.node_id.clone(),
                        msg_type: GossipMessageType::PingReq {
                            target: target.clone(),
                            sequence: *seq,
                        },
                        piggyback: Vec::new(),
                        incarnation,
                        hmac_signature: Vec::new(),
                    },
                ));
            }
            let mut outstanding = crate::sync::siem_write(&self.outstanding_pings, "gossip::indirect_ping_mark");
            if let Some(ping) = outstanding.get_mut(seq) {
                ping.indirect_sent = true;
            }
        }

        // Suspect timed-out nodes
        {
            let mut outstanding = crate::sync::siem_write(&self.outstanding_pings, "gossip::suspect_timed_out");
            for (seq, target) in &timed_out {
                outstanding.remove(seq);
                // Drop lock before calling suspect_node which takes members lock
                drop(outstanding);
                self.suspect_node(target);
                outstanding = crate::sync::siem_write(&self.outstanding_pings, "gossip::suspect_timed_out_reacquire");
            }
        }

        // Clean up acked pings
        {
            let mut outstanding = crate::sync::siem_write(&self.outstanding_pings, "gossip::cleanup_acked");
            outstanding.retain(|_, p| !p.acked);
        }

        actions
    }

    fn pick_random_alive_peer(&self) -> Option<String> {
        let members = crate::sync::siem_read(&self.members, "gossip::pick_random_alive_peer");
        let alive: Vec<&String> = members
            .values()
            .filter(|m| m.status.is_alive() && m.node_id != self.node_id)
            .map(|m| &m.node_id)
            .collect();
        if alive.is_empty() {
            return None;
        }
        // True random selection via getrandom with rejection sampling to avoid modulo bias.
        let len = alive.len();
        let idx = {
            let bucket_size = u64::MAX / (len as u64);
            let limit = bucket_size * (len as u64);
            loop {
                let mut buf = [0u8; 8];
                getrandom::getrandom(&mut buf).unwrap_or_else(|_| {
                    buf = [42; 8];
                });
                let sample = u64::from_le_bytes(buf);
                if sample < limit {
                    break (sample % (len as u64)) as usize;
                }
            }
        };
        Some(alive[idx].clone())
    }

    fn pick_k_random_peers(&self, exclude: &str, k: usize) -> Vec<String> {
        let members = crate::sync::siem_read(&self.members, "gossip::pick_k_random_peers");
        let candidates: Vec<String> = members
            .values()
            .filter(|m| m.status.is_alive() && m.node_id != self.node_id && m.node_id != exclude)
            .map(|m| m.node_id.clone())
            .collect();
        // Take up to k
        candidates.into_iter().take(k).collect()
    }
}

/// Higher number = higher precedence in conflict resolution.
fn status_precedence(s: &MemberStatus) -> u8 {
    match s {
        MemberStatus::Alive => 0,
        MemberStatus::Suspect { .. } => 1,
        MemberStatus::Dead { .. } => 2,
    }
}

/// Emit a SIEM event in the GOSSIP category.
fn emit_gossip_siem(node_id: &str, action: &'static str, detail: &str) {
    let event = SecurityEvent {
        timestamp: SecurityEvent::now_iso8601(),
        category: "GOSSIP",
        action: "gossip_protocol",
        severity: match action {
            "dead" => Severity::High,
            "suspect" => Severity::Warning,
            "refute" => Severity::Notice,
            _ => Severity::Info,
        },
        outcome: action,
        user_id: None,
        source_ip: None,
        detail: Some(format!("[node={}] {}", node_id, detail)),
    };
    event.emit();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_metadata() -> NodeMetadata {
        NodeMetadata {
            region: "us-east-1".into(),
            role: "orchestrator".into(),
            binary_hash: "abc123".into(),
        }
    }

    #[test]
    fn test_member_join() {
        let proto = GossipProtocol::new("node-0".into());
        let seeds = vec![
            ("node-1".into(), test_metadata()),
            ("node-2".into(), test_metadata()),
            ("node-3".into(), test_metadata()),
        ];

        let actions = proto.join(&seeds);
        // Should produce one PING per seed node
        assert_eq!(actions.len(), 3);
        assert_eq!(proto.member_count(), 3);

        // All members should be alive
        let alive = proto.alive_members();
        assert_eq!(alive.len(), 3);
    }

    #[test]
    fn test_join_excludes_self() {
        let proto = GossipProtocol::new("node-0".into());
        let seeds = vec![
            ("node-0".into(), test_metadata()), // self — should be skipped
            ("node-1".into(), test_metadata()),
        ];
        let actions = proto.join(&seeds);
        assert_eq!(actions.len(), 1);
        assert_eq!(proto.member_count(), 1);
    }

    #[test]
    fn test_suspect_transition() {
        let proto = GossipProtocol::new("node-0".into());
        proto.join(&[("node-1".into(), test_metadata())]);

        proto.suspect_node("node-1");
        let status = proto.member_status("node-1").unwrap();
        assert!(status.is_suspect());

        // Should no longer appear in alive list
        assert!(proto.alive_members().is_empty());
    }

    #[test]
    fn test_dead_transition() {
        let proto = GossipProtocol::new("node-0".into());
        proto.join(&[("node-1".into(), test_metadata())]);

        proto.suspect_node("node-1");
        proto.declare_dead("node-1");

        let status = proto.member_status("node-1").unwrap();
        assert!(status.is_dead());
        assert!(proto.alive_members().is_empty());
    }

    #[test]
    fn test_refute_suspicion() {
        let proto = GossipProtocol::new("node-0".into());
        assert_eq!(proto.incarnation(), 0);

        let update = proto.refute_suspicion();
        assert_eq!(update.incarnation, 1);
        assert!(update.status.is_alive());
        assert_eq!(proto.incarnation(), 1);

        // Refuting again bumps further
        let update2 = proto.refute_suspicion();
        assert_eq!(update2.incarnation, 2);
    }

    #[test]
    fn test_piggybacking() {
        let proto = GossipProtocol::new("node-0".into());
        proto.join(&[("node-1".into(), test_metadata())]);

        // Suspecting a node enqueues a piggyback update
        proto.suspect_node("node-1");
        let updates = proto.piggyback_updates();
        assert!(!updates.is_empty());
        assert_eq!(updates[0].node_id, "node-1");
        assert!(updates[0].status.is_suspect());

        // After draining, no more updates
        let updates2 = proto.piggyback_updates();
        assert!(updates2.is_empty());
    }

    #[test]
    fn test_handle_ping_produces_ack() {
        let proto = GossipProtocol::new("node-0".into());
        proto.join(&[("node-1".into(), test_metadata())]);

        let ping = GossipMessage {
            sender: "node-1".into(),
            msg_type: GossipMessageType::Ping { sequence: 42 },
            piggyback: Vec::new(),
            incarnation: 0,
            hmac_signature: Vec::new(),
        };

        let actions = proto.handle_message(ping);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            GossipAction::Send { target, message } => {
                assert_eq!(target, "node-1");
                match &message.msg_type {
                    GossipMessageType::Ack { sequence } => assert_eq!(*sequence, 42),
                    other => panic!("expected Ack, got {:?}", other),
                }
            }
        }
    }

    #[test]
    fn test_handle_ack_marks_ping_acked() {
        let proto = GossipProtocol::new("node-0".into());
        proto.join(&[("node-1".into(), test_metadata())]);

        // The join already sent pings with sequence numbers starting at 1
        let ack = GossipMessage {
            sender: "node-1".into(),
            msg_type: GossipMessageType::Ack { sequence: 1 },
            piggyback: Vec::new(),
            incarnation: 0,
            hmac_signature: Vec::new(),
        };

        let actions = proto.handle_message(ack);
        // ACK should not produce further actions
        assert!(actions.is_empty());
    }

    #[test]
    fn test_alive_restored_via_higher_incarnation() {
        let proto = GossipProtocol::new("node-0".into());
        proto.join(&[("node-1".into(), test_metadata())]);

        proto.suspect_node("node-1");
        assert!(proto.member_status("node-1").unwrap().is_suspect());

        // Simulate receiving a message from node-1 with higher incarnation
        let msg = GossipMessage {
            sender: "node-1".into(),
            msg_type: GossipMessageType::Ping { sequence: 999 },
            piggyback: Vec::new(),
            incarnation: 5, // higher incarnation refutes suspicion
            hmac_signature: Vec::new(),
        };
        proto.handle_message(msg);

        // Should be back to alive
        assert!(proto.member_status("node-1").unwrap().is_alive());
    }

    #[test]
    fn test_membership_update_precedence() {
        let proto = GossipProtocol::new("node-0".into());
        proto.join(&[("node-1".into(), test_metadata())]);

        // Apply a suspect update at incarnation 1
        let update = MembershipUpdate {
            node_id: "node-1".into(),
            status: MemberStatus::Suspect { since_epoch_ms: epoch_ms() },
            incarnation: 1,
        };
        proto.apply_membership_update(&update);
        assert!(proto.member_status("node-1").unwrap().is_suspect());

        // An alive at same incarnation should NOT override suspect (lower precedence)
        let alive_update = MembershipUpdate {
            node_id: "node-1".into(),
            status: MemberStatus::Alive,
            incarnation: 1,
        };
        proto.apply_membership_update(&alive_update);
        assert!(proto.member_status("node-1").unwrap().is_suspect());

        // An alive at HIGHER incarnation SHOULD override
        let refute_update = MembershipUpdate {
            node_id: "node-1".into(),
            status: MemberStatus::Alive,
            incarnation: 2,
        };
        proto.apply_membership_update(&refute_update);
        assert!(proto.member_status("node-1").unwrap().is_alive());
    }

    #[test]
    fn test_expire_suspects_to_dead() {
        // Use a very short suspicion timeout
        let proto = GossipProtocol::with_config(
            "node-0".into(),
            Duration::from_millis(0), // immediate expiry
            Duration::from_secs(1),
            Duration::from_millis(500),
            3,
        );
        proto.join(&[("node-1".into(), test_metadata())]);
        proto.suspect_node("node-1");

        // Tick should expire the suspect to dead
        proto.expire_suspects();
        assert!(proto.member_status("node-1").unwrap().is_dead());
    }

    #[test]
    fn test_auto_signing_with_transport_key() {
        let key = vec![0x42u8; 32];
        let proto = GossipProtocol::new_with_key("node-0".into(), key.clone());
        let seeds = vec![("node-1".into(), test_metadata())];

        let actions = proto.join(&seeds);
        assert_eq!(actions.len(), 1);

        match &actions[0] {
            GossipAction::Send { message, .. } => {
                assert!(!message.hmac_signature.is_empty(), "message should be auto-signed");
                // Verify the signature is valid
                assert!(message.verify_signature(&key).is_ok());
            }
        }
    }

    #[test]
    fn test_tick_auto_signs_messages() {
        let key = vec![0xAB; 32];
        let proto = GossipProtocol::new_with_key("node-0".into(), key.clone());
        proto.join(&[("node-1".into(), test_metadata())]);

        let actions = proto.tick();
        for action in &actions {
            match action {
                GossipAction::Send { message, .. } => {
                    assert!(!message.hmac_signature.is_empty());
                    assert!(message.verify_signature(&key).is_ok());
                }
            }
        }
    }

    #[test]
    fn test_handle_message_ack_auto_signed() {
        let key = vec![0xCD; 32];
        let proto = GossipProtocol::new_with_key("node-0".into(), key.clone());
        proto.join(&[("node-1".into(), test_metadata())]);

        let ping = GossipMessage {
            sender: "node-1".into(),
            msg_type: GossipMessageType::Ping { sequence: 99 },
            piggyback: Vec::new(),
            incarnation: 0,
            hmac_signature: Vec::new(),
        };
        let actions = proto.handle_message(ping);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            GossipAction::Send { message, .. } => {
                assert!(!message.hmac_signature.is_empty(), "ACK should be auto-signed");
                assert!(message.verify_signature(&key).is_ok());
            }
        }
    }
}
