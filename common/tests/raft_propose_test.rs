//! Tests for the auto-response ↔ Raft propose integration.
//!
//! Verifies that:
//! 1. Pipeline commands produced by `respond_to_tamper` are serializable
//!    through postcard (required for Raft log replication over the wire).
//! 2. `take_pending_commands` drains commands from the pipeline correctly,
//!    so the Raft-propose loop never double-proposes a command.

#[test]
fn test_auto_response_commands_are_serializable() {
    use common::auto_response::{AutoResponseConfig, AutoResponsePipeline};
    use common::raft::{ClusterCommand, NodeId};

    let mut pipeline = AutoResponsePipeline::new(AutoResponseConfig {
        quarantine_hold_secs: 0,
        ..AutoResponseConfig::default()
    });

    let node = NodeId::random();
    pipeline.respond_to_tamper(node, [0xAA; 64], [0xBB; 64]);

    let cmds = pipeline.take_pending_commands();
    assert!(
        !cmds.is_empty(),
        "pipeline must produce at least one ClusterCommand after respond_to_tamper, got 0 \
         — check that AutoResponsePipeline.take_pending_commands() is wired correctly"
    );

    for (i, cmd) in cmds.iter().enumerate() {
        let bytes = postcard::to_allocvec(cmd).unwrap_or_else(|e| {
            panic!(
                "ClusterCommand at index {i} must be serializable via postcard (needed for \
                 Raft log replication), but serialization failed: {e}\ncmd = {cmd:?}"
            )
        });

        let decoded: ClusterCommand = postcard::from_bytes(&bytes).unwrap_or_else(|e| {
            panic!(
                "ClusterCommand at index {i} must round-trip through postcard (serialize then \
                 deserialize), but deserialization failed: {e}\nbytes = {bytes:?}"
            )
        });

        assert_eq!(
            *cmd, decoded,
            "ClusterCommand at index {i} did not survive postcard round-trip without mutation \
             — the Raft log would replay a different command than was proposed\n\
             original = {cmd:?}\ndecoded  = {decoded:?}"
        );
    }
}

#[test]
fn test_take_pending_commands_drains_pipeline() {
    use common::auto_response::{AutoResponseConfig, AutoResponsePipeline};
    use common::raft::NodeId;

    let mut pipeline = AutoResponsePipeline::new(AutoResponseConfig {
        quarantine_hold_secs: 0,
        ..AutoResponseConfig::default()
    });

    let node = NodeId::random();
    pipeline.respond_to_tamper(node, [0xAA; 64], [0xBB; 64]);

    // First call must return the commands.
    let first = pipeline.take_pending_commands();
    assert!(
        !first.is_empty(),
        "take_pending_commands() must return commands immediately after respond_to_tamper; \
         the Raft-propose loop depends on this to know when to call propose()"
    );

    // Second call must return nothing — commands must not be double-proposed.
    let second = pipeline.take_pending_commands();
    assert!(
        second.is_empty(),
        "take_pending_commands() must drain the queue: a second call immediately after the \
         first must return 0 commands (got {}), otherwise Raft would receive duplicate proposals",
        second.len()
    );
}

#[tokio::test]
async fn test_connect_to_cluster_drains_pipeline_async() {
    use common::auto_response::{AutoResponseConfig, AutoResponsePipeline};
    use common::raft::NodeId;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Verify that the pipeline correctly accumulates and drains via the
    // same Mutex<AutoResponsePipeline> interface that connect_to_cluster uses.
    let pipeline = Arc::new(Mutex::new(AutoResponsePipeline::new(AutoResponseConfig {
        quarantine_hold_secs: 0,
        ..AutoResponseConfig::default()
    })));

    // Simulate what respond_to_tamper does when stealth detection fires.
    let node = NodeId::random();
    {
        let mut p = pipeline.lock().await;
        p.respond_to_tamper(node, [0xAA; 64], [0xBB; 64]);
    }

    // Simulate one iteration of connect_to_cluster's background loop.
    let commands = {
        let mut p = pipeline.lock().await;
        p.take_pending_commands()
    };

    assert!(
        !commands.is_empty(),
        "connect_to_cluster background loop must find commands after respond_to_tamper; \
         got 0 — quarantine events would silently fail to reach Raft"
    );

    // After draining, the pipeline must be empty (no double-propose).
    let commands_again = {
        let mut p = pipeline.lock().await;
        p.take_pending_commands()
    };

    assert!(
        commands_again.is_empty(),
        "after the first drain in connect_to_cluster's loop, subsequent loop iterations must \
         find 0 commands (got {}), otherwise each quarantine would be proposed multiple times",
        commands_again.len()
    );
}

// ── Raft message authentication tests ────────────────────────────────────

/// SECURITY: Raft messages with valid HMAC pass verification.
#[test]
fn raft_authenticated_message_round_trip() {
    use common::raft::{AuthenticatedRaftMessage, NodeId, RaftMessage, Term, LogIndex};

    let transport_key = b"MILNET-RAFT-TRANSPORT-KEY-32BYTE!MILNET-RAFT-TRANSPORT-KEY-32BYTE!";
    let sender = NodeId::random();
    let msg = RaftMessage::RequestVote {
        term: Term::new(1),
        candidate_id: sender,
        last_log_index: LogIndex::zero(),
        last_log_term: Term::new(0),
    };

    let authenticated = AuthenticatedRaftMessage::sign(msg.clone(), sender, transport_key);
    let (verified_msg, verified_sender) = authenticated.verify(transport_key)
        .expect("valid HMAC must pass verification");
    assert_eq!(*verified_msg, msg);
    assert_eq!(verified_sender, sender);
}

/// SECURITY: Raft messages with wrong key are REJECTED.
/// A compromised node using a different transport key cannot forge messages.
#[test]
fn raft_authenticated_message_rejects_wrong_key() {
    use common::raft::{AuthenticatedRaftMessage, NodeId, RaftMessage, Term, LogIndex};

    let legit_key = b"MILNET-RAFT-TRANSPORT-KEY-LEGIT!!MILNET-RAFT-TRANSPORT-KEY-LEGIT!!";
    let attacker_key = b"ATTACKER-FORGED-KEY-00000000000!!ATTACKER-FORGED-KEY-00000000000!!";

    let sender = NodeId::random();
    let msg = RaftMessage::AppendEntries {
        term: Term::new(5),
        leader_id: sender,
        prev_log_index: LogIndex::zero(),
        prev_log_term: Term::new(4),
        entries: Vec::new(),
        leader_commit: LogIndex::zero(),
    };

    let authenticated = AuthenticatedRaftMessage::sign(msg, sender, attacker_key);
    let result = authenticated.verify(legit_key);
    assert!(
        result.is_err(),
        "message signed with attacker's key MUST be rejected by legitimate transport key"
    );
}

/// SECURITY: Raft message tampering (flipping a bit) is detected.
#[test]
fn raft_authenticated_message_detects_tampering() {
    use common::raft::{AuthenticatedRaftMessage, NodeId, RaftMessage, Term, LogIndex};

    let transport_key = b"MILNET-RAFT-TRANSPORT-KEY-32BYTE!MILNET-RAFT-TRANSPORT-KEY-32BYTE!";
    let sender = NodeId::random();
    let msg = RaftMessage::RequestVoteResponse {
        term: Term::new(3),
        vote_granted: true,
    };

    let mut authenticated = AuthenticatedRaftMessage::sign(msg, sender, transport_key);
    // Tamper: flip the vote_granted field
    authenticated.message = RaftMessage::RequestVoteResponse {
        term: Term::new(3),
        vote_granted: false,
    };
    let result = authenticated.verify(transport_key);
    assert!(
        result.is_err(),
        "tampered Raft message MUST be rejected — Byzantine vote manipulation detected"
    );
}

// ── Gossip message authentication tests ──────────────────────────────────

/// SECURITY: Gossip messages with valid HMAC pass verification.
#[test]
fn gossip_message_sign_and_verify() {
    use common::gossip::{GossipMessage, GossipMessageType};

    let transport_key = b"MILNET-GOSSIP-KEY-64BYTES-ABCDEFGHIJKLMNOP0123456789abcdefghijklm";
    let mut msg = GossipMessage {
        sender: "node-1".into(),
        msg_type: GossipMessageType::Ping { sequence: 42 },
        piggyback: Vec::new(),
        incarnation: 7,
        hmac_signature: Vec::new(),
    };

    msg.sign(transport_key);
    assert!(!msg.hmac_signature.is_empty(), "sign must produce a non-empty HMAC");
    msg.verify_signature(transport_key)
        .expect("valid signed gossip message must verify");
}

/// SECURITY: Gossip messages from a forged sender are REJECTED.
/// Prevents incarnation spoofing and membership poisoning.
#[test]
fn gossip_message_rejects_wrong_key() {
    use common::gossip::{GossipMessage, GossipMessageType};

    let legit_key = b"MILNET-GOSSIP-LEGIT-KEY-64BYTES-0123456789abcdefghijklmnopqrstuv";
    let attacker_key = b"ATTACKER-GOSSIP-FORGED-KEY-64BY-0123456789abcdefghijklmnopqrstuv";

    let mut msg = GossipMessage {
        sender: "node-1".into(),
        msg_type: GossipMessageType::Ack { sequence: 99 },
        piggyback: Vec::new(),
        incarnation: u64::MAX, // Attacker tries max incarnation to kill nodes
        hmac_signature: Vec::new(),
    };

    msg.sign(attacker_key);
    let result = msg.verify_signature(legit_key);
    assert!(
        result.is_err(),
        "gossip message signed with attacker key MUST be rejected — \
         prevents incarnation spoofing and Byzantine membership poisoning"
    );
}

/// SECURITY: Gossip message tampering (incarnation change) is detected.
#[test]
fn gossip_message_detects_incarnation_tampering() {
    use common::gossip::{GossipMessage, GossipMessageType};

    let transport_key = b"MILNET-GOSSIP-KEY-64BYTES-ABCDEFGHIJKLMNOP0123456789abcdefghijklm";
    let mut msg = GossipMessage {
        sender: "node-1".into(),
        msg_type: GossipMessageType::Ping { sequence: 1 },
        piggyback: Vec::new(),
        incarnation: 5,
        hmac_signature: Vec::new(),
    };

    msg.sign(transport_key);
    // Attacker modifies incarnation after signing
    msg.incarnation = u64::MAX;
    let result = msg.verify_signature(transport_key);
    assert!(
        result.is_err(),
        "tampered gossip incarnation MUST be detected — prevents node kill attacks"
    );
}
