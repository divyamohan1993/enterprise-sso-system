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
