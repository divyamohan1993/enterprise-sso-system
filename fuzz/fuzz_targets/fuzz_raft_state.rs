#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use common::raft::{
    ClusterCommand, LogEntry, LogIndex, NodeId, RaftConfig, RaftMessage, RaftState, Term,
};

#[derive(Arbitrary, Debug)]
enum FuzzCommand {
    Propose(FuzzClusterCommand),
    HandleMessage(FuzzRaftMessage),
    Tick,
}

#[derive(Arbitrary, Debug)]
enum FuzzClusterCommand {
    MemberJoin { addr_byte: u8, service_byte: u8 },
    MemberLeave,
    RoleAssignment { role_byte: u8 },
    HealthUpdate { healthy: bool },
    Noop,
}

#[derive(Arbitrary, Debug)]
enum FuzzRaftMessage {
    RequestVote {
        term: u64,
        last_log_index: u64,
        last_log_term: u64,
    },
    RequestVoteResponse {
        term: u64,
        vote_granted: bool,
    },
    AppendEntries {
        term: u64,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entry_count: u8,
    },
    AppendEntriesResponse {
        term: u64,
        success: bool,
        match_index: u64,
    },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    commands: Vec<FuzzCommand>,
}

fuzz_target!(|input: FuzzInput| {
    if input.commands.len() > 64 {
        return; // Bound sequence length
    }

    let node_id = NodeId::random();
    let peer_id = NodeId::random();
    let config = RaftConfig {
        heartbeat_ms: 500,
        election_timeout_min_ms: 1500,
        election_timeout_max_ms: 3000,
        peers: vec![(peer_id, "127.0.0.1:9000".to_string())],
    };
    let mut state = RaftState::new(node_id, config);

    for cmd in &input.commands {
        match cmd {
            FuzzCommand::Propose(fc) => {
                let command = match fc {
                    FuzzClusterCommand::MemberJoin { addr_byte, service_byte } => {
                        ClusterCommand::MemberJoin {
                            node_id: NodeId::random(),
                            addr: format!("10.0.0.{}", addr_byte),
                            service_type: format!("svc-{}", service_byte),
                        }
                    }
                    FuzzClusterCommand::MemberLeave => ClusterCommand::MemberLeave {
                        node_id: peer_id,
                    },
                    FuzzClusterCommand::RoleAssignment { role_byte } => {
                        ClusterCommand::RoleAssignment {
                            node_id: peer_id,
                            role: format!("role-{}", role_byte),
                        }
                    }
                    FuzzClusterCommand::HealthUpdate { healthy } => {
                        ClusterCommand::HealthUpdate {
                            node_id: peer_id,
                            healthy: *healthy,
                        }
                    }
                    FuzzClusterCommand::Noop => ClusterCommand::Noop,
                };
                let _ = state.propose(command);
            }
            FuzzCommand::HandleMessage(fm) => {
                let msg = match fm {
                    FuzzRaftMessage::RequestVote {
                        term,
                        last_log_index,
                        last_log_term,
                    } => RaftMessage::RequestVote {
                        term: Term(*term),
                        candidate_id: peer_id,
                        last_log_index: LogIndex(*last_log_index),
                        last_log_term: Term(*last_log_term),
                    },
                    FuzzRaftMessage::RequestVoteResponse { term, vote_granted } => {
                        RaftMessage::RequestVoteResponse {
                            term: Term(*term),
                            vote_granted: *vote_granted,
                        }
                    }
                    FuzzRaftMessage::AppendEntries {
                        term,
                        prev_log_index,
                        prev_log_term,
                        leader_commit,
                        entry_count,
                    } => {
                        let entries: Vec<LogEntry> = (0..(*entry_count).min(8))
                            .map(|i| LogEntry {
                                term: Term(*term),
                                index: LogIndex(*prev_log_index + i as u64 + 1),
                                command: ClusterCommand::Noop,
                                entry_signature: None,
                            })
                            .collect();
                        RaftMessage::AppendEntries {
                            term: Term(*term),
                            leader_id: peer_id,
                            prev_log_index: LogIndex(*prev_log_index),
                            prev_log_term: Term(*prev_log_term),
                            entries,
                            leader_commit: LogIndex(*leader_commit),
                        }
                    }
                    FuzzRaftMessage::AppendEntriesResponse {
                        term,
                        success,
                        match_index,
                    } => RaftMessage::AppendEntriesResponse {
                        term: Term(*term),
                        success: *success,
                        match_index: LogIndex(*match_index),
                    },
                };
                let _ = state.handle_message(peer_id, msg);
            }
            FuzzCommand::Tick => {
                let _ = state.tick();
            }
        }
    }
});
