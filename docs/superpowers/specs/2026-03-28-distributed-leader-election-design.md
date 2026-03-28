# Distributed Leader Election & Auto-Healing Design

## Problem

Orchestrator, TSS Coordinator, and OPAQUE services are 1-of-1 SPOFs. If any single instance dies, the entire authentication system goes down.

## Solution

Hybrid Raft consensus for leader election + PostgreSQL for persistent state. Each service type runs 3+ instances with one leader elected via Raft. Followers proxy requests to leader. Dead leaders trigger automatic re-election in <3 seconds.

## Architecture

### Raft Groups (per service type)

Each service type forms its own Raft group:
- `orchestrator`: 3 instances, 1 leader handles auth ceremonies
- `tss-coordinator`: 3 instances, 1 leader coordinates FROST signing
- `opaque`: 3 instances with threshold shares, leader fans out to peers

### Modules

| Module | Purpose |
|--------|---------|
| `common/src/raft.rs` | Raft state machine, message types, election logic |
| `common/src/cluster.rs` | ClusterNode wrapper, config, startup/shutdown |
| `common/src/cluster_roles.rs` | Role registry, request routing, leader proxy |
| `common/src/auto_heal.rs` | Failure detection, recovery, membership mgmt |

### Raft State Machine

States: Follower -> Candidate -> Leader
- Heartbeat: 500ms
- Election timeout: 1500-3000ms (randomized)
- Communication: SHARD mTLS (existing transport)
- Serialization: postcard (existing)

Log entries are cluster commands only:
- MemberJoin, MemberLeave, RoleAssignment, HealthUpdate

### Request Routing

Followers proxy requests to leader transparently. Callers (gateway) don't need to know cluster topology. Fencing tokens prevent stale leaders from processing requests.

### Failure Detection

1. Raft heartbeat (500ms) — detects leader death in 1.5-3s
2. Health probe (5s) — detects follower death in 15-30s
3. Raft membership — leader commits MemberLeave for dead nodes

### Auto-Healing

- Leader death: automatic re-election via Raft
- Follower death: leader marks dead, cluster continues
- Node recovery: auto-rejoin, Raft log sync, enter follower state
- Split brain: fencing tokens reject stale leader requests
- Network partition: minority cannot elect (no quorum)

### OPAQUE Special Case

All 3 OPAQUE instances hold threshold shares. Leader receives request, fans out to all peers for threshold computation, combines 2-of-3 responses.

### Configuration

```
MILNET_NODE_ID=node-1
MILNET_CLUSTER_PEERS=node-1@10.0.1.1:11101,node-2@10.0.1.2:11101,node-3@10.0.1.3:11101
MILNET_RAFT_ADDR=0.0.0.0:11101
```

Raft port default: service port + 2000.

### Quorum

- 3 nodes: quorum=2, tolerates 1 failure
- 5 nodes: quorum=3, tolerates 2 failures
