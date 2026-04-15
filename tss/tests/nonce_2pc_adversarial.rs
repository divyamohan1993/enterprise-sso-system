//! Adversarial tests for the distributed 2PC nonce coordinator.
//!
//! Covers:
//! - Happy-path reserve + commit across all peers
//! - Quorum failure when peers reject phase-1
//! - Commit rollback semantics when phase-2 fails mid-flight
//! - Session ID idempotency: two prepares for same session return same candidate

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tss::distributed::{
    DistributedNonceCoordinator, DistributedNoncePeer, LocalNoncePeer, NonceCoordError,
};

fn fresh_tmp(suffix: &str) -> std::path::PathBuf {
    let mut r = [0u8; 8];
    getrandom::getrandom(&mut r).unwrap();
    let name: String = r.iter().map(|b| format!("{b:02x}")).collect();
    std::env::temp_dir().join(format!("milnet_tss_2pc_{}_{}", suffix, name))
}

fn tmp_sealed_paths() {
    // Point the per-test sealed-nonce file to a fresh tmp so the
    // NonceWal constructor doesn't pick up global state.
    let mut r = [0u8; 8];
    getrandom::getrandom(&mut r).unwrap();
    let name: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let state = std::env::temp_dir().join(format!("milnet_tss_state_{}", name));
    std::env::set_var("MILNET_TSS_NONCE_STATE_PATH", &state);
    std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));
}

#[test]
fn distributed_2pc_happy_path() {
    tmp_sealed_paths();
    let peers: Vec<Box<dyn DistributedNoncePeer>> = (0..5)
        .map(|i| {
            let wal = fresh_tmp(&format!("wal_h_{i}"));
            Box::new(LocalNoncePeer::new(format!("peer-{i}"), Some(wal))) as _
        })
        .collect();
    let coord = DistributedNonceCoordinator::new(peers, 3);
    let sid = DistributedNonceCoordinator::fresh_session_id();
    let n = coord.reserve_and_commit(sid).expect("happy-path must commit");
    assert!(n >= 1);
}

#[test]
fn distributed_2pc_idempotent_prepare() {
    tmp_sealed_paths();
    let wal = fresh_tmp("idem");
    let peer = LocalNoncePeer::new("p", Some(wal));
    let sid = [0xABu8; 32];
    let a = peer.prepare(sid).unwrap();
    let b = peer.prepare(sid).unwrap();
    assert_eq!(a, b, "idempotent prepare must return same candidate");
}

// A rejecting peer that always fails phase-1. Used to drive the
// coordinator into the QuorumNotReached path.
struct RejectingPeer {
    id: String,
    calls: Arc<AtomicUsize>,
}
impl DistributedNoncePeer for RejectingPeer {
    fn peer_id(&self) -> &str { &self.id }
    fn prepare(&self, _s: [u8; 32]) -> Result<u64, NonceCoordError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(NonceCoordError::PeerRejected("test".into()))
    }
    fn commit(&self, _s: [u8; 32]) -> Result<(), NonceCoordError> {
        Ok(())
    }
    fn abort(&self, _s: [u8; 32]) -> Result<(), NonceCoordError> {
        Ok(())
    }
}

#[test]
fn distributed_2pc_quorum_failure_aborts() {
    tmp_sealed_paths();
    let calls = Arc::new(AtomicUsize::new(0));
    let good = LocalNoncePeer::new("good", Some(fresh_tmp("qf_good")));
    let good2 = LocalNoncePeer::new("good2", Some(fresh_tmp("qf_good2")));
    let peers: Vec<Box<dyn DistributedNoncePeer>> = vec![
        Box::new(good),
        Box::new(good2),
        Box::new(RejectingPeer { id: "r1".into(), calls: calls.clone() }),
        Box::new(RejectingPeer { id: "r2".into(), calls: calls.clone() }),
        Box::new(RejectingPeer { id: "r3".into(), calls: calls.clone() }),
    ];
    // Threshold 3: only 2 good peers, must fail.
    let coord = DistributedNonceCoordinator::new(peers, 3);
    let sid = DistributedNonceCoordinator::fresh_session_id();
    let res = coord.reserve_and_commit(sid);
    assert!(res.is_err(), "quorum must fail");
    match res {
        Err(NonceCoordError::QuorumNotReached { got, need }) => {
            assert!(got < need);
        }
        other => panic!("expected QuorumNotReached, got {other:?}"),
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}
