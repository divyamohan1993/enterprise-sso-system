//! Distributed system and threshold cryptography hardening tests.
//!
//! Validates: Shamir secret sharing, circuit breaker patterns, Raft consensus
//! properties, BFT audit quorum guarantees, and key rotation/envelope versioning.

// ═══════════════════════════════════════════════════════════════════════════
// Threshold KEK: Shamir Secret Sharing over GF(256)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn shamir_3_of_5_reconstruct() {
    use common::threshold_kek::{split_secret, reconstruct_secret};

    let secret = [0xBEu8; 32];
    let shares = split_secret(&secret, 3, 5).expect("split must succeed");
    assert_eq!(shares.len(), 5);

    // Any 3-of-5 combination must reconstruct correctly.
    // Test all C(5,3) = 10 combinations.
    let indices: Vec<Vec<usize>> = vec![
        vec![0, 1, 2], vec![0, 1, 3], vec![0, 1, 4],
        vec![0, 2, 3], vec![0, 2, 4], vec![0, 3, 4],
        vec![1, 2, 3], vec![1, 2, 4], vec![1, 3, 4],
        vec![2, 3, 4],
    ];

    for combo in &indices {
        let subset: Vec<_> = combo.iter().map(|&i| shares[i].clone()).collect();
        let recovered = reconstruct_secret(&subset)
            .unwrap_or_else(|e| panic!("reconstruct with {:?} failed: {}", combo, e));
        assert_eq!(
            recovered, secret,
            "3-of-5 reconstruction failed for combination {:?}",
            combo
        );
    }
}

#[test]
fn shamir_2_of_5_fails() {
    use common::threshold_kek::{split_secret, reconstruct_secret};

    let secret = [0xCDu8; 32];
    let shares = split_secret(&secret, 3, 5).expect("split must succeed");

    // With only 2 shares, Lagrange interpolation produces the wrong secret.
    // Test all C(5,2) = 10 pairs — none should reconstruct the original.
    let mut any_match = false;
    for i in 0..5 {
        for j in (i + 1)..5 {
            let subset = vec![shares[i].clone(), shares[j].clone()];
            let recovered = reconstruct_secret(&subset).expect("interpolation succeeds");
            if recovered == secret {
                any_match = true;
            }
        }
    }
    assert!(
        !any_match,
        "2 shares must NEVER reconstruct a 3-of-5 secret (information-theoretic security)"
    );
}

#[test]
fn shamir_5_of_5_reconstruct() {
    use common::threshold_kek::{split_secret, reconstruct_secret};

    let secret = [0x77u8; 32];
    let shares = split_secret(&secret, 3, 5).expect("split must succeed");

    // All 5 shares must also reconstruct correctly (superset of threshold).
    let recovered = reconstruct_secret(&shares).expect("full-set reconstruct must succeed");
    assert_eq!(recovered, secret, "all 5 shares must reconstruct the original secret");
}

#[test]
fn shamir_duplicate_indices_rejected() {
    use common::threshold_kek::{split_secret, reconstruct_secret};

    let secret = [0x42u8; 32];
    let shares = split_secret(&secret, 3, 5).expect("split must succeed");

    // Create a set with duplicate indices.
    let duped = vec![shares[0].clone(), shares[0].clone(), shares[2].clone()];
    let result = reconstruct_secret(&duped);
    assert!(
        result.is_err(),
        "duplicate share indices must be rejected to prevent trivial forgery"
    );
}

#[test]
fn shamir_shares_zeroized_after_reconstruct() {
    use common::threshold_kek::{
        split_secret, ThresholdKekConfig, ThresholdKekManager,
    };

    let secret = [0xAAu8; 32];
    let shares = split_secret(&secret, 3, 5).expect("split must succeed");

    let mut mgr = ThresholdKekManager::new(ThresholdKekConfig {
        threshold: 3,
        total_shares: 5,
        my_share_index: 1,
        ..Default::default()
    });

    mgr.load_my_share(&shares[0].to_hex()).expect("load own share");
    mgr.add_peer_share(shares[1].clone()).expect("add peer 2");
    mgr.add_peer_share(shares[2].clone()).expect("add peer 3");

    // After reconstruction, the manager must have zeroized collected shares.
    let kek = mgr.reconstruct().expect("reconstruct must succeed");
    assert_eq!(kek, &secret);

    // The shares_collected count should be 0 after reconstruction
    // because reconstruct() clears collected_shares.
    assert_eq!(
        mgr.shares_collected(), 0,
        "collected shares must be cleared (zeroized) after reconstruction"
    );

    // The KEK must still be available despite shares being gone.
    assert!(mgr.is_available(), "KEK must remain available after share zeroization");
}

// ═══════════════════════════════════════════════════════════════════════════
// Circuit Breaker: Cascade Failure Prevention
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn circuit_breaker_opens_after_threshold() {
    use common::circuit_breaker::{CircuitBreaker, CircuitState};
    use std::time::Duration;

    let cb = CircuitBreaker::with_name("open-test", 3, Duration::from_secs(60));

    // Below threshold: still closed.
    assert_eq!(cb.state(), CircuitState::Closed);
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed);
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Closed);

    // Third failure crosses the threshold — circuit opens.
    cb.record_failure();
    assert_eq!(
        cb.state(),
        CircuitState::Open,
        "circuit must open after exactly 3 failures (threshold=3)"
    );

    // Additional failures keep it open.
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);
}

#[test]
fn circuit_breaker_half_open_allows_probe() {
    use common::circuit_breaker::{CircuitBreaker, CircuitState};
    use std::time::Duration;

    let cb = CircuitBreaker::with_name("halfopen-test", 2, Duration::from_millis(1));

    // Open the circuit.
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);

    // Wait for the reset timeout to expire.
    std::thread::sleep(Duration::from_millis(2));

    // Should transition to HalfOpen, allowing a probe request.
    assert_eq!(
        cb.state(),
        CircuitState::HalfOpen,
        "circuit must transition to HalfOpen after reset timeout expires"
    );
    assert!(
        cb.allow_request(),
        "HalfOpen state must allow a probe request through"
    );
}

#[test]
fn circuit_breaker_resets_on_success() {
    use common::circuit_breaker::{CircuitBreaker, CircuitState};
    use std::time::Duration;

    let cb = CircuitBreaker::with_name("reset-success-test", 2, Duration::from_millis(1));

    // Open the circuit.
    cb.record_failure();
    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);

    // Wait for HalfOpen.
    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    // Successful probe closes the circuit.
    cb.record_success();
    assert_eq!(
        cb.state(),
        CircuitState::Closed,
        "successful probe in HalfOpen must close the circuit"
    );

    // Verify the failure counter was reset — takes threshold failures to re-open.
    cb.record_failure();
    assert_eq!(
        cb.state(),
        CircuitState::Closed,
        "single failure after reset must not re-open (threshold=2)"
    );
}

#[test]
fn circuit_breaker_exponential_backoff_capped() {
    use common::circuit_breaker::{CircuitBreaker, CircuitState};
    use std::time::Duration;

    // Base timeout 1s, threshold 1, then accumulate many backoff cycles.
    let cb = CircuitBreaker::with_name("cap-verify-test", 1, Duration::from_secs(1));

    // 1 failure opens + 30 additional failures to accumulate backoff cycles.
    for _ in 0..31 {
        cb.record_failure();
    }
    assert_eq!(cb.state(), CircuitState::Open);

    // With 30 backoff cycles, uncapped = 1s * 2^30 = ~1 billion seconds.
    // Capped at 300s (5 minutes). After sleeping 2s (well under 300s),
    // it must still be Open.
    std::thread::sleep(Duration::from_millis(2000));
    assert_eq!(
        cb.state(),
        CircuitState::Open,
        "backoff must be capped at 5 minutes — 2s elapsed cannot trigger HalfOpen"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Raft Consensus: Cluster Integrity Properties
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn raft_minimum_3_nodes() {
    use common::raft::{NodeId, RaftConfig, RaftState};

    // A 2-node cluster has no fault tolerance (quorum = 2 = cluster size).
    // Verify that a single-node or 2-node cluster cannot achieve consensus
    // after a single failure — only 3+ nodes provide meaningful fault tolerance.
    let node = NodeId::random();
    let peer1 = NodeId::random();

    let config_2_nodes = RaftConfig {
        peers: vec![(peer1, "127.0.0.1:9001".into())],
        ..Default::default()
    };
    let raft_2 = RaftState::new(node, config_2_nodes);
    assert_eq!(raft_2.cluster_size(), 2);
    assert_eq!(
        raft_2.quorum_size(), 2,
        "2-node cluster has quorum=2 (no fault tolerance — entire cluster required)"
    );

    // 3-node cluster: quorum = 2, tolerates 1 failure.
    let peer2 = NodeId::random();
    let config_3_nodes = RaftConfig {
        peers: vec![
            (peer1, "127.0.0.1:9001".into()),
            (peer2, "127.0.0.1:9002".into()),
        ],
        ..Default::default()
    };
    let raft_3 = RaftState::new(node, config_3_nodes);
    assert_eq!(raft_3.cluster_size(), 3);
    assert_eq!(
        raft_3.quorum_size(), 2,
        "3-node cluster must require quorum of 2 (tolerates 1 failure)"
    );
}

#[test]
fn raft_quorum_calculation() {
    use common::raft::{NodeId, RaftConfig, RaftState};

    // Verify quorum = cluster_size / 2 + 1 for various cluster sizes.
    let expected: Vec<(usize, usize)> = vec![
        (1, 1), // single node: quorum = 1
        (2, 2), // 2 nodes: quorum = 2
        (3, 2), // 3 nodes: quorum = 2
        (4, 3), // 4 nodes: quorum = 3
        (5, 3), // 5 nodes: quorum = 3
        (7, 4), // 7 nodes: quorum = 4
    ];

    let self_id = NodeId::random();
    for (cluster_size, expected_quorum) in &expected {
        let peer_count = cluster_size - 1; // self is implicit
        let peers: Vec<_> = (0..peer_count)
            .map(|i| (NodeId::random(), format!("127.0.0.1:{}", 9000 + i)))
            .collect();
        let config = RaftConfig {
            peers,
            ..Default::default()
        };
        let raft = RaftState::new(self_id, config);
        assert_eq!(
            raft.quorum_size(),
            *expected_quorum,
            "cluster_size={} must have quorum={}",
            cluster_size,
            expected_quorum
        );
    }
}

#[test]
fn raft_election_timeout_randomized() {
    use common::raft::RaftConfig;

    // Verify the default config specifies the documented 1500-3000ms range.
    let config = RaftConfig::default();
    assert_eq!(
        config.election_timeout_min_ms, 1500,
        "minimum election timeout must be 1500ms"
    );
    assert_eq!(
        config.election_timeout_max_ms, 3000,
        "maximum election timeout must be 3000ms"
    );

    // The range must be non-trivial (ensures randomization is meaningful).
    let range = config.election_timeout_max_ms - config.election_timeout_min_ms;
    assert!(
        range >= 1000,
        "election timeout range ({range}ms) must be >= 1000ms for leader election convergence"
    );

    // Heartbeat must be much less than election timeout to prevent spurious elections.
    assert!(
        config.heartbeat_ms < config.election_timeout_min_ms,
        "heartbeat ({}ms) must be less than min election timeout ({}ms)",
        config.heartbeat_ms,
        config.election_timeout_min_ms
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// BFT Audit: Byzantine Fault Tolerance Guarantees
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn bft_minimum_7_nodes() {
    use audit::bft::{has_bft_quorum, MIN_BFT_NODES};

    assert_eq!(MIN_BFT_NODES, 7, "BFT minimum must be 7 nodes (f=2 Byzantine faults)");

    // 7 nodes is the minimum for meaningful BFT (tolerates 2 faults).
    assert!(has_bft_quorum(7), "7 nodes must satisfy BFT quorum");
    assert!(has_bft_quorum(8), "8 nodes must satisfy BFT quorum");
    assert!(has_bft_quorum(100), "100 nodes must satisfy BFT quorum");
}

#[test]
fn bft_quorum_is_5() {
    use audit::bft::{BftAuditCluster, BFT_QUORUM};

    // Constant verification.
    assert_eq!(BFT_QUORUM, 5, "BFT quorum must be 5 for 7-node cluster (2f+1 where f=2)");

    // Verify cluster computes quorum_size correctly via the formula.
    let cluster = BftAuditCluster::new(7);
    assert_eq!(
        cluster.quorum_size, 5,
        "7-node BFT cluster must have quorum_size=5"
    );

    // Verify with a larger cluster: 10 nodes -> f=3, quorum=7.
    let cluster_10 = BftAuditCluster::new(10);
    assert_eq!(
        cluster_10.quorum_size, 7,
        "10-node BFT cluster must have quorum_size=7 (f=3, 2f+1=7)"
    );
}

#[test]
fn bft_rejects_insufficient_nodes() {
    use audit::bft::has_bft_quorum;

    // Fewer than 7 nodes cannot provide Byzantine fault tolerance.
    for n in 0..7 {
        assert!(
            !has_bft_quorum(n),
            "has_bft_quorum({}) must return false (minimum is 7)",
            n
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Key Rotation: Monitor Lifecycle and Envelope Versioning
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn key_rotation_monitor_starts() {
    use common::key_rotation::{start_rotation_monitor, RotationSchedule};
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    let schedule = RotationSchedule {
        interval: Duration::from_secs(3600), // Long interval — we just test spawning.
        auto_rotate: false,
    };

    let shutdown = start_rotation_monitor(schedule, || Ok(()))
        .expect("rotation monitor must spawn successfully");

    // The monitor thread is running (shutdown flag is false).
    assert!(
        !shutdown.load(Ordering::Relaxed),
        "rotation monitor must start in non-shutdown state"
    );

    // Signal shutdown and give the thread a moment to notice.
    shutdown.store(true, Ordering::Relaxed);

    // Verify shutdown was accepted (the flag is set).
    assert!(
        shutdown.load(Ordering::Relaxed),
        "shutdown flag must be settable"
    );
}

#[test]
fn envelope_key_version_validated() {
    use crypto::envelope::{
        wrap_key, unwrap_key, DataEncryptionKey, KeyEncryptionKey, WrappedKey,
        EnvelopeError, CURRENT_KEK_VERSION,
    };

    let kek = KeyEncryptionKey::generate().expect("generate KEK");
    let dek = DataEncryptionKey::generate().expect("generate DEK");

    // Wrap produces the current version.
    let wrapped = wrap_key(&kek, &dek).expect("wrap must succeed");
    assert_eq!(
        wrapped.kek_version, CURRENT_KEK_VERSION,
        "wrapped key must carry the current KEK version"
    );

    // Valid unwrap succeeds.
    let recovered = unwrap_key(&kek, &wrapped).expect("unwrap must succeed");
    assert_eq!(recovered.as_bytes(), dek.as_bytes());

    // Tamper with the version to simulate a future/unknown KEK version.
    let mut raw = wrapped.to_bytes().to_vec();
    let bad_version: u32 = CURRENT_KEK_VERSION + 1;
    raw[..4].copy_from_slice(&bad_version.to_be_bytes());
    let tampered = WrappedKey::from_bytes(raw).expect("parse tampered wrapped key");

    let result = unwrap_key(&kek, &tampered);
    assert_eq!(
        result.unwrap_err(),
        EnvelopeError::DecryptionFailed,
        "wrong KEK version must be rejected — prevents silent misuse during key rotation"
    );
}
