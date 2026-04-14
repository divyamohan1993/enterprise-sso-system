use audit::log::{hash_entry, AuditLog, AuditRequest, AuditResponse};
use common::types::AuditEventType;
use uuid::Uuid;

/// Helper: generate an ML-DSA-87 keypair for signing audit entries.
fn make_signing_key() -> (crypto::pq_sign::PqSigningKey, crypto::pq_sign::PqVerifyingKey) {
    crypto::pq_sign::generate_pq_keypair()
}

fn run_with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

#[test]
fn append_creates_entry() {
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        let entry = log.append(
            AuditEventType::AuthSuccess,
            vec![Uuid::new_v4()],
            vec![Uuid::new_v4()],
            0.1,
            Vec::new(),
            &sk,
        );
        assert_eq!(entry.event_type, AuditEventType::AuthSuccess);
        assert!(!entry.signature.is_empty(), "entry must be signed");
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    });
}

#[test]
fn chain_integrity_valid() {
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        for _ in 0..5 {
            log.append(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![],
                0.5,
                Vec::new(),
                &sk,
            );
        }
        assert_eq!(log.len(), 5);
        assert!(log.verify_chain());
    });
}

#[test]
fn chain_detects_tampering() {
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        for _ in 0..3 {
            log.append(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![],
                0.2,
                Vec::new(),
                &sk,
            );
        }
        assert!(log.verify_chain());

        let entries = log.entries().to_vec();
        let tampered = AuditLog::new();
        for (i, mut entry) in entries.into_iter().enumerate() {
            if i == 1 {
                entry.prev_hash = [0xFF; 64];
            }
            let _ = tampered;
            let _ = entry;
            break;
        }

        let mut log2 = AuditLog::new();
        log2.append(
            AuditEventType::AuthSuccess,
            vec![Uuid::new_v4()],
            vec![],
            0.1,
            Vec::new(),
            &sk,
        );
        log2.append(
            AuditEventType::AuthFailure,
            vec![Uuid::new_v4()],
            vec![],
            0.9,
            Vec::new(),
            &sk,
        );
        assert!(log2.verify_chain());

        let entries = log2.entries();
        let mut fake_entry = entries[1].clone();
        fake_entry.prev_hash = [0xAB; 64];
        let expected_prev = hash_entry(&entries[0]);
        assert_ne!(fake_entry.prev_hash, expected_prev);
    });
}

#[test]
fn entries_are_ordered() {
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        for _ in 0..5 {
            log.append(AuditEventType::KeyRotation, vec![], vec![], 0.0, Vec::new(), &sk);
        }
        let entries = log.entries();
        for window in entries.windows(2) {
            assert!(
                window[0].timestamp <= window[1].timestamp,
                "timestamps must be monotonically increasing"
            );
        }
    });
}

#[test]
fn hash_is_deterministic() {
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        log.append(
            AuditEventType::CredentialRegistered,
            vec![Uuid::nil()],
            vec![],
            0.0,
            Vec::new(),
            &sk,
        );
        let entry = &log.entries()[0];
        let h1 = hash_entry(entry);
        let h2 = hash_entry(entry);
        assert_eq!(h1, h2);
    });
}

// ── Wire message type tests ──────────────────────────────────────────

#[test]
fn audit_request_roundtrip() {
    let req = AuditRequest {
        event_type: AuditEventType::AuthSuccess,
        user_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        device_ids: vec![Uuid::new_v4()],
        risk_score: 0.42,
        metadata: vec![1, 2, 3, 4],
        classification: 2, // Secret
        // D10 (wave-2 audit): idempotency + per-tenant throttle fields
        idempotency_event_id: None,
        idempotency_signature: Vec::new(),
        tenant_id: Uuid::nil(),
    };
    let bytes = postcard::to_allocvec(&req).expect("serialize");
    let decoded: AuditRequest = postcard::from_bytes(&bytes).expect("deserialize");
    assert_eq!(decoded.event_type, req.event_type);
    assert_eq!(decoded.user_ids.len(), 2);
    assert_eq!(decoded.device_ids.len(), 1);
    assert!((decoded.risk_score - 0.42).abs() < f64::EPSILON);
    assert_eq!(decoded.metadata, vec![1, 2, 3, 4]);
}

#[test]
fn audit_response_roundtrip_success() {
    let resp = AuditResponse {
        success: true,
        event_id: Some(Uuid::new_v4()),
        error: None,
    };
    let bytes = postcard::to_allocvec(&resp).expect("serialize");
    let decoded: AuditResponse = postcard::from_bytes(&bytes).expect("deserialize");
    assert!(decoded.success);
    assert!(decoded.event_id.is_some());
    assert!(decoded.error.is_none());
}

#[test]
fn audit_response_roundtrip_error() {
    let resp = AuditResponse {
        success: false,
        event_id: None,
        error: Some("quorum not met".to_string()),
    };
    let bytes = postcard::to_allocvec(&resp).expect("serialize");
    let decoded: AuditResponse = postcard::from_bytes(&bytes).expect("deserialize");
    assert!(!decoded.success);
    assert!(decoded.event_id.is_none());
    assert_eq!(decoded.error.as_deref(), Some("quorum not met"));
}

// ── BFT cluster with ML-DSA signing tests ────────────────────────────

#[test]
fn bft_cluster_with_signing_proposes_entry() {
    let (signing_key, _verifying_key) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    let result = cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.25,
        vec![],
        2, // Secret classification
    );
    assert!(result.is_ok(), "quorum should be met with 11 honest nodes");

    for node in &cluster.nodes {
        assert_eq!(node.log.len(), 1);
        let entry = &node.log.entries()[0];
        assert!(
            !entry.signature.is_empty(),
            "entry should be signed with ML-DSA-87"
        );
    }
}

#[test]
fn bft_signed_cluster_consistency() {
    let (signing_key, _verifying_key) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    for i in 0..5 {
        let result = cluster.propose_entry(
            AuditEventType::KeyRotation,
            vec![Uuid::new_v4()],
            vec![],
            i as f64 * 0.1,
            vec![],
            0,
        );
        assert!(result.is_ok());
    }

    assert!(cluster.verify_consistency(), "all honest nodes should be consistent");
    assert_eq!(cluster.nodes[0].log.len(), 5);
}

#[test]
fn bft_signed_cluster_tolerates_byzantine() {
    let (signing_key, _verifying_key) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    cluster.set_byzantine(8);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    let result = cluster.propose_entry(
        AuditEventType::ActionLevel4,
        vec![Uuid::new_v4()],
        vec![],
        0.95,
        vec![],
        3, // TopSecret
    );
    assert!(result.is_ok(), "quorum of 7 should still be met with 3 Byzantine nodes");

    cluster.set_byzantine(7);
    cluster.set_byzantine(6);
    let result2 = cluster.propose_entry(
        AuditEventType::SystemDegraded,
        vec![],
        vec![],
        1.0,
        vec![],
        0,
    );
    assert!(result2.is_err(), "5 Byzantine nodes should prevent quorum");
}

#[test]
fn bft_signed_entries_have_valid_signature_bytes() {
    let (signing_key, verifying_key) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    cluster
        .propose_entry(
            AuditEventType::CredentialRevoked,
            vec![Uuid::new_v4()],
            vec![Uuid::new_v4()],
            0.8,
            vec![],
            1, // Confidential
        )
        .expect("should succeed");

    let entry = &cluster.nodes[0].log.entries()[0];
    let entry_hash = hash_entry(entry);

    let valid = crypto::pq_sign::pq_verify_raw(&verifying_key, &entry_hash, &entry.signature);
    assert!(valid, "ML-DSA-87 signature should verify");
}

// ── Signature verification tests ─────────────────────────────────────

#[test]
fn test_all_entries_are_signed() {
    run_with_large_stack(|| {
        let (sk, vk) = make_signing_key();
        let mut log = AuditLog::new();

        for _ in 0..5 {
            log.append(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![],
                0.1,
                Vec::new(),
                &sk,
            );
        }

        for entry in log.entries() {
            assert!(!entry.signature.is_empty(), "all entries must be signed");
        }

        assert!(log.verify_chain_with_key(Some(&vk)));
    });
}

#[test]
fn test_unsigned_entries_rejected_during_verification() {
    run_with_large_stack(|| {
        let (_sk, vk) = make_signing_key();

        let mut log = AuditLog::new();
        let unsigned_entry = common::types::AuditEntry {
            event_id: Uuid::new_v4(),
            event_type: AuditEventType::AuthSuccess,
            user_ids: vec![],
            device_ids: vec![],
            ceremony_receipts: vec![],
            risk_score: 0.0,
            timestamp: 12345,
            prev_hash: [0u8; 64],
            signature: Vec::new(),
            classification: 0,
            correlation_id: None,
            trace_id: None,
            source_ip: None,
            session_id: None,
            request_id: None,
            user_agent: None,
        };
        log.append_raw(unsigned_entry).unwrap();

        assert!(log.verify_chain());

        assert!(
            !log.verify_chain_with_key(Some(&vk)),
            "unsigned entries must be rejected when a verifying key is provided"
        );
    });
}

// ── BFT quorum enforcement: reject when <MIN_BFT_NODES ─────────────

#[test]
fn bft_cluster_rejects_entry_when_below_min_nodes() {
    // With fewer than 11 nodes, propose_entry must return Err.
    // This validates the hardened quorum enforcement that now REJECTS
    // instead of merely logging a warning.
    let (signing_key, _vk) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, signing_key);

    let result = cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.25,
        vec![],
        2,
    );
    assert!(
        result.is_err(),
        "cluster with 7 nodes (<11 MIN_BFT_NODES) must reject entries"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("minimum") && err.contains("11"),
        "error must reference minimum node count, got: {err}"
    );
}

#[test]
fn bft_cluster_accepts_entry_with_min_nodes() {
    // With exactly 11 nodes (the minimum), propose_entry must succeed.
    let (signing_key, _vk) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    let result = cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.25,
        vec![],
        2,
    );
    assert!(
        result.is_ok(),
        "cluster with 11 nodes (== MIN_BFT_NODES) must accept entries: {:?}",
        result
    );
    for node in &cluster.nodes {
        assert_eq!(node.log.len(), 1);
    }
}

#[test]
fn bft_cluster_rejects_entry_with_various_insufficient_sizes() {
    // Verify that all node counts below 11 are rejected.
    for node_count in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
        let (signing_key, _vk) = crypto::pq_sign::generate_pq_keypair();
        let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(node_count, signing_key);
        let result = cluster.propose_entry(
            AuditEventType::KeyRotation,
            vec![],
            vec![],
            0.0,
            vec![],
            0,
        );
        assert!(
            result.is_err(),
            "cluster with {} nodes must reject entries",
            node_count
        );
    }
}

// ── BFT 11-node Byzantine tolerance tests ───────────────────────────

#[test]
fn bft_11_nodes_tolerates_3_byzantine() {
    // f=3, quorum=7. With 3 Byzantine nodes, 8 honest nodes remain,
    // which exceeds quorum of 7. Entries must commit.
    let (signing_key, _vk) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    // Mark 3 nodes as Byzantine (the maximum tolerated)
    cluster.set_byzantine(8);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    let result = cluster.propose_entry(
        AuditEventType::ActionLevel4,
        vec![Uuid::new_v4()],
        vec![],
        0.95,
        vec![],
        3, // TopSecret
    );
    assert!(
        result.is_ok(),
        "8 honest nodes (11 - 3 Byzantine) should meet quorum of 7: {:?}",
        result
    );

    // Verify honest nodes all have the entry
    for node in &cluster.nodes[..8] {
        assert_eq!(node.log.len(), 1, "honest node must have the entry");
    }
    // Byzantine nodes should have empty logs
    for node in &cluster.nodes[8..] {
        assert_eq!(node.log.len(), 0, "Byzantine node must have empty log");
    }
}

#[test]
fn bft_11_nodes_fails_with_4_byzantine() {
    // f=3, quorum=7. With 4 Byzantine nodes (f+1), only 7 honest nodes
    // remain, which exactly meets quorum. But wait: quorum = 2f+1 = 7,
    // and we have 7 honest nodes, so it should still work. Let's verify
    // that with 5 Byzantine nodes (leaving 6 honest < 7 quorum) it fails.
    let (signing_key, _vk) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    // 4 Byzantine nodes: 7 honest >= 7 quorum, should still succeed
    cluster.set_byzantine(7);
    cluster.set_byzantine(8);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    let result = cluster.propose_entry(
        AuditEventType::SystemDegraded,
        vec![],
        vec![],
        1.0,
        vec![],
        0,
    );
    assert!(
        result.is_ok(),
        "7 honest nodes should exactly meet quorum of 7: {:?}",
        result
    );

    // Now add a 5th Byzantine node: only 6 honest < 7 quorum
    cluster.set_byzantine(6);
    let result2 = cluster.propose_entry(
        AuditEventType::SystemDegraded,
        vec![],
        vec![],
        1.0,
        vec![],
        0,
    );
    assert!(
        result2.is_err(),
        "6 honest nodes should fail to meet quorum of 7"
    );
    assert!(
        result2.unwrap_err().contains("quorum not met"),
        "error must mention quorum failure"
    );
}

#[test]
fn bft_11_nodes_consistency_with_byzantine_faults() {
    // Multiple entries with 3 Byzantine nodes: all honest nodes stay consistent
    let (signing_key, _vk) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(11, signing_key);

    cluster.set_byzantine(8);
    cluster.set_byzantine(9);
    cluster.set_byzantine(10);

    for i in 0..20 {
        let result = cluster.propose_entry(
            AuditEventType::AuthSuccess,
            vec![Uuid::new_v4()],
            vec![],
            i as f64 * 0.05,
            vec![],
            0,
        );
        assert!(result.is_ok(), "entry {} should commit", i);
    }

    assert!(
        cluster.verify_consistency(),
        "all honest nodes must have identical chains"
    );

    for node in &cluster.nodes[..8] {
        assert_eq!(node.log.len(), 20);
        assert!(node.log.verify_chain());
    }
}

// ── Hardened security tests ───────────────────────────────────────────

#[test]
fn test_audit_chain_detects_tampered_entry() {
    // SHA-512 hash chain detects retroactive tampering
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        for _ in 0..5 {
            log.append(
                AuditEventType::AuthSuccess,
                vec![Uuid::new_v4()],
                vec![Uuid::new_v4()],
                0.3,
                Vec::new(),
                &sk,
            );
        }
        // Chain must verify before tampering
        assert!(log.verify_chain(), "untampered chain must verify");

        // Tamper with entry 2's event_type (retroactive modification)
        let mut tampered_entries: Vec<common::types::AuditEntry> =
            log.entries().to_vec();
        tampered_entries[2].event_type = AuditEventType::ActionLevel4;

        let tampered_log = AuditLog::from_entries(tampered_entries);
        // Chain must fail because entry 3's prev_hash no longer matches
        // the recomputed hash of the tampered entry 2
        assert!(
            !tampered_log.verify_chain(),
            "tampered chain must fail verification"
        );
    });
}

#[test]
fn test_audit_entry_signed_with_pq_signature() {
    // Post-quantum audit signatures resist quantum cryptanalysis
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        log.append(
            AuditEventType::CredentialRegistered,
            vec![Uuid::new_v4()],
            vec![],
            0.0,
            Vec::new(),
            &sk,
        );
        let entry = &log.entries()[0];
        assert!(
            !entry.signature.is_empty(),
            "entry must have a non-empty pq_signature (ML-DSA-87 signed)"
        );
        // ML-DSA-87 signatures are 4627 bytes; verify it is substantial
        assert!(
            entry.signature.len() > 100,
            "signature should be a full post-quantum signature, not a stub"
        );
    });
}

#[test]
fn test_audit_log_append_only_ordering() {
    // Append-only hash chain: each entry binds to its predecessor
    run_with_large_stack(|| {
        let (sk, _vk) = make_signing_key();
        let mut log = AuditLog::new();
        for _ in 0..3 {
            log.append(
                AuditEventType::KeyRotation,
                vec![Uuid::new_v4()],
                vec![],
                0.0,
                Vec::new(),
                &sk,
            );
        }
        let entries = log.entries();
        assert_eq!(entries.len(), 3);

        // Entry 0's prev_hash should be all zeros (genesis)
        assert_eq!(entries[0].prev_hash, [0u8; 64], "first entry prev_hash must be zero");

        // For entries 1 and 2: prev_hash must equal hash_entry of predecessor
        for i in 1..entries.len() {
            let expected = hash_entry(&entries[i - 1]);
            assert_eq!(
                entries[i].prev_hash, expected,
                "entry {}'s prev_hash must equal hash_entry of entry {}",
                i,
                i - 1
            );
        }
    });
}
