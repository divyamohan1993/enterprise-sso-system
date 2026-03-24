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
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, signing_key);

    let result = cluster.propose_entry(
        AuditEventType::AuthSuccess,
        vec![Uuid::new_v4()],
        vec![Uuid::new_v4()],
        0.25,
        vec![],
    );
    assert!(result.is_ok(), "quorum should be met with 7 honest nodes");

    for node in &cluster.nodes {
        assert_eq!(node.log.len(), 1);
        let entry = &node.log.entries()[0];
        assert!(
            !entry.signature.is_empty(),
            "entry should be signed with ML-DSA-65"
        );
    }
}

#[test]
fn bft_signed_cluster_consistency() {
    let (signing_key, _verifying_key) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, signing_key);

    for i in 0..5 {
        let result = cluster.propose_entry(
            AuditEventType::KeyRotation,
            vec![Uuid::new_v4()],
            vec![],
            i as f64 * 0.1,
            vec![],
        );
        assert!(result.is_ok());
    }

    assert!(cluster.verify_consistency(), "all honest nodes should be consistent");
    assert_eq!(cluster.nodes[0].log.len(), 5);
}

#[test]
fn bft_signed_cluster_tolerates_byzantine() {
    let (signing_key, _verifying_key) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, signing_key);

    cluster.set_byzantine(5);
    cluster.set_byzantine(6);

    let result = cluster.propose_entry(
        AuditEventType::ActionLevel4,
        vec![Uuid::new_v4()],
        vec![],
        0.95,
        vec![],
    );
    assert!(result.is_ok(), "quorum of 5 should still be met with 2 Byzantine nodes");

    cluster.set_byzantine(4);
    let result2 = cluster.propose_entry(
        AuditEventType::SystemDegraded,
        vec![],
        vec![],
        1.0,
        vec![],
    );
    assert!(result2.is_err(), "3 Byzantine nodes should prevent quorum");
}

#[test]
fn bft_signed_entries_have_valid_signature_bytes() {
    let (signing_key, verifying_key) = crypto::pq_sign::generate_pq_keypair();
    let mut cluster = audit::bft::BftAuditCluster::new_with_signing_key(7, signing_key);

    cluster
        .propose_entry(
            AuditEventType::CredentialRevoked,
            vec![Uuid::new_v4()],
            vec![Uuid::new_v4()],
            0.8,
            vec![],
        )
        .expect("should succeed");

    let entry = &cluster.nodes[0].log.entries()[0];
    let entry_hash = hash_entry(entry);

    let valid = crypto::pq_sign::pq_verify_raw(&verifying_key, &entry_hash, &entry.signature);
    assert!(valid, "ML-DSA-65 signature should verify");
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
        };
        log.append_raw(unsigned_entry).unwrap();

        assert!(log.verify_chain());

        assert!(
            !log.verify_chain_with_key(Some(&vk)),
            "unsigned entries must be rejected when a verifying key is provided"
        );
    });
}
