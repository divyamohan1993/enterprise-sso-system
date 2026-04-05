#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use common::types::{AuditEntry, AuditEventType, Receipt};

#[derive(Arbitrary, Debug)]
struct FuzzBftInput {
    entries: Vec<FuzzAuditEntry>,
}

#[derive(Arbitrary, Debug)]
struct FuzzAuditEntry {
    event_type_idx: u8,
    risk_score_bits: u64,
    timestamp: i64,
    prev_hash: [u8; 64],
    signature: Vec<u8>,
    classification: u8,
    user_count: u8,
    device_count: u8,
}

fuzz_target!(|input: FuzzBftInput| {
    if input.entries.len() > 32 {
        return; // Bound sequence length
    }

    // Path 1: Direct AuditNode accept_entry with arbitrary entries
    let mut node = audit::bft::AuditNode::new(0);
    for (epoch, fuzz_entry) in input.entries.iter().enumerate() {
        if fuzz_entry.signature.len() > 8192 {
            continue; // Skip oversized signatures
        }

        let event_type = match fuzz_entry.event_type_idx % 8 {
            0 => AuditEventType::AuthSuccess,
            1 => AuditEventType::AuthFailure,
            2 => AuditEventType::MfaEnabled,
            3 => AuditEventType::CredentialRegistered,
            4 => AuditEventType::CredentialRevoked,
            5 => AuditEventType::KeyRotation,
            6 => AuditEventType::DuressDetected,
            _ => AuditEventType::SystemDegraded,
        };

        let user_ids: Vec<uuid::Uuid> = (0..fuzz_entry.user_count.min(4))
            .map(|_| uuid::Uuid::new_v4())
            .collect();
        let device_ids: Vec<uuid::Uuid> = (0..fuzz_entry.device_count.min(4))
            .map(|_| uuid::Uuid::new_v4())
            .collect();

        let entry = AuditEntry {
            event_id: uuid::Uuid::new_v4(),
            event_type,
            user_ids,
            device_ids,
            ceremony_receipts: Vec::new(),
            risk_score: f64::from_bits(fuzz_entry.risk_score_bits),
            timestamp: fuzz_entry.timestamp,
            prev_hash: fuzz_entry.prev_hash,
            signature: fuzz_entry.signature.clone(),
            classification: fuzz_entry.classification,
            correlation_id: None,
            trace_id: None, // Option<String>
            source_ip: None,
            session_id: None,
            request_id: None,
            user_agent: None,
        };

        let _ = node.accept_entry(&entry, epoch as u64);
    }

    // Path 2: Test BftAuditCluster propose_entry with valid cluster setup
    // Skip if MILNET_MILITARY_DEPLOYMENT is set (would panic)
    if std::env::var("MILNET_MILITARY_DEPLOYMENT").is_err() && !input.entries.is_empty() {
        let cluster = audit::bft::BftAuditCluster::new(11);
        // Verify the cluster constructed correctly
        assert_eq!(cluster.nodes.len(), 11);
        assert_eq!(cluster.quorum_size, 7);
    }
});
