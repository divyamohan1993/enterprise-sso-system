use common::domain;
use common::types::*;
use std::collections::HashSet;

#[test]
fn token_round_trip() {
    let token = Token::test_fixture_unsigned();
    let bytes = postcard::to_allocvec(&token).expect("serialize token");
    let decoded: Token = postcard::from_bytes(&bytes).expect("deserialize token");

    assert_eq!(decoded.header.version, 0x01);
    assert_eq!(decoded.header.algorithm, 0x01);
    assert_eq!(decoded.header.tier, 1);
    assert_eq!(decoded.claims.sub, token.claims.sub);
    assert_eq!(decoded.claims.iss, token.claims.iss);
    assert_eq!(decoded.claims.iat, token.claims.iat);
    assert_eq!(decoded.claims.exp, token.claims.exp);
    assert_eq!(decoded.claims.scope, token.claims.scope);
    assert_eq!(decoded.claims.dpop_hash, token.claims.dpop_hash);
    assert_eq!(decoded.claims.ceremony_id, token.claims.ceremony_id);
    assert_eq!(decoded.claims.tier, token.claims.tier);
    assert_eq!(decoded.claims.ratchet_epoch, token.claims.ratchet_epoch);
    assert_eq!(decoded.ratchet_tag, token.ratchet_tag);
    assert_eq!(decoded.frost_signature, token.frost_signature);
    assert_eq!(decoded.pq_signature, token.pq_signature);
}

#[test]
fn receipt_round_trip() {
    let receipt = Receipt::test_fixture_unsigned();
    let bytes = postcard::to_allocvec(&receipt).expect("serialize receipt");
    let decoded: Receipt = postcard::from_bytes(&bytes).expect("deserialize receipt");

    assert_eq!(decoded.ceremony_session_id, receipt.ceremony_session_id);
    assert_eq!(decoded.step_id, receipt.step_id);
    assert_eq!(decoded.prev_receipt_hash, receipt.prev_receipt_hash);
    assert_eq!(decoded.user_id, receipt.user_id);
    assert_eq!(decoded.dpop_key_hash, receipt.dpop_key_hash);
    assert_eq!(decoded.timestamp, receipt.timestamp);
    assert_eq!(decoded.nonce, receipt.nonce);
    assert_eq!(decoded.signature, receipt.signature);
    assert_eq!(decoded.ttl_seconds, 30);
}

#[test]
fn device_tier_ordering() {
    // Numeric repr ordering: Sovereign(1) < Operational(2) < Sensor(3) < Emergency(4)
    assert!(DeviceTier::Sovereign < DeviceTier::Operational);
    assert!(DeviceTier::Operational < DeviceTier::Sensor);
    assert!(DeviceTier::Sensor < DeviceTier::Emergency);
}

#[test]
fn action_level_ordering() {
    assert!(ActionLevel::Read < ActionLevel::Modify);
    assert!(ActionLevel::Modify < ActionLevel::Privileged);
    assert!(ActionLevel::Privileged < ActionLevel::Critical);
    assert!(ActionLevel::Critical < ActionLevel::Sovereign);
}

#[test]
fn shard_message_round_trip() {
    let msg = ShardMessage {
        version: 1,
        sender_module: ModuleId::Gateway,
        sequence: 99,
        timestamp: 1_700_000_000_000_000,
        payload: vec![0xAB; 64],
        hmac: [0xCD; 64],
    };
    let bytes = postcard::to_allocvec(&msg).expect("serialize shard message");
    let decoded: ShardMessage = postcard::from_bytes(&bytes).expect("deserialize shard message");

    assert_eq!(decoded.version, 1);
    assert_eq!(decoded.sender_module, ModuleId::Gateway);
    assert_eq!(decoded.sequence, 99);
    assert_eq!(decoded.payload, msg.payload);
    assert_eq!(decoded.hmac, msg.hmac);
}

#[test]
fn audit_entry_round_trip() {
    let entry = AuditEntry {
        event_id: uuid::Uuid::nil(),
        event_type: AuditEventType::AuthSuccess,
        user_ids: vec![uuid::Uuid::nil()],
        device_ids: vec![],
        ceremony_receipts: vec![Receipt::test_fixture_unsigned()],
        risk_score: 0.42,
        timestamp: 1_700_000_000_000_000,
        prev_hash: [0x00; 64],
        signature: vec![0x11; 64],
        classification: 0,
        correlation_id: None,
        trace_id: None,
        source_ip: None,
        session_id: None,
        request_id: None,
        user_agent: None,
    };
    let bytes = postcard::to_allocvec(&entry).expect("serialize audit entry");
    let decoded: AuditEntry = postcard::from_bytes(&bytes).expect("deserialize audit entry");

    assert_eq!(decoded.event_id, entry.event_id);
    assert_eq!(decoded.event_type, AuditEventType::AuthSuccess);
    assert_eq!(decoded.risk_score, 0.42);
    assert_eq!(decoded.ceremony_receipts.len(), 1);
}

#[test]
fn domain_separation_constants_are_unique() {
    let constants: Vec<&[u8]> = vec![
        domain::FROST_TOKEN,
        domain::RECEIPT_SIGN,
        domain::DPOP_PROOF,
        domain::AUDIT_ENTRY,
        domain::MODULE_ATTEST,
        domain::RATCHET_ADVANCE,
        domain::SHARD_AUTH,
        domain::TOKEN_TAG,
        domain::KT_LEAF,
        domain::RECEIPT_CHAIN,
        domain::ACTION_BIND,
    ];
    let set: HashSet<&[u8]> = constants.iter().copied().collect();
    assert_eq!(
        constants.len(),
        set.len(),
        "domain separation constants must all be unique"
    );
}

#[test]
fn new_domain_separators_unique() {
    let new_constants: Vec<&[u8]> = vec![
        domain::ADMIN_ROLE_KEY_DERIVE,
        domain::CROSS_DOMAIN_AUDIT,
        domain::PENDING_ADMIN_ACTION,
    ];
    // All new constants must be unique among themselves
    let set: HashSet<&[u8]> = new_constants.iter().copied().collect();
    assert_eq!(new_constants.len(), set.len());
    // And must not collide with existing constants
    let existing = vec![
        domain::FROST_TOKEN,
        domain::RECEIPT_SIGN,
        domain::DPOP_PROOF,
        domain::AUDIT_ENTRY,
    ];
    for existing_const in &existing {
        for new_const in &new_constants {
            assert_ne!(existing_const, new_const, "domain separator collision detected");
        }
    }
}

#[test]
fn token_claims_classification_default() {
    let token = Token::test_fixture_unsigned();
    assert_eq!(token.claims.classification, 0, "default classification must be Unclassified (0)");
}

#[test]
fn audit_entry_classification_default() {
    let entry = AuditEntry {
        event_id: uuid::Uuid::nil(),
        event_type: AuditEventType::AuthSuccess,
        user_ids: vec![],
        device_ids: vec![],
        ceremony_receipts: vec![],
        risk_score: 0.0,
        timestamp: 0,
        prev_hash: [0u8; 64],
        signature: vec![],
        classification: 0,
        correlation_id: None,
        trace_id: None,
        source_ip: None,
        session_id: None,
        request_id: None,
        user_agent: None,
    };
    assert_eq!(entry.classification, 0);
}

#[test]
fn new_audit_event_types_exist() {
    // Ensure the new event types can be serialized/deserialized
    let events = vec![
        AuditEventType::AdminRbacDenied,
        AuditEventType::AdminRbacGranted,
        AuditEventType::CrossDomainDecision,
        AuditEventType::AdminCeremonyRequired,
        AuditEventType::DpopReplayDetected,
    ];
    for event in events {
        let bytes = postcard::to_allocvec(&event).expect("serialize audit event type");
        let decoded: AuditEventType = postcard::from_bytes(&bytes).expect("deserialize audit event type");
        assert_eq!(decoded, event);
    }
}
