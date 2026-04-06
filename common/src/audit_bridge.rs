//! Bridge between SIEM events and the BFT audit chain.
//!
//! Services that cannot directly connect to the audit SHARD endpoint
//! can use this module to persist security-critical events as local
//! audit entries that are later swept into the BFT chain.

use crate::types::{AuditEntry, AuditEventType};
use std::sync::Mutex;
use std::sync::OnceLock;

/// Maximum buffered audit entries before forced flush.
const MAX_BUFFERED_ENTRIES: usize = 10_000;

static AUDIT_BUFFER: OnceLock<Mutex<Vec<AuditEntry>>> = OnceLock::new();

/// Buffer an audit entry for later collection by the audit service.
pub fn buffer_audit_entry(entry: AuditEntry) {
    let buf = AUDIT_BUFFER.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut entries) = buf.lock() {
        if entries.len() < MAX_BUFFERED_ENTRIES {
            entries.push(entry);
        } else {
            tracing::error!("SIEM:CRITICAL audit buffer full, dropping entry");
        }
    }
}

/// Drain all buffered audit entries (called by the audit service collector).
pub fn drain_audit_buffer() -> Vec<AuditEntry> {
    let buf = AUDIT_BUFFER.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut entries) = buf.lock() {
        std::mem::take(&mut *entries)
    } else {
        Vec::new()
    }
}

/// Helper to create an audit entry from common parameters.
pub fn create_audit_entry(
    event_type: AuditEventType,
    user_ids: Vec<uuid::Uuid>,
    device_ids: Vec<uuid::Uuid>,
    source_ip: Option<String>,
    request_id: Option<String>,
) -> AuditEntry {
    use crate::secure_time::secure_now_us_i64;
    AuditEntry {
        event_id: uuid::Uuid::new_v4(),
        event_type,
        user_ids,
        device_ids,
        ceremony_receipts: Vec::new(),
        risk_score: 0.0,
        classification: 0,
        timestamp: secure_now_us_i64(),
        prev_hash: [0u8; 64],  // Set by audit service on chain insertion
        signature: Vec::new(),   // Set by audit service
        correlation_id: None,
        trace_id: None,
        source_ip,
        session_id: None,
        request_id,
        user_agent: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_entry(event_type: AuditEventType) -> AuditEntry {
        AuditEntry {
            event_id: Uuid::new_v4(),
            event_type,
            user_ids: vec![Uuid::new_v4()],
            device_ids: vec![],
            ceremony_receipts: Vec::new(),
            risk_score: 0.0,
            classification: 0,
            timestamp: 1234567890,
            prev_hash: [0u8; 64],
            signature: Vec::new(),
            correlation_id: None,
            trace_id: None,
            source_ip: None,
            session_id: None,
            request_id: None,
            user_agent: None,
        }
    }

    // ── 1. Buffer an audit entry and drain it ────────────────────────────

    #[test]
    fn buffer_and_drain_single_entry() {
        // Drain any leftover state from other tests
        let _ = drain_audit_buffer();

        let entry = make_entry(AuditEventType::AuthSuccess);
        let event_id = entry.event_id;
        buffer_audit_entry(entry);

        let drained = drain_audit_buffer();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].event_id, event_id);
    }

    // ── 2. Buffer multiple entries and drain all ─────────────────────────

    #[test]
    fn buffer_multiple_and_drain_all() {
        let _ = drain_audit_buffer();

        let ids: Vec<Uuid> = (0..5)
            .map(|_| {
                let entry = make_entry(AuditEventType::AuthFailure);
                let id = entry.event_id;
                buffer_audit_entry(entry);
                id
            })
            .collect();

        let drained = drain_audit_buffer();
        assert_eq!(drained.len(), 5);
        for (i, entry) in drained.iter().enumerate() {
            assert_eq!(entry.event_id, ids[i]);
        }
    }

    // ── 3. Drain empty buffer returns empty vec ──────────────────────────

    #[test]
    fn drain_empty_returns_empty() {
        let _ = drain_audit_buffer();
        let drained = drain_audit_buffer();
        assert!(drained.is_empty());
    }

    // ── 4. Concurrent buffer writes are safe ─────────────────────────────

    #[test]
    fn concurrent_buffer_writes() {
        let _ = drain_audit_buffer();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..10 {
                        buffer_audit_entry(make_entry(AuditEventType::KeyRotation));
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let drained = drain_audit_buffer();
        assert_eq!(drained.len(), 100);
    }

    // ── 5. Buffer respects capacity limit ────────────────────────────────

    #[test]
    fn buffer_respects_max_capacity() {
        let _ = drain_audit_buffer();

        // Buffer exactly MAX_BUFFERED_ENTRIES entries
        for _ in 0..MAX_BUFFERED_ENTRIES {
            buffer_audit_entry(make_entry(AuditEventType::AuthSuccess));
        }

        // One more should be dropped
        buffer_audit_entry(make_entry(AuditEventType::AuthFailure));

        let drained = drain_audit_buffer();
        assert_eq!(drained.len(), MAX_BUFFERED_ENTRIES);
    }

    // ── 6. Entry integrity preserved through buffer/drain cycle ──────────

    #[test]
    fn entry_integrity_preserved() {
        let _ = drain_audit_buffer();

        let entry = AuditEntry {
            event_id: Uuid::new_v4(),
            event_type: AuditEventType::CredentialRegistered,
            user_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            device_ids: vec![Uuid::new_v4()],
            ceremony_receipts: Vec::new(),
            risk_score: 0.75,
            classification: 2,
            timestamp: 9999999999,
            prev_hash: [0xAB; 64],
            signature: vec![1, 2, 3, 4],
            correlation_id: Some(Uuid::new_v4()),
            trace_id: Some("trace-123".to_string()),
            source_ip: Some("10.0.0.1".to_string()),
            session_id: Some("sess-abc".to_string()),
            request_id: Some("req-xyz".to_string()),
            user_agent: Some("test-agent".to_string()),
        };

        let event_id = entry.event_id;
        let user_ids = entry.user_ids.clone();
        let risk = entry.risk_score;
        let ts = entry.timestamp;
        let sig = entry.signature.clone();
        let trace = entry.trace_id.clone();

        buffer_audit_entry(entry);
        let drained = drain_audit_buffer();
        assert_eq!(drained.len(), 1);

        let got = &drained[0];
        assert_eq!(got.event_id, event_id);
        assert_eq!(got.user_ids, user_ids);
        assert!((got.risk_score - risk).abs() < f64::EPSILON);
        assert_eq!(got.timestamp, ts);
        assert_eq!(got.signature, sig);
        assert_eq!(got.trace_id, trace);
        assert_eq!(got.classification, 2);
    }

    // ── 7. Drain clears the buffer ───────────────────────────────────────

    #[test]
    fn drain_clears_buffer() {
        let _ = drain_audit_buffer();

        for _ in 0..3 {
            buffer_audit_entry(make_entry(AuditEventType::SystemDegraded));
        }

        let first = drain_audit_buffer();
        assert_eq!(first.len(), 3);

        let second = drain_audit_buffer();
        assert!(second.is_empty(), "buffer should be empty after drain");
    }
}

/// Create an audit entry with distributed tracing context.
///
/// Use this from gateway/orchestrator paths where a `RequestContext` is available
/// to populate correlation_id and trace_id for end-to-end tracing.
pub fn create_audit_entry_with_context(
    event_type: AuditEventType,
    user_ids: Vec<uuid::Uuid>,
    device_ids: Vec<uuid::Uuid>,
    source_ip: Option<String>,
    request_id: Option<String>,
    ctx: &crate::types::RequestContext,
) -> AuditEntry {
    use crate::secure_time::secure_now_us_i64;
    AuditEntry {
        event_id: uuid::Uuid::new_v4(),
        event_type,
        user_ids,
        device_ids,
        ceremony_receipts: Vec::new(),
        risk_score: 0.0,
        classification: 0,
        timestamp: secure_now_us_i64(),
        prev_hash: [0u8; 64],
        signature: Vec::new(),
        correlation_id: Some(ctx.correlation_id),
        trace_id: Some(ctx.trace_id.clone()),
        source_ip,
        session_id: None,
        request_id,
        user_agent: None,
    }
}
