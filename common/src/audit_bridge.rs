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
