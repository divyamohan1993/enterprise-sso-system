use milnet_common::domain;
use milnet_common::types::{AuditEntry, AuditEventType, Receipt};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub struct AuditLog {
    entries: Vec<AuditEntry>,
    last_hash: [u8; 32],
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: [0u8; 32],
        }
    }

    pub fn append(
        &mut self,
        event_type: AuditEventType,
        user_ids: Vec<Uuid>,
        device_ids: Vec<Uuid>,
        risk_score: f64,
        ceremony_receipts: Vec<Receipt>,
    ) -> &AuditEntry {
        let entry = AuditEntry {
            event_id: Uuid::new_v4(),
            event_type,
            user_ids,
            device_ids,
            ceremony_receipts,
            risk_score,
            timestamp: now_us(),
            prev_hash: self.last_hash,
            signature: Vec::new(), // placeholder for ML-DSA-65
        };
        self.last_hash = hash_entry(&entry);
        self.entries.push(entry);
        self.entries.last().unwrap()
    }

    pub fn verify_chain(&self) -> bool {
        let mut expected_prev = [0u8; 32];
        for entry in &self.entries {
            if entry.prev_hash != expected_prev {
                return false;
            }
            expected_prev = hash_entry(entry);
        }
        true
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hash_entry(entry: &AuditEntry) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain::AUDIT_ENTRY);
    hasher.update(entry.event_id.as_bytes());
    hasher.update(&entry.timestamp.to_le_bytes());
    hasher.update(&entry.prev_hash);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64
}
