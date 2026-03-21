//! External witness checkpoints (spec Section 15)
//! Periodic publication of Merkle roots to independent infrastructure.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessCheckpoint {
    pub audit_root: [u8; 32],
    pub kt_root: [u8; 32],
    pub timestamp: i64,
    pub sequence: u64,
    pub signature: Vec<u8>, // ML-DSA-65
}

pub struct WitnessLog {
    checkpoints: Vec<WitnessCheckpoint>,
}

impl WitnessLog {
    pub fn new() -> Self {
        Self {
            checkpoints: Vec::new(),
        }
    }

    pub fn add_checkpoint(
        &mut self,
        audit_root: [u8; 32],
        kt_root: [u8; 32],
        signature: Vec<u8>,
    ) {
        let seq = self.checkpoints.len() as u64;
        self.checkpoints.push(WitnessCheckpoint {
            audit_root,
            kt_root,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64,
            sequence: seq,
            signature,
        });
    }

    pub fn latest(&self) -> Option<&WitnessCheckpoint> {
        self.checkpoints.last()
    }

    pub fn len(&self) -> usize {
        self.checkpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checkpoints.is_empty()
    }
}

impl Default for WitnessLog {
    fn default() -> Self {
        Self::new()
    }
}
