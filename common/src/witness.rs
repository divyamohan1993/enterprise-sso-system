//! External witness checkpoints (spec Section 15)
//! Periodic publication of Merkle roots to independent infrastructure.
//!
//! CNSA 2.0: Root hashes are SHA-512 (64 bytes).

use serde::{Deserialize, Serialize};

/// Serde helper for `[u8; 64]` — serde only supports arrays up to 32 natively.
mod byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessCheckpoint {
    #[serde(with = "byte_array_64")]
    pub audit_root: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub kt_root: [u8; 64],
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
        audit_root: [u8; 64],
        kt_root: [u8; 64],
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

    /// Add a signed checkpoint using a provided signing function.
    ///
    /// The signing function receives the concatenation of `audit_root || kt_root`
    /// and returns the ML-DSA-65 signature bytes.
    pub fn add_signed_checkpoint(
        &mut self,
        audit_root: [u8; 64],
        kt_root: [u8; 64],
        sign_fn: impl FnOnce(&[u8]) -> Vec<u8>,
    ) {
        let mut data = Vec::with_capacity(128);
        data.extend_from_slice(&audit_root);
        data.extend_from_slice(&kt_root);
        let signature = sign_fn(&data);
        self.add_checkpoint(audit_root, kt_root, signature);
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
