//! Duress PIN protocol (spec Section 7, Errata B.4)
//! A secondary PIN that appears to work but silently triggers lockdown.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressConfig {
    pub user_id: Uuid,
    pub normal_pin_hash: [u8; 32],
    pub duress_pin_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq)]
pub enum PinVerification {
    Normal,  // Legitimate authentication
    Duress,  // Coercion detected — fake success, trigger alert
    Invalid, // Wrong PIN
}

impl DuressConfig {
    pub fn new(user_id: Uuid, normal_pin: &[u8], duress_pin: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            user_id,
            normal_pin_hash: Sha256::digest(normal_pin).into(),
            duress_pin_hash: Sha256::digest(duress_pin).into(),
        }
    }

    pub fn verify_pin(&self, pin: &[u8]) -> PinVerification {
        use sha2::{Digest, Sha256};
        let hash: [u8; 32] = Sha256::digest(pin).into();
        use subtle::ConstantTimeEq;
        if hash.ct_eq(&self.normal_pin_hash).into() {
            PinVerification::Normal
        } else if hash.ct_eq(&self.duress_pin_hash).into() {
            PinVerification::Duress
        } else {
            PinVerification::Invalid
        }
    }
}

/// Duress alert — generated when duress PIN is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuressAlert {
    pub user_id: Uuid,
    pub timestamp: i64,
    pub fake_token_issued: bool,
    pub lockdown_triggered: bool,
}
