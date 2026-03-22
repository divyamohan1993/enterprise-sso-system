use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// Serde helper for `[u8; 64]` — serde only supports arrays up to 32 natively.
mod byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        // Serialize as a byte slice; postcard handles this efficiently.
        data.as_slice().serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(de)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}

// ── Token types (spec B.14) ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenHeader {
    pub version: u8,
    pub algorithm: u8,
    pub tier: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: Uuid,
    pub iss: [u8; 32],
    pub iat: i64,
    pub exp: i64,
    pub scope: u32,
    pub dpop_hash: [u8; 32],
    pub ceremony_id: [u8; 32],
    pub tier: u8,
    pub ratchet_epoch: u64,
}

/// Zeroize sensitive claim fields on drop.
impl Drop for TokenClaims {
    fn drop(&mut self) {
        self.iss.zeroize();
        self.dpop_hash.zeroize();
        self.ceremony_id.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub header: TokenHeader,
    pub claims: TokenClaims,
    #[serde(with = "byte_array_64")]
    pub ratchet_tag: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub frost_signature: [u8; 64],
    pub pq_signature: Vec<u8>,
}

impl Token {
    /// Returns a deterministic fixture suitable for tests.
    pub fn test_fixture() -> Self {
        Token {
            header: TokenHeader {
                version: 0x01,
                algorithm: 0x01,
                tier: 1,
            },
            claims: TokenClaims {
                sub: Uuid::nil(),
                iss: [0xAA; 32],
                iat: 1_700_000_000_000_000,
                exp: 1_700_000_030_000_000,
                scope: 0x0000_000F,
                dpop_hash: [0xBB; 32],
                ceremony_id: [0xCC; 32],
                tier: 1,
                ratchet_epoch: 42,
            },
            ratchet_tag: [0xDD; 64],
            frost_signature: [0xEE; 64],
            pq_signature: vec![0xFF; 128],
        }
    }
}

// ── Receipt (spec Section 6) ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub ceremony_session_id: [u8; 32],
    pub step_id: u8,
    pub prev_receipt_hash: [u8; 32],
    pub user_id: Uuid,
    pub dpop_key_hash: [u8; 32],
    pub timestamp: i64,
    pub nonce: [u8; 32],
    pub signature: Vec<u8>,
    pub ttl_seconds: u8,
}

/// Zeroize the signature on drop.
impl Drop for Receipt {
    fn drop(&mut self) {
        self.signature.zeroize();
    }
}

impl Receipt {
    /// Returns a deterministic fixture suitable for tests.
    pub fn test_fixture() -> Self {
        Receipt {
            ceremony_session_id: [0x01; 32],
            step_id: 1,
            prev_receipt_hash: [0x00; 32],
            user_id: Uuid::nil(),
            dpop_key_hash: [0x02; 32],
            timestamp: 1_700_000_000_000_000,
            nonce: [0x03; 32],
            signature: vec![0x04; 64],
            ttl_seconds: 30,
        }
    }
}

// ── Enums ─────────────────────────────────────────────────────────────

/// Device security tier. Numeric ordering: Sovereign(1) < Operational(2) < Sensor(3) < Emergency(4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeviceTier {
    Sovereign = 1,
    Operational = 2,
    Sensor = 3,
    Emergency = 4,
}

/// Action privilege level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ActionLevel {
    Read = 0,
    Modify = 1,
    Privileged = 2,
    Critical = 3,
    Sovereign = 4,
}

/// Identifies a system module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ModuleId {
    Gateway = 1,
    Orchestrator = 2,
    Tss = 3,
    Verifier = 4,
    Opaque = 5,
    Ratchet = 6,
    Kt = 7,
    Risk = 8,
    Audit = 9,
}

/// Audit event classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    AuthSuccess,
    AuthFailure,
    MfaEnabled,
    CredentialRegistered,
    CredentialRevoked,
    ActionLevel3,
    ActionLevel4,
    KeyRotation,
    ShareRefresh,
    SystemDegraded,
    SystemRecovered,
    DuressDetected,
}

// ── AuditEntry ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_id: Uuid,
    pub event_type: AuditEventType,
    pub user_ids: Vec<Uuid>,
    pub device_ids: Vec<Uuid>,
    pub ceremony_receipts: Vec<Receipt>,
    pub risk_score: f64,
    pub timestamp: i64,
    pub prev_hash: [u8; 32],
    pub signature: Vec<u8>,
}

// ── ShardMessage (spec Section 11) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMessage {
    pub version: u8,
    pub sender_module: ModuleId,
    pub sequence: u64,
    pub timestamp: i64,
    pub payload: Vec<u8>,
    #[serde(with = "byte_array_64")]
    pub hmac: [u8; 64],
}
