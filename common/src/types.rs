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

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: Uuid,
    pub iss: [u8; 32],
    pub iat: i64,
    pub exp: i64,
    pub scope: u32,
    #[serde(with = "byte_array_64")]
    pub dpop_hash: [u8; 64],
    pub ceremony_id: [u8; 32],
    pub tier: u8,
    pub ratchet_epoch: u64,
    /// Unique token identifier for revocation lookups.
    pub token_id: [u8; 16],
    /// Audience — the relying party this token is bound to.
    #[serde(default)]
    pub aud: Option<String>,
    /// Classification level for Mandatory Access Control (MAC).
    /// Default: 0 (Unclassified) for backward compatibility.
    #[serde(default)]
    pub classification: u8,
}

/// Custom Debug for TokenClaims — redacts cryptographic material.
impl std::fmt::Debug for TokenClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenClaims")
            .field("sub", &self.sub)
            .field("iss", &"[REDACTED]")
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("scope", &self.scope)
            .field("dpop_hash", &"[REDACTED]")
            .field("ceremony_id", &"[REDACTED]")
            .field("tier", &self.tier)
            .field("ratchet_epoch", &self.ratchet_epoch)
            .field("token_id", &"[REDACTED]")
            .field("aud", &"[REDACTED]")
            .field("classification", &self.classification)
            .finish()
    }
}

/// Zeroize sensitive claim fields on drop.
impl Drop for TokenClaims {
    fn drop(&mut self) {
        self.iss.zeroize();
        self.dpop_hash.zeroize();
        self.ceremony_id.zeroize();
        self.token_id.zeroize();
        if let Some(ref mut aud) = self.aud {
            aud.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Token {
    pub header: TokenHeader,
    pub claims: TokenClaims,
    #[serde(with = "byte_array_64")]
    pub ratchet_tag: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub frost_signature: [u8; 64],
    pub pq_signature: Vec<u8>,
}

/// Custom Debug for Token — redacts signatures and cryptographic tags.
impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("header", &self.header)
            .field("claims", &"[REDACTED]")
            .field("ratchet_tag", &"[REDACTED]")
            .field("frost_signature", &"[REDACTED]")
            .field("pq_signature", &"[REDACTED]")
            .finish()
    }
}

/// Zeroize cryptographic material on drop — prevents memory forensics.
impl Drop for Token {
    fn drop(&mut self) {
        self.ratchet_tag.zeroize();
        self.frost_signature.zeroize();
        self.pq_signature.zeroize();
    }
}

impl Token {
    /// Returns a deterministic fixture with INVALID signatures for tests.
    ///
    /// **WARNING**: The `frost_signature` and `pq_signature` fields contain
    /// dummy bytes (`0xEE` and `0xFF`). They are NOT real cryptographic
    /// signatures. This fixture MUST NOT be used to test signature
    /// verification, token validation, or any security property that depends
    /// on signature correctness. Use it only for serialization, formatting,
    /// and structural tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_fixture_unsigned() -> Self {
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
                dpop_hash: [0xBB; 64],
                ceremony_id: [0xCC; 32],
                tier: 1,
                ratchet_epoch: 42,
                token_id: [0xAB; 16],
                aud: Some("test-service".to_string()),
                classification: 0,
            },
            ratchet_tag: [0xDD; 64],
            frost_signature: [0xEE; 64],
            pq_signature: vec![0xFF; 128],
        }
    }
}

// ── Encrypted claims (JWE-style) ─────────────────────────────────────

/// Encrypted token claims — claims are never plaintext on the wire.
///
/// Uses AES-256-GCM envelope encryption with per-token random nonce.
/// The ciphertext includes the 16-byte GCM authentication tag.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedClaims {
    /// AES-256-GCM nonce (12 bytes).
    pub nonce: [u8; 12],
    /// Encrypted serialized TokenClaims + 16-byte GCM tag.
    pub ciphertext: Vec<u8>,
}

/// Token with encrypted claims — used for wire transmission.
/// Claims are AES-256-GCM encrypted so they are never plaintext on the wire.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedToken {
    pub header: TokenHeader,
    /// JWE-encrypted claims (AES-256-GCM).
    pub encrypted_claims: EncryptedClaims,
    #[serde(with = "byte_array_64")]
    pub ratchet_tag: [u8; 64],
    #[serde(with = "byte_array_64")]
    pub frost_signature: [u8; 64],
    pub pq_signature: Vec<u8>,
}

/// Custom Debug for EncryptedToken — redacts everything sensitive.
impl std::fmt::Debug for EncryptedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedToken")
            .field("header", &self.header)
            .field("encrypted_claims", &"[ENCRYPTED]")
            .field("ratchet_tag", &"[REDACTED]")
            .field("frost_signature", &"[REDACTED]")
            .field("pq_signature", &"[REDACTED]")
            .finish()
    }
}

/// Zeroize cryptographic material on drop — prevents memory forensics.
impl Drop for EncryptedToken {
    fn drop(&mut self) {
        self.ratchet_tag.zeroize();
        self.frost_signature.zeroize();
        self.pq_signature.zeroize();
        self.encrypted_claims.ciphertext.zeroize();
    }
}

// ── Receipt (spec Section 6) ──────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub ceremony_session_id: [u8; 32],
    pub step_id: u8,
    #[serde(with = "byte_array_64")]
    pub prev_receipt_hash: [u8; 64],
    pub user_id: Uuid,
    #[serde(with = "byte_array_64")]
    pub dpop_key_hash: [u8; 64],
    pub timestamp: i64,
    pub nonce: [u8; 32],
    pub signature: Vec<u8>,
    pub ttl_seconds: u8,
}

/// Custom Debug for Receipt — redacts cryptographic material.
impl std::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receipt")
            .field("ceremony_session_id", &"[REDACTED]")
            .field("step_id", &self.step_id)
            .field("prev_receipt_hash", &"[REDACTED]")
            .field("user_id", &self.user_id)
            .field("dpop_key_hash", &"[REDACTED]")
            .field("timestamp", &self.timestamp)
            .field("nonce", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish()
    }
}

/// Zeroize the signature on drop.
impl Drop for Receipt {
    fn drop(&mut self) {
        self.signature.zeroize();
    }
}

impl Receipt {
    /// Returns a deterministic fixture with an INVALID signature for tests.
    ///
    /// **WARNING**: The `signature` field contains dummy bytes (`0x04`).
    /// It is NOT a real cryptographic signature. This fixture MUST NOT be
    /// used to test signature verification or any security property that
    /// depends on signature correctness. Use it only for serialization,
    /// structural, and receipt-chain tests (which re-sign after construction).
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_fixture_unsigned() -> Self {
        Receipt {
            ceremony_session_id: [0x01; 32],
            step_id: 1,
            prev_receipt_hash: [0x00; 64],
            user_id: Uuid::nil(),
            dpop_key_hash: [0x02; 64],
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
    Admin = 10,
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
    RecoveryCodeUsed,
    RecoveryCodesGenerated,
    UserDeleted,
    /// Admin RBAC: insufficient role for requested operation.
    AdminRbacDenied,
    /// Admin RBAC: role-based access granted.
    AdminRbacGranted,
    /// Cross-domain transfer decision (allowed or denied).
    CrossDomainDecision,
    /// Destructive admin action submitted for multi-person ceremony.
    AdminCeremonyRequired,
    /// DPoP proof replay detected.
    DpopReplayDetected,
    /// Super admin access attempt (logged BEFORE auth, hash-chained, BFT-replicated).
    /// Includes both granted and denied attempts.
    SuperAdminAccess,
    /// Super admin table modification (INSERT during setup, DELETE for decommission).
    SuperAdminTableChange,
    /// New super admin created via unanimous ceremony.
    SuperAdminCeremonyCreate,
    /// FIPS mode toggled via admin panel.
    FipsModeToggle,
    /// Error level changed via admin panel.
    ErrorLevelChange,
}

// ── AuditEntry ────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub event_id: Uuid,
    pub event_type: AuditEventType,
    pub user_ids: Vec<Uuid>,
    pub device_ids: Vec<Uuid>,
    pub ceremony_receipts: Vec<Receipt>,
    pub risk_score: f64,
    pub timestamp: i64,
    #[serde(with = "byte_array_64")]
    pub prev_hash: [u8; 64],
    pub signature: Vec<u8>,
    /// Classification level of this audit entry for MAC enforcement.
    /// Default: 0 (Unclassified) for backward compatibility.
    #[serde(default)]
    pub classification: u8,
    /// Correlation ID linking related audit events across the request lifecycle.
    /// Threads through gateway -> orchestrator -> OPAQUE -> TSS for a single auth flow.
    #[serde(default)]
    pub correlation_id: Option<Uuid>,
    /// Distributed trace ID for observability integration (OpenTelemetry compatible).
    #[serde(default)]
    pub trace_id: Option<String>,
    /// Source IP address of the request that triggered this audit event.
    /// Populated by the gateway/orchestrator from the inbound connection.
    #[serde(default)]
    pub source_ip: Option<String>,
    /// Session ID associated with the authentication ceremony.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Unique request ID for tracing individual requests through the pipeline.
    #[serde(default)]
    pub request_id: Option<String>,
    /// User-Agent header from the originating HTTP request.
    #[serde(default)]
    pub user_agent: Option<String>,
}

/// Custom Debug for AuditEntry — redacts cryptographic material.
impl std::fmt::Debug for AuditEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditEntry")
            .field("event_id", &self.event_id)
            .field("event_type", &self.event_type)
            .field("user_ids", &self.user_ids)
            .field("device_ids", &self.device_ids)
            .field("ceremony_receipts", &self.ceremony_receipts)
            .field("risk_score", &self.risk_score)
            .field("timestamp", &self.timestamp)
            .field("prev_hash", &"[REDACTED]")
            .field("signature", &"[REDACTED]")
            .field("classification", &self.classification)
            .field("correlation_id", &self.correlation_id)
            .field("trace_id", &self.trace_id)
            .field("source_ip", &self.source_ip)
            .field("session_id", &self.session_id)
            .field("request_id", &self.request_id)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

// ── ShardMessage (spec Section 11) ────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct ShardMessage {
    pub version: u8,
    pub sender_module: ModuleId,
    pub sequence: u64,
    pub timestamp: i64,
    pub payload: Vec<u8>,
    #[serde(with = "byte_array_64")]
    pub hmac: [u8; 64],
}

/// Custom Debug for ShardMessage — redacts payload and HMAC.
impl std::fmt::Debug for ShardMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardMessage")
            .field("version", &self.version)
            .field("sender_module", &self.sender_module)
            .field("sequence", &self.sequence)
            .field("timestamp", &self.timestamp)
            .field("payload", &"[REDACTED]")
            .field("hmac", &"[REDACTED]")
            .finish()
    }
}

// ── Recovery codes ────────────────────────────────────────────────────

/// A recovery code stored in the database (hash only, never plaintext)
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredRecoveryCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: Vec<u8>,
    pub code_salt: Vec<u8>,
    pub is_used: bool,
    pub used_at: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Custom Debug for StoredRecoveryCode — redacts cryptographic material.
impl std::fmt::Debug for StoredRecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredRecoveryCode")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("code_hash", &"[REDACTED]")
            .field("code_salt", &"[REDACTED]")
            .field("is_used", &self.is_used)
            .field("used_at", &self.used_at)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
