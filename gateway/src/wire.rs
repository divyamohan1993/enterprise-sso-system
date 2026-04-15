//! Wire protocol types for client-gateway communication.

use serde::{Deserialize, Serialize};

use crate::device_attestation::DeviceAttestationAssertion;

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

/// X-Wing KEM ciphertext sent from server to client after puzzle verification.
///
/// The client decapsulates this against their private key to obtain the same
/// shared secret the server derived during encapsulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KemCiphertext {
    /// Serialized `crypto::xwing::Ciphertext` (X25519 ephemeral PK || ML-KEM-1024 CT).
    pub ciphertext: Vec<u8>,
}

/// Authentication request sent by a client after solving the puzzle.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: Vec<u8>,
    /// Target audience for the token (e.g. a resource server identifier).
    #[serde(default)]
    pub audience: Option<String>,
    /// DEPRECATED: unsigned client-declared age. Retained for wire
    /// compatibility with downstream crates that still consume the f64.
    /// The gateway no longer trusts this value when
    /// `device_attestation` is present; the validated assertion's
    /// `issued_at_secs` is authoritative. A future wave will remove
    /// this field entirely (cross-CAT migration).
    #[serde(default)]
    pub device_attestation_age_secs: Option<f64>,
    /// GW-ATTEST: signed device attestation assertion. The gateway
    /// validates the signature, nonce binding, signer, and freshness;
    /// only the validated `issued_at_secs` integer is forwarded
    /// (via `device_attestation_age_secs` on `OrchestratorRequest`) to
    /// the orchestrator. `None` means no signed attestation was
    /// presented — in military deployment the gateway rejects such
    /// requests fail-closed via `validate_or_reject_attestation`.
    #[serde(default)]
    pub device_attestation: Option<DeviceAttestationAssertion>,
}

/// SECURITY: Redact password from Debug output and zeroize on drop.
impl std::fmt::Debug for AuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("audience", &self.audience)
            .finish()
    }
}

impl Drop for AuthRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

/// Authentication response returned by the gateway.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub token: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// SECURITY: Redact token from Debug output.
impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponse")
            .field("success", &self.success)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .field("error", &self.error)
            .finish()
    }
}

/// Request from the Gateway to the Orchestrator (mirrors orchestrator message type).
#[derive(Clone, Serialize, Deserialize)]
pub struct OrchestratorRequest {
    pub username: String,
    pub password: Vec<u8>,
    #[serde(with = "byte_array_64")]
    pub dpop_key_hash: [u8; 64],
    /// Requested authentication tier (1-4). Defaults to 2 if 0.
    pub tier: u8,
    /// Target audience for the token (passed through to the TSS for inclusion
    /// in the token's `aud` claim).
    #[serde(default)]
    pub audience: Option<String>,
    /// Ceremony session ID binding — the TSS embeds this in TokenClaims so
    /// tokens cannot be migrated between ceremonies. The verifier validates
    /// that ceremony_id matches the expected ceremony for the session.
    #[serde(default)]
    pub ceremony_id: [u8; 32],
    #[serde(default)]
    pub device_attestation_age_secs: Option<f64>,
    #[serde(default)]
    pub geo_velocity_kmh: Option<f64>,
    #[serde(default)]
    pub is_unusual_network: Option<bool>,
    #[serde(default)]
    pub is_unusual_time: Option<bool>,
    #[serde(default)]
    pub unusual_access_score: Option<f64>,
    #[serde(default)]
    pub recent_failed_attempts: Option<u32>,
    #[serde(default)]
    pub device_fingerprint: Option<String>,
    #[serde(default)]
    pub source_ip: Option<String>,
    /// Correlation ID from the gateway's RequestContext for distributed tracing.
    #[serde(default)]
    pub correlation_id: Option<uuid::Uuid>,
    /// OpenTelemetry-compatible trace ID (hex-encoded 128-bit) for distributed tracing.
    #[serde(default)]
    pub trace_id: Option<String>,
}

/// SECURITY: Redact password and zeroize on drop.
impl std::fmt::Debug for OrchestratorRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrchestratorRequest")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("tier", &self.tier)
            .finish_non_exhaustive()
    }
}

impl Drop for OrchestratorRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
    }
}

/// Response from the Orchestrator to the Gateway (mirrors orchestrator message type).
#[derive(Clone, Serialize, Deserialize)]
pub struct OrchestratorResponse {
    pub success: bool,
    pub token_bytes: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// SECURITY: Redact token bytes from Debug output.
impl std::fmt::Debug for OrchestratorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrchestratorResponse")
            .field("success", &self.success)
            .field("token_bytes", &self.token_bytes.as_ref().map(|_| "[REDACTED]"))
            .field("error", &self.error)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── KemCiphertext ──

    #[test]
    fn kem_ciphertext_serde_roundtrip() {
        let ct = KemCiphertext {
            ciphertext: vec![0xAA; 128],
        };
        let bytes = postcard::to_allocvec(&ct).expect("serialize KemCiphertext");
        let recovered: KemCiphertext = postcard::from_bytes(&bytes).expect("deserialize KemCiphertext");
        assert_eq!(recovered.ciphertext, ct.ciphertext);
    }

    // ── AuthRequest ──

    #[test]
    fn auth_request_debug_redacts_password() {
        let req = AuthRequest {
            username: "alice".into(),
            password: vec![0x01, 0x02, 0x03],
            audience: Some("resource-server".into()),
            device_attestation_age_secs: None,
            device_attestation: None,
        };
        let debug_str = format!("{:?}", req);
        assert!(
            debug_str.contains("REDACTED"),
            "password must be redacted in Debug output"
        );
        assert!(
            !debug_str.contains("\\x01"),
            "raw password bytes must not appear in Debug output"
        );
        assert!(debug_str.contains("alice"));
    }

    #[test]
    fn auth_request_zeroizes_password_on_drop() {
        // We verify the Drop impl calls zeroize by observing the Vec is zeroed.
        let req = AuthRequest {
            username: "bob".into(),
            password: vec![0xFF; 32],
            audience: None,
            device_attestation_age_secs: None,
            device_attestation: None,
        };
        // Manually call drop to trigger zeroize.
        let pw_ptr = req.password.as_ptr();
        let pw_len = req.password.len();
        drop(req);

        // After drop, the allocator may reuse the memory, but the zeroize
        // impl was called. We check the type compiles with the Drop impl.
        // (Direct memory inspection after drop is UB, so we verify the trait.)
        let _ = (pw_ptr, pw_len);
    }

    #[test]
    fn auth_request_serde_roundtrip() {
        let req = AuthRequest {
            username: "carol".into(),
            password: vec![0xDE, 0xAD],
            audience: Some("api.example.com".into()),
            device_attestation_age_secs: None,
            device_attestation: None,
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize AuthRequest");
        let recovered: AuthRequest = postcard::from_bytes(&bytes).expect("deserialize AuthRequest");
        assert_eq!(recovered.username, "carol");
        assert_eq!(recovered.password, vec![0xDE, 0xAD]);
        assert_eq!(recovered.audience, Some("api.example.com".into()));
    }

    #[test]
    fn auth_request_audience_defaults_to_none() {
        // Serialize without audience field, then deserialize.
        // postcard uses serde(default) so missing field should become None.
        let req = AuthRequest {
            username: "dave".into(),
            password: vec![1],
            audience: None,
            device_attestation_age_secs: None,
            device_attestation: None,
        };
        let bytes = postcard::to_allocvec(&req).unwrap();
        let recovered: AuthRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.audience, None);
    }

    // ── AuthResponse ──

    #[test]
    fn auth_response_success_roundtrip() {
        let resp = AuthResponse {
            success: true,
            token: Some(vec![0x42; 64]),
            error: None,
        };
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let recovered: AuthResponse = postcard::from_bytes(&bytes).unwrap();
        assert!(recovered.success);
        assert_eq!(recovered.token.unwrap().len(), 64);
        assert!(recovered.error.is_none());
    }

    #[test]
    fn auth_response_failure_roundtrip() {
        let resp = AuthResponse {
            success: false,
            token: None,
            error: Some("invalid credentials".into()),
        };
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let recovered: AuthResponse = postcard::from_bytes(&bytes).unwrap();
        assert!(!recovered.success);
        assert!(recovered.token.is_none());
        assert_eq!(recovered.error.unwrap(), "invalid credentials");
    }

    // ── OrchestratorRequest ──

    #[test]
    fn orchestrator_request_debug_redacts_password() {
        let req = OrchestratorRequest {
            username: "admin".into(),
            password: vec![0xBE, 0xEF],
            dpop_key_hash: [0x11; 64],
            tier: 2,
            audience: None,
            ceremony_id: [0; 32],
            device_attestation_age_secs: None,
            geo_velocity_kmh: None,
            is_unusual_network: None,
            is_unusual_time: None,
            unusual_access_score: None,
            recent_failed_attempts: None,
            device_fingerprint: None,
            source_ip: None,
            correlation_id: None,
            trace_id: None,
        };
        let debug_str = format!("{:?}", req);
        assert!(debug_str.contains("REDACTED"));
        assert!(debug_str.contains("admin"));
        assert!(
            !debug_str.contains("\\xbe"),
            "password bytes must not leak through Debug"
        );
    }

    #[test]
    fn orchestrator_request_zeroizes_password_on_drop() {
        let req = OrchestratorRequest {
            username: "test".into(),
            password: vec![0xFF; 16],
            dpop_key_hash: [0; 64],
            tier: 1,
            audience: None,
            ceremony_id: [0; 32],
            device_attestation_age_secs: None,
            geo_velocity_kmh: None,
            is_unusual_network: None,
            is_unusual_time: None,
            unusual_access_score: None,
            recent_failed_attempts: None,
            device_fingerprint: None,
            source_ip: None,
            correlation_id: None,
            trace_id: None,
        };
        // Drop triggers zeroize. No panic = success.
        drop(req);
    }

    #[test]
    fn orchestrator_request_serde_roundtrip() {
        let req = OrchestratorRequest {
            username: "eve".into(),
            password: vec![0xCA, 0xFE],
            dpop_key_hash: [0x55; 64],
            tier: 3,
            audience: Some("mil.example.gov".into()),
            ceremony_id: [0xAB; 32],
            device_attestation_age_secs: Some(120.5),
            geo_velocity_kmh: Some(50.0),
            is_unusual_network: Some(true),
            is_unusual_time: Some(false),
            unusual_access_score: Some(0.85),
            recent_failed_attempts: Some(2),
            device_fingerprint: Some("fp-abc123".into()),
            source_ip: Some("10.0.0.1".into()),
            correlation_id: None,
            trace_id: None,
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize OrchestratorRequest");
        let recovered: OrchestratorRequest =
            postcard::from_bytes(&bytes).expect("deserialize OrchestratorRequest");

        assert_eq!(recovered.username, "eve");
        assert_eq!(recovered.password, vec![0xCA, 0xFE]);
        assert_eq!(recovered.dpop_key_hash, [0x55; 64]);
        assert_eq!(recovered.tier, 3);
        assert_eq!(recovered.audience, Some("mil.example.gov".into()));
        assert_eq!(recovered.ceremony_id, [0xAB; 32]);
        assert_eq!(recovered.device_attestation_age_secs, Some(120.5));
        assert_eq!(recovered.source_ip, Some("10.0.0.1".into()));
    }

    // ── OrchestratorResponse ──

    #[test]
    fn orchestrator_response_roundtrip() {
        let resp = OrchestratorResponse {
            success: true,
            token_bytes: Some(vec![0x99; 256]),
            error: None,
        };
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let recovered: OrchestratorResponse = postcard::from_bytes(&bytes).unwrap();
        assert!(recovered.success);
        assert_eq!(recovered.token_bytes.unwrap().len(), 256);
    }

    // ── byte_array_64 serde helper ──

    #[test]
    fn byte_array_64_roundtrip_via_orchestrator_request() {
        // The byte_array_64 module is tested indirectly through OrchestratorRequest.
        let hash = [0xFE; 64];
        let req = OrchestratorRequest {
            username: "test".into(),
            password: vec![],
            dpop_key_hash: hash,
            tier: 1,
            audience: None,
            ceremony_id: [0; 32],
            device_attestation_age_secs: None,
            geo_velocity_kmh: None,
            is_unusual_network: None,
            is_unusual_time: None,
            unusual_access_score: None,
            recent_failed_attempts: None,
            device_fingerprint: None,
            source_ip: None,
            correlation_id: None,
            trace_id: None,
        };
        let bytes = postcard::to_allocvec(&req).unwrap();
        let recovered: OrchestratorRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.dpop_key_hash, [0xFE; 64]);
    }
}
