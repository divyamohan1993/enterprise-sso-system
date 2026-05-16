//! OIDC Back-Channel Logout 1.0 (J5).
//!
//! Builds a `logout_token` JWT and POSTs it to every relying-party logout
//! endpoint registered for an SSO session, with bounded retry + backoff.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum LogoutError {
    #[error("http: {0}")]
    Http(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("invalid backchannel_logout_uri: {0}")]
    InvalidUri(String),
}

/// Validate that a back-channel logout URI is safe to POST a signed logout
/// token to.
///
/// SECURITY: the logout token carries `iss/aud/sub/sid/jti` and proves an
/// authenticated logout event. It MUST NOT be transmitted in cleartext. We
/// reject anything that is not `https://`, anything embedding userinfo
/// (`user:pass@host`, an open-redirect / credential-leak vector), and any
/// URI with a fragment. A misconfigured or attacker-poisoned RP entry
/// beginning with `http://` would otherwise leak the token on-path.
fn validate_logout_uri(uri: &str) -> Result<(), LogoutError> {
    // Scheme must be exactly `https` (case-insensitive per RFC 3986 §3.1).
    let rest = match uri.split_once("://") {
        Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
        _ => {
            return Err(LogoutError::InvalidUri(
                "scheme must be https".into(),
            ));
        }
    };
    // Authority is everything up to the first '/', '?' or '#'.
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(LogoutError::InvalidUri("missing host".into()));
    }
    // Reject embedded userinfo (`user:pass@host`).
    if authority.contains('@') {
        return Err(LogoutError::InvalidUri(
            "userinfo is not permitted in a logout uri".into(),
        ));
    }
    // Reject fragments — a logout endpoint never has one and it can carry
    // injected state.
    if uri.contains('#') {
        return Err(LogoutError::InvalidUri(
            "fragment is not permitted in a logout uri".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub jti: String,
    pub sid: String,
    pub events: serde_json::Value,
}

impl LogoutTokenClaims {
    /// Build logout-token claims for the current instant.
    ///
    /// Fails if the system clock is set before the Unix epoch: a clock-rewind
    /// is itself a security-relevant incident (replay windows, cert validity
    /// drift). We surface it instead of fabricating a sentinel `iat = 0`,
    /// which would silently mint a 1970-dated token every compliant RP rejects.
    pub fn new(iss: &str, aud: &str, sub: &str, sid: &str) -> Result<Self, LogoutError> {
        Ok(Self {
            iss: iss.into(),
            aud: aud.into(),
            sub: sub.into(),
            iat: chrono_now()?,
            jti: Uuid::new_v4().to_string(),
            sid: sid.into(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
        })
    }
}

fn chrono_now() -> Result<i64, LogoutError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| {
            LogoutError::Encode(format!("system clock is before the Unix epoch: {e}"))
        })
}

#[derive(Debug, Clone)]
pub struct RpEndpoint {
    pub client_id: String,
    pub backchannel_logout_uri: String,
}

#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub client_id: String,
    pub success: bool,
    pub status: u16,
    pub error: Option<String>,
}

/// Encode the logout token as a signed compact JWS using the supplied signer.
pub fn encode_logout_token<F>(claims: &LogoutTokenClaims, sign: F) -> Result<String, LogoutError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
{
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header = serde_json::json!({"alg": "ML-DSA-65", "typ": "logout+jwt"});
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|e| LogoutError::Encode(e.to_string()))?);
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|e| LogoutError::Encode(e.to_string()))?);
    let signing_input = format!("{}.{}", h, p);
    let sig = sign(signing_input.as_bytes()).map_err(LogoutError::Encode)?;
    Ok(format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(sig)))
}

/// Deliver a logout token to a single RP with bounded retries.
pub async fn deliver(
    client: &reqwest::Client,
    rp: &RpEndpoint,
    logout_token: &str,
    max_attempts: u32,
) -> DeliveryResult {
    // SECURITY: validate the destination BEFORE the first send. A non-https
    // (or userinfo/fragment-bearing) URI is a permanent misconfiguration —
    // never POST the signed token to it and never retry.
    if let Err(e) = validate_logout_uri(&rp.backchannel_logout_uri) {
        return DeliveryResult {
            client_id: rp.client_id.clone(),
            success: false,
            status: 0,
            error: Some(e.to_string()),
        };
    }
    let mut delay = Duration::from_millis(250);
    for attempt in 0..max_attempts {
        let resp = client
            .post(&rp.backchannel_logout_uri)
            .form(&[("logout_token", logout_token)])
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        match resp {
            Ok(r) => {
                let s = r.status().as_u16();
                if (200..300).contains(&s) {
                    return DeliveryResult { client_id: rp.client_id.clone(), success: true, status: s, error: None };
                }
                if attempt + 1 == max_attempts {
                    return DeliveryResult { client_id: rp.client_id.clone(), success: false, status: s, error: Some("non-2xx".into()) };
                }
            }
            Err(e) => {
                if attempt + 1 == max_attempts {
                    return DeliveryResult { client_id: rp.client_id.clone(), success: false, status: 0, error: Some(e.to_string()) };
                }
            }
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(8));
    }
    DeliveryResult { client_id: rp.client_id.clone(), success: false, status: 0, error: Some("exhausted".into()) }
}

/// Fan out delivery to every RP in the set, returning per-RP results.
///
/// Deliveries run concurrently: a slow or dead RP cannot stall any other RP.
/// Wall-clock time is bounded by the slowest single RP's retry budget, not by
/// the sum across all RPs. Results are returned in the same order as `rps`.
pub async fn fan_out(
    client: &reqwest::Client,
    rps: &[RpEndpoint],
    token: &str,
    max_attempts: u32,
) -> Vec<DeliveryResult> {
    // `reqwest::Client` is internally an `Arc`, so cloning is cheap and shares
    // the connection pool. Spawn one task per RP so deliveries are concurrent.
    let mut handles = Vec::with_capacity(rps.len());
    for rp in rps {
        let client = client.clone();
        let rp = rp.clone();
        let token = token.to_owned();
        handles.push(tokio::spawn(async move {
            deliver(&client, &rp, &token, max_attempts).await
        }));
    }
    let mut out = Vec::with_capacity(handles.len());
    for (rp, handle) in rps.iter().zip(handles) {
        match handle.await {
            Ok(result) => out.push(result),
            // A panicked delivery task must not drop the RP from the report;
            // surface it as a failed delivery so the caller sees full coverage.
            Err(join_err) => out.push(DeliveryResult {
                client_id: rp.client_id.clone(),
                success: false,
                status: 0,
                error: Some(format!("delivery task failed: {join_err}")),
            }),
        }
    }
    out
}
