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
    pub fn new(iss: &str, aud: &str, sub: &str, sid: &str) -> Self {
        Self {
            iss: iss.into(),
            aud: aud.into(),
            sub: sub.into(),
            iat: chrono_now(),
            jti: Uuid::new_v4().to_string(),
            sid: sid.into(),
            events: serde_json::json!({
                "http://schemas.openid.net/event/backchannel-logout": {}
            }),
        }
    }
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
pub async fn fan_out(
    client: &reqwest::Client,
    rps: &[RpEndpoint],
    token: &str,
    max_attempts: u32,
) -> Vec<DeliveryResult> {
    let mut futs = Vec::with_capacity(rps.len());
    for rp in rps {
        futs.push(deliver(client, rp, token, max_attempts));
    }
    let mut out = Vec::with_capacity(futs.len());
    for f in futs {
        out.push(f.await);
    }
    out
}
