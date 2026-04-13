//! SMS + push MFA providers (J10).
//!
//! `MfaProvider` is the abstraction; `TwilioSmsProvider` is the production
//! adapter for SMS. Push delivery is an interface only — concrete adapters
//! (APNS/FCM) live behind a feature flag once the platform certs are
//! provisioned.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MfaError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("rate-limited; retry after {0}s")]
    RateLimited(u64),
    #[error("provider rejected: {0}")]
    Rejected(String),
}

#[derive(Debug, Clone, Copy)]
pub enum Channel {
    Sms,
    Push,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaMessage {
    pub destination: String,
    pub body: String,
}

#[async_trait]
pub trait MfaProvider: Send + Sync {
    fn channel(&self) -> Channel;
    async fn send(&self, msg: &MfaMessage) -> Result<String, MfaError>;
}

pub struct TwilioSmsProvider {
    pub account_sid: String,
    pub auth_token: String,
    pub from: String,
    pub http: reqwest::Client,
}

impl TwilioSmsProvider {
    pub fn new(account_sid: String, auth_token: String, from: String) -> Self {
        Self {
            account_sid,
            auth_token,
            from,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait]
impl MfaProvider for TwilioSmsProvider {
    fn channel(&self) -> Channel { Channel::Sms }

    async fn send(&self, msg: &MfaMessage) -> Result<String, MfaError> {
        let url = format!("https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json", self.account_sid);
        let basic = STANDARD.encode(format!("{}:{}", self.account_sid, self.auth_token));
        let resp = self.http
            .post(&url)
            .header("Authorization", format!("Basic {}", basic))
            .form(&[("To", &msg.destination), ("From", &self.from), ("Body", &msg.body)])
            .send()
            .await
            .map_err(|e| MfaError::Transport(e.to_string()))?;
        if resp.status() == 429 {
            return Err(MfaError::RateLimited(60));
        }
        if !resp.status().is_success() {
            return Err(MfaError::Rejected(format!("HTTP {}", resp.status())));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| MfaError::Transport(e.to_string()))?;
        Ok(body.get("sid").and_then(|s| s.as_str()).unwrap_or("").to_string())
    }
}

/// Generic push provider interface — concrete APNS/FCM adapters land behind
/// `--features apns,fcm` once platform certificates are provisioned.
pub struct PushProvider {
    pub vendor: String,
}

#[async_trait]
impl MfaProvider for PushProvider {
    fn channel(&self) -> Channel { Channel::Push }
    async fn send(&self, _msg: &MfaMessage) -> Result<String, MfaError> {
        Err(MfaError::Rejected(format!(
            "push vendor `{}` not yet wired — gated behind apns/fcm features",
            self.vendor
        )))
    }
}
