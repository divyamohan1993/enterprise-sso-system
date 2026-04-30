//! SMS + push MFA providers (J10).
//!
//! `MfaProvider` is the abstraction; `TwilioSmsProvider` is the production
//! adapter for SMS. Push delivery is an interface only — concrete adapters
//! (APNS/FCM) live behind a feature flag once the platform certs are
//! provisioned.
//!
//! ## SMS policy gate
//!
//! SMS is the cheapest factor to subvert (SIM swap, SS7, eSIM transfer).
//! On a Pentagon-grade SSO, SMS MUST NOT be the deciding factor for
//! anything except low-risk / low-assurance contexts. [`SmsPolicy::evaluate`]
//! is the single chokepoint that any caller wishing to send an SMS-MFA
//! message must pass first; it hard-rejects when the user has a hardware
//! authenticator (FIDO2/WebAuthn or a smartcard) enrolled, or when the
//! current risk tier is anything stronger than `Normal`.
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
    /// SMS MFA is policy-blocked for this user / risk context.
    #[error("SMS MFA policy-blocked: {0}")]
    PolicyBlocked(&'static str),
}

/// Risk tier feeding the SMS policy gate. Mirrors `risk::RiskLevel` so
/// downstream callers can convert without taking a dep on the risk crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskTierForSms {
    Normal,
    Elevated,
    High,
    Critical,
}

/// Per-user enrolment context fed into the SMS policy gate.
#[derive(Debug, Clone, Copy)]
pub struct SmsPolicyContext {
    /// True if the user has at least one usable FIDO2/WebAuthn or smartcard
    /// (CAC/PIV) credential. SMS is denied whenever a hardware factor is
    /// available, because allowing the SMS fallback would silently downgrade
    /// the user's effective AAL to the weakest enrolled factor.
    pub has_hardware_factor: bool,
    /// Current risk tier from the risk-scoring engine.
    pub risk: RiskTierForSms,
    /// Caller-determined assurance level requirement: if true, SMS is
    /// rejected unconditionally.
    pub require_high_assurance: bool,
}

/// Single chokepoint for the SMS-MFA policy decision. Always fail-closed —
/// caller must present an `Allow` before sending an SMS.
pub enum SmsPolicy {
    /// SMS allowed for this context.
    Allow,
    /// SMS rejected; caller must present a hardware factor instead.
    Deny(&'static str),
}

impl SmsPolicy {
    /// Evaluate the policy against the supplied context.
    pub fn evaluate(ctx: SmsPolicyContext) -> Self {
        if ctx.require_high_assurance {
            return SmsPolicy::Deny("SMS denied: high-assurance context — present hardware factor");
        }
        if ctx.has_hardware_factor {
            return SmsPolicy::Deny("SMS denied: hardware factor enrolled — SMS would downgrade AAL");
        }
        match ctx.risk {
            RiskTierForSms::Normal => SmsPolicy::Allow,
            RiskTierForSms::Elevated
            | RiskTierForSms::High
            | RiskTierForSms::Critical => SmsPolicy::Deny(
                "SMS denied: risk tier above Normal — present hardware factor",
            ),
        }
    }

    pub fn allowed(&self) -> bool {
        matches!(self, SmsPolicy::Allow)
    }
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

    /// Send an SMS only if the policy gate authorises it.
    pub async fn send_with_policy(
        &self,
        ctx: SmsPolicyContext,
        msg: &MfaMessage,
    ) -> Result<String, MfaError> {
        match SmsPolicy::evaluate(ctx) {
            SmsPolicy::Allow => self.send(msg).await,
            SmsPolicy::Deny(reason) => Err(MfaError::PolicyBlocked(reason)),
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
/// `--features apns,fcm` once platform certificates are provisioned. The
/// shared logic for number-matching anti-fatigue is implemented here so
/// future adapters share a single, audited primitive.
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

/// Per-request number-matching challenge for push MFA. The user enrols
/// the matching N-digit code into their push notification UI; if the
/// digits typed at the verifier do not match, the push is rejected.
#[derive(Debug, Clone)]
pub struct NumberMatchChallenge {
    pub digits: String,
    pub challenge_id: [u8; 32],
    pub expires_at: i64,
}

pub const PUSH_NUMBER_MATCH_DIGITS: usize = 2;

/// Build a fresh number-match challenge.
pub fn new_number_match_challenge(now_unix: i64) -> Result<NumberMatchChallenge, MfaError> {
    let mut buf = [0u8; PUSH_NUMBER_MATCH_DIGITS];
    getrandom::getrandom(&mut buf).map_err(|e| MfaError::Transport(e.to_string()))?;
    let digits: String = buf.iter().map(|b| ((*b % 10) + b'0') as char).collect();
    let mut id = [0u8; 32];
    getrandom::getrandom(&mut id).map_err(|e| MfaError::Transport(e.to_string()))?;
    Ok(NumberMatchChallenge {
        digits,
        challenge_id: id,
        expires_at: now_unix + 60,
    })
}

/// Constant-time verify of a typed digit string against a challenge.
pub fn verify_number_match(
    challenge: &NumberMatchChallenge,
    typed: &str,
    now_unix: i64,
) -> bool {
    if now_unix > challenge.expires_at {
        return false;
    }
    if typed.len() != challenge.digits.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    typed
        .as_bytes()
        .ct_eq(challenge.digits.as_bytes())
        .unwrap_u8()
        == 1
}

#[cfg(test)]
mod number_match_tests {
    use super::*;

    #[test]
    fn fresh_challenge_has_correct_digit_count_and_unexpired() {
        let now = 1_000_000;
        let c = new_number_match_challenge(now).unwrap();
        assert_eq!(c.digits.len(), PUSH_NUMBER_MATCH_DIGITS);
        assert!(c.digits.bytes().all(|b| (b'0'..=b'9').contains(&b)));
        assert!(c.expires_at > now);
        assert_ne!(c.challenge_id, [0u8; 32]);
    }

    #[test]
    fn correct_digits_verify() {
        let now = 1_000_000;
        let c = new_number_match_challenge(now).unwrap();
        let typed = c.digits.clone();
        assert!(verify_number_match(&c, &typed, now));
    }

    #[test]
    fn wrong_digits_rejected() {
        let now = 1_000_000;
        let c = new_number_match_challenge(now).unwrap();
        let typed: String = c
            .digits
            .chars()
            .map(|d| {
                let n = d.to_digit(10).unwrap();
                std::char::from_digit((n + 5) % 10, 10).unwrap()
            })
            .collect();
        assert_ne!(typed, c.digits);
        assert!(!verify_number_match(&c, &typed, now));
    }

    #[test]
    fn expired_rejected() {
        let now = 1_000_000;
        let c = new_number_match_challenge(now).unwrap();
        let typed = c.digits.clone();
        assert!(!verify_number_match(&c, &typed, now + 120));
    }

    #[test]
    fn wrong_length_rejected() {
        let now = 1_000_000;
        let c = new_number_match_challenge(now).unwrap();
        assert!(!verify_number_match(&c, "1", now));
        assert!(!verify_number_match(&c, "12345", now));
    }
}
