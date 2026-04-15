//! MDM device compliance feed (J11).
//!
//! Polls Intune / Jamf / Workspace ONE on a fixed cadence and produces
//! `DevicePosture` events that are pushed into the existing common posture
//! store via the supplied sink callback.
#![forbid(unsafe_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MdmError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("auth: {0}")]
    Auth(String),
    #[error("parse: {0}")]
    Parse(String),
    /// Adapter is not implemented in this build. CAT-I fail-closed rule:
    /// callers MUST treat this as DENY for Tier 1 (Sovereign) classification.
    #[error("not implemented: {adapter}")]
    NotImplemented { adapter: &'static str },
}

/// CAT-I fail-closed helper: map an MDM fetch result to a policy decision
/// for high-assurance tiers. A `NotImplemented` or any other error MUST
/// deny access at Tier 1 (Sovereign). Unknown posture is never "allow".
///
/// Consumers in `common::conditional_access` should call this when they
/// consume an MDM result on the authorization path.
pub fn fail_closed_for_tier1<T>(result: &Result<T, MdmError>) -> bool {
    // Returns true iff access should be DENIED.
    result.is_err()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceState {
    Compliant,
    NonCompliant,
    Unknown,
    InGracePeriod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePosture {
    pub device_id: String,
    pub user_principal: Option<String>,
    pub state: ComplianceState,
    pub os: String,
    pub last_check_in: i64,
    pub source: String,
}

#[async_trait]
pub trait MdmAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    async fn fetch(&self) -> Result<Vec<DevicePosture>, MdmError>;
}

pub struct IntuneAdapter {
    pub tenant_id: String,
    pub client_id: String,
    pub client_secret: String,
    pub http: reqwest::Client,
}

#[async_trait]
impl MdmAdapter for IntuneAdapter {
    fn name(&self) -> &'static str { "intune" }
    async fn fetch(&self) -> Result<Vec<DevicePosture>, MdmError> {
        // CAT-I: Real Graph API integration is not implemented in this build.
        // Fail closed — do NOT return an empty vec (which would be read as
        // "no non-compliant devices"). Callers on the authorization path
        // must treat this as DENY for Tier 1.
        Err(MdmError::NotImplemented { adapter: "intune" })
    }
}

pub struct JamfAdapter {
    pub base_url: String,
    pub bearer: String,
    pub http: reqwest::Client,
}

#[async_trait]
impl MdmAdapter for JamfAdapter {
    fn name(&self) -> &'static str { "jamf" }
    async fn fetch(&self) -> Result<Vec<DevicePosture>, MdmError> {
        // CAT-I: fail-closed stub. See IntuneAdapter::fetch for rationale.
        Err(MdmError::NotImplemented { adapter: "jamf" })
    }
}

pub struct WorkspaceOneAdapter {
    pub base_url: String,
    pub api_key: String,
    pub http: reqwest::Client,
}

#[async_trait]
impl MdmAdapter for WorkspaceOneAdapter {
    fn name(&self) -> &'static str { "workspaceone" }
    async fn fetch(&self) -> Result<Vec<DevicePosture>, MdmError> {
        // CAT-I: fail-closed stub. See IntuneAdapter::fetch for rationale.
        Err(MdmError::NotImplemented { adapter: "workspaceone" })
    }
}

pub async fn poll_loop<F>(
    adapters: Vec<Box<dyn MdmAdapter>>,
    interval: Duration,
    mut sink: F,
) where
    F: FnMut(DevicePosture) + Send,
{
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        for a in &adapters {
            match a.fetch().await {
                Ok(list) => for p in list { sink(p); },
                Err(e) => tracing::warn!(adapter = a.name(), error = %e, "mdm poll failed"),
            }
        }
    }
}
