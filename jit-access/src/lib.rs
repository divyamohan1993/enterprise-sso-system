//! Just-in-time role elevation (J4).
//!
//! Users request short-lived role grants; an approver acks; the elevation
//! auto-expires. The store is in-memory + serializable so the binary can be
//! mounted behind an axum router or reused from tests without a DB.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum JitError {
    #[error("not found")]
    NotFound,
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("expired")]
    Expired,
    #[error("lock poisoned")]
    Poisoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElevationStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElevationRequest {
    pub id: Uuid,
    pub user_id: String,
    pub requested_role: String,
    pub justification: String,
    pub approver_id: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: ElevationStatus,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Default)]
pub struct JitStore {
    inner: Mutex<HashMap<Uuid, ElevationRequest>>,
}

impl JitStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(
        &self,
        user_id: impl Into<String>,
        role: impl Into<String>,
        justification: impl Into<String>,
        ttl: Duration,
    ) -> Result<ElevationRequest, JitError> {
        let id = Uuid::new_v4();
        let req = ElevationRequest {
            id,
            user_id: user_id.into(),
            requested_role: role.into(),
            justification: justification.into(),
            approver_id: None,
            created_at: now_secs(),
            expires_at: now_secs() + ttl.as_secs() as i64,
            status: ElevationStatus::Pending,
        };
        self.inner
            .lock()
            .map_err(|_| JitError::Poisoned)?
            .insert(id, req.clone());
        Ok(req)
    }

    pub fn approve(&self, id: Uuid, approver: impl Into<String>) -> Result<(), JitError> {
        let mut g = self.inner.lock().map_err(|_| JitError::Poisoned)?;
        let r = g.get_mut(&id).ok_or(JitError::NotFound)?;
        if r.status != ElevationStatus::Pending {
            return Err(JitError::InvalidState(format!("{:?}", r.status)));
        }
        r.approver_id = Some(approver.into());
        r.status = ElevationStatus::Approved;
        Ok(())
    }

    pub fn deny(&self, id: Uuid, approver: impl Into<String>) -> Result<(), JitError> {
        let mut g = self.inner.lock().map_err(|_| JitError::Poisoned)?;
        let r = g.get_mut(&id).ok_or(JitError::NotFound)?;
        if r.status != ElevationStatus::Pending {
            return Err(JitError::InvalidState(format!("{:?}", r.status)));
        }
        r.approver_id = Some(approver.into());
        r.status = ElevationStatus::Denied;
        Ok(())
    }

    pub fn revoke(&self, id: Uuid) -> Result<(), JitError> {
        let mut g = self.inner.lock().map_err(|_| JitError::Poisoned)?;
        let r = g.get_mut(&id).ok_or(JitError::NotFound)?;
        r.status = ElevationStatus::Revoked;
        Ok(())
    }

    pub fn list_for_user(&self, user_id: &str) -> Result<Vec<ElevationRequest>, JitError> {
        let g = self.inner.lock().map_err(|_| JitError::Poisoned)?;
        Ok(g.values().filter(|r| r.user_id == user_id).cloned().collect())
    }

    pub fn get(&self, id: Uuid) -> Result<ElevationRequest, JitError> {
        let g = self.inner.lock().map_err(|_| JitError::Poisoned)?;
        g.get(&id).cloned().ok_or(JitError::NotFound)
    }

    pub fn expire_pass(&self) -> Result<usize, JitError> {
        let n = now_secs();
        let mut g = self.inner.lock().map_err(|_| JitError::Poisoned)?;
        let mut count = 0;
        for r in g.values_mut() {
            if r.expires_at <= n
                && matches!(r.status, ElevationStatus::Pending | ElevationStatus::Approved)
            {
                r.status = ElevationStatus::Expired;
                count += 1;
            }
        }
        Ok(count)
    }
}

/// Spawn the auto-expiry sweeper task. Caller owns the JoinHandle.
pub fn spawn_expiry_sweeper(store: Arc<JitStore>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            if let Err(e) = store.expire_pass() {
                tracing::warn!(error = %e, "jit expiry sweeper failed");
            }
        }
    })
}
