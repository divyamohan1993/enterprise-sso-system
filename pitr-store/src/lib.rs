//! Point-in-time recovery (J18).
//!
//! Architecture + state machine for continuous WAL archive to S3-compatible
//! object storage and roll-forward replay to a target timestamp. The actual
//! WAL streaming hooks into PostgreSQL via `pg_basebackup`/`archive_command`;
//! this crate models the recovery plan and exposes the procedure as code so
//! the runbook is testable.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PitrError {
    #[error("base backup not found")]
    NoBaseBackup,
    #[error("target {0} predates earliest WAL {1}")]
    TargetTooOld(i64, i64),
    #[error("target {0} exceeds latest WAL {1}")]
    TargetTooNew(i64, i64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseBackup {
    pub backup_id: String,
    pub taken_at: i64,
    pub object_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalSegment {
    pub lsn: String,
    pub start_ts: i64,
    pub end_ts: i64,
    pub object_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    pub base: BaseBackup,
    pub segments: Vec<WalSegment>,
    pub target_ts: i64,
}

pub fn plan_recovery(
    bases: &[BaseBackup],
    wals: &[WalSegment],
    target_ts: i64,
) -> Result<RecoveryPlan, PitrError> {
    let base = bases
        .iter()
        .filter(|b| b.taken_at <= target_ts)
        .max_by_key(|b| b.taken_at)
        .ok_or(PitrError::NoBaseBackup)?
        .clone();

    let earliest = wals.iter().map(|w| w.start_ts).min().unwrap_or(i64::MAX);
    let latest = wals.iter().map(|w| w.end_ts).max().unwrap_or(0);
    if target_ts < earliest { return Err(PitrError::TargetTooOld(target_ts, earliest)); }
    if target_ts > latest { return Err(PitrError::TargetTooNew(target_ts, latest)); }

    let mut segs: Vec<WalSegment> = wals
        .iter()
        .filter(|w| w.end_ts >= base.taken_at && w.start_ts <= target_ts)
        .cloned()
        .collect();
    segs.sort_by_key(|s| s.start_ts);

    Ok(RecoveryPlan { base, segments: segs, target_ts })
}
