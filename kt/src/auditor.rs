//! KT auditor — periodically verifies every persisted checkpoint in the
//! hash-chained log against the pinned 2-of-5 quorum verifying keys.
//!
//! Each entry in the checkpoint log is produced by [`publish_checkpoint`]
//! (see `consensus.rs`) and committed under a 2-of-5 ML-DSA-87 signature
//! set. The auditor re-validates every row on startup and on a periodic
//! timer so that any tamper to the on-disk log is detected out-of-band
//! from normal KT operations.
//!
//! Witness gossip is optional: when `MILNET_KT_WITNESSES` is set to a
//! comma-separated list of peer addresses, each newly-published checkpoint
//! is forwarded to them over mTLS by the publisher. The auditor here is
//! read-only — it does not speak the gossip protocol.

use crate::consensus::{Checkpoint, verify_checkpoint};
use crypto::pq_sign::PqVerifyingKey;

/// Errors returned by the auditor.
#[derive(Debug, Clone)]
pub enum AuditorError {
    /// I/O error reading the checkpoint log.
    Io(String),
    /// Malformed JSONL row.
    Malformed(String),
    /// Hash chain mismatch at a given row index.
    ChainBreak(usize),
    /// Signature quorum failed at a given row index.
    QuorumFailed(usize),
}

impl std::fmt::Display for AuditorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(d) => write!(f, "auditor I/O: {d}"),
            Self::Malformed(d) => write!(f, "auditor malformed row: {d}"),
            Self::ChainBreak(i) => write!(f, "auditor hash chain break at row {i}"),
            Self::QuorumFailed(i) => write!(f, "auditor quorum failed at row {i}"),
        }
    }
}

impl std::error::Error for AuditorError {}

/// Verify every row in the supplied checkpoint log bytes. Returns the
/// number of valid checkpoints read, or an error naming the offending row.
pub fn verify_log(
    log_bytes: &[u8],
    pinned_vks: &[PqVerifyingKey],
) -> Result<usize, AuditorError> {
    let text = std::str::from_utf8(log_bytes)
        .map_err(|e| AuditorError::Malformed(format!("utf8: {e}")))?;
    let mut prev_hash: [u8; 64] = [0u8; 64];
    let mut count = 0usize;
    for (i, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let cp: Checkpoint = serde_json::from_str(line)
            .map_err(|e| AuditorError::Malformed(format!("row {i}: {e}")))?;
        if cp.prev_hash != prev_hash {
            return Err(AuditorError::ChainBreak(i));
        }
        if !verify_checkpoint(&cp, pinned_vks) {
            return Err(AuditorError::QuorumFailed(i));
        }
        prev_hash = crate::consensus::hash_checkpoint(&cp);
        count += 1;
    }
    Ok(count)
}

/// Read the log at `path` and verify every row.
pub fn verify_log_file(
    path: &std::path::Path,
    pinned_vks: &[PqVerifyingKey],
) -> Result<usize, AuditorError> {
    let bytes = std::fs::read(path).map_err(|e| AuditorError::Io(e.to_string()))?;
    verify_log(&bytes, pinned_vks)
}
