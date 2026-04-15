//! Bounded LRU + TTL replay cache for `Assertion.ID`.
//!
//! Entries auto-expire at `NotOnOrAfter`. Bounded LRU caps memory under
//! adversarial flooding. For multi-instance deployments, implement
//! `DistributedReplayStore` (mirror of `gateway::puzzle::DistributedNonceStore`)
//! and back it with the same Raft / Redis primitive the gateway already uses.

use crate::SamlError;
use parking_lot::Mutex;
use std::collections::HashMap;

const MAX_ENTRIES: usize = 1 << 20;

#[derive(Debug)]
struct Slot {
    expires_at: i64,
    /// Monotonic insertion ticket for LRU eviction.
    seq: u64,
}

#[derive(Debug, Default)]
pub struct ReplayCache {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<String, Slot>,
    next_seq: u64,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically check-and-insert. Returns `Err(Replay)` if the assertion ID
    /// has already been seen and is still within its `NotOnOrAfter` window.
    pub fn check_and_insert(
        &self,
        assertion_id: &str,
        not_on_or_after: i64,
        now: i64,
    ) -> Result<(), SamlError> {
        let mut g = self.inner.lock();
        Self::purge(&mut g, now);

        if let Some(slot) = g.map.get(assertion_id) {
            if slot.expires_at >= now {
                return Err(SamlError::Replay);
            }
        }

        if g.map.len() >= MAX_ENTRIES {
            // LRU evict: drop oldest seq.
            if let Some((victim, _)) =
                g.map.iter().min_by_key(|(_, s)| s.seq).map(|(k, s)| (k.clone(), s.seq))
            {
                g.map.remove(&victim);
            }
        }

        let seq = g.next_seq.wrapping_add(1);
        g.next_seq = seq;
        g.map.insert(
            assertion_id.to_string(),
            Slot { expires_at: not_on_or_after, seq },
        );
        Ok(())
    }

    fn purge(inner: &mut Inner, now: i64) {
        inner.map.retain(|_, s| s.expires_at >= now);
    }
}

/// Distribution trait — implement in the deployment crate using the same
/// transport (Raft / Redis) that backs `gateway::puzzle::DistributedNonceStore`.
pub trait DistributedReplayStore: Send + Sync {
    fn check_and_insert(
        &self,
        assertion_id: &str,
        not_on_or_after: i64,
        now: i64,
    ) -> Result<(), SamlError>;
}

impl DistributedReplayStore for ReplayCache {
    fn check_and_insert(
        &self,
        assertion_id: &str,
        not_on_or_after: i64,
        now: i64,
    ) -> Result<(), SamlError> {
        ReplayCache::check_and_insert(self, assertion_id, not_on_or_after, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_ok_second_replay() {
        let c = ReplayCache::new();
        c.check_and_insert("aid-1", 1000, 100).unwrap();
        let e = c.check_and_insert("aid-1", 1000, 100).unwrap_err();
        matches!(e, SamlError::Replay);
    }
    #[test]
    fn expired_entry_recyclable() {
        let c = ReplayCache::new();
        c.check_and_insert("aid-1", 100, 50).unwrap();
        // Same ID, but the prior entry has expired.
        c.check_and_insert("aid-1", 200, 150).unwrap();
    }
}
