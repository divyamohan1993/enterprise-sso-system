//! Pending `AuthnRequest.ID` cache.
//!
//! When the SP issues an `AuthnRequest`, it remembers the ID with a TTL. The
//! incoming `Response.InResponseTo` MUST match a still-live entry. Single-use:
//! consumed on first match.
//!
//! In-process implementation backed by a hashmap and a min-heap-like vector
//! purge. For multi-instance deployments wire `DistributedRequestCache` (same
//! pattern as `gateway::puzzle::DistributedNonceStore`).

use crate::SamlError;
use parking_lot::Mutex;
use std::collections::HashMap;

const MAX_PENDING: usize = 65_536;

#[derive(Debug)]
struct Entry {
    expires_at: i64,
}

#[derive(Debug, Default)]
pub struct RequestCache {
    inner: Mutex<HashMap<String, Entry>>,
}

impl RequestCache {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    /// Register a pending AuthnRequest ID. TTL in seconds.
    pub fn register(&self, id: String, now: i64, ttl: i64) -> Result<(), SamlError> {
        let mut g = self.inner.lock();
        Self::purge(&mut g, now);
        if g.len() >= MAX_PENDING {
            return Err(SamlError::Internal);
        }
        g.insert(id, Entry { expires_at: now.saturating_add(ttl) });
        Ok(())
    }

    /// Single-use consume. Returns Ok(()) only if the ID was registered and
    /// not yet expired.
    pub fn consume(&self, id: &str, now: i64) -> Result<(), SamlError> {
        let mut g = self.inner.lock();
        Self::purge(&mut g, now);
        match g.remove(id) {
            Some(e) if e.expires_at >= now => Ok(()),
            _ => Err(SamlError::InResponseToMismatch),
        }
    }

    fn purge(map: &mut HashMap<String, Entry>, now: i64) {
        map.retain(|_, e| e.expires_at >= now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let c = RequestCache::new();
        c.register("a".into(), 100, 60).unwrap();
        assert!(c.consume("a", 110).is_ok());
        // single-use
        assert!(c.consume("a", 110).is_err());
    }
    #[test]
    fn expired_rejected() {
        let c = RequestCache::new();
        c.register("a".into(), 100, 60).unwrap();
        assert!(c.consume("a", 200).is_err());
    }
}
