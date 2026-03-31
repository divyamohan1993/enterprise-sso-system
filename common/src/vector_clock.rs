//! Vector clock for tracking causal ordering across distributed nodes.
//!
//! Each node maintains a counter per known node. When sending a message,
//! increment own counter. When receiving, take max of each component.
//!
//! Used for: detecting concurrent events, ordering audit entries,
//! conflict detection in state replication.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;

/// A vector clock maps node identifiers to logical timestamps.
///
/// The invariant is: if clock A happens-before clock B, then every component
/// of A is <= the corresponding component of B, with at least one strictly less.
/// If neither dominates the other, the events are concurrent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorClock {
    clocks: HashMap<String, u64>,
    node_id: String,
}

impl VectorClock {
    /// Create a new vector clock for the given node, initialized at 0.
    pub fn new(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        let mut clocks = HashMap::new();
        clocks.insert(node_id.clone(), 0);
        Self { clocks, node_id }
    }

    /// Increment this node's logical clock (local event).
    pub fn increment(&mut self) {
        let counter = self.clocks.entry(self.node_id.clone()).or_insert(0);
        *counter += 1;
    }

    /// Increment own counter and return a serializable snapshot for sending.
    pub fn send_event(&mut self) -> VectorClockSnapshot {
        self.increment();
        VectorClockSnapshot {
            clocks: self.clocks.clone(),
        }
    }

    /// Merge an incoming clock snapshot: take the component-wise max, then
    /// increment own counter to record the receive event.
    pub fn receive_event(&mut self, other: &VectorClockSnapshot) {
        for (node, &time) in &other.clocks {
            let entry = self.clocks.entry(node.clone()).or_insert(0);
            if time > *entry {
                *entry = time;
            }
        }
        // Receiving is itself a local event.
        self.increment();
    }

    /// Compare two vector clocks for causal ordering.
    ///
    /// Returns `Less` if self happens-before other, `Greater` if other
    /// happens-before self, `Equal` if identical, and `None` if concurrent.
    pub fn happens_before(&self, other: &VectorClock) -> Option<Ordering> {
        Self::compare_maps(&self.clocks, &other.clocks)
    }

    /// Returns true if the two clocks are concurrent (neither dominates).
    pub fn is_concurrent(&self, other: &VectorClock) -> bool {
        Self::compare_maps(&self.clocks, &other.clocks).is_none()
    }

    /// Merge another clock into this one (component-wise max, no increment).
    ///
    /// Useful for combining knowledge from multiple sources without recording
    /// a new event.
    pub fn merge(&mut self, other: &VectorClock) {
        for (node, &time) in &other.clocks {
            let entry = self.clocks.entry(node.clone()).or_insert(0);
            if time > *entry {
                *entry = time;
            }
        }
    }

    /// Return this node's current logical time.
    pub fn local_time(&self) -> u64 {
        self.clocks.get(&self.node_id).copied().unwrap_or(0)
    }

    /// Return the logical time for an arbitrary node, or 0 if unknown.
    pub fn time_for(&self, node_id: &str) -> u64 {
        self.clocks.get(node_id).copied().unwrap_or(0)
    }

    /// Serialize to bytes using postcard.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_else(|e| {
            tracing::error!("VectorClock serialization failed: {e}");
            Vec::new()
        })
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// Compare two clock maps. Returns `Some(Ordering)` or `None` for concurrent.
    fn compare_maps(a: &HashMap<String, u64>, b: &HashMap<String, u64>) -> Option<Ordering> {
        let mut a_less = false;
        let mut b_less = false;

        // Collect all node ids from both maps.
        // Iterate a's keys.
        for (node, &a_val) in a {
            let b_val = b.get(node).copied().unwrap_or(0);
            match a_val.cmp(&b_val) {
                Ordering::Less => a_less = true,
                Ordering::Greater => b_less = true,
                Ordering::Equal => {}
            }
            if a_less && b_less {
                return None;
            }
        }
        // Check keys in b that are not in a.
        for (node, &b_val) in b {
            if a.contains_key(node) {
                continue;
            }
            // a implicitly has 0 for this node.
            if b_val > 0 {
                a_less = true;
            }
            if a_less && b_less {
                return None;
            }
        }

        match (a_less, b_less) {
            (false, false) => Some(Ordering::Equal),
            (true, false) => Some(Ordering::Less),
            (false, true) => Some(Ordering::Greater),
            (true, true) => None, // concurrent
        }
    }
}

/// A serializable snapshot of a vector clock, sent on the wire.
///
/// Does not include the node_id of the sender — the receiver merges
/// the raw counters and increments its own.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VectorClockSnapshot {
    pub clocks: HashMap<String, u64>,
}

impl VectorClockSnapshot {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_else(|e| {
            tracing::error!("VectorClockSnapshot serialization failed: {e}");
            Vec::new()
        })
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_clock_starts_at_zero() {
        let vc = VectorClock::new("node-1");
        assert_eq!(vc.local_time(), 0);
        assert_eq!(vc.time_for("node-1"), 0);
        assert_eq!(vc.time_for("unknown"), 0);
    }

    #[test]
    fn increment_advances_local_time() {
        let mut vc = VectorClock::new("A");
        vc.increment();
        assert_eq!(vc.local_time(), 1);
        vc.increment();
        vc.increment();
        assert_eq!(vc.local_time(), 3);
    }

    #[test]
    fn send_event_increments_and_snapshots() {
        let mut vc = VectorClock::new("A");
        let snap = vc.send_event();
        assert_eq!(vc.local_time(), 1);
        assert_eq!(snap.clocks.get("A"), Some(&1));
    }

    #[test]
    fn receive_event_merges_and_increments() {
        let mut a = VectorClock::new("A");
        let mut b = VectorClock::new("B");

        // A sends to B.
        a.increment(); // A: {A:1}
        a.increment(); // A: {A:2}
        let snap = a.send_event(); // A: {A:3}

        b.increment(); // B: {B:1}
        b.receive_event(&snap); // B merges {A:3}, then increments B -> {A:3, B:2}

        assert_eq!(b.time_for("A"), 3);
        assert_eq!(b.time_for("B"), 2);
    }

    #[test]
    fn happens_before_linear() {
        let mut a = VectorClock::new("A");
        let a0 = a.clone();
        a.increment();
        let a1 = a.clone();

        assert_eq!(a0.happens_before(&a1), Some(Ordering::Less));
        assert_eq!(a1.happens_before(&a0), Some(Ordering::Greater));
        assert_eq!(a0.happens_before(&a0), Some(Ordering::Equal));
    }

    #[test]
    fn concurrent_detection() {
        let mut a = VectorClock::new("A");
        let mut b = VectorClock::new("B");

        a.increment(); // A: {A:1}
        b.increment(); // B: {B:1}

        assert!(a.is_concurrent(&b));
        assert!(b.is_concurrent(&a));
        assert_eq!(a.happens_before(&b), None);
    }

    #[test]
    fn merge_takes_componentwise_max() {
        let mut a = VectorClock::new("A");
        let mut b = VectorClock::new("B");

        a.increment(); // A: {A:1}
        a.increment(); // A: {A:2}
        b.increment(); // B: {B:1}
        b.increment(); // B: {B:2}
        b.increment(); // B: {B:3}

        a.merge(&b);
        assert_eq!(a.time_for("A"), 2);
        assert_eq!(a.time_for("B"), 3);
    }

    #[test]
    fn serialization_roundtrip() {
        let mut vc = VectorClock::new("node-x");
        vc.increment();
        vc.increment();

        let bytes = vc.to_bytes();
        let restored = VectorClock::from_bytes(&bytes).unwrap();
        assert_eq!(vc, restored);
    }

    #[test]
    fn snapshot_serialization_roundtrip() {
        let mut vc = VectorClock::new("S");
        vc.increment();
        let snap = vc.send_event();

        let bytes = snap.to_bytes();
        let restored = VectorClockSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(snap, restored);
    }

    #[test]
    fn three_node_causality() {
        // A -> B -> C chain: A sends to B, B sends to C.
        let mut a = VectorClock::new("A");
        let mut b = VectorClock::new("B");
        let mut c = VectorClock::new("C");

        let snap_a = a.send_event(); // A:{A:1}
        b.receive_event(&snap_a);    // B:{A:1, B:1}
        let snap_b = b.send_event(); // B:{A:1, B:2}
        c.receive_event(&snap_b);    // C:{A:1, B:2, C:1}

        // A happens-before C (transitively).
        // A's clock after send_event: {A:1}
        // C's clock: {A:1, B:2, C:1}
        // Every component of A <= corresponding in C, at least one strictly less.
        assert_eq!(a.happens_before(&c), Some(Ordering::Less));
    }

    #[test]
    fn diamond_concurrency_then_merge() {
        // A sends to B and C independently. B and C are concurrent.
        // Then both send to D, which merges everything.
        let mut a = VectorClock::new("A");
        let snap_a = a.send_event();

        let mut b = VectorClock::new("B");
        b.receive_event(&snap_a);
        b.increment(); // local work on B

        let mut c = VectorClock::new("C");
        c.receive_event(&snap_a);
        c.increment(); // local work on C

        // B and C are concurrent.
        assert!(b.is_concurrent(&c));

        let snap_b = b.send_event();
        let snap_c = c.send_event();

        let mut d = VectorClock::new("D");
        d.receive_event(&snap_b);
        d.receive_event(&snap_c);

        // D should know about all nodes and dominate all of them.
        assert_eq!(d.happens_before(&a), Some(Ordering::Greater));
        assert_eq!(d.happens_before(&b), Some(Ordering::Greater));
        assert_eq!(d.happens_before(&c), Some(Ordering::Greater));
    }
}
