//! CRDTs provide deterministic conflict resolution for replicated state.
//! No coordination needed — all replicas converge to the same state.
//!
//! Used for: session counts, rate limit counters, revocation sets,
//! distributed configuration that must eventually converge.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;

// ---------------------------------------------------------------------------
// G-Counter: grow-only counter (each node increments its own slot)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GCounter {
    counts: HashMap<String, u64>,
}

impl GCounter {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    /// Increment this node's slot by `amount`.
    pub fn increment(&mut self, node_id: &str, amount: u64) {
        *self.counts.entry(node_id.to_owned()).or_insert(0) += amount;
    }

    /// Read the total counter value (sum of all node slots).
    pub fn value(&self) -> u64 {
        self.counts.values().sum()
    }

    /// Merge another replica. Takes the per-node max (commutative, associative, idempotent).
    pub fn merge(&mut self, other: &Self) {
        for (node, &count) in &other.counts {
            let entry = self.counts.entry(node.clone()).or_insert(0);
            if count > *entry {
                *entry = count;
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("GCounter serialization")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

impl Default for GCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PN-Counter: positive-negative counter (increment and decrement)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PNCounter {
    increments: GCounter,
    decrements: GCounter,
}

impl PNCounter {
    pub fn new() -> Self {
        Self {
            increments: GCounter::new(),
            decrements: GCounter::new(),
        }
    }

    pub fn increment(&mut self, node_id: &str, amount: u64) {
        self.increments.increment(node_id, amount);
    }

    pub fn decrement(&mut self, node_id: &str, amount: u64) {
        self.decrements.increment(node_id, amount);
    }

    /// Read the counter value (increments - decrements). Returns i64 because
    /// decrements may exceed increments.
    pub fn value(&self) -> i64 {
        self.increments.value() as i64 - self.decrements.value() as i64
    }

    pub fn merge(&mut self, other: &Self) {
        self.increments.merge(&other.increments);
        self.decrements.merge(&other.decrements);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("PNCounter serialization")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

impl Default for PNCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// G-Set: grow-only set (elements can only be added, never removed)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GSet<T: Eq + Hash + Clone> {
    elements: HashSet<T>,
}

impl<T: Eq + Hash + Clone> GSet<T> {
    pub fn new() -> Self {
        Self {
            elements: HashSet::new(),
        }
    }

    pub fn insert(&mut self, element: T) {
        self.elements.insert(element);
    }

    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains(element)
    }

    /// Read the current set of elements.
    pub fn value(&self) -> &HashSet<T> {
        &self.elements
    }

    /// Merge another replica (set union — commutative, associative, idempotent).
    pub fn merge(&mut self, other: &Self) {
        for element in &other.elements {
            self.elements.insert(element.clone());
        }
    }
}

impl<T: Eq + Hash + Clone + Serialize> GSet<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("GSet serialization")
    }
}

impl<T: Eq + Hash + Clone + for<'de> Deserialize<'de>> GSet<T> {
    pub fn from_bytes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

impl<T: Eq + Hash + Clone> Default for GSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OR-Set (Observed-Remove Set): add and remove with unique tags
// ---------------------------------------------------------------------------

/// Each add is tagged with (node_id, timestamp). Remove removes all *observed*
/// tags for that element. Concurrent adds after a remove survive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ORSet<T: Eq + Hash + Clone> {
    elements: HashMap<T, HashSet<(String, u64)>>,
    tombstones: HashMap<T, HashSet<(String, u64)>>,
}

impl<T: Eq + Hash + Clone> ORSet<T> {
    pub fn new() -> Self {
        Self {
            elements: HashMap::new(),
            tombstones: HashMap::new(),
        }
    }

    /// Add an element with a unique tag (node_id, timestamp).
    pub fn add(&mut self, element: T, node_id: &str, timestamp: u64) {
        let tag = (node_id.to_owned(), timestamp);
        self.elements
            .entry(element)
            .or_insert_with(HashSet::new)
            .insert(tag);
    }

    /// Remove an element by tombstoning all currently observed tags.
    /// Concurrent adds (tags not yet seen) will survive.
    pub fn remove(&mut self, element: &T) {
        if let Some(tags) = self.elements.get(element) {
            let removed_tags = tags.clone();
            self.tombstones
                .entry(element.clone())
                .or_insert_with(HashSet::new)
                .extend(removed_tags);
        }
        // Remove all currently-known tags from elements
        self.elements.remove(element);
    }

    pub fn contains(&self, element: &T) -> bool {
        self.elements
            .get(element)
            .map_or(false, |tags| !tags.is_empty())
    }

    /// Read the current set of live elements.
    pub fn value(&self) -> HashSet<T> {
        self.elements
            .iter()
            .filter(|(_, tags)| !tags.is_empty())
            .map(|(elem, _)| elem.clone())
            .collect()
    }

    /// Merge another replica.
    /// For each element: live tags = (local_tags ∪ remote_tags) - (local_tombstones ∪ remote_tombstones)
    pub fn merge(&mut self, other: &Self) {
        // Merge tombstones first
        for (elem, other_ts) in &other.tombstones {
            self.tombstones
                .entry(elem.clone())
                .or_insert_with(HashSet::new)
                .extend(other_ts.iter().cloned());
        }

        // Merge element tags from other
        for (elem, other_tags) in &other.elements {
            self.elements
                .entry(elem.clone())
                .or_insert_with(HashSet::new)
                .extend(other_tags.iter().cloned());
        }

        // Now remove all tombstoned tags from elements
        let all_tombstones = self.tombstones.clone();
        for (elem, ts) in &all_tombstones {
            if let Some(tags) = self.elements.get_mut(elem) {
                for t in ts {
                    tags.remove(t);
                }
                if tags.is_empty() {
                    self.elements.remove(elem);
                }
            }
        }
    }
}

impl<T: Eq + Hash + Clone + Serialize> ORSet<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("ORSet serialization")
    }
}

impl<T: Eq + Hash + Clone + for<'de> Deserialize<'de>> ORSet<T> {
    pub fn from_bytes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

impl<T: Eq + Hash + Clone> Default for ORSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LWW-Register: Last-Writer-Wins register for single values
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LWWRegister<T: Clone> {
    value: T,
    timestamp: u64,
    node_id: String,
}

impl<T: Clone> LWWRegister<T> {
    pub fn new(value: T, timestamp: u64, node_id: &str) -> Self {
        Self {
            value,
            timestamp,
            node_id: node_id.to_owned(),
        }
    }

    /// Set a new value. Only takes effect if the timestamp is newer,
    /// or equal timestamp with a higher node_id (deterministic tiebreak).
    pub fn set(&mut self, value: T, timestamp: u64, node_id: &str) {
        if timestamp > self.timestamp
            || (timestamp == self.timestamp && node_id > self.node_id.as_str())
        {
            self.value = value;
            self.timestamp = timestamp;
            self.node_id = node_id.to_owned();
        }
    }

    /// Read the current value.
    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Merge another replica (last-writer-wins by timestamp, tiebreak by node_id).
    pub fn merge(&mut self, other: &Self) {
        if other.timestamp > self.timestamp
            || (other.timestamp == self.timestamp && other.node_id > self.node_id)
        {
            self.value = other.value.clone();
            self.timestamp = other.timestamp;
            self.node_id = other.node_id.clone();
        }
    }
}

impl<T: Clone + Serialize> LWWRegister<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("LWWRegister serialization")
    }
}

impl<T: Clone + for<'de> Deserialize<'de>> LWWRegister<T> {
    pub fn from_bytes(data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(data)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── GCounter ──

    #[test]
    fn gcounter_basic() {
        let mut c = GCounter::new();
        assert_eq!(c.value(), 0);
        c.increment("a", 5);
        c.increment("b", 3);
        assert_eq!(c.value(), 8);
        c.increment("a", 2);
        assert_eq!(c.value(), 10);
    }

    #[test]
    fn gcounter_merge_commutativity() {
        let mut a = GCounter::new();
        a.increment("x", 10);
        a.increment("y", 5);

        let mut b = GCounter::new();
        b.increment("y", 8);
        b.increment("z", 3);

        let mut ab = a.clone();
        ab.merge(&b);

        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab, ba);
    }

    #[test]
    fn gcounter_merge_associativity() {
        let mut a = GCounter::new();
        a.increment("x", 1);
        let mut b = GCounter::new();
        b.increment("y", 2);
        let mut c = GCounter::new();
        c.increment("z", 3);

        // (a merge b) merge c
        let mut ab = a.clone();
        ab.merge(&b);
        let mut abc1 = ab;
        abc1.merge(&c);

        // a merge (b merge c)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut abc2 = a.clone();
        abc2.merge(&bc);

        assert_eq!(abc1, abc2);
    }

    #[test]
    fn gcounter_merge_idempotence() {
        let mut a = GCounter::new();
        a.increment("x", 7);
        a.increment("y", 3);

        let before = a.clone();
        a.merge(&before);
        assert_eq!(a, before);
    }

    #[test]
    fn gcounter_serialization_roundtrip() {
        let mut c = GCounter::new();
        c.increment("node1", 42);
        c.increment("node2", 99);
        let bytes = c.to_bytes();
        let c2 = GCounter::from_bytes(&bytes).unwrap();
        assert_eq!(c, c2);
    }

    // ── PNCounter ──

    #[test]
    fn pncounter_basic() {
        let mut c = PNCounter::new();
        c.increment("a", 10);
        c.decrement("b", 3);
        assert_eq!(c.value(), 7);
    }

    #[test]
    fn pncounter_negative() {
        let mut c = PNCounter::new();
        c.decrement("a", 5);
        assert_eq!(c.value(), -5);
    }

    #[test]
    fn pncounter_merge_commutativity() {
        let mut a = PNCounter::new();
        a.increment("x", 10);
        a.decrement("x", 3);

        let mut b = PNCounter::new();
        b.increment("y", 5);
        b.decrement("y", 1);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab, ba);
    }

    #[test]
    fn pncounter_merge_idempotence() {
        let mut a = PNCounter::new();
        a.increment("x", 10);
        a.decrement("y", 3);
        let before = a.clone();
        a.merge(&before);
        assert_eq!(a, before);
    }

    #[test]
    fn pncounter_serialization_roundtrip() {
        let mut c = PNCounter::new();
        c.increment("a", 10);
        c.decrement("b", 3);
        let bytes = c.to_bytes();
        let c2 = PNCounter::from_bytes(&bytes).unwrap();
        assert_eq!(c, c2);
    }

    // ── GSet ──

    #[test]
    fn gset_basic() {
        let mut s = GSet::<String>::new();
        s.insert("alice".into());
        s.insert("bob".into());
        assert!(s.contains(&"alice".into()));
        assert!(!s.contains(&"carol".into()));
        assert_eq!(s.value().len(), 2);
    }

    #[test]
    fn gset_merge_commutativity() {
        let mut a = GSet::new();
        a.insert("x".to_string());
        let mut b = GSet::new();
        b.insert("y".to_string());

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab, ba);
    }

    #[test]
    fn gset_merge_idempotence() {
        let mut a = GSet::new();
        a.insert("x".to_string());
        let before = a.clone();
        a.merge(&before);
        assert_eq!(a, before);
    }

    #[test]
    fn gset_serialization_roundtrip() {
        let mut s = GSet::new();
        s.insert("hello".to_string());
        let bytes = s.to_bytes();
        let s2 = GSet::<String>::from_bytes(&bytes).unwrap();
        assert_eq!(s, s2);
    }

    // ── ORSet ──

    #[test]
    fn orset_add_remove() {
        let mut s = ORSet::new();
        s.add("x".to_string(), "n1", 1);
        assert!(s.contains(&"x".to_string()));
        s.remove(&"x".to_string());
        assert!(!s.contains(&"x".to_string()));
    }

    #[test]
    fn orset_concurrent_add_survives_remove() {
        // Node A adds "x", node B adds "x" concurrently. Node A removes "x".
        // After merge, node B's concurrent add must survive.
        let mut a = ORSet::new();
        a.add("x".to_string(), "a", 1);

        let mut b = ORSet::new();
        b.add("x".to_string(), "b", 2); // concurrent add

        // A removes (only sees its own tag)
        a.remove(&"x".to_string());
        assert!(!a.contains(&"x".to_string()));

        // Merge: B's concurrent add survives
        a.merge(&b);
        assert!(a.contains(&"x".to_string()));
    }

    #[test]
    fn orset_merge_commutativity() {
        let mut a = ORSet::new();
        a.add("x".to_string(), "a", 1);
        a.add("y".to_string(), "a", 2);

        let mut b = ORSet::new();
        b.add("y".to_string(), "b", 3);
        b.add("z".to_string(), "b", 4);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.value(), ba.value());
    }

    #[test]
    fn orset_merge_idempotence() {
        let mut a = ORSet::new();
        a.add("x".to_string(), "a", 1);
        a.remove(&"x".to_string());
        a.add("y".to_string(), "a", 2);

        let before_val = a.value();
        let snapshot = a.clone();
        a.merge(&snapshot);
        assert_eq!(a.value(), before_val);
    }

    #[test]
    fn orset_serialization_roundtrip() {
        let mut s = ORSet::new();
        s.add("test".to_string(), "n1", 100);
        let bytes = s.to_bytes();
        let s2 = ORSet::<String>::from_bytes(&bytes).unwrap();
        assert_eq!(s.value(), s2.value());
    }

    // ── LWWRegister ──

    #[test]
    fn lww_register_basic() {
        let mut r = LWWRegister::new("first".to_string(), 1, "a");
        assert_eq!(r.value(), "first");
        r.set("second".to_string(), 2, "a");
        assert_eq!(r.value(), "second");
        // Older write is rejected
        r.set("old".to_string(), 1, "b");
        assert_eq!(r.value(), "second");
    }

    #[test]
    fn lww_register_tiebreak() {
        let mut r = LWWRegister::new("from_a".to_string(), 5, "a");
        // Same timestamp, higher node_id wins
        r.set("from_b".to_string(), 5, "b");
        assert_eq!(r.value(), "from_b");
        // Same timestamp, lower node_id loses
        r.set("from_a2".to_string(), 5, "a");
        assert_eq!(r.value(), "from_b");
    }

    #[test]
    fn lww_register_merge_commutativity() {
        let a = LWWRegister::new("val_a".to_string(), 10, "a");
        let b = LWWRegister::new("val_b".to_string(), 10, "b");

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);

        assert_eq!(ab.value(), ba.value());
    }

    #[test]
    fn lww_register_merge_idempotence() {
        let a = LWWRegister::new("val".to_string(), 5, "n1");
        let mut aa = a.clone();
        aa.merge(&a);
        assert_eq!(aa.value(), a.value());
        assert_eq!(aa.timestamp(), a.timestamp());
    }

    #[test]
    fn lww_register_serialization_roundtrip() {
        let r = LWWRegister::new(42u64, 100, "node");
        let bytes = r.to_bytes();
        let r2 = LWWRegister::<u64>::from_bytes(&bytes).unwrap();
        assert_eq!(r.value(), r2.value());
        assert_eq!(r.timestamp(), r2.timestamp());
    }

    // ── Associativity: multi-CRDT ──

    #[test]
    fn pncounter_merge_associativity() {
        let mut a = PNCounter::new();
        a.increment("a", 5);
        let mut b = PNCounter::new();
        b.decrement("b", 3);
        let mut c = PNCounter::new();
        c.increment("c", 7);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut abc1 = ab;
        abc1.merge(&c);

        let mut bc = b.clone();
        bc.merge(&c);
        let mut abc2 = a.clone();
        abc2.merge(&bc);

        assert_eq!(abc1, abc2);
    }

    #[test]
    fn gset_merge_associativity() {
        let mut a = GSet::new();
        a.insert(1u64);
        let mut b = GSet::new();
        b.insert(2u64);
        let mut c = GSet::new();
        c.insert(3u64);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut abc1 = ab;
        abc1.merge(&c);

        let mut bc = b.clone();
        bc.merge(&c);
        let mut abc2 = a.clone();
        abc2.merge(&bc);

        assert_eq!(abc1, abc2);
    }
}
