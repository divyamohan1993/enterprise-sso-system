#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split data in half to create two replicas for merge testing
    let mid = data.len() / 2;
    let (left, right) = data.split_at(mid);

    // GCounter
    if let Ok(mut a) = common::crdt::GCounter::from_bytes(left) {
        if let Ok(b) = common::crdt::GCounter::from_bytes(right) {
            a.merge(&b);
            let _ = a.value();
        }
    }

    // PNCounter
    if let Ok(mut a) = common::crdt::PNCounter::from_bytes(left) {
        if let Ok(b) = common::crdt::PNCounter::from_bytes(right) {
            a.merge(&b);
            let _ = a.value();
        }
    }

    // GSet<String>
    if let Ok(mut a) = common::crdt::GSet::<String>::from_bytes(left) {
        if let Ok(b) = common::crdt::GSet::<String>::from_bytes(right) {
            a.merge(&b);
            let _ = a.value();
        }
    }

    // ORSet<String>
    if let Ok(mut a) = common::crdt::ORSet::<String>::from_bytes(left) {
        if let Ok(b) = common::crdt::ORSet::<String>::from_bytes(right) {
            a.merge(&b);
            let _ = a.value();
        }
    }

    // LWWRegister<u64>
    if let Ok(mut a) = common::crdt::LWWRegister::<u64>::from_bytes(left) {
        if let Ok(b) = common::crdt::LWWRegister::<u64>::from_bytes(right) {
            a.merge(&b);
            let _ = a.value();
        }
    }
});
