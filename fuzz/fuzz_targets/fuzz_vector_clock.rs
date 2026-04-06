#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mid = data.len() / 2;
    let (left, right) = data.split_at(mid);

    // Fuzz VectorClock deserialization and merge
    if let Ok(mut a) = common::vector_clock::VectorClock::from_bytes(left) {
        if let Ok(b) = common::vector_clock::VectorClock::from_bytes(right) {
            let _ = a.happens_before(&b);
            let _ = a.is_concurrent(&b);
            a.merge(&b);
            let _ = a.local_time();
        }
    }

    // Fuzz VectorClockSnapshot deserialization and receive_event
    if let Ok(mut vc) = common::vector_clock::VectorClock::from_bytes(left) {
        if let Ok(snap) = common::vector_clock::VectorClockSnapshot::from_bytes(right) {
            vc.receive_event(&snap);
            let _ = vc.local_time();
        }
    }
});
