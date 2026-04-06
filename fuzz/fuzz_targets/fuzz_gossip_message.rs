#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz gossip message deserialization (postcard + serde_json)
    let _ = postcard::from_bytes::<common::gossip::GossipMessage>(data);
    let _ = serde_json::from_slice::<common::gossip::GossipMessage>(data);

    // Also fuzz membership update deserialization
    let _ = postcard::from_bytes::<common::gossip::MembershipUpdate>(data);

    // Fuzz HMAC verification with a dummy key on deserialized messages
    if let Ok(msg) = postcard::from_bytes::<common::gossip::GossipMessage>(data) {
        let dummy_key = [0x42u8; 64];
        let _ = msg.verify_signature(&dummy_key);
    }
});
