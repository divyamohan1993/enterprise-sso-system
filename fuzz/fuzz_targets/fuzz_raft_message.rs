#![no_main]
use libfuzzer_sys::fuzz_target;
use common::raft::{deserialize_message, AuthenticatedRaftMessage};

fuzz_target!(|data: &[u8]| {
    // Fuzz Raft message deserialization (postcard format)
    let _ = deserialize_message(data);

    // Fuzz authenticated Raft message deserialization (serde/postcard)
    let _ = postcard::from_bytes::<AuthenticatedRaftMessage>(data);
});
