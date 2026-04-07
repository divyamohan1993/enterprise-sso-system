#![no_main]
use libfuzzer_sys::fuzz_target;
use crypto::attest::deserialize_manifest;

fuzz_target!(|data: &[u8]| {
    // Fuzz the binary attestation manifest deserializer.
    // This parses a custom binary format and is a prime target for
    // out-of-bounds reads, integer overflows, and allocation bombs.
    let _ = deserialize_manifest(data);
});
