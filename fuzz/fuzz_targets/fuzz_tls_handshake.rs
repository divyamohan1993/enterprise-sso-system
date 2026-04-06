#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the SHARD wire protocol framing: 4-byte length prefix + payload
    // This exercises the frame length validation and message parsing paths
    if data.len() >= 4 {
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        // Exercise the certificate fingerprint computation with arbitrary data
        let _ = shard::tls::compute_cert_fingerprint(data);

        // Exercise certificate pin set operations
        let mut pin_set = shard::tls::CertificatePinSet::new();
        pin_set.add_certificate(data);
        let _ = pin_set.verify_pin(&data[4..]);
        let _ = pin_set.verify_pin(data);
    }

    // Fuzz SHARD protocol message verification
    let module_id = common::types::ModuleId::Gateway;
    let mut protocol = shard::protocol::ShardProtocol::new(module_id, [0x42u8; 64]);
    let _ = protocol.verify_message(data);
});
