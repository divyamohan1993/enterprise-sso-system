#![no_main]
use libfuzzer_sys::fuzz_target;
use sha2::Digest;
use fido::verification::{
    parse_authenticator_data, parse_cose_key_es256, validate_client_data_authentication,
    validate_client_data_registration, verify_attestation_object,
};

fuzz_target!(|data: &[u8]| {
    // Fuzz authenticator data parsing with raw bytes
    let _ = parse_authenticator_data(data);

    // Fuzz COSE key parsing
    let _ = parse_cose_key_es256(data);

    // Fuzz client data JSON validation (authentication and registration)
    let challenge = b"fuzz-challenge-0123456789abcdef";
    let origin = "https://sso.milnet.example";
    let _ = validate_client_data_authentication(data, challenge, origin);
    let _ = validate_client_data_registration(data, challenge, origin);

    // Fuzz attestation object parsing (CBOR)
    let rp_id = "sso.milnet.example";
    let client_data_hash = sha2::Sha256::digest(data);
    let _ = verify_attestation_object(data, &client_data_hash, rp_id);
});
