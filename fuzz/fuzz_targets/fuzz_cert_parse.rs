#![no_main]
use libfuzzer_sys::fuzz_target;
use common::cert_lifecycle::{
    CertificateEntry, CertificateLifecycleManager, CrlEntry, KeyUsage, OcspStaple, RotationPolicy,
};
use common::ocsp_crl::{CrlConfig, OcspConfig, RevocationChecker};

fuzz_target!(|data: &[u8]| {
    // Fuzz JSON deserialization of certificate-related types
    let _ = serde_json::from_slice::<CertificateEntry>(data);
    let _ = serde_json::from_slice::<OcspStaple>(data);
    let _ = serde_json::from_slice::<CrlEntry>(data);
    let _ = serde_json::from_slice::<RotationPolicy>(data);
    let _ = serde_json::from_slice::<Vec<KeyUsage>>(data);

    // Fuzz OCSP/CRL config deserialization
    let _ = serde_json::from_slice::<OcspConfig>(data);
    let _ = serde_json::from_slice::<CrlConfig>(data);

    // Fuzz certificate registration with arbitrary DER bytes
    if data.len() >= 16 {
        let mgr = CertificateLifecycleManager::new(RotationPolicy::default());
        let half = data.len() / 2;
        let _ = mgr.register_certificate(
            data.to_vec(),
            String::from_utf8_lossy(&data[..half.min(64)]).to_string(),
            String::from_utf8_lossy(&data[half..]).to_string(),
            data[..8.min(data.len())].to_vec(),
            0,
            i64::MAX,
            data[..half].to_vec(),
            vec![KeyUsage::DigitalSignature],
        );
    }

    // Fuzz revocation checker with arbitrary fingerprint/serial
    if data.len() >= 32 {
        let mut checker = RevocationChecker::new(OcspConfig::default(), CrlConfig::default());
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&data[..32]);
        let serial = u64::from_le_bytes({
            let mut buf = [0u8; 8];
            let copy_len = 8.min(data.len() - 32);
            buf[..copy_len].copy_from_slice(&data[32..32 + copy_len]);
            buf
        });
        let _ = checker.check_certificate(&fp, serial);
    }
});
