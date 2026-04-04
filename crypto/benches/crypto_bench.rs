//! Criterion benchmarks for core cryptographic primitives.
//!
//! Covers ML-DSA-87 signing/verification, X-Wing KEM, AES-256-GCM,
//! AEGIS-256, FROST threshold signing, HKDF-SHA512, receipt chain
//! operations, and constant-time comparison.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// ---------------------------------------------------------------------------
// ML-DSA-87 sign + verify cycle
// ---------------------------------------------------------------------------

fn bench_mldsa87_sign_verify(c: &mut Criterion) {
    // ML-DSA-87 needs a large stack for key generation, so we generate once.
    let (sk, vk) = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(crypto::pq_sign::generate_pq_keypair)
        .expect("spawn keygen thread")
        .join()
        .expect("keygen thread panicked");

    let message = b"benchmark payload for ML-DSA-87 signing";
    let frost_sig = [0xABu8; 64]; // dummy FROST sig for nested signing

    c.bench_function("ml_dsa_87_sign_verify", |b| {
        b.iter(|| {
            let sig = crypto::pq_sign::pq_sign(black_box(&sk), black_box(message), black_box(&frost_sig));
            let valid = crypto::pq_sign::pq_verify(black_box(&vk), black_box(message), black_box(&frost_sig), black_box(&sig));
            assert!(valid);
        });
    });
}

// ---------------------------------------------------------------------------
// X-Wing encapsulate + decapsulate
// ---------------------------------------------------------------------------

fn bench_xwing_encap_decap(c: &mut Criterion) {
    let (pk, kp) = crypto::xwing::xwing_keygen();

    c.bench_function("xwing_encap_decap", |b| {
        b.iter(|| {
            let (shared_secret, ciphertext) =
                crypto::xwing::xwing_encapsulate(black_box(&pk)).expect("encapsulate");
            let recovered = crypto::xwing::xwing_decapsulate(black_box(&kp), black_box(&ciphertext));
            assert!(recovered.is_ok());
            let _ = (shared_secret, recovered);
        });
    });
}

// ---------------------------------------------------------------------------
// AES-256-GCM encrypt 1KB + decrypt
// ---------------------------------------------------------------------------

fn bench_aes256gcm_1kb(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let plaintext = vec![0xABu8; 1024];
    let aad = b"benchmark-aad";

    c.bench_function("aes256gcm_encrypt_decrypt_1kb", |b| {
        b.iter(|| {
            let sealed = crypto::symmetric::encrypt_with(
                crypto::symmetric::SymmetricAlgorithm::Aes256Gcm,
                black_box(&key),
                black_box(&plaintext),
                black_box(aad),
            )
            .expect("encrypt");
            let recovered = crypto::symmetric::decrypt(black_box(&key), black_box(&sealed), black_box(aad))
                .expect("decrypt");
            assert_eq!(recovered.len(), 1024);
        });
    });
}

// ---------------------------------------------------------------------------
// AEGIS-256 encrypt 1KB + decrypt
// ---------------------------------------------------------------------------

fn bench_aegis256_1kb(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let plaintext = vec![0xABu8; 1024];
    let aad = b"benchmark-aad";

    c.bench_function("aegis256_encrypt_decrypt_1kb", |b| {
        b.iter(|| {
            let sealed = crypto::symmetric::encrypt_with(
                crypto::symmetric::SymmetricAlgorithm::Aegis256,
                black_box(&key),
                black_box(&plaintext),
                black_box(aad),
            )
            .expect("encrypt");
            let recovered = crypto::symmetric::decrypt(black_box(&key), black_box(&sealed), black_box(aad))
                .expect("decrypt");
            assert_eq!(recovered.len(), 1024);
        });
    });
}

// ---------------------------------------------------------------------------
// FROST 3-of-5 threshold sign
// ---------------------------------------------------------------------------

fn bench_frost_3of5_sign(c: &mut Criterion) {
    c.bench_function("frost_3of5_sign", |b| {
        // We need fresh shares each iteration because threshold_sign mutates nonce_counter
        b.iter_with_setup(
            || {
                let r = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");
                (r.shares, r.group)
            },
            |(mut shares, group)| {
                let sig = crypto::threshold::threshold_sign(
                    black_box(&mut shares),
                    black_box(&group),
                    black_box(b"benchmark message"),
                    3,
                )
                .expect("threshold sign");
                let _ = sig;
            },
        );
    });

    // Also benchmark verification
    let mut setup_result = crypto::threshold::dkg(5, 3).expect("DKG ceremony failed");
    let sig = crypto::threshold::threshold_sign(
        &mut setup_result.shares,
        &setup_result.group,
        b"benchmark message",
        3,
    )
    .unwrap();

    c.bench_function("frost_verify_group_signature", |b| {
        b.iter(|| {
            let valid = crypto::threshold::verify_group_signature(
                black_box(&setup_result.group),
                black_box(b"benchmark message"),
                black_box(&sig),
            );
            assert!(valid);
        });
    });
}

// ---------------------------------------------------------------------------
// HKDF-SHA512 derive
// ---------------------------------------------------------------------------

fn bench_hkdf_sha512_derive(c: &mut Criterion) {
    use hkdf::Hkdf;
    use sha2::Sha512;

    let ikm = [0x42u8; 32];
    let salt = b"MILNET-BENCH-SALT";
    let info = b"MILNET-BENCH-KEY-v1";

    c.bench_function("hkdf_sha512_derive_32bytes", |b| {
        b.iter(|| {
            let hk = Hkdf::<Sha512>::new(Some(black_box(salt)), black_box(&ikm));
            let mut okm = [0u8; 32];
            hk.expand(black_box(info), &mut okm).expect("hkdf expand");
            black_box(okm);
        });
    });
}

// ---------------------------------------------------------------------------
// Receipt chain append + verify
// ---------------------------------------------------------------------------

fn bench_receipt_chain(c: &mut Criterion) {
    use common::types::Receipt;
    use crypto::receipts::{hash_receipt, sign_receipt, ReceiptChain};
    use uuid::Uuid;

    let signing_key = [0x42u8; 64];
    let session_id = [0x01u8; 32];

    c.bench_function("receipt_chain_append_verify_5steps", |b| {
        b.iter(|| {
            let mut chain = ReceiptChain::new(session_id);
            let mut prev_hash = [0u8; 64];

            for step in 1..=5u8 {
                let mut receipt = Receipt {
                    ceremony_session_id: session_id,
                    step_id: step,
                    prev_receipt_hash: prev_hash,
                    user_id: Uuid::nil(),
                    dpop_key_hash: [0xBB; 64],
                    timestamp: 1_700_000_000_000_000 + (step as i64 * 1_000_000),
                    nonce: [step; 32],
                    signature: Vec::new(),
                    ttl_seconds: 30,
                };
                sign_receipt(&mut receipt, &signing_key).unwrap();
                prev_hash = hash_receipt(&receipt);
                chain.add_receipt(receipt).expect("add receipt");
            }

            chain.validate_with_key(&signing_key).expect("validate chain");
        });
    });
}

// ---------------------------------------------------------------------------
// ct_eq comparison (various sizes)
// ---------------------------------------------------------------------------

fn bench_ct_eq(c: &mut Criterion) {
    let a32 = [0xABu8; 32];
    let b32 = [0xABu8; 32];
    let a64 = [0xCDu8; 64];
    let b64 = [0xCDu8; 64];
    let a256 = vec![0xEFu8; 256];
    let b256 = vec![0xEFu8; 256];

    c.bench_function("ct_eq_32", |b| {
        b.iter(|| {
            assert!(crypto::ct::ct_eq_32(black_box(&a32), black_box(&b32)));
        });
    });

    c.bench_function("ct_eq_64", |b| {
        b.iter(|| {
            assert!(crypto::ct::ct_eq_64(black_box(&a64), black_box(&b64)));
        });
    });

    c.bench_function("ct_eq_256", |b| {
        b.iter(|| {
            assert!(crypto::ct::ct_eq(black_box(&a256), black_box(&b256)));
        });
    });
}

// ---------------------------------------------------------------------------
// Group & main
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_mldsa87_sign_verify,
    bench_xwing_encap_decap,
    bench_aes256gcm_1kb,
    bench_aegis256_1kb,
    bench_frost_3of5_sign,
    bench_hkdf_sha512_derive,
    bench_receipt_chain,
    bench_ct_eq,
);

criterion_main!(benches);
