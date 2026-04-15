//! CAT-A task 3: build-time gate for TLS PQ Level 5 (ML-KEM-1024).
//!
//! rustls/aws_lc_rs does not yet ship an `X25519MLKEM1024` key-exchange
//! group, which leaves the SHARD TLS surface pinned to ML-KEM-768 (NIST
//! Level 3). Until upstream closes this gap, every build prints a
//! `cargo::warning=CNSA-2.0-GAP ...` notice so operators cannot claim
//! ignorance, and a runtime startup error (see `shard/src/tls.rs`)
//! tagged `CNSA-2.0-GAP` documents the same in SIEM.
//!
//! Enable the `tls_pq_level5` cargo feature once rustls ≥ 0.24 exposes
//! `X25519MLKEM1024` via `rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM1024`.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MILNET_TLS_PQ_LEVEL");

    #[cfg(not(feature = "tls_pq_level5"))]
    {
        println!(
            "cargo::warning=CNSA-2.0-GAP: `tls_pq_level5` feature is OFF. TLS key \
             exchange will negotiate X25519MLKEM768 (NIST Level 3) only. ML-KEM-1024 \
             (Level 5) is NOT wired at the TLS layer because rustls/aws_lc_rs does \
             not yet export `X25519MLKEM1024`. Application-layer X-Wing provides \
             Level 5 defence-in-depth; re-enable the feature when upstream lands \
             the kx-group symbol."
        );
    }
}
