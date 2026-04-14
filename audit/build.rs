//! build.rs: generate pinned_vks.bin — the compile-time list of all 11 BFT
//! node ML-DSA-87 verifying keys. During a release ceremony this file is
//! regenerated from `sealed_keys`; for local dev builds a zero-filled
//! placeholder is produced so cargo can compile.
//!
//! Wire format of `pinned_vks.bin`:
//!   * 4-byte LE `u32`: number of keys (N)
//!   * N records, each: 4-byte LE `u32` length L, then L bytes of encoded
//!     ML-DSA-87 verifying key.
//!
//! Runtime loader lives in `audit::bft::pinned_vks`.

use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dst = out_dir.join("pinned_vks.bin");

    // If a ceremony-produced file is present in the source tree, copy it.
    // Otherwise emit an empty placeholder (zero keys) so the binary compiles.
    // The runtime asserts that the loaded count equals 11 when standalone
    // mode is active, so release builds will refuse to start with a stub.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pinned_vks.bin");
    println!("cargo:rerun-if-changed=pinned_vks.bin");
    println!("cargo:rerun-if-changed=build.rs");

    if src.exists() {
        std::fs::copy(&src, &dst).expect("copy pinned_vks.bin");
    } else {
        // Empty placeholder: u32(0) count.
        let empty: [u8; 4] = [0u8; 4];
        std::fs::write(&dst, empty).expect("write empty pinned_vks.bin");
    }
}
