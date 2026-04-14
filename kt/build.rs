//! build.rs: generate pinned_vks.bin for the 5 KT consensus nodes.
//!
//! Wire format identical to `audit/build.rs`:
//!   * u32 LE count
//!   * repeated (u32 LE len, encoded ML-DSA-87 verifying key)

use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let dst = out_dir.join("pinned_vks.bin");
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("pinned_vks.bin");
    println!("cargo:rerun-if-changed=pinned_vks.bin");
    println!("cargo:rerun-if-changed=build.rs");
    if src.exists() {
        std::fs::copy(&src, &dst).expect("copy pinned_vks.bin");
    } else {
        std::fs::write(&dst, [0u8; 4]).expect("write empty pinned_vks.bin");
    }
}
