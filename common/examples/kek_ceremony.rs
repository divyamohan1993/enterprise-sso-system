//! MILNET threshold-KEK ceremony.
//!
//! Generates a fresh 32-byte master KEK, performs a `t`-of-`n` Shamir split
//! (default 3-of-5) with hash-based VSS commitments, and writes ONLY the
//! shares + commitments to disk. The master KEK is generated in memory,
//! split, and zeroized immediately — it is NEVER persisted and never leaves
//! this process. After the ceremony no single artifact can reconstruct the
//! KEK; `t` shares held by `t` distinct nodes are required.
//!
//! Usage:
//!   cargo run --release --example kek_ceremony -p common -- <out-dir> [t] [n]
//!
//! Output (out-dir, created 0700; files 0600):
//!   kek-share-1.hex .. kek-share-n.hex   one Shamir share per node
//!   vss-commitments.hex                  VSS commitments (distributed to all)
//!   ceremony-manifest.txt                t, n, indices, timestamp (no secrets)
//!
//! SECURITY: run this on a trusted, offline-capable machine. Treat the output
//! directory as TOP SECRET key material. In a real deployment each share is
//! delivered to exactly one node via a sealed channel (Vault, External
//! Secrets, or sneakernet) — never all shares to one host.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use common::threshold_kek::split_secret_with_commitments;
use zeroize::Zeroize;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = args.get(1).cloned().unwrap_or_else(|| {
        eprintln!("usage: kek_ceremony <out-dir> [threshold] [total]");
        std::process::exit(2);
    });
    let threshold: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let total: u8 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);

    // ── Output directory, 0700 ───────────────────────────────────────────────
    std::fs::create_dir_all(&out_dir).expect("create out-dir");
    std::fs::set_permissions(&out_dir, std::fs::Permissions::from_mode(0o700))
        .expect("chmod 0700 out-dir");

    // ── 1. Fresh master KEK from the OS CSPRNG ───────────────────────────────
    let mut master = [0u8; 32];
    getrandom::getrandom(&mut master).expect("CSPRNG failed");

    // ── 2. t-of-n Shamir split + VSS commitments ─────────────────────────────
    let (shares, commitments) = split_secret_with_commitments(&master, threshold, total)
        .unwrap_or_else(|e| {
            master.zeroize();
            eprintln!("FATAL: split failed: {e}");
            std::process::exit(1);
        });

    // ── 3. Destroy the master KEK — it never touches disk ────────────────────
    master.zeroize();

    // ── 4. Emit one file per share, 0600 ─────────────────────────────────────
    for s in &shares {
        let hex = s.to_hex(); // Zeroizing<String>
        let path = format!("{out_dir}/kek-share-{}.hex", s.index);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .expect("create share file");
        f.write_all(hex.as_bytes()).expect("write share");
    }

    // VSS commitments — distributed to ALL nodes, not secret-by-themselves but
    // still written 0600 for tidiness.
    {
        let path = format!("{out_dir}/vss-commitments.hex");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .expect("create commitments file");
        f.write_all(commitments.to_hex().as_bytes())
            .expect("write commitments");
    }

    // ── 5. Non-secret manifest for audit ─────────────────────────────────────
    {
        let indices: Vec<String> = shares.iter().map(|s| s.index.to_string()).collect();
        let manifest = format!(
            "milnet-kek-ceremony\nthreshold={threshold}\ntotal={total}\n\
             share_indices={}\nalgorithm=shamir-gf256+hash-vss\n",
            indices.join(",")
        );
        std::fs::write(format!("{out_dir}/ceremony-manifest.txt"), manifest)
            .expect("write manifest");
    }

    println!(
        "KEK ceremony complete: {threshold}-of-{total} split, {} shares + VSS \
         commitments written to {out_dir}/",
        shares.len()
    );
    println!("The master KEK was zeroized and never written to disk.");
}
