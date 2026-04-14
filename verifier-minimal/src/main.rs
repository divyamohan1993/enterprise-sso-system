#![forbid(unsafe_code)]
//! verifier-minimal CLI — read a length-prefixed receipt blob from stdin and
//! exit 0 on successful verification, non-zero on any failure. Designed for
//! use as a sidecar by callers that need a tiny external verifier they can
//! audit end-to-end.

use std::io::Read;

fn main() {
    let mut buf = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
        eprintln!("verifier-minimal: read stdin failed: {}", e);
        std::process::exit(2);
    }
    match verifier_minimal::verify_receipt_bytes(&buf) {
        Ok(()) => {
            println!("OK");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("verifier-minimal: {}", e);
            std::process::exit(1);
        }
    }
}
