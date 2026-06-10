//! MILNET per-node IDENTITY vTPM seal ceremony (Wave-2A anti-root / anti-clone).
//!
//! Companion to `seal_kek_ceremony` (which seals master-KEK material). This one
//! seals a node's INDEPENDENT per-node ML-DSA-87 identity seed — the seed that
//! signs that node's Raft transport messages, session-revocation events, and the
//! attestation it publishes at cluster join. The seed is fresh CSPRNG output,
//! NOT derived from the master KEK, and is sealed to THIS node's measured-boot
//! PCRs (`platform_integrity::MASTER_KEK_PCR_LIST` = sha256:0,2,4,7). Therefore:
//!   * root on node A can unseal ONLY A's seed (forges only AS A, never a quorum), and
//!   * a clone of A's disk on DIFFERENT hardware cannot unseal it (PCR mismatch).
//!
//! This exercises the REAL production path used by
//! `distributed_startup::NodeIdentity::for_node` in military mode:
//!   * `seal`         -> `sealed_keys::seal_node_identity_to_tpm` (generate + seal)
//!   * `unseal-check` -> `sealed_keys::load_node_identity_seed_sealed` (UNSEAL-ONLY;
//!     the loader itself exits(199) fail-closed on no-TPM / absent-blob / PCR
//!     mismatch — exactly what a service does at startup).
//!
//! Usage (node-id is the node's canonical UUID string):
//!   cargo run --example node_identity_seal -p common -- seal <node-uuid>
//!   cargo run --example node_identity_seal -p common -- unseal-check <node-uuid>
//!
//! Blob dir from `MILNET_SEALED_KEK_DIR` (default /var/lib/milnet/sealed); blob
//! name `node-identity-<node-uuid>` (.pub/.priv). Needs a real TPM 2.0 device;
//! on a test host start swtpm first.
//!
//! SWTPM EXERCISE (the verification plan):
//!   1. seal <uuid>          -> writes the sealed blob (exit 0)
//!   2. unseal-check <uuid>  -> PASS, exit 0 (same boot chain)
//!   3. tpm2_pcrextend 0:... ; unseal-check <uuid> -> exit 199 (fail-closed; a
//!      service started now refuses identity acquisition = anti-clone).

use common::sealed_keys::{
    load_node_identity_seed_sealed, sealed_node_identity_name, seal_node_identity_to_tpm,
    Tpm2ToolsKekSealer, TpmKekSealer,
};
use zeroize::Zeroize;

fn usage_exit() -> ! {
    eprintln!(
        "usage:\n  \
         node_identity_seal seal <node-uuid>\n  \
         node_identity_seal unseal-check <node-uuid>\n\n\
         MILNET_SEALED_KEK_DIR selects the blob dir (default /var/lib/milnet/sealed)."
    );
    std::process::exit(2);
}

fn do_seal(node_id: &str) {
    let sealer = Tpm2ToolsKekSealer::from_env();
    if !sealer.tpm_available() {
        eprintln!(
            "FATAL: no vTPM device (/dev/tpmrm0 or /dev/tpm0). Sealing the per-node \
             identity seed requires a real TPM 2.0. On a test host start swtpm first."
        );
        std::process::exit(1);
    }
    match seal_node_identity_to_tpm(&sealer, node_id) {
        Ok(mut seed) => {
            seed.zeroize();
            println!(
                "OK: generated + sealed INDEPENDENT per-node identity seed for '{}' to vTPM \
                 as '{}' under PCR policy {} (dir: {}).",
                node_id,
                sealed_node_identity_name(node_id),
                common::platform_integrity::MASTER_KEK_PCR_LIST,
                std::env::var("MILNET_SEALED_KEK_DIR")
                    .unwrap_or_else(|_| common::platform_integrity::DEFAULT_SEALED_DIR.to_string()),
            );
            println!(
                "NEXT: publish this node's verifying key for peer pinning, set \
                 MILNET_MILITARY_DEPLOYMENT=1, and start the service (it will unseal this seed)."
            );
        }
        Err(e) => {
            eprintln!("FATAL: per-node identity seal failed: {e}");
            std::process::exit(1);
        }
    }
}

fn do_unseal_check(node_id: &str) {
    // This calls the REAL production loader. On no-TPM / absent-blob / PCR
    // mismatch it does NOT return — it logs a SIEM-critical refusal and the
    // process exits(199), exactly as a service would at startup. So if we reach
    // the println below, the unseal succeeded on this genuine boot chain.
    let mut seed = load_node_identity_seed_sealed(node_id);
    seed.zeroize();
    println!(
        "PASS: unsealed INDEPENDENT per-node identity seed for '{}' on this boot chain. \
         PCR policy satisfied — genuine hardware. (A clone / changed boot chain would exit 199.)",
        node_id
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seal") => do_seal(args.get(2).map(String::as_str).unwrap_or_else(|| usage_exit())),
        Some("unseal-check") => {
            do_unseal_check(args.get(2).map(String::as_str).unwrap_or_else(|| usage_exit()))
        }
        _ => usage_exit(),
    }
}
