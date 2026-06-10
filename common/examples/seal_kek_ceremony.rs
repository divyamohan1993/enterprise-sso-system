//! MILNET vTPM master-KEK seal ceremony (anti-clone binding).
//!
//! Seals master-KEK material to THIS node's vTPM under the measured-boot PCR
//! policy (`platform_integrity::MASTER_KEK_PCR_LIST` = sha256:0,2,4,7) so that a
//! clone of the disk image on DIFFERENT hardware cannot unseal it. This is the
//! operator-run, per-node companion to `kek_ceremony` (which only generates the
//! Shamir shares): here we take ONE node's share (or a single 32-byte KEK) and
//! bind it to that node's TPM.
//!
//! Requires a real TPM 2.0 device (`/dev/tpmrm0` or `/dev/tpm0`) and tpm2-tools
//! on PATH (`/usr/bin` or `/usr/local/bin`). On a test host use `swtpm` +
//! `tpm2-abrmd` (or `TPM2TOOLS_TCTI=swtpm:...`).
//!
//! Usage:
//!   # Seal a single 32-byte master KEK (hex, 64 chars):
//!   cargo run --release --example seal_kek_ceremony -p common -- \
//!       seal single <kek-hex-64>
//!
//!   # Seal this node's Shamir share (66-char KekShare hex from kek_ceremony):
//!   cargo run --release --example seal_kek_ceremony -p common -- \
//!       seal share <kekshare-hex-66>
//!   #   ...or read the share hex from a file (e.g. kek-share-1.hex):
//!   cargo run --release --example seal_kek_ceremony -p common -- \
//!       seal share @/path/to/kek-share-1.hex
//!
//!   # Verify the sealed blob unseals on THIS boot chain (positive check):
//!   cargo run --release --example seal_kek_ceremony -p common -- \
//!       unseal-check single|share
//!
//! The sealed blob directory is read from `MILNET_SEALED_KEK_DIR`
//! (default `/var/lib/milnet/sealed`). Blob names: `master-kek-tpm` (single) /
//! `kek-share-tpm` (share), as `.pub`/`.priv` pairs.
//!
//! SWTPM EXERCISE (matches the audit verification plan):
//!   1. seal share  @kek-share-1.hex            -> writes the sealed blob
//!   2. unseal-check share                      -> PASS (same boot chain)
//!   3. export MILNET_MILITARY_DEPLOYMENT=1; unset MILNET_MASTER_KEK MILNET_KEK_SHARE
//!      then start a service -> get_master_kek() unseals + derives.
//!   4. tpm2_pcrextend 0:sha256=<any> ; unseal-check share
//!      -> FAILS (PCR mismatch). A service started now exits(199): fail-closed.
//!
//! SECURITY: run on the genuine node, as the service user. The material passed
//! on argv is sensitive; prefer the `@file` form (0600) so the KEK/share does
//! not land in shell history or `/proc/<pid>/cmdline` of a long-lived process.
//! This binary zeroizes the in-memory material after sealing.

use common::sealed_keys::{
    seal_master_kek_to_tpm, seal_node_identity_to_tpm, sealed_node_identity_name, SealedKekMode,
    Tpm2ToolsKekSealer, TpmKekSealer, SEALED_KEK_SHARE_NAME, SEALED_KEK_SINGLE_NAME,
};
use zeroize::Zeroize;

fn usage_exit() -> ! {
    eprintln!(
        "usage:\n  \
         seal_kek_ceremony seal single <kek-hex-64>\n  \
         seal_kek_ceremony seal share  <kekshare-hex-66 | @file>\n  \
         seal_kek_ceremony seal node-identity <node-id>\n  \
         seal_kek_ceremony unseal-check single|share\n  \
         seal_kek_ceremony unseal-check node-identity <node-id>\n\n\
         MILNET_SEALED_KEK_DIR selects the blob dir (default /var/lib/milnet/sealed)."
    );
    std::process::exit(2);
}

fn parse_mode(s: &str) -> SealedKekMode {
    match s {
        "single" => SealedKekMode::SingleKek,
        "share" => SealedKekMode::Share,
        other => {
            eprintln!("unknown mode '{other}' (expected 'single' or 'share')");
            std::process::exit(2);
        }
    }
}

/// Resolve material from an argv token: literal hex, or `@path` to read the hex
/// (whitespace-trimmed) from a file.
fn resolve_material(token: &str) -> String {
    if let Some(path) = token.strip_prefix('@') {
        match std::fs::read_to_string(path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                eprintln!("cannot read material file '{path}': {e}");
                std::process::exit(2);
            }
        }
    } else {
        token.to_string()
    }
}

/// Decode a hex string into bytes, exiting on malformed input.
fn decode_hex_or_exit(hex: &str, what: &str) -> Vec<u8> {
    match hex::decode(hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{what} is not valid hex: {e}");
            std::process::exit(2);
        }
    }
}

fn do_seal(mode: SealedKekMode, material_token: &str) {
    let sealer = Tpm2ToolsKekSealer::from_env();
    if !sealer.tpm_available() {
        eprintln!(
            "FATAL: no vTPM device (/dev/tpmrm0 or /dev/tpm0). \
             Sealing requires a real TPM 2.0. On a test host start swtpm first."
        );
        std::process::exit(1);
    }

    let mut hex_str = resolve_material(material_token);

    let result = match mode {
        SealedKekMode::SingleKek => {
            // Single mode: material is the raw 32-byte KEK (hex -> bytes).
            let mut kek = decode_hex_or_exit(&hex_str, "single KEK");
            if kek.len() != 32 {
                kek.zeroize();
                hex_str.zeroize();
                eprintln!(
                    "FATAL: single KEK must be exactly 32 bytes (64 hex chars), got {} bytes",
                    kek.len()
                );
                std::process::exit(2);
            }
            let r = seal_master_kek_to_tpm(&sealer, mode, &kek);
            kek.zeroize();
            r
        }
        SealedKekMode::Share => {
            // Share mode: material IS the ASCII KekShare hex; seal_master_kek_to_tpm
            // validates it parses as a KekShare before sealing.
            seal_master_kek_to_tpm(&sealer, mode, hex_str.as_bytes())
        }
    };

    hex_str.zeroize();

    match result {
        Ok(()) => {
            let name = match mode {
                SealedKekMode::SingleKek => SEALED_KEK_SINGLE_NAME,
                SealedKekMode::Share => SEALED_KEK_SHARE_NAME,
            };
            println!(
                "OK: sealed {:?} material to vTPM as '{}' under PCR policy {} (dir: {}).",
                mode,
                name,
                common::platform_integrity::MASTER_KEK_PCR_LIST,
                std::env::var("MILNET_SEALED_KEK_DIR")
                    .unwrap_or_else(|_| common::platform_integrity::DEFAULT_SEALED_DIR.to_string()),
            );
            println!(
                "NEXT: remove MILNET_MASTER_KEK / MILNET_KEK_SHARE from this node's \
                 deployment, set MILNET_MILITARY_DEPLOYMENT=1, and (re)start the service."
            );
        }
        Err(e) => {
            eprintln!("FATAL: seal failed: {e}");
            std::process::exit(1);
        }
    }
}

fn do_unseal_check(mode: SealedKekMode) {
    let sealer = Tpm2ToolsKekSealer::from_env();
    if !sealer.tpm_available() {
        eprintln!("FATAL: no vTPM device — cannot unseal-check.");
        std::process::exit(1);
    }
    let name = match mode {
        SealedKekMode::SingleKek => SEALED_KEK_SINGLE_NAME,
        SealedKekMode::Share => SEALED_KEK_SHARE_NAME,
    };
    match sealer.unseal(name) {
        Ok(mut bytes) => {
            let len = bytes.len();
            bytes.zeroize();
            println!(
                "PASS: unsealed '{}' ({} bytes) on this boot chain. \
                 PCR policy satisfied — genuine hardware.",
                name, len
            );
        }
        Err(e) => {
            // This is the EXPECTED outcome on a clone / after tpm2_pcrextend:
            // fail-closed. We exit non-zero so a test harness can assert it.
            eprintln!(
                "FAIL-CLOSED: unseal of '{}' refused: {}. \
                 (Expected on a clone / different hardware / changed boot chain — \
                 a service started here would exit 199.)",
                name, e
            );
            std::process::exit(199);
        }
    }
}

/// CEREMONY: generate a fresh INDEPENDENT per-node ML-DSA-87 identity seed and
/// seal it to THIS node's vTPM. Prints the derived verifying key (hex) to publish
/// for peer pinning. The seed itself never leaves the node.
fn do_seal_node_identity(raw_node_id: &str) {
    let sealer = Tpm2ToolsKekSealer::from_env();
    if !sealer.tpm_available() {
        eprintln!(
            "FATAL: no vTPM device (/dev/tpmrm0 or /dev/tpm0). \
             Sealing requires a real TPM 2.0. On a test host start swtpm first."
        );
        std::process::exit(1);
    }

    // CANONICALIZE the operator's node-id the SAME way the runtime does
    // (UUID / hex / UUIDv5 fallback). The sealed-blob name is derived from the
    // canonical UUID string, so it matches what `for_node` will look up at
    // startup even if the deploy uses a non-UUID id like `orchestrator-0`.
    let nid = common::cluster::canonical_node_id(raw_node_id);
    let canonical = nid.to_string();

    match seal_node_identity_to_tpm(&sealer, &canonical) {
        Ok(mut seed) => {
            println!(
                "OK: generated + sealed per-node identity to vTPM as '{}' under PCR \
                 policy {} (dir: {}).",
                sealed_node_identity_name(&canonical),
                common::platform_integrity::MASTER_KEK_PCR_LIST,
                std::env::var("MILNET_SEALED_KEK_DIR")
                    .unwrap_or_else(|_| common::platform_integrity::DEFAULT_SEALED_DIR.to_string()),
            );
            if raw_node_id != canonical {
                println!(
                    "NOTE: '{raw_node_id}' canonicalized to NodeId {canonical} \
                     (set MILNET_NODE_ID='{raw_node_id}' on the node; the runtime \
                     derives the same NodeId)."
                );
            }
            // Derive + print the verifying key to publish (seed stays sealed) —
            // exactly the VK the running service publishes for peer pinning.
            let vk = common::distributed_startup::NodeIdentity::from_sealed_seed(nid.0, seed)
                .verifying_key();
            println!(
                "RAFT_VERIFYING_KEY (publish this for peer pinning): {}",
                hex::encode(&vk)
            );
            seed.zeroize();
            println!(
                "NEXT: set MILNET_MILITARY_DEPLOYMENT=1 and start the service; \
                 for_node will UNSEAL this seed (fail-closed if absent)."
            );
        }
        Err(e) => {
            eprintln!("FATAL: node-identity seal failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Verify the per-node identity blob unseals on THIS boot chain (positive check;
/// fails closed with exit 199 on a clone / changed PCRs).
fn do_unseal_check_node_identity(raw_node_id: &str) {
    let sealer = Tpm2ToolsKekSealer::from_env();
    if !sealer.tpm_available() {
        eprintln!("FATAL: no vTPM device — cannot unseal-check.");
        std::process::exit(1);
    }
    // Same canonicalization as seal + runtime, so the blob name lines up.
    let canonical = common::cluster::canonical_node_id(raw_node_id).to_string();
    let name = sealed_node_identity_name(&canonical);
    match sealer.unseal(&name) {
        Ok(mut bytes) => {
            let len = bytes.len();
            bytes.zeroize();
            println!(
                "PASS: unsealed '{}' ({} bytes) on this boot chain. \
                 PCR policy satisfied — genuine hardware.",
                name, len
            );
        }
        Err(e) => {
            eprintln!(
                "FAIL-CLOSED: unseal of '{}' refused: {}. \
                 (Expected on a clone / different hardware / changed boot chain — \
                 a service started here would exit 199.)",
                name, e
            );
            std::process::exit(199);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seal") => {
            let what = args.get(2).map(String::as_str).unwrap_or_else(|| usage_exit());
            if what == "node-identity" {
                let node_id = args.get(3).map(String::as_str).unwrap_or_else(|| usage_exit());
                do_seal_node_identity(node_id);
            } else {
                let mode = parse_mode(what);
                let material = args.get(3).map(String::as_str).unwrap_or_else(|| usage_exit());
                do_seal(mode, material);
            }
        }
        Some("unseal-check") => {
            let what = args.get(2).map(String::as_str).unwrap_or_else(|| usage_exit());
            if what == "node-identity" {
                let node_id = args.get(3).map(String::as_str).unwrap_or_else(|| usage_exit());
                do_unseal_check_node_identity(node_id);
            } else {
                do_unseal_check(parse_mode(what));
            }
        }
        _ => usage_exit(),
    }
}
