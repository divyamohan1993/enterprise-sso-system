//! Integration-test environment bootstrap.
//!
//! audit/src/bft.rs guards (check_single_process_military_deployment,
//! cached_master_kek, check_bft_node_addresses, synthesize_or_load_signing_keys)
//! early-return only on cfg!(test) || cfg!(feature = "test-support"). For
//! integration tests the audit lib is linked as a normal dep — neither is set —
//! so we must set the ack envs BEFORE any BftAuditCluster constructor runs.
//!
//! Uses #[ctor] so the env is populated before libtest spawns test threads.
//! MILNET_MASTER_KEK value matches audit/src/bft.rs:1727 unit-test convention
//! and e2e/tests/error_path_hardened_test.rs:234 — 64-char hex, non-zero.

use ctor::ctor;
use once_cell::sync::Lazy;

static BOOTSTRAP: Lazy<()> = Lazy::new(|| {
    // 64-char hex, non-zero — satisfies load_master_kek_inner (sealed_keys.rs:655).
    std::env::set_var("MILNET_MASTER_KEK", "ab".repeat(32));
    // Bypasses the single-process military panic (bft.rs:585).
    std::env::set_var("MILNET_BFT_SINGLE_PROCESS_ACK", "1");
    // MILNET_MILITARY_DEPLOYMENT / MILNET_PRODUCTION deliberately LEFT UNSET so
    // fail-closed paths stay cold.
});

#[ctor]
fn init_test_env() {
    Lazy::force(&BOOTSTRAP);
}
