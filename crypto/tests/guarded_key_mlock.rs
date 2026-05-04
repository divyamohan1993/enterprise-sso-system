//! Regression test for **X-A.2** — `mlock`-after-move on
//! `crypto::dpop::GuardedSigningKey::new`.
//!
//! Defect cited at:
//!   - `crypto/src/dpop.rs:51-66` (legacy `GuardedSigningKey::new`)
//!
//! Original bug: the constructor calls `libc::mlock` against `&guarded.key`
//! *inside* the constructor; `guarded` is then returned by value and
//! `memcpy`'d into the caller's slot. The mlocked region is the
//! constructor's stack/return slot, not the final storage location. The
//! Drop impl then `munlock`s the new (never-locked) address — and panics
//! in military mode if munlock returns EINVAL.
//!
//! Fix under test: `GuardedSigningKey::new_pinned` places the wrapper on
//! the heap first via `Pin<Box<Self>>`, then calls `lock_in_place` to
//! mlock the address of the inner `DpopSigningKey` at its now-stable
//! pinned location. After construction, `mlock` covers the bytes where
//! the signing key actually lives.

use crypto::dpop::{generate_dpop_keypair_pinned, GuardedSigningKey, DpopSigningKey};
use ml_dsa::{KeyGen, MlDsa87};
use std::fs;

fn locked_kb_for_addr(addr: usize) -> Option<u64> {
    let smaps = fs::read_to_string("/proc/self/smaps").ok()?;
    let mut current_range: Option<(usize, usize)> = None;
    for line in smaps.lines() {
        if let Some((range_part, _rest)) = line.split_once(' ') {
            if let Some((start_hex, end_hex)) = range_part.split_once('-') {
                if let (Ok(s), Ok(e)) = (
                    usize::from_str_radix(start_hex, 16),
                    usize::from_str_radix(end_hex, 16),
                ) {
                    current_range = Some((s, e));
                    continue;
                }
            }
        }
        if let Some((s, e)) = current_range {
            if addr >= s && addr < e {
                if let Some(rest) = line.strip_prefix("Locked:") {
                    let kb_str = rest.trim().split_whitespace().next().unwrap_or("0");
                    return kb_str.parse::<u64>().ok();
                }
            }
        }
    }
    None
}

#[test]
fn guarded_signing_key_new_pinned_locks_live_address() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("entropy");
    let kp = MlDsa87::from_seed(&seed.into());
    let pinned = GuardedSigningKey::new_pinned(kp.signing_key().clone())
        .expect("new_pinned must succeed");

    let live_addr = pinned.signing_key() as *const DpopSigningKey as usize;
    let locked_kb = locked_kb_for_addr(live_addr)
        .expect("live signing-key address must lie inside a /proc/self/smaps region");

    assert!(
        locked_kb > 0,
        "the page containing the live ML-DSA-87 signing key must report Locked > 0 kB \
         (got {} kB) — mlock was not applied to the post-move address",
        locked_kb
    );
}

#[test]
fn generate_dpop_keypair_pinned_round_trips() {
    let (pinned, _vk) = generate_dpop_keypair_pinned()
        .expect("generate_dpop_keypair_pinned must succeed");
    // Smoke: signing_key accessor works through Pin<Box<...>>.
    let _sk = pinned.signing_key();
}

#[test]
fn drop_after_pinned_lock_does_not_panic() {
    // Regression: legacy Drop tried to munlock an address that was never
    // mlocked (because mlock targeted the constructor frame, not the
    // post-move address). With `new_pinned` both happen at the same
    // pinned address, so munlock on Drop should succeed silently.
    for _ in 0..4 {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("entropy");
        let kp = MlDsa87::from_seed(&seed.into());
        let pinned = GuardedSigningKey::new_pinned(kp.signing_key().clone())
            .expect("new_pinned");
        drop(pinned);
    }
}

#[test]
fn deprecated_new_still_compiles_for_compat() {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("entropy");
    let kp = MlDsa87::from_seed(&seed.into());
    #[allow(deprecated)]
    {
        let _legacy = GuardedSigningKey::new(kp.signing_key().clone());
    }
}
