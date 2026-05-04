//! Regression test for **X-B** — `mlock`-after-move on
//! `common::encrypted_db::EncryptedPool::new`.
//!
//! Defect cited at:
//!   - `common/src/encrypted_db.rs:42-57` (legacy `EncryptedPool::new`)
//!
//! Original bug: the constructor builds `let s = Self { ... master_kek }`,
//! then runs `libc::mlock(s.master_kek.as_ptr(), 32)` against the local
//! stack copy, then returns `s` by value. After the move the master KEK
//! lives at the caller's address, which is NOT mlocked. The doc-comment
//! claim "Required to prevent the root database encryption key from being
//! written to swap" is therefore false on the resident copy.
//!
//! Fix under test: `EncryptedPool::new_pinned(pool, Zeroizing<[u8;32]>)`
//! places `Self` on the heap, then calls `lock_in_place(self: Pin<&mut
//! Self>)` to mlock the live KEK address.
//!
//! This test does NOT require a live PostgreSQL connection — we only
//! need a `PgPool` value to construct the wrapper. `PgPool::connect_lazy`
//! defers any actual DB connection, so we can assemble the pool struct,
//! pin it, and read `/proc/self/smaps` for the live KEK address.

use common::encrypted_db::EncryptedPool;
use sqlx::postgres::PgPoolOptions;
use std::fs;
use zeroize::Zeroizing;

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

/// Build an `EncryptedPool` whose `pool` field is a lazy connection that
/// is never actually opened. This lets the test run without a live
/// Postgres instance — sufficient because we only probe the KEK address.
fn build_lazy_pool() -> sqlx::PgPool {
    // `connect_lazy` does not contact the server; it only constructs the
    // pool descriptor. Any URL with valid syntax is accepted.
    PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://test:test@127.0.0.1:5432/none")
        .expect("connect_lazy must succeed for a syntactically valid URL")
}

#[test]
fn encrypted_pool_new_pinned_locks_live_kek() {
    let pool = build_lazy_pool();
    let kek = Zeroizing::new([0xC3u8; 32]);
    let pinned = EncryptedPool::new_pinned(pool, kek);

    // The KEK lives inside the heap allocation that backs `Pin<Box<...>>`.
    // We can't read the field directly (it's private), but we can take
    // the address of `&*pinned` — the inline `master_kek: [u8; 32]` lives
    // at a known offset within `Self`. The *whole struct* is mlocked, so
    // probing the struct's base address suffices.
    let base_addr = &*pinned as *const EncryptedPool as usize;
    let locked_kb = locked_kb_for_addr(base_addr)
        .expect("EncryptedPool heap address must lie inside a /proc/self/smaps region");

    assert!(
        locked_kb > 0,
        "the page containing the live master KEK must report Locked > 0 kB \
         (got {} kB) — mlock was not applied to the post-move address",
        locked_kb
    );
}

#[test]
fn encrypted_pool_drop_zeroes_kek_path() {
    // Regression: legacy Drop munlocks an address that was never mlocked
    // (because mlock targeted the constructor frame, not the post-move
    // address). With `new_pinned` mlock and munlock both target the
    // pinned heap address; drop must complete cleanly.
    for _ in 0..4 {
        let pool = build_lazy_pool();
        let pinned = EncryptedPool::new_pinned(pool, Zeroizing::new([0u8; 32]));
        drop(pinned);
    }
}

#[test]
fn deprecated_new_still_compiles_for_compat() {
    let pool = build_lazy_pool();
    #[allow(deprecated)]
    {
        let _legacy = EncryptedPool::new(pool, [0u8; 32]);
    }
}
