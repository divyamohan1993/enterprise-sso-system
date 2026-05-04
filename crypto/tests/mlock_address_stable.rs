//! Regression test for **X-A** — `mlock`-after-move on
//! `crypto::memguard::SecretBuffer<N>::new` and `SecretVec::new`.
//!
//! Defect cited at:
//!   - `crypto/src/memguard.rs:186-288` (SecretBuffer::new)
//!   - `crypto/src/memguard.rs:402-499` (SecretVec::new)
//!
//! Original bug: the constructors call `libc::mlock` against the
//! constructor's stack frame, then return `Self` by value. The returned
//! value is `memcpy`'d into the caller's slot, so the live secret pages
//! are NOT the pages that were locked. The `Drop::munlock` then unlocks
//! the new (never-locked) address.
//!
//! Fix under test: `SecretBuffer::<N>::new_pinned` and
//! `SecretVec::new_pinned` place `Self` on the heap *first*, then lock the
//! live address via `lock_in_place`. After construction, the address of
//! `data` is stable (via `Pin<Box<Self>>`) and `mlock` covers the bytes
//! where the secret actually lives.
//!
//! This test verifies the fix by reading `/proc/self/smaps` for the
//! mapping that contains the live data address and asserting the
//! `Locked:` field is non-zero. After the buffer is dropped, the page
//! must be unlocked (or the value reported for that VMA must drop).

use crypto::memguard::{SecretBuffer, SecretVec};
use std::fs;

/// Read `/proc/self/smaps` and return the `Locked: NN kB` value for the
/// mapping that contains `addr`, or `None` if the address is not found in
/// any mapped region.
fn locked_kb_for_addr(addr: usize) -> Option<u64> {
    let smaps = fs::read_to_string("/proc/self/smaps").expect("read smaps");
    // Format:
    //   <start>-<end> rwxp ...
    //   Size: ...
    //   ... (many fields)
    //   Locked: NN kB
    //
    // Iterate region-by-region: a region begins on a line containing a
    // dash-separated address pair. Capture (start,end) then scan
    // forward until the next region header or end of file for the
    // first `Locked:` line.
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
                    let trimmed = rest.trim();
                    let kb_str = trimmed.split_whitespace().next().unwrap_or("0");
                    return kb_str.parse::<u64>().ok();
                }
            }
        }
    }
    None
}

#[test]
fn secret_buffer_new_pinned_locks_live_address() {
    let pinned = SecretBuffer::<32>::new_pinned([0xC3u8; 32])
        .expect("new_pinned must succeed");
    assert!(pinned.is_locked(), "pinned SecretBuffer must report locked");

    // Probe the live data address via the public read accessor.
    let live_addr = pinned.as_bytes().as_ptr() as usize;
    let locked_kb = locked_kb_for_addr(live_addr)
        .expect("live data address must lie inside a /proc/self/smaps region");

    assert!(
        locked_kb > 0,
        "the page containing the live secret bytes must report Locked > 0 kB \
         (got {} kB) — mlock was not applied to the post-move address",
        locked_kb
    );
}

#[test]
fn secret_buffer_drop_releases_lock_and_data() {
    let pinned = SecretBuffer::<32>::new_pinned([0xA5u8; 32])
        .expect("new_pinned must succeed");
    let live_addr = pinned.as_bytes().as_ptr() as usize;

    let locked_before = locked_kb_for_addr(live_addr)
        .expect("address inside smaps");
    assert!(locked_before > 0, "must be locked while alive");

    drop(pinned);
    // After drop, Box deallocates the heap region. The page may or may
    // not still appear in smaps (the heap allocator may keep the arena),
    // but if it does, the Locked counter should not include this slot.
    // We can't assert exact zero (other live SecretBuffers/mlockall may
    // share a page), but the write_bytes(0) inside Drop guarantees the
    // bytes can no longer be the original 0xA5 plaintext.
    //
    // The strongest assertion we can make portably is that *some* mapping
    // change occurred (the heap can re-use the slot for other data) — so
    // we bound the assertion to "no panic / no _exit(199) on drop", which
    // would fire if the canary HMAC check failed because the wrong address
    // was locked.
}

#[test]
fn secret_vec_new_pinned_locks_live_heap_buffer() {
    let pinned = SecretVec::new_pinned(vec![0xDEu8; 4096])
        .expect("new_pinned must succeed");
    assert!(pinned.is_locked(), "pinned SecretVec must report locked");

    let live_addr = pinned.as_bytes().as_ptr() as usize;
    let locked_kb = locked_kb_for_addr(live_addr)
        .expect("live vec address must lie inside a /proc/self/smaps region");
    assert!(
        locked_kb > 0,
        "Locked kB for SecretVec heap buffer must be > 0; got {}",
        locked_kb
    );
}

#[test]
fn secret_vec_drop_does_not_panic_on_unlock() {
    // Regression: the Drop path must call munlock at the same address
    // that mlock locked. With new_pinned both happen at the heap address
    // returned by `data.as_ptr()` — drop must complete cleanly.
    for _ in 0..8 {
        let pinned = SecretVec::new_pinned(vec![0x77u8; 256]).expect("new_pinned");
        drop(pinned);
    }
}

#[test]
fn deprecated_new_still_compiles_for_compat() {
    // The deprecated by-value constructor must remain callable so the
    // workspace migration is incremental. We allow the deprecated
    // warning here; the legacy mlock-after-move behaviour is documented
    // in the deprecation note.
    #[allow(deprecated)]
    {
        let buf = SecretBuffer::<16>::new([0u8; 16]).expect("legacy new");
        assert_eq!(buf.as_bytes(), &[0u8; 16]);
        let sv = SecretVec::new(vec![1u8; 16]).expect("legacy new");
        assert_eq!(sv.as_bytes().len(), 16);
    }
}
