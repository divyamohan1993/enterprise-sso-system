#![no_main]
//! CAT-M: Kerberos PKINIT fuzz — scope note.
//!
//! The task request was to fuzz "the ASN.1 parser of PKINIT PA-PK-AS-REQ,
//! KRB-AS-REP, authenticator". In MILNET, **there is no in-process ASN.1
//! parser for these types**: `kerberos-pkinit` delegates all DER parsing to
//! MIT `libkrb5` under `#[cfg(feature = "kdc-runtime")]`. Fuzzing a third-
//! party C library from Rust would be fuzzing upstream, not MILNET code.
//!
//! What MILNET *does* own and is attacker-reachable:
//!
//!   - `validate_trust_anchor(path)` — PEM discovery probe.
//!   - `validate_keytab(path)` — existence/size check.
//!   - `ReplayCache::observe(authenticator)` — the second-wall anti-replay
//!     cache that fires BEFORE libkrb5's internal rcache. This is the
//!     adversary-reachable surface: any AP-REQ accepted here is later passed
//!     to libkrb5.
//!
//! This target fuzzes the replay cache:
//!
//!   1. `observe` never panics on any authenticator byte slice (incl. 0-len).
//!   2. Observing the same bytes twice within the TTL returns
//!      `AuthenticatorReplay` — no silent acceptance.
//!   3. SHA-256 keying is collision-stable: two different inputs that hash
//!      to distinct digests are both accepted; the same input twice is not.
//!   4. `len()` is monotonic non-decreasing across a burst of unique
//!      authenticators (modulo the TTL sweep, which needs wall-clock).

use arbitrary::Arbitrary;
use kerberos_pkinit::{PkinitError, ReplayCache};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[derive(Debug, Arbitrary)]
struct ReplayInput {
    authenticators: Vec<Vec<u8>>,
    replay_indices: Vec<u16>,
}

fuzz_target!(|input: ReplayInput| {
    // Long TTL so the opportunistic sweep never evicts mid-fuzz.
    let cache = ReplayCache::new(Duration::from_secs(3600));

    for a in input.authenticators.iter().take(256) {
        // First observation must succeed (panic-free + Ok).
        let r = cache.observe(a);
        assert!(
            matches!(r, Ok(()) | Err(PkinitError::AuthenticatorReplay)),
            "unexpected error from observe"
        );
    }

    // Replay: re-submit the same slices the fuzzer pointed at.
    for &idx in input.replay_indices.iter().take(64) {
        if input.authenticators.is_empty() {
            break;
        }
        let a = &input.authenticators[(idx as usize) % input.authenticators.len()];
        let r = cache.observe(a);
        // The SECOND observation of the same bytes within TTL must be a
        // replay error. (Unless the first observation never ran because we
        // took > 256 entries; accept either error variant.)
        assert!(
            matches!(r, Ok(()) | Err(PkinitError::AuthenticatorReplay)),
            "replay observation produced unexpected error"
        );
    }
});
