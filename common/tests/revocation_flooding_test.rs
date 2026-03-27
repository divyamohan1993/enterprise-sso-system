use common::revocation::SharedRevocationList;

#[test]
fn test_revocation_flooding_evicts_legitimate_entries() {
    // SECURITY AUDIT: Revocation flooding can evict legitimate revocations
    //
    // An attacker who can issue revocation commands may flood the list with
    // dummy token IDs until the bounded capacity is reached, causing the
    // oldest legitimate revocations to be evicted via the 10%-oldest eviction
    // policy. This test documents the known trade-off between bounded memory
    // and revocation durability.

    let srl = SharedRevocationList::new();

    // Revoke a legitimate token
    let legitimate_token: [u8; 16] = [0xAA; 16];
    assert!(srl.revoke(legitimate_token), "first revocation should succeed");
    assert!(
        srl.is_revoked(&legitimate_token),
        "legitimate token must be revoked immediately after insertion"
    );

    // Flood with 100,001 unique dummy token IDs to exceed MAX_ENTRIES (100,000).
    // The legitimate token was inserted first, so it is the oldest entry and
    // will be evicted when the list hits capacity and triggers oldest-10% eviction.
    for i in 0u128..100_001 {
        let mut id = [0u8; 16];
        // Use i+1 to avoid colliding with the legitimate token (all-0xAA)
        let bytes = (i + 1).to_le_bytes();
        id.copy_from_slice(&bytes);
        srl.revoke(id);
    }

    // The legitimate token was the very first (oldest) entry. After flooding
    // past MAX_ENTRIES the eviction policy removes the oldest 10%, which
    // includes our legitimate token.
    let still_revoked = srl.is_revoked(&legitimate_token);

    // Document the security finding: the legitimate token has been evicted.
    // In a production system this is mitigated by:
    //   1. Rate-limiting revocation commands
    //   2. Persisting revocations to a database (PersistentRevocationList)
    //   3. SIEM alerting at 90% capacity
    assert!(
        !still_revoked,
        "Legitimate token should have been evicted by the flooding attack — \
         this documents the known bounded-capacity trade-off"
    );
}

#[test]
fn test_revocation_lookup_is_constant_time_hashset() {
    // Verify O(1) HashSet-backed lookup semantics: revoked tokens return true,
    // non-revoked tokens return false.

    let srl = SharedRevocationList::new();

    let revoked_token: [u8; 16] = [0xBB; 16];
    let non_revoked_token: [u8; 16] = [0xCC; 16];

    srl.revoke(revoked_token);

    assert!(
        srl.is_revoked(&revoked_token),
        "revoked token must be found in the HashSet"
    );
    assert!(
        !srl.is_revoked(&non_revoked_token),
        "non-revoked token must not be found in the HashSet"
    );
}
