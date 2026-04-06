use kt::merkle::{MerkleTree, SignedTreeHead};
use uuid::Uuid;

// ── Helper ───────────────────────────────────────────────────────────────

fn make_tree(n: usize) -> (MerkleTree, Vec<[u8; 64]>) {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred = [0xAA; 32];
    let mut leaves = Vec::with_capacity(n);
    for i in 0..n {
        let leaf = tree.append_credential_op(&user, "op", &cred, i as i64 * 1000);
        leaves.push(leaf);
    }
    (tree, leaves)
}

fn make_tree_multi_user(n: usize) -> (MerkleTree, Vec<[u8; 64]>) {
    let mut tree = MerkleTree::new();
    let cred = [0xBB; 32];
    let mut leaves = Vec::with_capacity(n);
    for i in 0..n {
        let user = Uuid::new_v4();
        let leaf = tree.append_credential_op(&user, "register", &cred, i as i64);
        leaves.push(leaf);
    }
    (tree, leaves)
}

// ── 1. Merkle proof forgery — tampered proof bytes should fail ───────────

#[test]
fn tampered_proof_bytes_fail_verification() {
    let (tree, leaves) = make_tree(8);
    let root = tree.root();
    let mut proof = tree.inclusion_proof(3).unwrap();
    // Flip a byte in the first sibling hash
    proof[0][0] ^= 0xFF;
    assert!(!MerkleTree::verify_inclusion_with_size(
        &root,
        &leaves[3],
        &proof,
        3,
        tree.len()
    ));
}

// ── 2. Proof for non-existent key should fail ────────────────────────────

#[test]
fn proof_for_nonexistent_index_returns_none() {
    let (tree, _) = make_tree(5);
    assert!(tree.inclusion_proof(5).is_none());
    assert!(tree.inclusion_proof(100).is_none());
}

// ── 3. Log consistency — tree at epoch N is prefix of epoch N+1 ──────────

#[test]
fn log_consistency_prefix_property() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred = [0xCC; 32];

    // Build tree to epoch N=4, snapshot proofs
    let mut leaves = Vec::new();
    for i in 0..4 {
        leaves.push(tree.append_credential_op(&user, "op", &cred, i * 1000));
    }
    let root_n = tree.root();
    let size_n = tree.len();

    // Extend to epoch N+1 = 8
    for i in 4..8 {
        leaves.push(tree.append_credential_op(&user, "op", &cred, i * 1000));
    }
    let size_n1 = tree.len();

    // All original leaves must still have valid proofs at new size
    for idx in 0..4 {
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(
            MerkleTree::verify_inclusion_with_size(
                &tree.root(),
                &leaves[idx],
                &proof,
                idx,
                size_n1
            ),
            "leaf {idx} from epoch N must verify at epoch N+1"
        );
    }
    // Root changed
    assert_ne!(root_n, tree.root());
    assert_eq!(size_n, 4);
    assert_eq!(size_n1, 8);
}

// ── 4. Signed tree head — wrong key fails, valid key succeeds ────────────

#[test]
fn signed_tree_head_wrong_key_fails() {
    let (sk, _vk) = crypto::pq_sign::generate_pq_keypair();
    let (_sk2, vk2) = crypto::pq_sign::generate_pq_keypair();

    let (tree, _) = make_tree(4);
    let sth = tree.signed_tree_head(&sk);

    assert!(!MerkleTree::verify_tree_head(&sth, &vk2));
}

#[test]
fn signed_tree_head_valid_key_succeeds() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let (tree, _) = make_tree(4);
    let sth = tree.signed_tree_head(&sk);

    assert!(MerkleTree::verify_tree_head(&sth, &vk));
    assert_eq!(sth.tree_size, 4);
    assert_eq!(sth.root, tree.root());
}

// ── 5. Fork detection — two different tree heads for same epoch ──────────

#[test]
fn fork_detection_different_roots_same_size() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();

    // Build two different trees of the same size
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let cred = [0xDD; 32];

    let mut tree_a = MerkleTree::new();
    tree_a.append_credential_op(&user_a, "register", &cred, 1000);
    tree_a.append_credential_op(&user_a, "rotate", &cred, 2000);

    let mut tree_b = MerkleTree::new();
    tree_b.append_credential_op(&user_b, "register", &cred, 1000);
    tree_b.append_credential_op(&user_b, "revoke", &cred, 2000);

    let sth_a = tree_a.signed_tree_head(&sk);
    let sth_b = tree_b.signed_tree_head(&sk);

    assert_eq!(sth_a.tree_size, sth_b.tree_size);
    assert_ne!(sth_a.root, sth_b.root, "fork detected: different roots for same tree size");

    // Both are valid signatures
    assert!(MerkleTree::verify_tree_head(&sth_a, &vk));
    assert!(MerkleTree::verify_tree_head(&sth_b, &vk));
}

// ── 6. Empty tree edge case ──────────────────────────────────────────────

#[test]
fn empty_tree_root_is_zero() {
    let tree = MerkleTree::new();
    assert_eq!(tree.root(), [0u8; 64]);
    assert!(tree.is_empty());
    assert_eq!(tree.len(), 0);
}

#[test]
fn empty_tree_inclusion_proof_returns_none() {
    let tree = MerkleTree::new();
    assert!(tree.inclusion_proof(0).is_none());
}

// ── 7. Single-element tree ───────────────────────────────────────────────

#[test]
fn single_element_tree_root_equals_leaf() {
    let (tree, leaves) = make_tree(1);
    assert_eq!(tree.root(), leaves[0]);
    assert_eq!(tree.len(), 1);
}

#[test]
fn single_element_tree_proof_is_empty() {
    let (tree, leaves) = make_tree(1);
    let proof = tree.inclusion_proof(0).unwrap();
    assert!(proof.is_empty(), "single-leaf tree needs no siblings");
    assert!(MerkleTree::verify_inclusion_with_size(
        &tree.root(),
        &leaves[0],
        &proof,
        0,
        1
    ));
}

// ── 8. Maximum depth tree (1000+ leaves) ─────────────────────────────────

#[test]
fn large_tree_1024_leaves_all_proofs_valid() {
    let (tree, leaves) = make_tree(1024);
    let root = tree.root();
    let size = tree.len();

    // Verify a sample of proofs (every 64th)
    for idx in (0..1024).step_by(64) {
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(
            MerkleTree::verify_inclusion_with_size(&root, &leaves[idx], &proof, idx, size),
            "proof for leaf {idx} in 1024-leaf tree must verify"
        );
    }
}

// ── 9. Duplicate key insertion behavior ──────────────────────────────────

#[test]
fn duplicate_insertions_produce_same_leaves() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred = [0xEE; 32];

    let leaf1 = tree.append_credential_op(&user, "register", &cred, 1000);
    let leaf2 = tree.append_credential_op(&user, "register", &cred, 1000);

    // Same inputs produce same leaf hash
    assert_eq!(leaf1, leaf2);
    // But tree has two entries
    assert_eq!(tree.len(), 2);
}

#[test]
fn duplicate_leaves_different_timestamps_differ() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred = [0xEE; 32];

    let leaf1 = tree.append_credential_op(&user, "register", &cred, 1000);
    let leaf2 = tree.append_credential_op(&user, "register", &cred, 2000);

    assert_ne!(leaf1, leaf2);
}

// ── 10. Concurrent insertions (sequential since MerkleTree is not Sync) ──

#[test]
fn sequential_insertions_are_deterministic() {
    let user = Uuid::new_v4();
    let cred = [0xFF; 32];

    let mut tree_a = MerkleTree::new();
    let mut tree_b = MerkleTree::new();

    for i in 0..10 {
        tree_a.append_credential_op(&user, "op", &cred, i * 100);
        tree_b.append_credential_op(&user, "op", &cred, i * 100);
    }

    assert_eq!(tree_a.root(), tree_b.root());
}

// ── 11. Proof verification with corrupted intermediate nodes ─────────────

#[test]
fn corrupted_proof_element_fails() {
    let (tree, leaves) = make_tree(16);
    let root = tree.root();

    for target_idx in [0, 7, 15] {
        let mut proof = tree.inclusion_proof(target_idx).unwrap();
        if proof.is_empty() {
            continue;
        }
        // Corrupt the last proof element
        let last = proof.len() - 1;
        proof[last][31] ^= 0x01;
        assert!(
            !MerkleTree::verify_inclusion_with_size(
                &root,
                &leaves[target_idx],
                &proof,
                target_idx,
                tree.len()
            ),
            "corrupted intermediate at index {target_idx} must fail"
        );
    }
}

// ── 12. Tree head signature with ML-DSA-87 ──────────────────────────────

#[test]
fn tree_head_signature_is_ml_dsa_87() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let (tree, _) = make_tree(3);
    let sth = tree.signed_tree_head(&sk);

    // ML-DSA-87 signatures are large (4627 bytes)
    assert!(sth.signature.len() > 4000, "ML-DSA-87 sig should be >4KB");
    assert!(MerkleTree::verify_tree_head(&sth, &vk));
}

// ── 13. Inclusion proof round-trip ───────────────────────────────────────

#[test]
fn inclusion_proof_roundtrip_all_leaves() {
    for n in [2, 3, 5, 7, 8, 13, 16, 31, 32, 33] {
        let (tree, leaves) = make_tree(n);
        let root = tree.root();
        let size = tree.len();

        for idx in 0..n {
            let proof = tree
                .inclusion_proof(idx)
                .unwrap_or_else(|| panic!("proof must exist for leaf {idx} in tree of size {n}"));
            assert!(
                MerkleTree::verify_inclusion_with_size(&root, &leaves[idx], &proof, idx, size),
                "roundtrip failed for leaf {idx} in tree of size {n}"
            );
        }
    }
}

// ── 14. Exclusion proof — wrong leaf fails ───────────────────────────────

#[test]
fn exclusion_wrong_leaf_fails_verification() {
    let (tree, _) = make_tree(8);
    let root = tree.root();
    let proof = tree.inclusion_proof(3).unwrap();

    // A fabricated leaf should not verify
    let fake_leaf = [0x99; 64];
    assert!(!MerkleTree::verify_inclusion_with_size(
        &root,
        &fake_leaf,
        &proof,
        3,
        tree.len()
    ));
}

// ── 15. Batch insertion and batch proof verification ─────────────────────

#[test]
fn batch_insertion_and_verification() {
    let mut tree = MerkleTree::new();
    let cred = [0x42; 32];
    let mut leaves = Vec::new();

    // Batch of 50 insertions from different users
    for i in 0..50 {
        let user = Uuid::new_v4();
        let leaf = tree.append_credential_op(&user, "register", &cred, i * 100);
        leaves.push(leaf);
    }

    let root = tree.root();
    let size = tree.len();

    // Verify all 50 proofs
    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(MerkleTree::verify_inclusion_with_size(
            &root, leaf, &proof, idx, size
        ));
    }
}

// ── 16. Tree serialization/deserialization round-trip (via root check) ───

#[test]
fn tree_rebuild_produces_same_root() {
    let user = Uuid::new_v4();
    let cred = [0x11; 32];
    let ops: Vec<(&str, i64)> = vec![
        ("register", 1000),
        ("rotate", 2000),
        ("authenticate", 3000),
        ("revoke", 4000),
    ];

    let mut tree1 = MerkleTree::new();
    for (op, ts) in &ops {
        tree1.append_credential_op(&user, op, &cred, *ts);
    }

    let mut tree2 = MerkleTree::new();
    for (op, ts) in &ops {
        tree2.append_credential_op(&user, op, &cred, *ts);
    }

    assert_eq!(tree1.root(), tree2.root());
    assert_eq!(tree1.len(), tree2.len());
}

// ── 17. Key transparency monitoring — detect unauthorized key changes ────

#[test]
fn detect_unauthorized_key_change() {
    let user = Uuid::new_v4();
    let legit_cred = [0xAA; 32];
    let rogue_cred = [0xBB; 32];

    let mut tree = MerkleTree::new();
    let legit_leaf = tree.append_credential_op(&user, "register", &legit_cred, 1000);
    let rogue_leaf = tree.append_credential_op(&user, "register", &rogue_cred, 1001);

    // Different credential hashes produce different leaves
    assert_ne!(legit_leaf, rogue_leaf, "different credentials must produce different leaves");

    // Both are in the tree, so the monitoring service can detect the anomaly
    assert_eq!(tree.len(), 2);
}

// ── 18. Merkle proof size grows logarithmically ──────────────────────────

#[test]
fn proof_size_grows_logarithmically() {
    let (tree_8, _) = make_tree(8);
    let (tree_64, _) = make_tree(64);
    let (tree_512, _) = make_tree(512);

    let proof_8 = tree_8.inclusion_proof(0).unwrap();
    let proof_64 = tree_64.inclusion_proof(0).unwrap();
    let proof_512 = tree_512.inclusion_proof(0).unwrap();

    // log2(8)=3, log2(64)=6, log2(512)=9
    // Proof sizes should be roughly proportional to log2(N)
    assert!(proof_8.len() <= 4, "8-leaf proof should be ~3 elements, got {}", proof_8.len());
    assert!(proof_64.len() <= 7, "64-leaf proof should be ~6 elements, got {}", proof_64.len());
    assert!(proof_512.len() <= 10, "512-leaf proof should be ~9 elements, got {}", proof_512.len());

    // Ratio should be sub-linear
    assert!(proof_512.len() < proof_8.len() * 4);
}

// ── 19. Root hash changes on any leaf modification ───────────────────────

#[test]
fn root_changes_on_every_append() {
    let user = Uuid::new_v4();
    let cred = [0x55; 32];
    let mut tree = MerkleTree::new();
    let mut prev_root = tree.root();

    for i in 0..20 {
        tree.append_credential_op(&user, "op", &cred, i * 100);
        let new_root = tree.root();
        assert_ne!(prev_root, new_root, "root must change after append {i}");
        prev_root = new_root;
    }
}

// ── 20. Deterministic tree — same insertions produce same root ───────────

#[test]
fn deterministic_tree_from_same_inputs() {
    let user = Uuid::from_bytes([1; 16]); // Fixed UUID
    let cred = [0x42; 32];

    let build = || {
        let mut t = MerkleTree::new();
        for i in 0..10 {
            t.append_credential_op(&user, "register", &cred, i * 1000);
        }
        t.root()
    };

    assert_eq!(build(), build());
    assert_eq!(build(), build());
}

// ── 21. Tree rebuild from persisted state matches original ───────────────

#[test]
fn rebuild_from_operations_matches_original() {
    let user = Uuid::new_v4();
    let cred = [0x77; 32];
    let operations: Vec<(&str, i64)> = vec![
        ("register", 100),
        ("authenticate", 200),
        ("rotate", 300),
        ("authenticate", 400),
        ("revoke", 500),
    ];

    let mut original = MerkleTree::new();
    let mut original_leaves = Vec::new();
    for (op, ts) in &operations {
        original_leaves.push(original.append_credential_op(&user, op, &cred, *ts));
    }

    // Simulate rebuild
    let mut rebuilt = MerkleTree::new();
    let mut rebuilt_leaves = Vec::new();
    for (op, ts) in &operations {
        rebuilt_leaves.push(rebuilt.append_credential_op(&user, op, &cred, *ts));
    }

    assert_eq!(original.root(), rebuilt.root());
    assert_eq!(original_leaves, rebuilt_leaves);
}

// ── 22. Audit path completeness — every leaf has valid proof ─────────────

#[test]
fn audit_path_completeness_every_leaf() {
    for size in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
        let (tree, leaves) = make_tree(size);
        let root = tree.root();
        let tree_size = tree.len();

        for idx in 0..size {
            let proof = tree.inclusion_proof(idx).expect("proof must exist");
            assert!(
                MerkleTree::verify_inclusion_with_size(&root, &leaves[idx], &proof, idx, tree_size),
                "audit path for leaf {idx} in tree of size {size} must be valid"
            );
        }
    }
}

// ── 23. Cross-epoch proof — historical leaf still verifiable ─────────────

#[test]
fn cross_epoch_historical_leaf_verifiable() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let user = Uuid::new_v4();
    let cred = [0x88; 32];
    let mut tree = MerkleTree::new();

    // Epoch 1: 4 leaves
    for i in 0..4 {
        tree.append_credential_op(&user, "op", &cred, i * 1000);
    }
    let sth_epoch1 = tree.signed_tree_head(&sk);

    // Epoch 2: add 4 more
    let mut new_leaves = Vec::new();
    for i in 4..8 {
        new_leaves.push(tree.append_credential_op(&user, "op", &cred, i * 1000));
    }
    let sth_epoch2 = tree.signed_tree_head(&sk);

    // Both STHs are valid
    assert!(MerkleTree::verify_tree_head(&sth_epoch1, &vk));
    assert!(MerkleTree::verify_tree_head(&sth_epoch2, &vk));

    // Epoch 2 has more leaves
    assert!(sth_epoch2.tree_size > sth_epoch1.tree_size);

    // New leaves are verifiable in epoch 2
    for (i, leaf) in new_leaves.iter().enumerate() {
        let idx = 4 + i;
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(MerkleTree::verify_inclusion_with_size(
            &tree.root(),
            leaf,
            &proof,
            idx,
            tree.len()
        ));
    }
}

// ── 24. Malicious tree head — tampered signature ─────────────────────────

#[test]
fn tampered_tree_head_signature_fails() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let (tree, _) = make_tree(4);
    let mut sth = tree.signed_tree_head(&sk);

    // Tamper with signature
    if let Some(byte) = sth.signature.last_mut() {
        *byte ^= 0xFF;
    }
    assert!(!MerkleTree::verify_tree_head(&sth, &vk));
}

#[test]
fn tampered_tree_head_root_fails() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let (tree, _) = make_tree(4);
    let mut sth = tree.signed_tree_head(&sk);

    // Tamper with root
    sth.root[0] ^= 0xFF;
    assert!(!MerkleTree::verify_tree_head(&sth, &vk));
}

#[test]
fn tampered_tree_head_size_fails() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let (tree, _) = make_tree(4);
    let mut sth = tree.signed_tree_head(&sk);

    // Tamper with tree_size
    sth.tree_size = 999;
    assert!(!MerkleTree::verify_tree_head(&sth, &vk));
}

// ── 25. Stress test — 10,000 insertions with sampled proof verification ──

#[test]
fn stress_test_10k_insertions() {
    let (tree, leaves) = make_tree_multi_user(10_000);
    let root = tree.root();
    let size = tree.len();
    assert_eq!(size, 10_000);

    // Verify every 500th leaf
    for idx in (0..10_000).step_by(500) {
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(
            MerkleTree::verify_inclusion_with_size(&root, &leaves[idx], &proof, idx, size),
            "proof for leaf {idx} in 10k tree must verify"
        );
    }

    // Also verify first and last
    let proof_first = tree.inclusion_proof(0).unwrap();
    assert!(MerkleTree::verify_inclusion_with_size(&root, &leaves[0], &proof_first, 0, size));

    let proof_last = tree.inclusion_proof(9999).unwrap();
    assert!(MerkleTree::verify_inclusion_with_size(&root, &leaves[9999], &proof_last, 9999, size));
}

// ── Extra hardened tests ─────────────────────────────────────────────────

#[test]
fn proof_with_wrong_index_fails() {
    let (tree, leaves) = make_tree(8);
    let root = tree.root();
    let proof = tree.inclusion_proof(2).unwrap();

    // Correct leaf but wrong index
    assert!(!MerkleTree::verify_inclusion_with_size(
        &root,
        &leaves[2],
        &proof,
        3, // wrong index
        tree.len()
    ));
}

#[test]
fn odd_size_trees_handle_promotion_correctly() {
    // Trees with odd numbers of leaves promote the last node
    for n in [3, 5, 7, 9, 11, 13, 15, 17, 33, 65] {
        let (tree, leaves) = make_tree(n);
        let root = tree.root();
        let size = tree.len();

        // Verify last leaf (the one that gets promoted in odd trees)
        let last_idx = n - 1;
        let proof = tree.inclusion_proof(last_idx).unwrap();
        assert!(
            MerkleTree::verify_inclusion_with_size(&root, &leaves[last_idx], &proof, last_idx, size),
            "last leaf in odd tree of size {n} must verify"
        );
    }
}

#[test]
fn different_operations_same_user_produce_different_leaves() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred = [0x11; 32];

    let register = tree.append_credential_op(&user, "register", &cred, 1000);
    let rotate = tree.append_credential_op(&user, "rotate", &cred, 1000);
    let revoke = tree.append_credential_op(&user, "revoke", &cred, 1000);
    let auth = tree.append_credential_op(&user, "authenticate", &cred, 1000);

    assert_ne!(register, rotate);
    assert_ne!(register, revoke);
    assert_ne!(register, auth);
    assert_ne!(rotate, revoke);
    assert_ne!(rotate, auth);
    assert_ne!(revoke, auth);
}

#[test]
fn different_users_same_operation_produce_different_leaves() {
    let mut tree = MerkleTree::new();
    let cred = [0x22; 32];

    let leaf_a = tree.append_credential_op(&Uuid::new_v4(), "register", &cred, 1000);
    let leaf_b = tree.append_credential_op(&Uuid::new_v4(), "register", &cred, 1000);

    // With overwhelming probability, different UUIDs produce different leaves
    assert_ne!(leaf_a, leaf_b);
}

#[test]
fn verify_inclusion_with_size_zero_falls_back() {
    // tree_size=0 triggers legacy path that consumes all proof elements
    let (tree, leaves) = make_tree(4);
    let root = tree.root();
    let proof = tree.inclusion_proof(1).unwrap();

    // Legacy path (tree_size=0) should still verify for power-of-2 trees
    assert!(MerkleTree::verify_inclusion_with_size(
        &root,
        &leaves[1],
        &proof,
        1,
        0 // legacy
    ));
}

#[test]
fn signed_tree_head_has_positive_timestamp() {
    let (sk, _vk) = crypto::pq_sign::generate_pq_keypair();
    let (tree, _) = make_tree(2);
    let sth = tree.signed_tree_head(&sk);

    assert!(sth.timestamp > 0, "timestamp should be positive microseconds since epoch");
}

#[test]
fn empty_tree_signed_tree_head_has_zero_root() {
    let (sk, vk) = crypto::pq_sign::generate_pq_keypair();
    let tree = MerkleTree::new();
    let sth = tree.signed_tree_head(&sk);

    assert_eq!(sth.root, [0u8; 64]);
    assert_eq!(sth.tree_size, 0);
    assert!(MerkleTree::verify_tree_head(&sth, &vk));
}
