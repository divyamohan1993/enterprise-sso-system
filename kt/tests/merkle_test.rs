use kt::merkle::MerkleTree;
use uuid::Uuid;

#[test]
fn empty_tree_has_zero_root() {
    let tree = MerkleTree::new();
    assert_eq!(tree.root(), [0u8; 64]);
    assert!(tree.is_empty());
}

#[test]
fn single_leaf_root_equals_leaf() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0xAA; 32];
    let leaf = tree.append_credential_op(&user, "register", &cred_hash, 1_000_000);
    assert_eq!(tree.root(), leaf);
    assert_eq!(tree.len(), 1);
}

#[test]
fn inclusion_proof_valid() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0xBB; 32];

    let mut leaves = Vec::new();
    for i in 0..4 {
        let leaf = tree.append_credential_op(&user, "register", &cred_hash, i * 1000);
        leaves.push(leaf);
    }

    let root = tree.root();
    let proof = tree.inclusion_proof(2).expect("proof should exist");
    assert!(MerkleTree::verify_inclusion(&root, &leaves[2], &proof, 2));
}

#[test]
fn inclusion_proof_rejects_wrong_leaf() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0xCC; 32];

    for i in 0..4 {
        tree.append_credential_op(&user, "register", &cred_hash, i * 1000);
    }

    let root = tree.root();
    let proof = tree.inclusion_proof(2).expect("proof should exist");
    let wrong_leaf = [0xFF; 64];
    assert!(!MerkleTree::verify_inclusion(&root, &wrong_leaf, &proof, 2));
}

#[test]
fn root_changes_on_append() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0xDD; 32];

    tree.append_credential_op(&user, "register", &cred_hash, 1000);
    let root_before = tree.root();

    tree.append_credential_op(&user, "rotate", &cred_hash, 2000);
    let root_after = tree.root();

    assert_ne!(root_before, root_after);
}

#[test]
fn multiple_operations_tracked() {
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0xEE; 32];

    let register_leaf = tree.append_credential_op(&user, "register", &cred_hash, 1000);
    let rotate_leaf = tree.append_credential_op(&user, "rotate", &cred_hash, 2000);
    let revoke_leaf = tree.append_credential_op(&user, "revoke", &cred_hash, 3000);

    // All leaves should be distinct since operations differ
    assert_ne!(register_leaf, rotate_leaf);
    assert_ne!(rotate_leaf, revoke_leaf);
    assert_ne!(register_leaf, revoke_leaf);

    assert_eq!(tree.len(), 3);
}

#[test]
fn inclusion_proof_out_of_bounds_returns_none() {
    let tree = MerkleTree::new();
    assert!(tree.inclusion_proof(0).is_none());

    let mut tree2 = MerkleTree::new();
    let user = Uuid::new_v4();
    tree2.append_credential_op(&user, "register", &[0; 32], 0);
    assert!(tree2.inclusion_proof(1).is_none());
}

// ── Hardened security tests ───────────────────────────────────────────

#[test]
fn test_merkle_inclusion_proof_verifies() {
    // Key transparency: clients can verify credential operations via Merkle proofs
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0x42; 32];

    let mut leaves = Vec::new();
    for i in 0..6 {
        let leaf = tree.append_credential_op(&user, "register", &cred_hash, i * 1000);
        leaves.push(leaf);
    }

    let root = tree.root();

    // Verify inclusion proof for each leaf
    for idx in 0..leaves.len() {
        let proof = tree
            .inclusion_proof(idx)
            .expect("proof must exist for valid index");
        assert!(
            MerkleTree::verify_inclusion(&root, &leaves[idx], &proof, idx),
            "inclusion proof for leaf {} must verify against root",
            idx
        );
    }
}

#[test]
fn test_merkle_root_changes_on_any_modification() {
    // Any change to the tree produces a different root — tamper evident
    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0x55; 32];

    tree.append_credential_op(&user, "register", &cred_hash, 1000);
    tree.append_credential_op(&user, "rotate", &cred_hash, 2000);
    tree.append_credential_op(&user, "authenticate", &cred_hash, 3000);

    let root_before = tree.root();

    // Adding one more entry must change the root
    tree.append_credential_op(&user, "revoke", &cred_hash, 4000);
    let root_after = tree.root();

    assert_ne!(
        root_before, root_after,
        "root must change after appending a new entry"
    );
}

#[test]
fn test_merkle_uses_rfc6962_domain_separation() {
    // RFC 6962 domain separation prevents second-preimage attacks
    use sha2::{Digest, Sha512};

    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0x77; 32];

    let leaf1 = tree.append_credential_op(&user, "register", &cred_hash, 1000);
    let leaf2 = tree.append_credential_op(&user, "rotate", &cred_hash, 2000);

    // Verify leaf nodes use 0x00 prefix: leaf hash starts with SHA-512(0x00 || ...)
    // We cannot directly inspect internal hashing, but we can verify that the
    // root of a 2-leaf tree equals SHA-512(0x01 || leaf1 || leaf2), confirming
    // internal nodes use the 0x01 prefix.
    let root = tree.root();

    let mut hasher = Sha512::new();
    hasher.update(&[0x01]); // RFC 6962 internal node prefix
    hasher.update(leaf1);
    hasher.update(leaf2);
    let expected_root: [u8; 64] = hasher.finalize().into();

    assert_eq!(
        root, expected_root,
        "2-leaf root must equal SHA-512(0x01 || leaf1 || leaf2), confirming RFC 6962 domain separation"
    );

    // Verify that a leaf computed WITHOUT the 0x00 prefix would differ,
    // proving the 0x00 prefix is actually applied.
    let mut bad_hasher = Sha512::new();
    // Omit the 0x00 prefix — just hash the raw content
    bad_hasher.update(b"kt-leaf");
    bad_hasher.update(user.as_bytes());
    bad_hasher.update(b"register");
    bad_hasher.update(&cred_hash);
    bad_hasher.update(1000i64.to_le_bytes());
    let bad_leaf: [u8; 64] = bad_hasher.finalize().into();

    assert_ne!(
        leaf1, bad_leaf,
        "leaf without 0x00 prefix must differ, proving domain separation is applied"
    );
}
