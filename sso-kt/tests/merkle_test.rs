use sso_kt::merkle::MerkleTree;
use uuid::Uuid;

#[test]
fn empty_tree_has_zero_root() {
    let tree = MerkleTree::new();
    assert_eq!(tree.root(), [0u8; 32]);
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
    let wrong_leaf = [0xFF; 32];
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
