use crypto::pq_sign::generate_pq_keypair;
use kt::merkle::MerkleTree;
use uuid::Uuid;

#[test]
fn test_kt_signed_tree_head() {
    let (sk, vk) = generate_pq_keypair();

    let mut tree = MerkleTree::new();
    let user = Uuid::new_v4();
    let cred_hash = [0xAA; 32];
    tree.append_credential_op(&user, "register", &cred_hash, 1_000_000);
    tree.append_credential_op(&user, "rotate", &cred_hash, 2_000_000);

    let sth = tree.signed_tree_head(&sk);
    assert_eq!(sth.root, tree.root());
    assert_eq!(sth.tree_size, 2);
    assert!(!sth.signature.is_empty());

    // Verify the signed tree head
    assert!(MerkleTree::verify_tree_head(&sth, &vk));

    // Wrong key should fail verification
    let (_sk2, vk2) = generate_pq_keypair();
    assert!(!MerkleTree::verify_tree_head(&sth, &vk2));
}
