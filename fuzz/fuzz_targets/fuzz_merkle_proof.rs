#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 64 bytes for a root hash, 64 for a leaf, 8 for index, 8 for tree_size
    if data.len() < 144 {
        return;
    }
    let mut root = [0u8; 64];
    root.copy_from_slice(&data[..64]);
    let mut leaf = [0u8; 64];
    leaf.copy_from_slice(&data[64..128]);
    // Clamp untrusted length prefixes to a fuzz-safe ceiling (1 << 20 leaves)
    // to prevent allocation blow-up and unreachable-branch explosion.
    const FUZZ_MAX_TREE: usize = 1 << 20;
    let raw_tree_size = u64::from_le_bytes(data[136..144].try_into().unwrap()) as usize;
    let tree_size = raw_tree_size.min(FUZZ_MAX_TREE);
    if tree_size == 0 {
        return;
    }
    let raw_index = u64::from_le_bytes(data[128..136].try_into().unwrap()) as usize;
    if raw_index >= tree_size {
        return;
    }
    let index = raw_index;

    // Build proof elements from remaining data (64 bytes each)
    let remaining = &data[144..];
    let num_proofs = remaining.len() / 64;
    let proof: Vec<[u8; 64]> = (0..num_proofs)
        .map(|i| {
            let mut p = [0u8; 64];
            p.copy_from_slice(&remaining[i * 64..(i + 1) * 64]);
            p
        })
        .collect();

    // Exercise verification -- should never panic, only return true/false
    let _ = kt::merkle::MerkleTree::verify_inclusion(&root, &leaf, &proof, index);
    let _ = kt::merkle::MerkleTree::verify_inclusion_with_size(&root, &leaf, &proof, index, tree_size);
});
