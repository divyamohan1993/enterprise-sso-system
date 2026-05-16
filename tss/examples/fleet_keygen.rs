//! MILNET Fleet Commander — offline FROST + PQ key ceremony helper.
//!
//! Invoked by `deploy/windows-fleet/keygen/key-ceremony.sh`. It runs the
//! production FROST 3-of-5 distributed key generation (Pedersen DKG — no
//! trusted dealer, via `crypto::threshold::dkg_distributed`), seals one
//! `KeyPackage` per signer with the fleet master KEK, and emits the group
//! public key plus a fresh ML-DSA-87 verifying key — all using the exact
//! crate functions the deployed services consume, so the formats match.
//!
//! Usage:
//!   cargo run --release --example fleet_keygen -p tss -- <out-dir>
//!
//! The environment MUST carry `MILNET_MASTER_KEK` (and the single-KEK acks)
//! so the sealed shares are decryptable by the signers, which share that KEK.
//!
//! Output files in <out-dir>:
//!   tss_share_1..5.b64       hex( seal_signer_share(..) )  -> MILNET_TSS_SHARE_SEALED
//!   tss_signer_1..5.id       hex( Identifier::serialize )  -> coordinator addr id
//!   tss_public_key.b64       hex( PublicKeyPackage::serialize ) -> MILNET_TSS_PUBLIC_KEY_PACKAGE
//!   group_verifying_key.hex  hex( postcard(PublicKeyPackage) )  -> MILNET_GROUP_VERIFYING_KEY
//!   pq_verifying_key.hex     hex( ML-DSA-87 encoded vk )         -> MILNET_PQ_VERIFYING_KEY
//!   tss_threshold.txt        the integer threshold (3)

use std::fs;
use std::path::PathBuf;

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: fleet_keygen <out-dir>");
    let out = PathBuf::from(out);
    fs::create_dir_all(&out).expect("create out dir");

    // 1. FROST 3-of-5 distributed key generation (Pedersen DKG, no trusted dealer).
    let mut dkg = crypto::threshold::dkg_distributed(5, 3);
    let threshold = dkg.group.threshold;
    let pkp = dkg.group.public_key_package.clone();

    // 2. Split the DKG result into the 5 independent signer nodes.
    let (_coordinator, signers) = tss::distributed::distribute_shares(&mut dkg);
    assert_eq!(signers.len(), 5, "expected exactly 5 FROST signer nodes");

    // 3. Seal each signer's share with the fleet master KEK and record its
    //    FROST identifier (the coordinator addresses signers by identifier).
    for (i, node) in signers.iter().enumerate() {
        let idx = i + 1;
        let sealed = tss::distributed::seal_signer_share(node, &pkp, threshold);
        fs::write(out.join(format!("tss_share_{idx}.b64")), hex::encode(&sealed))
            .expect("write sealed share");
        let id_hex = hex::encode(node.identifier().serialize());
        fs::write(out.join(format!("tss_signer_{idx}.id")), &id_hex)
            .expect("write signer id");
    }

    // 4. Group public key — two encodings for the two consumers.
    let pkp_ser = pkp.serialize().expect("serialize PublicKeyPackage");
    fs::write(out.join("tss_public_key.b64"), hex::encode(&pkp_ser))
        .expect("write public key package");
    let pkp_postcard = postcard::to_allocvec(&pkp).expect("postcard-encode PublicKeyPackage");
    fs::write(out.join("group_verifying_key.hex"), hex::encode(&pkp_postcard))
        .expect("write group verifying key");
    fs::write(out.join("tss_threshold.txt"), threshold.to_string())
        .expect("write threshold");

    // 5. ML-DSA-87 post-quantum verifying key for the verifier service.
    let (_pq_sk, pq_vk) = crypto::pq_sign::generate_pq_keypair();
    let pq_enc = pq_vk.encode();
    fs::write(
        out.join("pq_verifying_key.hex"),
        hex::encode(pq_enc.as_slice()),
    )
    .expect("write pq verifying key");

    eprintln!(
        "[fleet_keygen] FROST {}-of-5 + ML-DSA-87 material written to {}",
        threshold,
        out.display()
    );
}
