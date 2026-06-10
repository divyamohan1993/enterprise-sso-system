//! FIPS 140-3 Startup Known-Answer Tests (KATs).
//!
//! Implements self-tests per FIPS 140-3 Section 9 that MUST run at module
//! startup before any cryptographic service is provided. Each algorithm
//! is tested against hardcoded test vectors (from NIST CAVP where available).
//!
//! If ANY test fails, the module panics with a detailed error message
//! to prevent use of a potentially compromised cryptographic module.
//!
//! Tested algorithms:
//! - AES-256-GCM (FIPS 197 / SP 800-38D)
//! - SHA-512 (FIPS 180-4)
//! - SHA3-256 (FIPS 202)
//! - HKDF-SHA512 (SP 800-56C)
//! - HMAC-SHA512 (FIPS 198-1)
//! - PBKDF2-SHA512 (SP 800-132) — determinism test
//! - AEGIS-256 — encrypt/decrypt roundtrip
//! - ML-KEM-1024 (FIPS 203) — roundtrip test
//! - ML-DSA-87 (FIPS 204) — roundtrip test
//! - X-Wing combiner (ML-KEM-1024 + X25519) — full encap/decap + session key derivation
//! - FROST Ristretto255 — threshold signing (2-of-3 DKG + sign + verify)
//! - SLH-DSA-SHA2-256f (FIPS 205) — hash-based signature roundtrip

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::Sha3_256;

type HmacSha512 = Hmac<Sha512>;

// ────────────────────────────────────────────────────────────────────
// Test Vectors
// ────────────────────────────────────────────────────────────────────

/// AES-256-GCM test vector (NIST CAVP GCM Test Vectors).
/// Key:   feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
/// IV:    cafebabefacedbaddecaf888
/// PT:    d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
///        1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
/// AAD:   (empty)
const AES_GCM_KEY: [u8; 32] = [
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83,
    0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
    0x83, 0x08,
];

const AES_GCM_NONCE: [u8; 12] = [
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
];

const AES_GCM_PLAINTEXT: [u8; 64] = [
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26,
    0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
    0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49,
    0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
    0x1a, 0xaf, 0xd2, 0x55,
];

/// Expected AES-256-GCM ciphertext || tag for the above inputs (no AAD).
/// From NIST SP 800-38D test case #16.
const AES_GCM_EXPECTED_CT_TAG: [u8; 80] = [
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42,
    0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55,
    0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56,
    0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62,
    0x89, 0x80, 0x15, 0xad, 0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd, 0xec, 0x1a, 0x50,
    0x22, 0x70, 0xe3, 0xcc, 0x6c,
];

/// SHA-512 test vector (NIST CAVP).
/// Input: "abc"
/// Expected output (SHA-512):
const SHA512_INPUT: &[u8] = b"abc";
const SHA512_EXPECTED: [u8; 64] = [
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
    0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
    0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
    0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
    0xa5, 0x4c, 0xa4, 0x9f,
];

/// SHA3-256 test vector (NIST CAVP).
/// Input: "abc"
/// Expected output (SHA3-256):
const SHA3_256_INPUT: &[u8] = b"abc";
const SHA3_256_EXPECTED: [u8; 32] = [
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
    0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
    0x15, 0x32,
];

/// HKDF-SHA512 test vector (RFC 5869 adapted for SHA-512).
/// IKM:  0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
/// Salt: 0x000102030405060708090a0b0c (13 bytes)
/// Info: 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
/// L:    42
const HKDF_IKM: [u8; 22] = [
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
];

const HKDF_SALT: [u8; 13] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

const HKDF_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

/// HMAC-SHA512 test vector (RFC 4231 Test Case 2).
/// Key:  "Jefe"
/// Data: "what do ya want for nothing?"
const HMAC_KEY: &[u8] = b"Jefe";
const HMAC_DATA: &[u8] = b"what do ya want for nothing?";
const HMAC_SHA512_EXPECTED: [u8; 64] = [
    0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0,
    0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25,
    0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8,
    0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a,
    0x38, 0xbc, 0xe7, 0x37,
];

// ────────────────────────────────────────────────────────────────────
// Post-quantum KNOWN-ANSWER vectors (fixed input → fixed output)
//
// Unlike a roundtrip self-test (which a buggy or backdoored implementation
// can pass), these pin a deterministic input to the EXACT expected output
// bytes published by an authoritative source. A wrong/backdoored ML-KEM or
// ML-DSA implementation produces different bytes and fails closed.
//
// Sources:
// - ML-KEM-1024 (FIPS 203): NIST ACVP-Server, commit
//   65370b861b96efd30dfe0daae607bde26a78a5c8,
//   gen-val/json-files/ML-KEM-{keyGen,encapDecap}-FIPS203/internalProjection.json
//   (the same "internal projection" vectors the RustCrypto `ml-kem` crate
//   validates against). keyGen tcId 51, encapsulation tcId 51 (ML-KEM-1024).
// - ML-DSA-87 (FIPS 204): IETF LAMPS dilithium-certificates example
//   (github.com/lamps-wg/dilithium-certificates, examples/ML-DSA-87*),
//   also embedded in the `ml-dsa` crate's own test corpus. Seed 000102…1f
//   → fixed encoded verifying key.
// ────────────────────────────────────────────────────────────────────

/// ML-KEM-1024 keyGen KAT: deterministic seeds `d`,`z` → fixed `ek`,`dk`.
const MLKEM1024_KG_D: &str = "49ac8b99bb1e6a8ea818261f8be68bdeaa52897e7ec6c40b530bc760ab77dce3";
const MLKEM1024_KG_Z: &str = "99e3246884181f8e1dd44e0c7629093330221fd67d9b7d6e1510b2dbad8762f7";
const MLKEM1024_KG_EK: &str = "a04184d4bc7b532a0f70a54d7757cde6175a6843b861cb2bc4830c0012554cfc5d2c8a2027aa3cd967130e9b96241b11c4320c7649cc23a71bafe691afc08e680bcef42907000718e4eace8da28214197be1c269da9cb541e1a3ce97cfadf9c6058780fe6793dbfa8218a2760b802b8da2aa271a38772523a76736a7a31b9d3037ad21cebb11a472b8792eb17558b940e70883f264592c689b240bb43d5408bf446432f412f4b9a5f6865cc252a43cf40a320391555591d67561fdd05353ab6b019b3a08a73353d51b6113ab2fa51d975648ee254af89a230504a236a4658257740bdcbbe1708ab022c3c588a410db3b9c308a06275bdf5b4859d3a2617a295e1a22f90198bad0166f4a943417c5b831736cb2c8580abfde5714b586abeec0a175a08bc710c7a2895de93ac438061bf7765d0d21cd418167caf89d1efc3448bcbb96d69b3e010c82d15cab6cacc6799d3639669a5b21a633c865f8593b5b7bc800262bb837a924a6c5440e4fc73b41b23092c3912f4c6bebb4c7b4c62908b03775666c22220df9c88823e344c7308332345c8b795d34e8c051f21f5a21c214b69841358709b1c305b32cc2c3806ae9ccd3819fff4507fe520fbfc27199bc23be6b9b2d2ac1717579ac769279e2a7aac68a371a47ba3a7dbe016f14e1a727333663c4a5cd1a0f8836cf7b5c49ac51485ca60345c990e06888720003731322c5b8cd5e6907fda1157f468fd3fc20fa8175eec95c291a262ba8c5be990872418930852339d88a19b37fefa3cfe82175c224407ca414baeb37923b4d2d83134ae154e490a9b45a0563b06c953c3301450a2176a07c614a74e3478e48509f9a60ae945a8ebc7815121d90a3b0e07091a096cf02c57b25bca58126ad0c629ce166a7edb4b33221a0d3f72b85d562ec698b7d0a913d73806f1c5c87b38ec003cb303a3dc51b4b35356a67826d6edaa8feb93b98493b2d1c11b676a6ad9506a1aaae13a824c7c08d1c6c2c4dba9642c76ea7f6c8264b64a23ccca9a74635fcbf03e00f1b5722b214376790793b2c4f0a13b5c40760b4218e1d2594dcb30a70d9c1782a5dd30576fa4144bfc8416eda8118fc6472f56a979586f33bb070fb0f1b0b10bc4897ebe01bca3893d4e16adb25093a7417d0708c83a26322e22e6330091e30152bf823597c04ccf4cfc7331578f43a2726ccb428289a90c863259dd180c5ff142bef41c7717094be07856da2b140fa67710967356aa47dfbc8d255b4722ab86d439b7e0a6090251d2d4c1ed5f20bbe6807bf65a90b7cb2ec0102af02809dc9ac7d0a3abc69c18365bcff59185f33996887746185906c0191aed4407e139446459be29c6822717644353d24ab6339156a9c424909f0a9025bb74720779be43f16d81c8cc666e99710d8c68bb5cc4e12f314e925a551f09cc59003a1f88103c254bb978d75f394d3540e31e771cda36e39ec54a62b5832664d821a72f1e6afbba27f84295b2694c498498e812bc8e9378fe541cec5891b25062901cb7212e3cdc46179ec5bcec10bc0b9311de05074290687fd6a5392671654284cd9c8cc3eba80eb3b662eb53eb75116704a1feb5c2d056338532868ddf24eb8992ab8565d9e490cadf14804360daa90718eab616bab0765d33987b47efb6599c5563235e61e4be670e97955ab292d9732cb8930948ac82df230ac72297a23679d6b94c17f1359483254fedc2f05819f0d069a443b78e3fc6c3ef4714b05a3fca81cbba60242a7060cd885d8f39981bb18092b23daa59fd9578388688a09bba079bc809a54843a60385e2310bbcbcc0213ce3dfaab33b47f9d6305bc95c6107813c585c4b657bf30542833b14949f573c0612ad524baae69590c1277b86c286571bf66b3cff46a3858c09906a794df4a06e9d4b0a2e43f10f72a6c6c47e5646e2c799b71c33ed2f01eeb45938eb7a4e2e2908c53558a540d350369fa189c616943f7981d7618cf02a5b0a2bcc422e857d1a47871253d08293c1c179bcdc0437069107418205fdb9856623b8ca6b694c96c084b17f13bb6df12b2cfbbc2b0e0c34b00d0fcd0aecfb27924f6984e747be2a09d83a8664590a8077331491a4f7d720843f23e652c6fa840308db4020337aad37967034a9fb523b67ca70330f02d9ea20c1e84cb8e5757c9e1896b60581441ed618aa5b26da56c0a5a73c4dcfd755e610b4fc81ff84e21";
const MLKEM1024_KG_DK: &str = "8c8b3722a82e550565521611ebbc63079944c9b1abb3b0020ff12f631891a9c468d3a67bf6271280da58d03cb042b3a461441637f929c273469ad15311e910de18cb9537ba1be42e98bb59e498a13fd440d0e69ee832b45cd95c382177d67096a18c07f1781663651bdcac90deda3ddd143485864181c91fa2080f6dab3f86204ceb64a7b4446895c03987a031cb4b6d9e0462fda829172b6c012c638b29b5cd75a2c930a5596a3181c33a22d574d30261196bc350738d4fd9183a763336243aced99b3221c71d8866895c4e52c119bf3280daf80a95e15209a795c4435fbb3570fdb8aa9bf9aefd43b094b781d5a81136dab88b8799696556fec6ae14b0bb8be4695e9a124c2ab8ff4ab1229b8aaa8c6f41a60c34c7b56182c55c2c685e737c6ca00a23fb8a68c1cd61f30d3993a1653c1675ac5f0901a7160a73966408b8876b715396cfa4903fc69d60491f8146808c97cd5c533e71017909e97b835b86ff847b42a696375435e006061cf7a479463272114a89eb3eaf2246f0f8c104a14986828e0ad20420c9b37ea23f5c514949e77ad9e9ad12290dd1215e11da274457ac86b1ce6864b122677f3718aa31b02580e64317178d38f25f609bc6c55bc374a1bf78ea8ecc219b30b74cbb3272a599238c93985170048f176775fb19962ac3b135aa59db104f7114dbc2c2d42949adeca6a85b323ee2b2b23a77d9db235979a8e2d67cf7d2136bbba71f269574b38888e1541340c19284074f9b7c8cf37eb01384e6e3822ec4882dfbbec4e6098ef2b2fc177a1f0bcb65a57fdaa89315461beb7885fb68b3cd096eda596ac0e61dd7a9c507bc6345e0827dfcc8a3ac2dce51ad731aa0eb932a6d0983992347cbeb3cd0d9c9719797cc21cf0062b0ad94cad734c63e6b5d859cbe19f0368245351bf464d7505569790d2bb724d8659a9feb1c7c473dc4d061e29863a2714bac42adcd1a8372776556f7928a7a44e94b6a25322d03c0a1622a7fd261522b7358f085bdfb60758762cb901031901b5eecf4920c81020a9b1781bcb9dd19a9dfb66458e7757c52cec75b4ba740a24099cb56bb60a76b6901aa3e0169c9e83496d73c4c99435a28d613e97a1177f58b6cc595d3b2331e9ca7b57b74dc2c5277d26f2fe19240a55c35d6cfca26c73e9a2d7c980d97960ae1a04698c16b398a5f20c35a0914145ce1674b71abc6066a909a3e4b911e69d5a849430361f731b07246a6329b52361904225082d0aac5b21d6b34862481a890c3c360766f04263603a6b73e802b1f70b2eb00046836b8f493bf10b90b8737c6c548449b294c47253be26ca72336a632063ad3d0b48c8b0f4a34447ef13b764020de739eb79aba20e2be1951825f293bedd1089fcb0a91f560c8e17cdf52541dc2b81f972a7375b201f10c08d9b5bc8b95100054a3d0aaff89bd08d6a0e7f2115a435231290460c9ad435a3b3cf35e52091edd1890047bcc0aabb1acebc75f4a32bc1451acc4969940788e89412188946c9143c5046bd1b458df617c5df533b052cd6038b7754034a23c2f7720134c7b4eace01fac0a2853a9285847abbd06a3343a778ac6062e458bc5e61ece1c0de0206e6fe8a84034a7c5f1b005fb0a584051d3229b86c909ac5647b3d75569e05a88279d80e5c30f574dc327512c6bbe8101239ec62861f4be67b05b9cda9c545c13e7eb53cff260ad9870199c21f8c63d64f0458a7141285023feb829290872389644b0c3b73ac2c8e121a29bb1c43c19a233d56bed82740eb021c97b8ebba40ff328b541760fcc372b52d3bc4fcbc06f424eaf253804d4cb46f41ff254c0c5ba483b44a87c219654555ec7c163c79b9cb760a2ad9bb722b93e0c28bd4b1685949c496eab1aff90919e3761b346838abb2f01a91e554375afdaaaf3826e6db79fe7353a7a578a7c0598ce28b6d9915214236bbffa6d45b6376a07924a39a7be818286715c8a3c110cd76c02e0417af138bdb95c3cca798ac809ed69cfb672b6fddc24d89c06a6558814ab0c21c62b2f84c0e3e0803db337a4e0c7127a6b4c8c08b1d1a76bf07eb6e5b5bb47a16c74bc548375fb29cd789a5cff91bdbd071859f4846e355bb0d29484e264dff36c9177a7aca78908879695ca87f25436bc12630724bb22f0cb64897fe5c41195280da04184d4bc7b532a0f70a54d7757cde6175a6843b861cb2bc4830c0012554cfc5d2c8a2027aa3cd967130e9b96241b11c4320c7649cc23a71bafe691afc08e680bcef42907000718e4eace8da28214197be1c269da9cb541e1a3ce97cfadf9c6058780fe6793dbfa8218a2760b802b8da2aa271a38772523a76736a7a31b9d3037ad21cebb11a472b8792eb17558b940e70883f264592c689b240bb43d5408bf446432f412f4b9a5f6865cc252a43cf40a320391555591d67561fdd05353ab6b019b3a08a73353d51b6113ab2fa51d975648ee254af89a230504a236a4658257740bdcbbe1708ab022c3c588a410db3b9c308a06275bdf5b4859d3a2617a295e1a22f90198bad0166f4a943417c5b831736cb2c8580abfde5714b586abeec0a175a08bc710c7a2895de93ac438061bf7765d0d21cd418167caf89d1efc3448bcbb96d69b3e010c82d15cab6cacc6799d3639669a5b21a633c865f8593b5b7bc800262bb837a924a6c5440e4fc73b41b23092c3912f4c6bebb4c7b4c62908b03775666c22220df9c88823e344c7308332345c8b795d34e8c051f21f5a21c214b69841358709b1c305b32cc2c3806ae9ccd3819fff4507fe520fbfc27199bc23be6b9b2d2ac1717579ac769279e2a7aac68a371a47ba3a7dbe016f14e1a727333663c4a5cd1a0f8836cf7b5c49ac51485ca60345c990e06888720003731322c5b8cd5e6907fda1157f468fd3fc20fa8175eec95c291a262ba8c5be990872418930852339d88a19b37fefa3cfe82175c224407ca414baeb37923b4d2d83134ae154e490a9b45a0563b06c953c3301450a2176a07c614a74e3478e48509f9a60ae945a8ebc7815121d90a3b0e07091a096cf02c57b25bca58126ad0c629ce166a7edb4b33221a0d3f72b85d562ec698b7d0a913d73806f1c5c87b38ec003cb303a3dc51b4b35356a67826d6edaa8feb93b98493b2d1c11b676a6ad9506a1aaae13a824c7c08d1c6c2c4dba9642c76ea7f6c8264b64a23ccca9a74635fcbf03e00f1b5722b214376790793b2c4f0a13b5c40760b4218e1d2594dcb30a70d9c1782a5dd30576fa4144bfc8416eda8118fc6472f56a979586f33bb070fb0f1b0b10bc4897ebe01bca3893d4e16adb25093a7417d0708c83a26322e22e6330091e30152bf823597c04ccf4cfc7331578f43a2726ccb428289a90c863259dd180c5ff142bef41c7717094be07856da2b140fa67710967356aa47dfbc8d255b4722ab86d439b7e0a6090251d2d4c1ed5f20bbe6807bf65a90b7cb2ec0102af02809dc9ac7d0a3abc69c18365bcff59185f33996887746185906c0191aed4407e139446459be29c6822717644353d24ab6339156a9c424909f0a9025bb74720779be43f16d81c8cc666e99710d8c68bb5cc4e12f314e925a551f09cc59003a1f88103c254bb978d75f394d3540e31e771cda36e39ec54a62b5832664d821a72f1e6afbba27f84295b2694c498498e812bc8e9378fe541cec5891b25062901cb7212e3cdc46179ec5bcec10bc0b9311de05074290687fd6a5392671654284cd9c8cc3eba80eb3b662eb53eb75116704a1feb5c2d056338532868ddf24eb8992ab8565d9e490cadf14804360daa90718eab616bab0765d33987b47efb6599c5563235e61e4be670e97955ab292d9732cb8930948ac82df230ac72297a23679d6b94c17f1359483254fedc2f05819f0d069a443b78e3fc6c3ef4714b05a3fca81cbba60242a7060cd885d8f39981bb18092b23daa59fd9578388688a09bba079bc809a54843a60385e2310bbcbcc0213ce3dfaab33b47f9d6305bc95c6107813c585c4b657bf30542833b14949f573c0612ad524baae69590c1277b86c286571bf66b3cff46a3858c09906a794df4a06e9d4b0a2e43f10f72a6c6c47e5646e2c799b71c33ed2f01eeb45938eb7a4e2e2908c53558a540d350369fa189c616943f7981d7618cf02a5b0a2bcc422e857d1a47871253d08293c1c179bcdc0437069107418205fdb9856623b8ca6b694c96c084b17f13bb6df12b2cfbbc2b0e0c34b00d0fcd0aecfb27924f6984e747be2a09d83a8664590a8077331491a4f7d720843f23e652c6fa840308db4020337aad37967034a9fb523b67ca70330f02d9ea20c1e84cb8e5757c9e1896b60581441ed618aa5b26da56c0a5a73c4dcfd755e610b4fc81ff84e21d2e574dfd8cd0ae893aa7e125b44b924f45223ec09f2ad1141ea93a68050dbf699e3246884181f8e1dd44e0c7629093330221fd67d9b7d6e1510b2dbad8762f7";

/// ML-KEM-1024 encapsulation KAT: `ek`+coins `m` → fixed ciphertext `c`,
/// shared secret `k`. (Independent ek from the keyGen vector above.)
const MLKEM1024_ENC_EK: &str = "307a4cea4148219b958ea0b7886659235a4d1980b192610847d86ef32739f94c3b446c4d81d89b8b422a9d079c88b11acaf321b014294e18b296e52f3f744cf9634a4fb01db0d99ef20a633a552e76a0585c6109f018768b763af3678b4780089c1342b96907a29a1c11521c744c2797d0bf2b9ccdca614672b45076773f458a31ef869be1eb2efeb50d0e37495dc5ca55e07528934f6293c4168027d0e53d07facc6630cb08197e53fb193a171135dc8ad9979402a71b6926bcdcdc47b93401910a5fcc1a813b682b09ba7a72d2486d6c799516465c14729b26949b0b7cbc7c640f267fed80b162c51fd8e09227c101d505a8fae8a2d7054e28a78ba8750decf9057c83979f7abb084945648006c5b28804f34e73b238111a65a1f500b1cc606a848f2859070beba7573179f36149cf5801bf89a1c38cc278415528d03bdb943f96280c8cc52042d9b91faa9d6ea7bcbb7ab1897a3266966f78393426c76d8a49578b98b159ebb46ee0a883a270d8057cd0231c86906a91dbbade6b2469581e2bca2fea8389f7c74bcd70961ea5b934fbcf9a6590bf86b8db548854d9a3fb30110433bd7a1b659ca8568085639237b3bdc37b7fa716d482a25b54106b3a8f54d3aa99b5123da96066904592f3a54ee23a7981ab608a2f4413cc658946c6d7780ea765644b3cc06c70034ab4eb351912e7715b56755d09021571bf340ab92598a24e811893195b96a1629f8041f58658431561fc0ab15292b913ec473f04479bc145cd4c563a286235646cd305a9be1014e2c7b130c33eb77cc4a0d9786bd6bc2a954bf3005778f8917ce13789bbb962807858b67731572b6d3c9b4b5206fac9a7c8961698d88324a915186899b29923f08442a3d386bd416bcc9a100164c930ec35eafb6ab35851b6c8ce6377366a175f3d75298c518d44898933f53dee617145093379c4659f68583b2b28122666bec57838991ff16c368dd22c36e780c91a3582e25e19794c6bf2ab42458a8dd7705de2c2aa20c054e84b3ef35032798626c248263253a71a11943571340a978cd0a602e47dee540a8814ba06f31414797cdf6049582361bbaba387a83d89913fe4c0c112b95621a4bda8123a14d1a842fb57b83a4fbaf33a8e552238a596aae7a150d75da648bc44644977ba1f87a4c68a8c4bd245b7d00721f7d64e822b085b901312ec37a8169802160cce1160f010be8cbcace8e7b005d7839234a707868309d03784b4273b1c8a160133ed298184704625f29cfa086d13263ee5899123c596ba788e5c54a8e9ba829b8a9d904bc4bc0bbea76bc53ff811214598472c9c202b73eff035dc09703af7bf1babaac73193cb46117a7c9492a43fc95789a924c5912787b2e2090ebbcfd3796221f06debf9cf70e056b8b9161d6347f47335f3e1776da4bb87c15cc826146ff0249a413b45aa93a805196ea453114b524e310aedaa46e3b99642368782566d049a726d6cca910993aed621d0149ea588a9abd909dbb69aa22829d9b83ada2209a6c2659f2169d668b9314842c6e22a74958b4c25bbdcd293d99cb609d866749a485dfb56024883cf5465dba0363206587f45597f89002fb8607232138e03b2a894525f265370054b48863614472b95d0a2303442e378b0dd1c75acbab971a9a8d1281c79613acec6933c377b3c578c2a61a1ec181b101297a37cc5197b2942f6a0e4704c0ec63540481b9f159dc255b59bb55df496ae54217b7689bd51dba0383a3d72d852ffca76df05b66eeccbd47bc53040817628c71e361d6af889084916b408a466c96e7086c4a60a10fcf7537bb94afbcc7d437590919c28650c4f2368259226a9bfda3a3a0ba1b5087d9d76442fd786c6f81c68c0360d7194d7072c4533aea86c2d1f8c0a27696066f6cfd11003f797270b32389713cffa093d991b63844c385e72277f166f5a3934d6bb89a4788de28321defc7457ab484bd30986dc1dab3008cd7b22f69702fabb9a1045407da4791c3590ff599d81d688cfa7cc12a68c50f51a1009411b44850f9015dc84a93b17c7a207552c661ea9838e31b95ead546248e56be7a5130505268771199880a141771a9e47acfed590cb3aa7cb7c5f74911d8912c29d6233f4d53bc64139e2f55be75507dd77868e384aec581f3f411db1a742972d3ebfd3315c84a5ad63a0e75c8bca3e3041e05d9067aff3b1244f763e7983";
const MLKEM1024_ENC_M: &str = "59c5154c04ae43aaff32700f081700389d54bec4c37c088b1c53f66212b12c72";
const MLKEM1024_ENC_C: &str = "e2d5fd4c13cea0b52d874fea9012f3a51743a1093710bbf23950f9147a472ee5533928a2f46d592f35da8b4f758c893b0d7b98948be447b17cb2ae58af8a489ddd9232b99b1c0d2de77caa472bc3bbd4a7c60dbfdca92ebf3a1ce1c22dad13e887004e2924fd22656f5e508791de06d85e1a1426808ed9a89f6e2fd3c245d4758b22b02cade33b60fc889a33fc4447edebbfd4530de86596a33789d5dba6e6ec9f89879af4be4909a69017c9bb7a5e31815ea5f132eec4984faa7ccf594dd00d4d8487e45621af8f6e330551439c93ec078a7a3cc1594af91f8417375fd6088ceb5e85c67099091bac11498a0d711455f5e0d95cd7bbe5cdd8fecb319e6853c23c9be2c763df578666c40a40a87486e46ba8716146192904510a6dc59da8025825283d684db91410b4f12c6d8fbd0add75d3098918cb04ac7bc4db0d6bcdf1194dd86292e05b7b8630625b589cc509d215bbd06a2e7c66f424cdf8c40ac6c1e5ae6c964b7d9e92f95fc5c8852281628b81b9afabc7f03be3f62e8047bb88d01c68687b8dd4fe63820062b6788a53729053826ed3b7c7ef8241e19c85117b3c5341881d4f299e50374c8eefd5560bd18319a7963a3d02f0fbe84bc484b5a4018b97d274191c95f702bab9b0d105faf9fdcff97e437236567599faf73b075d406104d403cdf81224da590bec2897e30109e1f2e5ae4610c809a73f638c84210b3447a7c8b6dddb5ae200bf20e2fe4d4ba6c6b12767fb8760f66c5118e7a9935b41c9a471a1d3237688c1e618cc3be936aa3f5e44e086820b810e063211fc21c4044b3ac4d00df1bcc7b24dc07ba48b23b0fc12a3ed3d0a5cf7671415ab9cf21286fe63fb41418570555d4739b88104a8593f293025a4e3ee7c67e4b48e40f6ba8c09860c3fbbe55d45b45fc9ab629b17c276c9c9e2af3a043beafc18fd4f25ee7f83bddcd2d93914b7ed4f7c9af127f3f15c277be16551fef3ae03d7b9143f0c9c019ab97eea076366131f518363711b34e96d3f8a513f3e20b1d452c4b7ae3b975ea94d880dac6693399750d02220403f0d3e3fc1172a4de9dc280eaf0fee2883a6660bf5a3d246ff41d21b36ea521cf7aa689f800d0f86f4fa1057d8a13f9da8fffd0dc1fad3c04bb1cccb7c834db051a7ac2e4c60301996c93071ea416b421759935659cf62ca5f13ae07c3b195c148159d8beb03d440b00f5305765f20c0c46eee59c6d16206402db1c715e888bde59c781f35a7cc7c1c5ecb2155ae3e959c0964cc1ef8d7c69d1458a9a42f95f4c6b5b996345712aa290fbbf7dfd4a6e86463022a3f4725f6511bf7ea5e95c707cd3573609aadeaf540152c495f37fe6ec8bb9fa2aa61d15735934f4737928fde90ba995722465d4a64505a5201f07aa58cfd8ae226e02070b2dbf512b975319a7e8753b4fdae0eb4922869cc8e25c4a5560c2a0685de3ac392a8925ba882004894742e43ccfc277439ec8050a9aeb42932e01c840dfcedcc34d3991289a62c17d1284c839514b93351dbb2dda81f924565d70e7079d5b8126caab7a4a1c731655a53bcc09f5d63ec9086dea650055985edfa8297d9c95410c5d1894d17d5930549adbc2b8733c99fe62e17c4de34a5d89b12d18e42a422d2ce779c2c28eb2d98003d5cd323fcbecf02b5066e0e734810f09ed89013c00f011bd220f2e5d6a362df90599198a093b03c8d8efbfe0b617592faf1e64220c4440b53ffb47164f369c95290ba9f3108d686c57db645c53c012e57af25bd6693e2cc6b57651af1591fe5d8916640ec017c253df0606bb6b3035fae748f3d4034223b1b5efbf5283e778c1094291cf7b19be0f317350e6f8518fde0efb1381fb6e16c241f7f17a5210693a274159e7fac868cd0dc4359c3d9eefea0d9e31e43fa651392c65a543a59b3eee3a639dc9417d056a5ff0f160beee2eac29a7d88c0982cf70b5a46379f21e506aac61a9bb1b8c2b9dab0e44a823b61d0aa11d94f76a4a8e21f9d4280683208f4ea911116f6fd6a97426934ec3426b8c8f703da85e9dcf99336136003728b8ecdd04a389f6a817a78bfa61ba46020bf3c34829508f9d06d1553cd987aac380d86f168843ba3904de5f7058a41b4cd388bc9ce3aba7ee7139b7fc9e5b8cfaaa38990bd4a5db32e2613e7ec4f5f8b1292a38c6f4ff5a40490d76b126652fcf86e245235d636c65cd102b01e22781a72918c";
const MLKEM1024_ENC_K: &str = "7264bde5c6cec14849693e2c3c86e48f80958a4f6186fc69333a4148e6e497f3";

/// ML-DSA-87 keyGen KAT: seed `000102…1f` → fixed encoded verifying key.
const MLDSA87_KAT_SEED: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const MLDSA87_KAT_VK: &str = "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124a73b323b9ba21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e7fc4d115e7e48da1896d5fe119b10dcddef62cb307954074b42336e52836de61da941f8d37ea68ac8106fabe19070679af6008537120f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85f9b56b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449e91e23c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa91685de20af32c8b7e268c7f96877d0c85001135a4f0a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba61ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42fd3167f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e116cebe49229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b0439eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d870f1c02e5b2e3c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129db51f70740f31e63976b50c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571cce98b28da51db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb4c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc3280a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4faa45bea8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df080053e6969b251e875ecec32cfc592840d69ab69a75e06b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52104437fed66f8ee3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722788a3d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f915f6ae82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf72754e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce49731bd6650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0c643d1c551b6f3f7a98d29b85c2de05a65fa615eee16495bd90737672115b53e91c5d90028cf3f1a93953a153de53b44084e9ccff6b736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd1a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bdb6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e9147054ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239023897da0236630a53c0de7f435a19869792fab36e7b9e635760f09069e6432e700035ac2a02879fff0a1e1bec522047193d94eb5df1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea2c47e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07a80d54716b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c88f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e85095c81054994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731ab38344bc1636df16bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414ece7662927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b0472e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0bacb7c638d1b2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab3d21497528045c63262c8a42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e939528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11cfcaf4caa4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a9d329777a7084e4aadae7122ce97005930528eb3c7f7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7acffd95fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965bef1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f2e149d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d6107faa229d6f6373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c81dcf1c9c31e5b06568f97544c17dc15698c5cb38983a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f69587695cd6ff172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc697f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d1802762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5fdfe4a8a5c35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88debc53a595103acce4f1cff18acff07afe1eb5716aa1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c93661e00636b592704d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28ffaa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a34a60";

// ────────────────────────────────────────────────────────────────────
// Individual KAT functions
// ────────────────────────────────────────────────────────────────────

/// KAT: AES-256-GCM encrypt with known test vector.
fn kat_aes_256_gcm() -> Result<(), String> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&AES_GCM_KEY));
    let nonce = Nonce::from_slice(&AES_GCM_NONCE);

    let ciphertext_with_tag = cipher
        .encrypt(nonce, AES_GCM_PLAINTEXT.as_ref())
        .map_err(|e| format!("AES-256-GCM KAT: encryption failed: {}", e))?;

    if ciphertext_with_tag.as_slice() != AES_GCM_EXPECTED_CT_TAG.as_slice() {
        return Err(format!(
            "AES-256-GCM KAT: ciphertext mismatch. Got {} bytes, expected {} bytes. \
             First 16 bytes: {:02x?} vs {:02x?}",
            ciphertext_with_tag.len(),
            AES_GCM_EXPECTED_CT_TAG.len(),
            &ciphertext_with_tag[..core::cmp::min(16, ciphertext_with_tag.len())],
            &AES_GCM_EXPECTED_CT_TAG[..16],
        ));
    }

    // Verify decryption roundtrip
    let decrypted = cipher
        .decrypt(nonce, ciphertext_with_tag.as_ref())
        .map_err(|e| format!("AES-256-GCM KAT: decryption failed: {}", e))?;

    if decrypted.as_slice() != AES_GCM_PLAINTEXT.as_slice() {
        return Err("AES-256-GCM KAT: decryption roundtrip mismatch".into());
    }

    tracing::info!("FIPS KAT: AES-256-GCM PASSED");
    Ok(())
}

/// KAT: SHA-512 hash with known test vector.
fn kat_sha512() -> Result<(), String> {
    let mut hasher = Sha512::new();
    hasher.update(SHA512_INPUT);
    let result = hasher.finalize();

    if result.as_slice() != SHA512_EXPECTED.as_slice() {
        return Err(format!(
            "SHA-512 KAT: hash mismatch. Got {:02x?}, expected {:02x?}",
            &result[..8],
            &SHA512_EXPECTED[..8],
        ));
    }

    tracing::info!("FIPS KAT: SHA-512 PASSED");
    Ok(())
}

/// KAT: SHA3-256 hash with known test vector.
fn kat_sha3_256() -> Result<(), String> {
    let mut hasher = Sha3_256::new();
    hasher.update(SHA3_256_INPUT);
    let result = hasher.finalize();

    if result.as_slice() != SHA3_256_EXPECTED.as_slice() {
        return Err(format!(
            "SHA3-256 KAT: hash mismatch. Got {:02x?}, expected {:02x?}",
            &result[..8],
            &SHA3_256_EXPECTED[..8],
        ));
    }

    tracing::info!("FIPS KAT: SHA3-256 PASSED");
    Ok(())
}

/// KAT: HKDF-SHA512 key derivation.
///
/// We compute HKDF-SHA512 with known IKM/salt/info and verify the output
/// is deterministic and non-zero. Since RFC 5869 only provides SHA-256
/// test vectors, we verify determinism and roundtrip rather than a fixed
/// expected output.
fn kat_hkdf_sha512() -> Result<(), String> {
    let hk = Hkdf::<Sha512>::new(Some(&HKDF_SALT), &HKDF_IKM);
    let mut okm1 = [0u8; 42];
    hk.expand(&HKDF_INFO, &mut okm1)
        .map_err(|e| format!("HKDF-SHA512 KAT: expand failed: {}", e))?;

    // Verify output is non-zero
    if okm1 == [0u8; 42] {
        return Err("HKDF-SHA512 KAT: output is all zeros".into());
    }

    // Verify determinism
    let hk2 = Hkdf::<Sha512>::new(Some(&HKDF_SALT), &HKDF_IKM);
    let mut okm2 = [0u8; 42];
    hk2.expand(&HKDF_INFO, &mut okm2)
        .map_err(|e| format!("HKDF-SHA512 KAT: second expand failed: {}", e))?;

    if okm1 != okm2 {
        return Err("HKDF-SHA512 KAT: non-deterministic output".into());
    }

    // Verify known output (computed from reference implementation):
    // HKDF-SHA512 with these inputs produces a specific OKM.
    // We verify the first 16 bytes as a spot check.
    let expected_prefix: [u8; 16] = [
        0x83, 0x23, 0x90, 0x08, 0x6c, 0xda, 0x71, 0xfb, 0x47, 0x62, 0x5b, 0xb5, 0xce, 0xb1,
        0x68, 0xe4,
    ];
    if okm1[..16] != expected_prefix {
        return Err(format!(
            "HKDF-SHA512 KAT: output prefix mismatch. Got {:02x?}, expected {:02x?}",
            &okm1[..16], &expected_prefix
        ));
    }

    tracing::info!("FIPS KAT: HKDF-SHA512 PASSED");
    Ok(())
}

/// KAT: HMAC-SHA512 with known test vector (RFC 4231 Test Case 2).
fn kat_hmac_sha512() -> Result<(), String> {
    let mut mac =
        <HmacSha512 as hmac::Mac>::new_from_slice(HMAC_KEY).map_err(|e| format!("HMAC-SHA512 KAT: init failed: {}", e))?;
    mac.update(HMAC_DATA);
    let result = mac.finalize().into_bytes();

    if result.as_slice() != HMAC_SHA512_EXPECTED.as_slice() {
        return Err(format!(
            "HMAC-SHA512 KAT: MAC mismatch. Got {:02x?}, expected {:02x?}",
            &result[..8],
            &HMAC_SHA512_EXPECTED[..8],
        ));
    }

    tracing::info!("FIPS KAT: HMAC-SHA512 PASSED");
    Ok(())
}

/// KAT: ML-KEM-1024 encapsulate/decapsulate roundtrip.
///
/// Since ML-KEM uses randomized encapsulation, we cannot compare against
/// a fixed test vector. Instead we verify the roundtrip property:
/// decapsulate(encapsulate(ek)) produces the same shared secret.
fn kat_ml_kem_1024() -> Result<(), String> {
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{KemCore, MlKem1024};

    let mut rng = rand::rngs::OsRng;
    let (dk, ek) = MlKem1024::generate(&mut rng);

    let (ct, ss_enc) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "ML-KEM-1024 KAT: encapsulation failed".to_string())?;

    let ss_dec = dk
        .decapsulate(&ct)
        .map_err(|_| "ML-KEM-1024 KAT: decapsulation failed".to_string())?;

    if ss_enc.as_slice() != ss_dec.as_slice() {
        return Err("ML-KEM-1024 KAT: shared secret mismatch after roundtrip".into());
    }

    // Verify shared secret is non-zero
    if ss_enc.as_slice().iter().all(|&b| b == 0) {
        return Err("ML-KEM-1024 KAT: shared secret is all zeros".into());
    }

    // Verify shared secret length is 32 bytes (ML-KEM-1024 spec)
    if ss_enc.as_slice().len() != 32 {
        return Err(format!(
            "ML-KEM-1024 KAT: shared secret length is {}, expected 32",
            ss_enc.as_slice().len()
        ));
    }

    // Verify implicit rejection: decapsulating with a different key must produce
    // a DIFFERENT shared secret (ML-KEM uses implicit rejection, not an error).
    let (dk_wrong, _ek_wrong) = MlKem1024::generate(&mut rng);
    let ss_wrong = dk_wrong
        .decapsulate(&ct)
        .map_err(|_| "ML-KEM-1024 KAT: wrong-key decapsulation failed unexpectedly".to_string())?;

    if ss_wrong.as_slice() == ss_enc.as_slice() {
        return Err("ML-KEM-1024 KAT: wrong key produced same shared secret (implicit rejection broken)".into());
    }

    tracing::info!("FIPS KAT: ML-KEM-1024 PASSED");
    Ok(())
}

/// KAT: ML-KEM-1024 (FIPS 203) KNOWN-ANSWER test against NIST ACVP vectors.
///
/// This is a true fixed-input → fixed-output KAT, NOT a roundtrip. A buggy or
/// backdoored ML-KEM implementation that still round-trips with itself will
/// produce DIFFERENT bytes here and fail closed.
///
/// - keyGen:        deterministic seeds (d, z) MUST yield the exact published
///                  encapsulation key `ek` and decapsulation key `dk`.
/// - encapsulation: encapsulation key `ek` + coins `m` MUST yield the exact
///                  published ciphertext `c` and shared secret `k`.
///
/// Vectors: NIST ACVP-Server @65370b8, ML-KEM-{keyGen,encapDecap}-FIPS203
/// internalProjection.json, ML-KEM-1024 group, tcId 51.
fn kat_ml_kem_1024_acvp() -> Result<(), String> {
    // `EncapsulateDeterministic` (feature = "deterministic") provides
    // `encapsulate_deterministic`; `KemCore::generate_deterministic` provides
    // the fixed-seed keygen. Both are required for fixed-input → fixed-output.
    use ml_kem::{B32, Encoded, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024};

    let hex_to = |label: &str, s: &str| -> Result<Vec<u8>, String> {
        hex::decode(s).map_err(|e| format!("ML-KEM-1024 ACVP KAT: bad {label} hex: {e}"))
    };
    let to32 = |label: &str, v: Vec<u8>| -> Result<[u8; 32], String> {
        <[u8; 32]>::try_from(v.as_slice())
            .map_err(|_| format!("ML-KEM-1024 ACVP KAT: {label} is not 32 bytes"))
    };

    // ── keyGen KAT: (d, z) → ek, dk ──────────────────────────────────────
    let d_arr = to32("d", hex_to("d", MLKEM1024_KG_D)?)?;
    let z_arr = to32("z", hex_to("z", MLKEM1024_KG_Z)?)?;
    let expected_ek = hex_to("ek", MLKEM1024_KG_EK)?;
    let expected_dk = hex_to("dk", MLKEM1024_KG_DK)?;

    let d: B32 = d_arr.into();
    let z: B32 = z_arr.into();
    let (dk, ek) = MlKem1024::generate_deterministic(&d, &z);

    if ek.as_bytes().as_slice() != expected_ek.as_slice() {
        return Err("ML-KEM-1024 ACVP KAT: keyGen ek mismatch (wrong/backdoored impl)".into());
    }
    if dk.as_bytes().as_slice() != expected_dk.as_slice() {
        return Err("ML-KEM-1024 ACVP KAT: keyGen dk mismatch (wrong/backdoored impl)".into());
    }

    // ── encapsulation KAT: (ek, m) → c, k ────────────────────────────────
    let enc_ek_bytes = hex_to("enc ek", MLKEM1024_ENC_EK)?;
    let m_arr = to32("m", hex_to("m", MLKEM1024_ENC_M)?)?;
    let expected_c = hex_to("c", MLKEM1024_ENC_C)?;
    let expected_k = hex_to("k", MLKEM1024_ENC_K)?;

    let enc_ek_enc =
        Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(enc_ek_bytes.as_slice())
            .map_err(|_| "ML-KEM-1024 ACVP KAT: encap ek wrong length".to_string())?;
    let enc_ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&enc_ek_enc);

    let m: B32 = m_arr.into();
    let (ct, k) = enc_ek
        .encapsulate_deterministic(&m)
        .map_err(|_| "ML-KEM-1024 ACVP KAT: deterministic encapsulation failed".to_string())?;

    if ct.as_slice() != expected_c.as_slice() {
        return Err("ML-KEM-1024 ACVP KAT: encapsulation ciphertext mismatch".into());
    }
    if k.as_slice() != expected_k.as_slice() {
        return Err("ML-KEM-1024 ACVP KAT: encapsulation shared secret mismatch".into());
    }

    tracing::info!("FIPS KAT: ML-KEM-1024 ACVP known-answer (keyGen + encaps) PASSED");
    Ok(())
}

/// KAT: ML-DSA-87 (FIPS 204) KNOWN-ANSWER test against a published vector.
///
/// Fixed-input → fixed-output: the deterministic FIPS 204 KeyGen_internal seed
/// `000102…1f` MUST produce the EXACT published encoded verifying key. A
/// wrong/backdoored keygen produces different bytes and fails closed.
///
/// Vector: IETF LAMPS dilithium-certificates example (ML-DSA-87), also part of
/// the `ml-dsa` crate's own test corpus.
fn kat_ml_dsa_87_acvp() -> Result<(), String> {
    use ml_dsa::{KeyGen, MlDsa87};

    let expected_vk = hex::decode(MLDSA87_KAT_VK)
        .map_err(|e| format!("ML-DSA-87 KAT: bad vk hex: {e}"))?;

    // Deterministic keypair from the published 32-byte seed.
    let kp = MlDsa87::from_seed(&MLDSA87_KAT_SEED.into());
    let vk = kp.verifying_key();
    let vk_bytes = vk.encode();

    if vk_bytes.as_slice() != expected_vk.as_slice() {
        return Err(
            "ML-DSA-87 ACVP KAT: encoded verifying key mismatch for fixed seed \
             (wrong/backdoored keygen)"
                .into(),
        );
    }

    tracing::info!("FIPS KAT: ML-DSA-87 known-answer (seed → verifying key) PASSED");
    Ok(())
}

/// KAT: X-Wing hybrid KEM combiner (ML-KEM-1024 + X25519) roundtrip.
///
/// Verifies the full X-Wing encapsulate/decapsulate cycle produces matching
/// shared secrets, and that the HKDF-SHA512 session key derivation is
/// deterministic for the same inputs.
fn kat_xwing_combiner() -> Result<(), String> {
    use crate::xwing::{XWingKeyPair, xwing_encapsulate, xwing_decapsulate, derive_session_key};

    // Generate a keypair
    let kp = XWingKeyPair::generate();
    let pk = kp.public_key();

    // Encapsulate: client produces (shared_secret, ciphertext)
    let (ss_enc, ct) = xwing_encapsulate(&pk)
        .map_err(|e| format!("X-Wing KAT: encapsulation failed: {}", e))?;

    // Decapsulate: server recovers the same shared_secret
    let ss_dec = xwing_decapsulate(&kp, &ct)
        .map_err(|e| format!("X-Wing KAT: decapsulation failed: {}", e))?;

    // Shared secrets must match
    if ss_enc.as_bytes() != ss_dec.as_bytes() {
        return Err("X-Wing KAT: shared secret mismatch after encap/decap roundtrip".into());
    }

    // Shared secret must be non-zero
    if ss_enc.as_bytes().iter().all(|&b| b == 0) {
        return Err("X-Wing KAT: shared secret is all zeros".into());
    }

    // Session key derivation must be deterministic
    let context = b"KAT-test-context";
    let sk1 = derive_session_key(&ss_enc, context)
        .map_err(|e| format!("X-Wing KAT: session key derivation failed: {}", e))?;
    let sk2 = derive_session_key(&ss_enc, context)
        .map_err(|e| format!("X-Wing KAT: session key derivation failed: {}", e))?;
    if sk1 != sk2 {
        return Err("X-Wing KAT: session key derivation is non-deterministic".into());
    }

    // Session key must be non-zero
    if sk1.iter().all(|&b| b == 0) {
        return Err("X-Wing KAT: derived session key is all zeros".into());
    }

    // Different contexts must produce different session keys
    let sk3 = derive_session_key(&ss_enc, b"different-context")
        .map_err(|e| format!("X-Wing KAT: session key derivation failed: {}", e))?;
    if sk1 == sk3 {
        return Err("X-Wing KAT: different contexts produced same session key".into());
    }

    tracing::info!("FIPS KAT: X-Wing combiner (ML-KEM-1024 + X25519) PASSED");
    Ok(())
}

/// KAT: FROST Ristretto255 threshold signing roundtrip.
///
/// Verifies that a t-of-n threshold group can produce a valid signature
/// using the trusted dealer ceremony, and that the signature verifies
/// against the group's public key.
fn kat_frost_ristretto255() -> Result<(), String> {
    use crate::threshold;

    // Generate a 2-of-3 threshold group
    let mut dkg_result = threshold::dkg(3, 2)?;

    if dkg_result.shares.len() != 3 {
        return Err(format!(
            "FROST KAT: expected 3 shares, got {}",
            dkg_result.shares.len()
        ));
    }

    // Verify that the group has the correct threshold
    if dkg_result.group.threshold != 2 || dkg_result.group.total != 3 {
        return Err(format!(
            "FROST KAT: wrong group parameters t={}, n={}",
            dkg_result.group.threshold, dkg_result.group.total
        ));
    }

    // Perform a threshold signing round with 2 of 3 signers
    let test_message = b"FIPS 140-3 FROST Ristretto255 known-answer test message";

    let signing_result = threshold::threshold_sign(
        &mut dkg_result.shares,
        &dkg_result.group,
        test_message,
        2, // threshold
    );

    match signing_result {
        Ok(signature) => {
            // Verify the threshold signature against the group public key
            if !threshold::verify_group_signature(
                &dkg_result.group,
                test_message,
                &signature,
            ) {
                return Err("FROST KAT: threshold signature verification failed".into());
            }

            // Wrong message must not verify
            if threshold::verify_group_signature(
                &dkg_result.group,
                b"tampered message",
                &signature,
            ) {
                return Err("FROST KAT: verification succeeded for wrong message".into());
            }
        }
        Err(e) => {
            return Err(format!("FROST KAT: threshold signing failed: {}", e));
        }
    }

    tracing::info!("FIPS KAT: FROST Ristretto255 (2-of-3) PASSED");
    Ok(())
}

/// KAT: SLH-DSA-SHA2-256f (FIPS 205) sign/verify roundtrip.
///
/// Verifies that SLH-DSA key generation, signing, and verification produce
/// correct results, and that tampered messages are rejected.
fn kat_slh_dsa() -> Result<(), String> {
    use crate::slh_dsa;

    // Generate a keypair
    let (sk, vk) = slh_dsa::slh_dsa_keygen();

    let test_message = b"FIPS 140-3 SLH-DSA-SHA2-256f known-answer test message";

    // Sign the test message
    let signature = slh_dsa::slh_dsa_sign(&sk, test_message);

    // Verify the signature
    if !slh_dsa::slh_dsa_verify(&vk, test_message, &signature) {
        return Err("SLH-DSA KAT: signature verification failed".into());
    }

    // Wrong message must not verify
    if slh_dsa::slh_dsa_verify(&vk, b"tampered message", &signature) {
        return Err("SLH-DSA KAT: verification succeeded for wrong message".into());
    }

    // Public key must be non-zero
    let pk_bytes = vk.to_bytes();
    if pk_bytes.iter().all(|&b| b == 0) {
        return Err("SLH-DSA KAT: public key is all zeros".into());
    }

    tracing::info!("FIPS KAT: SLH-DSA-SHA2-256f (FIPS 205) PASSED");
    Ok(())
}

/// KAT: PBKDF2-SHA512 key derivation.
///
/// Uses known inputs (password="password", salt="salt", iterations=4096, len=32)
/// and verifies the output is non-zero and deterministic.
fn kat_pbkdf2_sha512() -> Result<(), String> {
    let password = b"password";
    let salt = b"salt";
    let iterations = 4096u32;
    let output_len = 32usize;

    let mut key1 = vec![0u8; output_len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, &mut key1);

    // Verify output is non-zero
    if key1.iter().all(|&b| b == 0) {
        return Err("PBKDF2-SHA512 KAT: derived key is all zeros".into());
    }

    // Verify determinism
    let mut key2 = vec![0u8; output_len];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, iterations, &mut key2);

    if key1 != key2 {
        return Err("PBKDF2-SHA512 KAT: non-deterministic output".into());
    }

    tracing::info!("FIPS KAT: PBKDF2-SHA512 PASSED");
    Ok(())
}

/// KAT: AEGIS-256 encrypt/decrypt roundtrip.
///
/// Generates a random key, encrypts a known plaintext, decrypts the result,
/// and verifies the roundtrip matches.
fn kat_aegis256() -> Result<(), String> {
    use crate::symmetric::{encrypt_with, decrypt, SymmetricAlgorithm};

    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
        .map_err(|e| format!("AEGIS-256 KAT: key generation failed: {}", e))?;

    let plaintext = b"AEGIS-256 KAT test data";
    let aad = &[];

    let sealed = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
        .map_err(|e| format!("AEGIS-256 KAT: encryption failed: {}", e))?;

    let decrypted = decrypt(&key, &sealed, aad)
        .map_err(|e| format!("AEGIS-256 KAT: decryption failed: {}", e))?;

    if decrypted != plaintext {
        return Err("AEGIS-256 KAT: decrypted plaintext does not match original".into());
    }

    // Determinism check: same key + same plaintext + same nonce must produce same ciphertext
    let sealed2 = encrypt_with(SymmetricAlgorithm::Aegis256, &key, plaintext, aad)
        .map_err(|e| format!("AEGIS-256 KAT: second encryption failed: {}", e))?;
    // Note: AEGIS-256 uses random nonces, so sealed != sealed2 is expected.
    // But both must decrypt to the same plaintext.
    let decrypted2 = decrypt(&key, &sealed2, aad)
        .map_err(|e| format!("AEGIS-256 KAT: second decryption failed: {}", e))?;
    if decrypted2 != plaintext {
        return Err("AEGIS-256 KAT: second roundtrip mismatch".into());
    }

    // Wrong key must fail decryption
    let mut wrong_key = key;
    wrong_key[0] ^= 0xFF;
    if decrypt(&wrong_key, &sealed, aad).is_ok() {
        return Err("AEGIS-256 KAT: decryption succeeded with wrong key".into());
    }

    tracing::info!("FIPS KAT: AEGIS-256 PASSED");
    Ok(())
}

/// KAT: ML-DSA-87 sign/verify with fixed seed (deterministic).
///
/// Uses a hardcoded seed for deterministic keypair generation, signs a fixed
/// message, verifies the signature, and checks that the same seed always
/// produces compatible keys.
fn kat_ml_dsa_87() -> Result<(), String> {
    use ml_dsa::{
        signature::{Signer, Verifier},
        KeyGen, MlDsa87,
    };

    // Fixed KAT seed — deterministic keypair generation
    let seed: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let kp = MlDsa87::from_seed(&seed.into());
    let sk = kp.signing_key();
    let vk = kp.verifying_key();

    let test_message = b"FIPS 140-3 ML-DSA-87 known-answer test message";
    let sig: ml_dsa::Signature<MlDsa87> = sk.sign(test_message);

    // Verify signature is valid
    vk.verify(test_message, &sig)
        .map_err(|_| "ML-DSA-87 KAT: signature verification failed".to_string())?;

    // Verify wrong message is rejected
    if vk.verify(b"tampered message", &sig).is_ok() {
        return Err("ML-DSA-87 KAT: verification succeeded for wrong message".into());
    }

    // Verify determinism: same seed must produce same keypair
    let kp2 = MlDsa87::from_seed(&seed.into());
    let _vk2 = kp2.verifying_key();
    let sig2: ml_dsa::Signature<MlDsa87> = kp2.signing_key().sign(test_message);

    vk.verify(test_message, &sig2)
        .map_err(|_| "ML-DSA-87 KAT: determinism check failed — same seed produced incompatible keys".to_string())?;

    tracing::info!("FIPS KAT: ML-DSA-87 PASSED (fixed-seed deterministic)");
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────

/// Run ALL FIPS 140-3 startup known-answer tests.
///
/// This function MUST be called at module startup before any cryptographic
/// operations are performed. It tests every algorithm used by the system
/// against known test vectors or verified roundtrip properties.
///
/// # Returns
///
/// `Ok(())` if all tests pass.
///
/// # Errors
///
/// Returns `Err(String)` with a detailed description of the first failing
/// test. In production, callers should `panic!` on any error to prevent
/// use of a potentially compromised cryptographic module.
///
/// # Panics
///
/// Individual sub-tests do not panic; errors are collected and returned.
/// The caller is responsible for deciding whether to panic.
pub fn run_startup_kats() -> Result<(), String> {
    tracing::info!("FIPS 140-3 startup known-answer tests: BEGIN");

    // Run each KAT. On first failure, return the error immediately.
    // ML-DSA-87 and X-Wing need large stacks for key generation.
    kat_aes_256_gcm()?;
    kat_sha512()?;
    kat_sha3_256()?;
    kat_hkdf_sha512()?;
    kat_hmac_sha512()?;
    kat_pbkdf2_sha512()?;
    kat_aegis256()?;
    kat_ml_kem_1024()?;
    // Real fixed-input → fixed-output ML-KEM-1024 KAT (NIST ACVP vectors).
    // A backdoored impl that still round-trips with itself fails HERE.
    kat_ml_kem_1024_acvp()?;

    // ML-DSA-87 keys are large (~4KB). Run in a thread with larger stack.
    // Runs BOTH the sign/verify roundtrip and the ACVP seed→verifying-key KAT.
    let ml_dsa_result = std::thread::Builder::new()
        .name("fips-kat-ml-dsa".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| -> Result<(), String> {
            kat_ml_dsa_87()?;
            kat_ml_dsa_87_acvp()?;
            Ok(())
        })
        .map_err(|e| format!("ML-DSA-87 KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "ML-DSA-87 KAT: thread panicked".to_string())?;
    ml_dsa_result?;

    // X-Wing combiner (ML-KEM-1024 + X25519) — needs large stack for ML-KEM.
    let xwing_result = std::thread::Builder::new()
        .name("fips-kat-xwing".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(kat_xwing_combiner)
        .map_err(|e| format!("X-Wing KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "X-Wing KAT: thread panicked".to_string())?;
    xwing_result?;

    // FROST Ristretto255 threshold signing — moderate stack requirements.
    let frost_result = std::thread::Builder::new()
        .name("fips-kat-frost".into())
        .stack_size(4 * 1024 * 1024)
        .spawn(kat_frost_ristretto255)
        .map_err(|e| format!("FROST KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "FROST KAT: thread panicked".to_string())?;
    frost_result?;

    // SLH-DSA-SHA2-256f (FIPS 205) — hash-based signatures.
    let slh_dsa_result = std::thread::Builder::new()
        .name("fips-kat-slh-dsa".into())
        .stack_size(4 * 1024 * 1024)
        .spawn(kat_slh_dsa)
        .map_err(|e| format!("SLH-DSA KAT: failed to spawn thread: {}", e))?
        .join()
        .map_err(|_| "SLH-DSA KAT: thread panicked".to_string())?;
    slh_dsa_result?;

    tracing::info!("FIPS 140-3 startup known-answer tests: ALL PASSED (14/14)");
    Ok(())
}

/// Run startup KATs and panic on failure.
///
/// This is the recommended entry point for production use. Call this
/// once at application startup.
pub fn run_startup_kats_or_panic() {
    if let Err(e) = run_startup_kats() {
        panic!(
            "FIPS 140-3 STARTUP SELF-TEST FAILURE: {}. \
             Cryptographic module is NOT safe to use. \
             This is a critical security event — investigate immediately.",
            e
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kat_aes_256_gcm() {
        kat_aes_256_gcm().expect("AES-256-GCM KAT should pass");
    }

    #[test]
    fn test_kat_sha512() {
        kat_sha512().expect("SHA-512 KAT should pass");
    }

    #[test]
    fn test_kat_sha3_256() {
        kat_sha3_256().expect("SHA3-256 KAT should pass");
    }

    #[test]
    fn test_kat_hkdf_sha512() {
        kat_hkdf_sha512().expect("HKDF-SHA512 KAT should pass");
    }

    #[test]
    fn test_kat_hmac_sha512() {
        kat_hmac_sha512().expect("HMAC-SHA512 KAT should pass");
    }

    #[test]
    fn test_kat_pbkdf2_sha512() {
        kat_pbkdf2_sha512().expect("PBKDF2-SHA512 KAT should pass");
    }

    #[test]
    fn test_kat_aegis256() {
        kat_aegis256().expect("AEGIS-256 KAT should pass");
    }

    #[test]
    fn test_kat_ml_kem_1024() {
        kat_ml_kem_1024().expect("ML-KEM-1024 KAT should pass");
    }

    #[test]
    fn test_kat_ml_dsa_87() {
        // Run with large stack for ML-DSA-87 key generation
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                kat_ml_dsa_87().expect("ML-DSA-87 KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_kat_ml_kem_1024_acvp() {
        // Fixed-input → fixed-output ML-KEM-1024 KAT (NIST ACVP vectors).
        kat_ml_kem_1024_acvp().expect("ML-KEM-1024 ACVP KAT should pass");
    }

    #[test]
    fn test_kat_ml_dsa_87_acvp() {
        // ML-DSA-87 seed → verifying-key KAT; large stack for keygen.
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                kat_ml_dsa_87_acvp().expect("ML-DSA-87 ACVP KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_kat_xwing_combiner() {
        // X-Wing needs large stack for ML-KEM-1024 key generation
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                kat_xwing_combiner().expect("X-Wing combiner KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_kat_frost_ristretto255() {
        std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                kat_frost_ristretto255().expect("FROST Ristretto255 KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_kat_slh_dsa() {
        std::thread::Builder::new()
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                kat_slh_dsa().expect("SLH-DSA KAT should pass");
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_run_all_startup_kats() {
        run_startup_kats().expect("All startup KATs should pass");
    }

    #[test]
    fn test_sha512_vector_correctness() {
        // Verify our hardcoded SHA-512("abc") vector is correct
        let mut hasher = Sha512::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        assert_eq!(
            result.as_slice(),
            SHA512_EXPECTED.as_slice(),
            "SHA-512 test vector must match NIST CAVP"
        );
    }

    #[test]
    fn test_sha3_256_vector_correctness() {
        // Verify our hardcoded SHA3-256("abc") vector is correct
        let mut hasher = Sha3_256::new();
        hasher.update(b"abc");
        let result = hasher.finalize();
        assert_eq!(
            result.as_slice(),
            SHA3_256_EXPECTED.as_slice(),
            "SHA3-256 test vector must match NIST CAVP"
        );
    }

    #[test]
    fn test_hmac_sha512_vector_correctness() {
        // Verify our hardcoded HMAC-SHA512 vector is correct (RFC 4231 TC2)
        let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        let result = mac.finalize().into_bytes();
        assert_eq!(
            result.as_slice(),
            HMAC_SHA512_EXPECTED.as_slice(),
            "HMAC-SHA512 test vector must match RFC 4231"
        );
    }
}
