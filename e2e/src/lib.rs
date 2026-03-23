#![forbid(unsafe_code)]
//! End-to-end integration tests for MILNET SSO

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use gateway::puzzle::{solve_challenge, PuzzleChallenge, PuzzleSolution};
use gateway::wire::{AuthRequest, AuthResponse, KemCiphertext};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send a length-prefixed postcard-serialized frame.
pub async fn send_frame<T: serde::Serialize>(
    stream: &mut TcpStream,
    value: &T,
) -> Result<(), String> {
    let payload = postcard::to_allocvec(value).map_err(|e| format!("serialize: {e}"))?;
    let len = payload.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write length: {e}"))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|e| format!("write payload: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Receive a length-prefixed postcard-serialized frame.
pub async fn recv_frame<T: serde::de::DeserializeOwned>(
    stream: &mut TcpStream,
) -> Result<T, String> {
    let buf = recv_raw_frame(stream).await?;
    postcard::from_bytes(&buf).map_err(|e| format!("deserialize: {e}"))
}

/// Send raw bytes as a length-prefixed frame.
pub async fn send_raw_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = data.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write length: {e}"))?;
    stream
        .write_all(data)
        .await
        .map_err(|e| format!("write payload: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Receive raw bytes as a length-prefixed frame.
pub async fn recv_raw_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read length: {e}"))?;
    let len = u32::from_be_bytes(len_buf);
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("read payload: {e}"))?;
    Ok(buf)
}

/// Run a full client auth flow against a gateway using the encrypted X-Wing channel.
///
/// Steps:
/// 1. Receive PuzzleChallenge (includes server X-Wing PK)
/// 2. Generate client X-Wing keypair, solve puzzle, send solution with client PK
/// 3. Receive KEM ciphertext from server
/// 4. Decapsulate to derive shared secret -> session key
/// 5. Encrypt AuthRequest with AES-256-GCM, send
/// 6. Receive encrypted AuthResponse, decrypt
pub async fn client_auth(
    gateway_addr: &str,
    username: &str,
    password: &[u8],
) -> AuthResponse {
    let mut stream = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to gateway");

    // 1. Receive puzzle challenge
    let challenge: PuzzleChallenge = recv_frame(&mut stream)
        .await
        .expect("receive puzzle challenge");

    // 2. Generate X-Wing keypair and solve puzzle
    //    Use spawn_blocking for both keygen and puzzle solving since they are
    //    CPU-intensive. ML-KEM-1024 keygen also uses significant stack space
    //    that can overflow the async task's stack in debug builds.
    let client_kp: Box<crypto::xwing::XWingKeyPair> = tokio::task::spawn_blocking(|| {
        Box::new(crypto::xwing::XWingKeyPair::generate())
    })
    .await
    .expect("keygen task");
    let client_pk_bytes = client_kp.public_key().to_bytes();

    let challenge_clone = challenge.clone();
    let solution_bytes = tokio::task::spawn_blocking(move || solve_challenge(&challenge_clone))
        .await
        .expect("puzzle solver task");
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
        xwing_client_pk: Some(client_pk_bytes),
    };
    send_frame(&mut stream, &solution)
        .await
        .expect("send puzzle solution");

    // 3. Receive KEM ciphertext from server
    //    If puzzle verification failed, the server sends an AuthResponse error
    //    instead of a KemCiphertext. Try to detect this.
    let raw_kem = recv_raw_frame(&mut stream).await.expect("receive KEM frame");
    // KemCiphertext should be ~1600+ bytes when serialized. If the raw frame
    // is much smaller, the server likely sent an error AuthResponse instead.
    if raw_kem.len() < 100 {
        if let Ok(err_resp) = postcard::from_bytes::<AuthResponse>(&raw_kem) {
            panic!("server sent error instead of KEM ciphertext: {:?}", err_resp.error);
        }
        panic!("unexpected small frame from server ({} bytes): {:?}", raw_kem.len(), &raw_kem[..raw_kem.len().min(32)]);
    }
    let kem_msg: KemCiphertext = postcard::from_bytes(&raw_kem)
        .unwrap_or_else(|e| panic!("deserialize KemCiphertext ({} bytes): {e}", raw_kem.len()));

    // 4. Decapsulate to get shared secret (spawn_blocking for ML-KEM stack usage)
    let kem_ct = crypto::xwing::Ciphertext::from_bytes(&kem_msg.ciphertext)
        .unwrap_or_else(|| {
            panic!(
                "parse KEM ciphertext: got {} bytes, expected >= 1600",
                kem_msg.ciphertext.len()
            )
        });
    let shared_secret = tokio::task::spawn_blocking(move || {
        crypto::xwing::xwing_decapsulate(&client_kp, &kem_ct)
    })
    .await
    .expect("decapsulate task");

    // 5. Derive session key
    let session_key =
        crypto::xwing::derive_session_key(&shared_secret, &challenge.nonce);
    let enc_key: [u8; 32] = session_key[..32].try_into().unwrap();

    // 6. Encrypt and send auth request
    let auth_req = AuthRequest {
        username: username.to_string(),
        password: password.to_vec(),
    };
    let auth_plain = postcard::to_allocvec(&auth_req).expect("serialize auth request");
    let cipher = Aes256Gcm::new_from_slice(&enc_key).expect("AES key init");
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes).expect("generate nonce");
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, auth_plain.as_ref())
        .expect("encrypt");
    let mut encrypted = Vec::with_capacity(12 + ciphertext.len());
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend_from_slice(&ciphertext);
    send_raw_frame(&mut stream, &encrypted)
        .await
        .expect("send encrypted auth");

    // 7. Receive and decrypt auth response
    let encrypted_resp = recv_raw_frame(&mut stream)
        .await
        .expect("receive encrypted response");
    let resp_nonce = GenericArray::from_slice(&encrypted_resp[..12]);
    let resp_plain = cipher
        .decrypt(resp_nonce, &encrypted_resp[12..])
        .expect("decrypt response");
    postcard::from_bytes(&resp_plain).expect("deserialize auth response")
}
