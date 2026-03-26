#![forbid(unsafe_code)]
//! End-to-end integration tests for MILNET SSO

pub mod chaos;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use gateway::puzzle::{solve_challenge, PuzzleChallenge, PuzzleSolution};
use gateway::wire::{AuthRequest, AuthResponse};
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
/// 2. Client encapsulates against server's X-Wing PK, solve puzzle, send solution with KEM ciphertext
/// 3. Server decapsulates to derive the same shared secret
/// 4. Both derive session key via HKDF-SHA512
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

    // 1. Receive puzzle challenge (includes server X-Wing PK)
    let challenge: PuzzleChallenge = recv_frame(&mut stream)
        .await
        .expect("receive puzzle challenge");

    // 2. Parse server X-Wing PK and encapsulate against it.
    //    The client produces a shared secret and a ciphertext.  The ciphertext
    //    is sent to the server alongside the puzzle solution.
    let server_pk_bytes = challenge
        .xwing_server_pk
        .as_ref()
        .expect("server X-Wing PK in challenge");
    let server_pk = crypto::xwing::XWingPublicKey::from_bytes(server_pk_bytes)
        .expect("parse server X-Wing PK");

    // ML-KEM-1024 encapsulation is CPU-intensive; run on a blocking thread.
    let (shared_secret, kem_ct) = tokio::task::spawn_blocking(move || {
        crypto::xwing::xwing_encapsulate(&server_pk)
    })
    .await
    .expect("encapsulate task");
    let kem_ct_bytes = kem_ct.to_bytes();

    // 3. Solve puzzle and send solution with KEM ciphertext
    let challenge_clone = challenge.clone();
    let solution_bytes = tokio::task::spawn_blocking(move || solve_challenge(&challenge_clone))
        .await
        .expect("puzzle solver task");
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
        xwing_kem_ciphertext: Some(kem_ct_bytes),
    };
    send_frame(&mut stream, &solution)
        .await
        .expect("send puzzle solution");

    // 4. Derive session key (both sides share the same secret)
    let session_key =
        crypto::xwing::derive_session_key(&shared_secret, &challenge.nonce);
    let enc_key: [u8; 32] = session_key[..32].try_into().unwrap();

    // 5. Encrypt and send auth request
    let auth_req = AuthRequest {
        username: username.to_string(),
        password: password.to_vec(),
        audience: None,
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

    // 6. Receive and decrypt auth response
    let encrypted_resp = recv_raw_frame(&mut stream)
        .await
        .expect("receive encrypted response");
    let resp_nonce = GenericArray::from_slice(&encrypted_resp[..12]);
    let resp_plain = cipher
        .decrypt(resp_nonce, &encrypted_resp[12..])
        .expect("decrypt response");
    postcard::from_bytes(&resp_plain).expect("deserialize auth response")
}

/// Like `client_auth` but also returns the DPoP binding key (KEM ciphertext bytes)
/// needed for token verification via `verify_token_bound`.
pub async fn client_auth_with_dpop(
    gateway_addr: &str,
    username: &str,
    password: &[u8],
) -> (AuthResponse, Vec<u8>) {
    let mut stream = TcpStream::connect(gateway_addr)
        .await
        .expect("connect to gateway");

    let challenge: PuzzleChallenge = recv_frame(&mut stream)
        .await
        .expect("receive puzzle challenge");

    let server_pk_bytes = challenge
        .xwing_server_pk
        .as_ref()
        .expect("server X-Wing PK in challenge");
    let server_pk = crypto::xwing::XWingPublicKey::from_bytes(server_pk_bytes)
        .expect("parse server X-Wing PK");

    let (shared_secret, kem_ct) = tokio::task::spawn_blocking(move || {
        crypto::xwing::xwing_encapsulate(&server_pk)
    })
    .await
    .expect("encapsulate task");
    let kem_ct_bytes = kem_ct.to_bytes();
    let dpop_key = kem_ct_bytes.clone();

    let challenge_clone = challenge.clone();
    let solution_bytes = tokio::task::spawn_blocking(move || solve_challenge(&challenge_clone))
        .await
        .expect("puzzle solver task");
    let solution = PuzzleSolution {
        nonce: challenge.nonce,
        solution: solution_bytes,
        xwing_kem_ciphertext: Some(kem_ct_bytes),
    };
    send_frame(&mut stream, &solution)
        .await
        .expect("send puzzle solution");

    let session_key =
        crypto::xwing::derive_session_key(&shared_secret, &challenge.nonce);
    let enc_key: [u8; 32] = session_key[..32].try_into().unwrap();

    let auth_req = AuthRequest {
        username: username.to_string(),
        password: password.to_vec(),
        audience: None,
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

    let encrypted_resp = recv_raw_frame(&mut stream)
        .await
        .expect("receive encrypted response");
    let resp_nonce = GenericArray::from_slice(&encrypted_resp[..12]);
    let resp_plain = cipher
        .decrypt(resp_nonce, &encrypted_resp[12..])
        .expect("decrypt response");
    let resp: AuthResponse = postcard::from_bytes(&resp_plain).expect("deserialize auth response");
    (resp, dpop_key)
}
