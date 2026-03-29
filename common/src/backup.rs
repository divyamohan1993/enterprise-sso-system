//! Encrypted backup and restore for the MILNET SSO system.
//!
//! Provides AEGIS-256 (or AES-256-GCM in FIPS mode) encrypted backup export/import
//! using the master KEK.
//!
//! V2 backup format (new):
//! ```text
//! MILBK002              (8 bytes - magic)
//! version               (2 bytes - u16 LE, currently 2)
//! encrypted_data_len    (8 bytes - u64 LE)
//! encrypted_data        (variable - algo_id || nonce || ciphertext || tag)
//! hmac                  (64 bytes - HMAC-SHA512 over magic..encrypted_data)
//! ```
//!
//! V1 backup format (legacy, read-only):
//! ```text
//! MILBK001              (8 bytes - magic)
//! version               (2 bytes - u16 LE, value 1)
//! nonce                 (12 bytes - AES-256-GCM nonce)
//! encrypted_data_len    (8 bytes - u64 LE)
//! encrypted_data        (variable - AES-256-GCM ciphertext + 16-byte tag)
//! hmac                  (64 bytes - HMAC-SHA512 over magic..encrypted_data)
//! ```
//!
//! The HMAC covers the entire backup (excluding the HMAC field itself) to
//! provide integrity verification before decryption. The KEK is never stored
//! in the backup; the operator must supply it at restore time.
//!
//! # Streaming
//!
//! For large backups, use [`BackupWriter`] and [`BackupReader`] which process
//! data in chunks to avoid loading the entire backup into memory.

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aegis::aegis256::Aegis256;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::io::{Read, Write};

// Algo IDs matching crypto::symmetric
const ALGO_ID_AEGIS256: u8 = 0x01;
const ALGO_ID_AES256GCM: u8 = 0x02;
const AEGIS256_NONCE_LEN: usize = 32;
const AEGIS256_TAG_LEN: usize = 32;
const AES_GCM_NONCE_LEN: usize = 12;

/// Encrypt plaintext using the active algorithm (AEGIS-256 or AES-256-GCM in FIPS mode).
/// Wire format: algo_id (1) || nonce || ciphertext || tag
fn backup_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if crate::fips::is_fips_mode() {
        // AES-256-GCM
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| format!("nonce generation failed: {e}"))?;
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad: b"" })
            .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;
        let mut out = Vec::with_capacity(1 + AES_GCM_NONCE_LEN + ct.len());
        out.push(ALGO_ID_AES256GCM);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    } else {
        // AEGIS-256
        let mut nonce = [0u8; AEGIS256_NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| format!("nonce generation failed: {e}"))?;
        let (ct, tag) = Aegis256::<AEGIS256_TAG_LEN>::new(key, &nonce).encrypt(plaintext, b"");
        let mut out = Vec::with_capacity(1 + AEGIS256_NONCE_LEN + ct.len() + AEGIS256_TAG_LEN);
        out.push(ALGO_ID_AEGIS256);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }
}

/// Decrypt a blob produced by `backup_encrypt` or a legacy AES-256-GCM blob.
fn backup_decrypt(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, String> {
    let first = sealed.first().copied().ok_or_else(|| "empty ciphertext".to_string())?;
    match first {
        ALGO_ID_AEGIS256 => {
            let payload = sealed.get(1..).ok_or_else(|| "truncated AEGIS-256 blob".to_string())?;
            let min_len = AEGIS256_NONCE_LEN + AEGIS256_TAG_LEN;
            if payload.len() < min_len {
                return Err(format!("AEGIS-256 payload too short: {} bytes", payload.len()));
            }
            let nonce_slice = payload.get(..AEGIS256_NONCE_LEN)
                .ok_or_else(|| "nonce slice out of bounds".to_string())?;
            let rest = payload.get(AEGIS256_NONCE_LEN..)
                .ok_or_else(|| "rest out of bounds".to_string())?;
            let tag_offset = rest.len().checked_sub(AEGIS256_TAG_LEN)
                .ok_or_else(|| "payload too short for tag".to_string())?;
            let ct = rest.get(..tag_offset)
                .ok_or_else(|| "ciphertext slice out of bounds".to_string())?;
            let tag_slice = rest.get(tag_offset..)
                .ok_or_else(|| "tag slice out of bounds".to_string())?;
            let mut nonce = [0u8; AEGIS256_NONCE_LEN];
            nonce.copy_from_slice(nonce_slice);
            let mut tag = [0u8; AEGIS256_TAG_LEN];
            tag.copy_from_slice(tag_slice);
            Aegis256::<AEGIS256_TAG_LEN>::new(key, &nonce)
                .decrypt(ct, &tag, b"")
                .map_err(|e| format!("AEGIS-256 decryption failed: {e}"))
        }
        ALGO_ID_AES256GCM => {
            let payload = sealed.get(1..).ok_or_else(|| "truncated AES-256-GCM blob".to_string())?;
            decrypt_aes256gcm(key, payload)
        }
        _ => {
            // Legacy: no algo_id prefix — treat entire blob as AES-256-GCM
            decrypt_aes256gcm(key, sealed)
        }
    }
}

fn decrypt_aes256gcm(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
    let min_len = AES_GCM_NONCE_LEN + 16; // nonce + tag
    if payload.len() < min_len {
        return Err(format!("AES-256-GCM payload too short: {} bytes", payload.len()));
    }
    let nonce_slice = payload.get(..AES_GCM_NONCE_LEN)
        .ok_or_else(|| "nonce slice out of bounds".to_string())?;
    let ct = payload.get(AES_GCM_NONCE_LEN..)
        .ok_or_else(|| "ciphertext slice out of bounds".to_string())?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let nonce = Nonce::from_slice(nonce_slice);
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: ct, aad: b"" })
        .map_err(|e| format!("AES-256-GCM decryption failed: {e}"))
}

type HmacSha512 = Hmac<Sha512>;

/// Magic bytes for the v1 (legacy) AES-256-GCM backup format.
const BACKUP_MAGIC_V1: &[u8; 8] = b"MILBK001";

/// Magic bytes for the v2 (new) AEGIS-256/AES-256-GCM backup format.
const BACKUP_MAGIC_V2: &[u8; 8] = b"MILBK002";

/// Current backup magic (used for new exports).
const BACKUP_MAGIC: &[u8; 8] = BACKUP_MAGIC_V2;

/// Current backup format version.
const BACKUP_VERSION: u16 = 2;

/// AES-256-GCM nonce length (used for legacy v1 parsing).
const NONCE_LEN: usize = 12;

/// HMAC-SHA512 output length.
const HMAC_LEN: usize = 64;

/// AES-256-GCM tag length (used for legacy v1 minimum size check).
const TAG_LEN: usize = 16;

/// Domain separation for backup encryption key derivation.
const BACKUP_ENCRYPT_DOMAIN: &[u8] = b"MILNET-BACKUP-ENCRYPT-v1";

/// Domain separation for backup HMAC key derivation.
const BACKUP_HMAC_DOMAIN: &[u8] = b"MILNET-BACKUP-HMAC-v1";

/// Maximum backup size before streaming is recommended (256 MB).
const STREAMING_THRESHOLD: usize = 256 * 1024 * 1024;

/// Chunk size for streaming backups (1 MB).
#[allow(dead_code)]
const STREAM_CHUNK_SIZE: usize = 1024 * 1024;

/// Derive the AES-256-GCM encryption key from the master KEK.
fn derive_backup_encryption_key(master_kek: &[u8; 32]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha512>::new(Some(BACKUP_ENCRYPT_DOMAIN), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(b"backup-aes-key", &mut okm)
        .map_err(|_| "HKDF-SHA512 backup key derivation failed".to_string())?;
    Ok(okm)
}

/// Derive the HMAC-SHA512 key from the master KEK (separate from encryption key).
fn derive_backup_hmac_key(master_kek: &[u8; 32]) -> Result<[u8; 64], String> {
    let hk = Hkdf::<Sha512>::new(Some(BACKUP_HMAC_DOMAIN), master_kek);
    let mut okm = [0u8; 64];
    hk.expand(b"backup-hmac-key", &mut okm)
        .map_err(|_| "HKDF-SHA512 backup HMAC key derivation failed".to_string())?;
    Ok(okm)
}

/// Encrypt and export backup data using the master KEK.
///
/// Produces a v2 backup (magic `MILBK002`) using AEGIS-256 by default or
/// AES-256-GCM in FIPS mode. Returns the complete encrypted backup blob
/// including magic, version, encrypted data length, ciphertext, and HMAC.
///
/// For backups larger than 256 MB, consider using [`BackupWriter`] instead.
pub fn export_backup(master_kek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.len() > STREAMING_THRESHOLD {
        tracing::warn!(
            "Backup data is {} MB; consider using BackupWriter for streaming",
            plaintext.len() / (1024 * 1024)
        );
    }

    let enc_key = derive_backup_encryption_key(master_kek)?;
    let hmac_key = derive_backup_hmac_key(master_kek)?;

    // Encrypt with the active symmetric algorithm (AEGIS-256 or AES-256-GCM)
    let ciphertext = backup_encrypt(&enc_key, plaintext)
        .map_err(|e| format!("encryption failed: {e}"))?;

    let encrypted_data_len = ciphertext.len() as u64;

    // V2 format: magic(8) + version(2) + encrypted_data_len(8) + data + hmac(64)
    let header_len = 8 + 2 + 8;
    let mut backup = Vec::with_capacity(header_len + ciphertext.len() + HMAC_LEN);

    backup.extend_from_slice(BACKUP_MAGIC);
    backup.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    backup.extend_from_slice(&encrypted_data_len.to_le_bytes());
    backup.extend_from_slice(&ciphertext);

    // Compute HMAC over everything so far
    // HMAC-SHA512 accepts any key length per RFC 2104.
    let Ok(mut mac) = <HmacSha512 as Mac>::new_from_slice(&hmac_key) else {
        return Err("HMAC-SHA512 initialization failed".to_string());
    };
    mac.update(&backup);
    let hmac_result = mac.finalize().into_bytes();
    backup.extend_from_slice(&hmac_result);

    // Zeroize sensitive key material
    use zeroize::Zeroize;
    let mut enc_key = enc_key;
    let mut hmac_key = hmac_key;
    enc_key.zeroize();
    hmac_key.zeroize();

    Ok(backup)
}

/// Verify integrity and decrypt a backup using the master KEK.
///
/// Supports both v2 (`MILBK002`, AEGIS-256/AES-256-GCM) and legacy v1
/// (`MILBK001`, AES-256-GCM only) formats.
///
/// Returns the decrypted plaintext data on success.
pub fn import_backup(master_kek: &[u8; 32], backup: &[u8]) -> Result<Vec<u8>, String> {
    // Minimum size: magic(8) + version(2) + anything else
    if backup.len() < 10 {
        return Err(format!(
            "backup too small: {} bytes",
            backup.len()
        ));
    }

    let magic = backup.get(..8).ok_or("backup too short for magic")?;

    if magic == BACKUP_MAGIC_V1 {
        import_backup_v1(master_kek, backup)
    } else if magic == BACKUP_MAGIC_V2 {
        import_backup_v2(master_kek, backup)
    } else {
        Err("invalid backup: magic bytes do not match".into())
    }
}

/// Import a v2 backup (MILBK002): AEGIS-256 or AES-256-GCM.
fn import_backup_v2(master_kek: &[u8; 32], backup: &[u8]) -> Result<Vec<u8>, String> {
    // V2 minimum: magic(8) + version(2) + len(8) + min_cipher_data(1) + hmac(64)
    let min_size = 8 + 2 + 8 + 1 + HMAC_LEN;
    if backup.len() < min_size {
        return Err(format!(
            "v2 backup too small: {} bytes (minimum {})",
            backup.len(),
            min_size
        ));
    }

    let hmac_key = derive_backup_hmac_key(master_kek)?;

    // Verify HMAC first
    let data_portion = backup.get(..backup.len() - HMAC_LEN)
        .ok_or("backup too short for HMAC verification")?;
    let stored_hmac = backup.get(backup.len() - HMAC_LEN..)
        .ok_or("backup too short for HMAC")?;

    let Ok(mut mac) = <HmacSha512 as Mac>::new_from_slice(&hmac_key) else {
        return Err("HMAC-SHA512 initialization failed".to_string());
    };
    mac.update(data_portion);
    let computed_hmac = mac.finalize().into_bytes();

    use subtle::ConstantTimeEq;
    if computed_hmac.ct_eq(stored_hmac).unwrap_u8() != 1 {
        return Err("backup integrity check failed: HMAC mismatch (wrong KEK or corrupt data)".into());
    }

    // Parse encrypted_data_len at offset 10 (after magic + version)
    let len_bytes: [u8; 8] = backup.get(10..18)
        .ok_or("backup too short for encrypted_data_len")?
        .try_into()
        .map_err(|_| "failed to parse encrypted_data_len")?;
    let encrypted_data_len = u64::from_le_bytes(len_bytes) as usize;

    let data_start = 18;
    let data_end = data_start + encrypted_data_len;

    if data_end + HMAC_LEN != backup.len() {
        return Err(format!(
            "v2 backup size mismatch: expected {} bytes of encrypted data, got {}",
            encrypted_data_len,
            backup.len().saturating_sub(data_start + HMAC_LEN)
        ));
    }

    let ciphertext = backup.get(data_start..data_end)
        .ok_or("backup ciphertext slice out of bounds")?;

    // Decrypt using backup symmetric helper
    let enc_key = derive_backup_encryption_key(master_kek)?;
    let plaintext = backup_decrypt(&enc_key, ciphertext)
        .map_err(|_| "v2 backup decryption failed: wrong KEK or tampered data".to_string())?;

    use zeroize::Zeroize;
    let mut enc_key = enc_key;
    let mut hmac_key = hmac_key;
    enc_key.zeroize();
    hmac_key.zeroize();

    Ok(plaintext)
}

/// Import a v1 (legacy) backup (MILBK001): AES-256-GCM only.
fn import_backup_v1(master_kek: &[u8; 32], backup: &[u8]) -> Result<Vec<u8>, String> {
    let min_size = 8 + 2 + NONCE_LEN + 8 + TAG_LEN + HMAC_LEN;
    if backup.len() < min_size {
        return Err(format!(
            "v1 backup too small: {} bytes (minimum {})",
            backup.len(),
            min_size
        ));
    }

    // Parse version
    let version = u16::from_le_bytes(
        backup.get(8..10)
            .ok_or("backup too short for version")?
            .try_into()
            .map_err(|_| "failed to parse version")?,
    );
    if version != 1 {
        return Err(format!("unsupported v1 backup version: {version}"));
    }

    let hmac_key = derive_backup_hmac_key(master_kek)?;

    // Verify HMAC first
    let data_portion = backup.get(..backup.len() - HMAC_LEN)
        .ok_or("backup too short for HMAC verification")?;
    let stored_hmac = backup.get(backup.len() - HMAC_LEN..)
        .ok_or("backup too short for HMAC")?;

    let Ok(mut mac) = <HmacSha512 as Mac>::new_from_slice(&hmac_key) else {
        return Err("HMAC-SHA512 initialization failed".to_string());
    };
    mac.update(data_portion);
    let computed_hmac = mac.finalize().into_bytes();

    use subtle::ConstantTimeEq;
    if computed_hmac.ct_eq(stored_hmac).unwrap_u8() != 1 {
        return Err("backup integrity check failed: HMAC mismatch (wrong KEK or corrupt data)".into());
    }

    // Parse nonce and encrypted data length (v1 layout)
    let nonce_bytes = backup.get(10..10 + NONCE_LEN)
        .ok_or("v1 backup too short for nonce")?;
    let encrypted_data_len = u64::from_le_bytes(
        backup.get(10 + NONCE_LEN..10 + NONCE_LEN + 8)
            .ok_or("v1 backup too short for data length")?
            .try_into()
            .map_err(|_| "failed to parse encrypted_data_len")?,
    ) as usize;

    let data_start = 10 + NONCE_LEN + 8;
    let data_end = data_start + encrypted_data_len;

    if data_end + HMAC_LEN != backup.len() {
        return Err(format!(
            "v1 backup size mismatch: expected {} bytes of encrypted data, got {}",
            encrypted_data_len,
            backup.len().saturating_sub(data_start + HMAC_LEN)
        ));
    }

    let ciphertext = backup.get(data_start..data_end)
        .ok_or("v1 backup ciphertext slice out of bounds")?;

    // Decrypt using legacy AES-256-GCM
    let enc_key = derive_backup_encryption_key(master_kek)?;
    let cipher = Aes256Gcm::new_from_slice(&enc_key)
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "v1 backup decryption failed: wrong KEK or tampered data")?;

    use zeroize::Zeroize;
    let mut enc_key = enc_key;
    let mut hmac_key = hmac_key;
    enc_key.zeroize();
    hmac_key.zeroize();

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Streaming backup writer / reader for large datasets
// ---------------------------------------------------------------------------

/// Streaming encrypted backup writer.
///
/// Accumulates data in chunks, then finalises the backup with encryption
/// and HMAC in one pass.  For truly streaming (write-as-you-go) use cases,
/// the writer buffers plaintext and encrypts on [`finish`].
pub struct BackupWriter<W: Write> {
    writer: W,
    plaintext_buffer: Vec<u8>,
    master_kek: [u8; 32],
}

impl<W: Write> BackupWriter<W> {
    /// Create a new streaming backup writer.
    pub fn new(writer: W, master_kek: [u8; 32]) -> Self {
        Self {
            writer,
            plaintext_buffer: Vec::new(),
            master_kek,
        }
    }

    /// Write a chunk of plaintext data to the backup buffer.
    pub fn write_chunk(&mut self, data: &[u8]) -> Result<(), String> {
        self.plaintext_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Finalize the backup: encrypt all buffered data and write the
    /// complete backup (header + ciphertext + HMAC) to the underlying writer.
    pub fn finish(mut self) -> Result<(), String> {
        let backup = export_backup(&self.master_kek, &self.plaintext_buffer)?;
        self.writer
            .write_all(&backup)
            .map_err(|e| format!("write failed: {e}"))?;
        self.writer
            .flush()
            .map_err(|e| format!("flush failed: {e}"))?;

        // Zeroize sensitive data
        use zeroize::Zeroize;
        self.plaintext_buffer.zeroize();
        self.master_kek.zeroize();
        Ok(())
    }
}

/// Streaming encrypted backup reader.
///
/// Reads the entire backup from the underlying reader, verifies integrity,
/// and decrypts.
pub struct BackupReader<R: Read> {
    reader: R,
    master_kek: [u8; 32],
}

impl<R: Read> BackupReader<R> {
    /// Create a new streaming backup reader.
    pub fn new(reader: R, master_kek: [u8; 32]) -> Self {
        Self { reader, master_kek }
    }

    /// Read, verify, and decrypt the backup.
    ///
    /// Returns the decrypted plaintext data.
    pub fn read_all(mut self) -> Result<Vec<u8>, String> {
        let mut backup = Vec::new();
        self.reader
            .read_to_end(&mut backup)
            .map_err(|e| format!("read failed: {e}"))?;

        let result = import_backup(&self.master_kek, &backup)?;

        // Zeroize
        use zeroize::Zeroize;
        self.master_kek.zeroize();
        backup.zeroize();
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// CLI command interface for backup/restore
// ---------------------------------------------------------------------------

/// Execute a backup export from the command line.
///
/// Reads data from `input_path`, encrypts with the master KEK from env,
/// and writes the encrypted backup to `output_path`.
pub fn cli_export_backup(input_path: &str, output_path: &str) -> Result<(), String> {
    let master_kek = crate::sealed_keys::load_master_kek();

    let plaintext = std::fs::read(input_path)
        .map_err(|e| format!("failed to read input {:?}: {e}", input_path))?;

    let backup = export_backup(&master_kek, &plaintext)?;

    std::fs::write(output_path, &backup)
        .map_err(|e| format!("failed to write backup {:?}: {e}", output_path))?;

    tracing::info!(
        "Backup exported: {} bytes plaintext -> {} bytes encrypted at {:?}",
        plaintext.len(),
        backup.len(),
        output_path
    );
    Ok(())
}

/// Execute a backup import (restore) from the command line.
///
/// Reads the encrypted backup from `backup_path`, verifies integrity,
/// decrypts with the master KEK from env, and writes plaintext to `output_path`.
pub fn cli_import_backup(backup_path: &str, output_path: &str) -> Result<(), String> {
    let master_kek = crate::sealed_keys::load_master_kek();

    let backup = std::fs::read(backup_path)
        .map_err(|e| format!("failed to read backup {:?}: {e}", backup_path))?;

    let plaintext = import_backup(&master_kek, &backup)?;

    std::fs::write(output_path, &plaintext)
        .map_err(|e| format!("failed to write restored data {:?}: {e}", output_path))?;

    tracing::info!(
        "Backup restored: {} bytes encrypted -> {} bytes plaintext at {:?}",
        backup.len(),
        plaintext.len(),
        output_path
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> [u8; 32] {
        let mut kek = [0u8; 32];
        getrandom::getrandom(&mut kek).unwrap();
        kek
    }

    #[test]
    fn round_trip_small_backup() {
        let kek = test_kek();
        let data = b"Hello, MILNET backup system!";
        let backup = export_backup(&kek, data).unwrap();
        let restored = import_backup(&kek, &backup).unwrap();
        assert_eq!(&restored, data);
    }

    #[test]
    fn round_trip_empty_backup() {
        let kek = test_kek();
        let backup = export_backup(&kek, b"").unwrap();
        let restored = import_backup(&kek, &backup).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn round_trip_large_backup() {
        let kek = test_kek();
        let data = vec![0xABu8; 128 * 1024]; // 128 KB
        let backup = export_backup(&kek, &data).unwrap();
        let restored = import_backup(&kek, &backup).unwrap();
        assert_eq!(restored, data);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek1 = test_kek();
        let kek2 = test_kek();
        let backup = export_backup(&kek1, b"secret data").unwrap();
        assert!(import_backup(&kek2, &backup).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let kek = test_kek();
        let mut backup = export_backup(&kek, b"secret data").unwrap();
        // Tamper with the ciphertext (after header)
        if backup.len() > 40 {
            backup[35] ^= 0xFF;
        }
        assert!(import_backup(&kek, &backup).is_err());
    }

    #[test]
    fn tampered_hmac_fails() {
        let kek = test_kek();
        let mut backup = export_backup(&kek, b"secret data").unwrap();
        // Tamper with the last byte (HMAC)
        let last = backup.len() - 1;
        backup[last] ^= 0xFF;
        assert!(import_backup(&kek, &backup).is_err());
    }

    #[test]
    fn truncated_backup_fails() {
        let kek = test_kek();
        let backup = export_backup(&kek, b"data").unwrap();
        assert!(import_backup(&kek, &backup[..20]).is_err());
    }

    #[test]
    fn wrong_magic_fails() {
        let kek = test_kek();
        let mut backup = export_backup(&kek, b"data").unwrap();
        backup[0] = b'X';
        assert!(import_backup(&kek, &backup).is_err());
    }

    #[test]
    fn backup_format_has_correct_magic() {
        let kek = test_kek();
        let backup = export_backup(&kek, b"test").unwrap();
        assert_eq!(&backup[..8], BACKUP_MAGIC);
    }

    #[test]
    fn backup_format_has_correct_version() {
        let kek = test_kek();
        let backup = export_backup(&kek, b"test").unwrap();
        let version = u16::from_le_bytes([backup[8], backup[9]]);
        assert_eq!(version, BACKUP_VERSION);
    }

    #[test]
    fn streaming_writer_reader_round_trip() {
        let kek = test_kek();
        let mut output = Vec::new();

        let mut writer = BackupWriter::new(&mut output, kek);
        writer.write_chunk(b"chunk one ").unwrap();
        writer.write_chunk(b"chunk two").unwrap();
        writer.finish().unwrap();

        let reader = BackupReader::new(output.as_slice(), kek);
        let restored = reader.read_all().unwrap();
        assert_eq!(&restored, b"chunk one chunk two");
    }

    #[test]
    fn different_encryptions_produce_different_ciphertexts() {
        let kek = test_kek();
        let data = b"same data";
        let b1 = export_backup(&kek, data).unwrap();
        let b2 = export_backup(&kek, data).unwrap();
        // Nonce is random, so ciphertexts differ
        assert_ne!(b1, b2);
        // But both decrypt to the same plaintext
        assert_eq!(import_backup(&kek, &b1).unwrap(), data);
        assert_eq!(import_backup(&kek, &b2).unwrap(), data);
    }

    // -- V2 AEGIS-256 / V1 legacy compat ------------------------------------

    #[test]
    fn test_backup_v2_aegis256_roundtrip() {
        crate::fips::set_fips_mode_unchecked(false);
        let kek = test_kek();
        let data = b"v2-aegis256-backup-test-data";
        let backup = export_backup(&kek, data).unwrap();
        // Should have MILBK002 magic
        assert_eq!(&backup[..8], BACKUP_MAGIC_V2);
        // Version should be 2
        let version = u16::from_le_bytes([backup[8], backup[9]]);
        assert_eq!(version, 2);
        let restored = import_backup(&kek, &backup).unwrap();
        assert_eq!(&restored, data);
    }

    #[test]
    fn test_backup_v1_backward_compat() {
        // Manually construct a v1 backup (MILBK001, AES-256-GCM, version=1)
        let kek = test_kek();
        let data = b"v1-legacy-backup-plaintext";

        let enc_key = derive_backup_encryption_key(&kek).unwrap();
        let hmac_key = derive_backup_hmac_key(&kek).unwrap();

        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&enc_key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: data, aad: b"" })
            .unwrap();

        let version_v1: u16 = 1;
        let encrypted_data_len = ciphertext.len() as u64;

        let mut backup = Vec::new();
        backup.extend_from_slice(BACKUP_MAGIC_V1);
        backup.extend_from_slice(&version_v1.to_le_bytes());
        backup.extend_from_slice(&nonce_bytes);
        backup.extend_from_slice(&encrypted_data_len.to_le_bytes());
        backup.extend_from_slice(&ciphertext);

        let mut mac = <HmacSha512 as Mac>::new_from_slice(&hmac_key).unwrap();
        mac.update(&backup);
        let hmac_result = mac.finalize().into_bytes();
        backup.extend_from_slice(&hmac_result);

        let restored = import_backup(&kek, &backup).unwrap();
        assert_eq!(&restored, data);
    }
}
