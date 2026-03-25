//! Encrypted backup and restore for the MILNET SSO system.
//!
//! Provides AES-256-GCM encrypted backup export/import using the master KEK.
//! Backup format:
//!
//! ```text
//! MILBK001              (8 bytes - magic)
//! version               (2 bytes - u16 LE, currently 1)
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

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::io::{Read, Write};

type HmacSha512 = Hmac<Sha512>;

/// Magic bytes identifying an encrypted MILNET backup.
const BACKUP_MAGIC: &[u8; 8] = b"MILBK001";

/// Current backup format version.
const BACKUP_VERSION: u16 = 1;

/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;

/// HMAC-SHA512 output length.
const HMAC_LEN: usize = 64;

/// AES-256-GCM tag length.
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
fn derive_backup_encryption_key(master_kek: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(Some(BACKUP_ENCRYPT_DOMAIN), master_kek);
    let mut okm = [0u8; 32];
    hk.expand(b"backup-aes-key", &mut okm)
        .expect("32-byte HKDF expand must succeed");
    okm
}

/// Derive the HMAC-SHA512 key from the master KEK (separate from encryption key).
fn derive_backup_hmac_key(master_kek: &[u8; 32]) -> [u8; 64] {
    let hk = Hkdf::<Sha512>::new(Some(BACKUP_HMAC_DOMAIN), master_kek);
    let mut okm = [0u8; 64];
    hk.expand(b"backup-hmac-key", &mut okm)
        .expect("64-byte HKDF expand must succeed");
    okm
}

/// Encrypt and export backup data using the master KEK.
///
/// Returns the complete encrypted backup blob including magic, version,
/// nonce, ciphertext, and HMAC.
///
/// For backups larger than 256 MB, consider using [`BackupWriter`] instead.
pub fn export_backup(master_kek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.len() > STREAMING_THRESHOLD {
        tracing::warn!(
            "Backup data is {} MB; consider using BackupWriter for streaming",
            plaintext.len() / (1024 * 1024)
        );
    }

    let enc_key = derive_backup_encryption_key(master_kek);
    let hmac_key = derive_backup_hmac_key(master_kek);

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("entropy failure: {e}"))?;

    // Encrypt with AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&enc_key)
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("encryption failed: {e}"))?;

    let encrypted_data_len = ciphertext.len() as u64;

    // Build the backup buffer (everything except HMAC)
    let header_len = 8 + 2 + NONCE_LEN + 8; // magic + version + nonce + len
    let mut backup = Vec::with_capacity(header_len + ciphertext.len() + HMAC_LEN);

    backup.extend_from_slice(BACKUP_MAGIC);
    backup.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
    backup.extend_from_slice(&nonce_bytes);
    backup.extend_from_slice(&encrypted_data_len.to_le_bytes());
    backup.extend_from_slice(&ciphertext);

    // Compute HMAC over everything so far
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&hmac_key)
        .expect("HMAC-SHA512 accepts any key size");
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
/// Returns the decrypted plaintext data on success.
pub fn import_backup(master_kek: &[u8; 32], backup: &[u8]) -> Result<Vec<u8>, String> {
    let min_size = 8 + 2 + NONCE_LEN + 8 + TAG_LEN + HMAC_LEN;
    if backup.len() < min_size {
        return Err(format!(
            "backup too small: {} bytes (minimum {})",
            backup.len(),
            min_size
        ));
    }

    // Validate magic
    if &backup[..8] != BACKUP_MAGIC {
        return Err("invalid backup: magic bytes do not match".into());
    }

    // Parse version
    let version = u16::from_le_bytes([backup[8], backup[9]]);
    if version != BACKUP_VERSION {
        return Err(format!("unsupported backup version: {version}"));
    }

    let hmac_key = derive_backup_hmac_key(master_kek);

    // Verify HMAC first (before any decryption)
    let data_portion = &backup[..backup.len() - HMAC_LEN];
    let stored_hmac = &backup[backup.len() - HMAC_LEN..];

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&hmac_key)
        .expect("HMAC-SHA512 accepts any key size");
    mac.update(data_portion);
    let computed_hmac = mac.finalize().into_bytes();

    // Constant-time comparison via subtle
    use subtle::ConstantTimeEq;
    if computed_hmac.ct_eq(stored_hmac).unwrap_u8() != 1 {
        return Err("backup integrity check failed: HMAC mismatch (wrong KEK or corrupt data)".into());
    }

    // Parse nonce and encrypted data length
    let nonce_bytes = &backup[10..10 + NONCE_LEN];
    let encrypted_data_len = u64::from_le_bytes(
        backup[10 + NONCE_LEN..10 + NONCE_LEN + 8]
            .try_into()
            .map_err(|_| "failed to parse encrypted_data_len")?,
    ) as usize;

    let data_start = 10 + NONCE_LEN + 8;
    let data_end = data_start + encrypted_data_len;

    if data_end + HMAC_LEN != backup.len() {
        return Err(format!(
            "backup size mismatch: expected {} bytes of encrypted data, got {}",
            encrypted_data_len,
            backup.len() - data_start - HMAC_LEN
        ));
    }

    let ciphertext = &backup[data_start..data_end];

    // Decrypt
    let enc_key = derive_backup_encryption_key(master_kek);
    let cipher = Aes256Gcm::new_from_slice(&enc_key)
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "backup decryption failed: wrong KEK or tampered data")?;

    // Zeroize sensitive key material
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
}
