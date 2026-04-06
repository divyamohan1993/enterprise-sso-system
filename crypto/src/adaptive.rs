//! Adaptive Cryptographic Framework for MILNET SSO.
//!
//! Risk-engine-driven automatic algorithm escalation.
//! Threat levels drive encryption strength from single-layer AEGIS-256
//! (Normal) up to triple-layer with ephemeral re-key (Critical).
//!
//! Wire format: `0xAD || threat_level (1 byte) || layer_data`

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use aes_gcm::KeyInit as AesKeyInit;
use aegis::aegis256::Aegis256;
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use chacha20poly1305::KeyInit as ChaChaKeyInit;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha512;

// ---------------------------------------------------------------------------
// Threat level
// ---------------------------------------------------------------------------

/// Cryptographic threat level driving algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum CryptoThreatLevel {
    Normal   = 0,
    Elevated = 1,
    High     = 2,
    Critical = 3,
}

impl CryptoThreatLevel {
    /// Map a continuous risk score in [0,1] to a threat level.
    pub fn from_risk_score(score: f64) -> Self {
        if score >= 0.8 {
            Self::Critical
        } else if score >= 0.6 {
            Self::High
        } else if score >= 0.3 {
            Self::Elevated
        } else {
            Self::Normal
        }
    }

    /// Convert from a raw u8 tag (values > 3 treated as Critical).
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Normal,
            1 => Self::Elevated,
            2 => Self::High,
            _ => Self::Critical,
        }
    }
}

// ---------------------------------------------------------------------------
// Wire format tag
// ---------------------------------------------------------------------------

/// First byte of every adaptive ciphertext blob.
const ADAPTIVE_TAG: u8 = 0xAD;

// ---------------------------------------------------------------------------
// Internal cipher constants
// ---------------------------------------------------------------------------

const AEGIS256_NONCE_LEN: usize = 32;
const AEGIS256_TAG_LEN:   usize = 32;
const AES_GCM_NONCE_LEN:  usize = 12;
const CHACHA_NONCE_LEN:   usize = 12;

// ---------------------------------------------------------------------------
// AdaptiveCrypto
// ---------------------------------------------------------------------------

/// Adaptive cryptographic service that scales algorithm strength to the
/// current threat level.
///
/// Features audit logging for every threat level change and hysteresis
/// (debounce) to prevent rapid oscillation between threat levels.
pub struct AdaptiveCrypto {
    current_level: AtomicU8,
    escalation_history: Mutex<Vec<(i64, CryptoThreatLevel)>>,
    /// Seconds that must pass at a lower threat level before de-escalation
    /// is allowed. Default: 900 (15 min).
    deescalation_cooldown_secs: u64,
    /// Pending escalation: (requested_level, first_seen_timestamp).
    /// The escalation only takes effect after the level is sustained for
    /// `debounce_secs` seconds.  Protected by Mutex for thread safety.
    pending_escalation: Mutex<Option<(CryptoThreatLevel, i64)>>,
    /// Seconds a threat level must be sustained before escalation applies.
    /// Configurable via `MILNET_ADAPTIVE_DEBOUNCE_SECS` env var (default: 10).
    debounce_secs: u64,
}

impl AdaptiveCrypto {
    /// Construct with Normal threat level and 15-minute de-escalation cooldown.
    ///
    /// Reads `MILNET_ADAPTIVE_DEBOUNCE_SECS` env var for hysteresis period
    /// (default: 10 seconds).
    pub fn new() -> Self {
        let debounce = std::env::var("MILNET_ADAPTIVE_DEBOUNCE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10);
        Self {
            current_level: AtomicU8::new(CryptoThreatLevel::Normal as u8),
            escalation_history: Mutex::new(Vec::new()),
            deescalation_cooldown_secs: 900,
            pending_escalation: Mutex::new(None),
            debounce_secs: debounce,
        }
    }

    /// Return the current threat level.
    pub fn current_level(&self) -> CryptoThreatLevel {
        CryptoThreatLevel::from_u8(self.current_level.load(Ordering::SeqCst))
    }

    /// Log a threat level change to the audit trail and SIEM channel.
    fn audit_level_change(
        previous: CryptoThreatLevel,
        new: CryptoThreatLevel,
        reason: &str,
        timestamp: i64,
    ) {
        tracing::warn!(
            previous_level = ?previous,
            new_level = ?new,
            reason = reason,
            timestamp = timestamp,
            "SIEM:AUDIT adaptive crypto threat level change: {:?} -> {:?} (reason: {}, ts: {})",
            previous, new, reason, timestamp
        );
    }

    /// Escalate to `new_level` with hysteresis (debounce).
    ///
    /// The escalation only takes effect if the same level (or higher) is
    /// requested for at least `debounce_secs` consecutive seconds.
    /// This prevents rapid oscillation from transient threat signals.
    ///
    /// To bypass debounce for immediate escalation (e.g., confirmed attack),
    /// use `escalate_immediate`.
    pub fn escalate(&self, new_level: CryptoThreatLevel) {
        let now = unix_timestamp_secs();
        let current = self.current_level();

        if current >= new_level {
            // Already at or above requested level — clear pending
            let mut pending = self.pending_escalation.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in adaptive - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
            *pending = None;
            return;
        }

        // Check debounce: has this level been sustained long enough?
        let mut pending = self.pending_escalation.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in adaptive - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        match *pending {
            Some((pending_level, first_seen)) if pending_level <= new_level => {
                let sustained_secs = now.saturating_sub(first_seen) as u64;
                if sustained_secs >= self.debounce_secs {
                    // Debounce period satisfied — apply escalation
                    *pending = None;
                    drop(pending);
                    self.escalate_immediate_with_reason(
                        new_level,
                        &format!("sustained for {}s (debounce: {}s)", sustained_secs, self.debounce_secs),
                    );
                } else {
                    // Update pending level if higher, keep original timestamp
                    if new_level > pending_level {
                        *pending = Some((new_level, first_seen));
                    }
                    // Still waiting for debounce period
                }
            }
            _ => {
                // No pending or pending is for a different (lower) level — start new debounce
                *pending = Some((new_level, now));

                // If debounce is 0, apply immediately
                if self.debounce_secs == 0 {
                    drop(pending);
                    self.escalate_immediate_with_reason(new_level, "debounce=0, immediate");
                }
            }
        }
    }

    /// Immediately escalate to `new_level` without debounce.
    ///
    /// Use for confirmed attacks or when debounce is inappropriate.
    pub fn escalate_immediate(&self, new_level: CryptoThreatLevel) {
        self.escalate_immediate_with_reason(new_level, "immediate escalation requested");
    }

    /// Internal: apply escalation with audit logging.
    fn escalate_immediate_with_reason(&self, new_level: CryptoThreatLevel, reason: &str) {
        let now = unix_timestamp_secs();
        let previous = self.current_level();

        // Store the escalation event regardless — it resets cooldown tracking.
        {
            let mut hist = self.escalation_history.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in adaptive - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
            hist.push((now, new_level));
        }
        // CAS loop: only raise the level.
        let mut did_change = false;
        loop {
            let cur = self.current_level.load(Ordering::SeqCst);
            if cur >= new_level as u8 {
                break;
            }
            if self
                .current_level
                .compare_exchange(cur, new_level as u8, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                did_change = true;
                break;
            }
        }

        if did_change {
            Self::audit_level_change(previous, new_level, reason, now);
        }
    }

    /// Attempt de-escalation by one level.
    ///
    /// Only succeeds when the most recent escalation occurred more than
    /// `deescalation_cooldown_secs` ago. Logs the de-escalation to the
    /// audit trail.
    pub fn deescalate(&self) {
        let now = unix_timestamp_secs();
        let hist = self.escalation_history.lock().unwrap_or_else(|e| {
                    tracing::warn!(target: "siem", "SIEM:WARNING mutex poisoned in adaptive - recovering: thread panicked while holding lock");
                    e.into_inner()
                });
        if let Some(&(last_ts, _)) = hist.last() {
            let elapsed = now.saturating_sub(last_ts) as u64;
            if elapsed < self.deescalation_cooldown_secs {
                return; // Still in cooldown — refuse de-escalation.
            }
        }
        drop(hist);

        let previous = self.current_level();

        // Decrement by one, bottom at Normal(0).
        let mut did_change = false;
        loop {
            let cur = self.current_level.load(Ordering::SeqCst);
            if cur == 0 {
                break;
            }
            if self
                .current_level
                .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                did_change = true;
                break;
            }
        }

        if did_change {
            let new_level = self.current_level();
            Self::audit_level_change(previous, new_level, "de-escalation after cooldown", now);
        }
    }

    // -----------------------------------------------------------------------
    // Public encrypt / decrypt
    // -----------------------------------------------------------------------

    /// Encrypt with the current threat level.
    ///
    /// Wire format: `0xAD || threat_level (1) || layer_data`
    pub fn encrypt_adaptive(
        &self,
        key: &[u8; 32],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        let level = self.current_level();
        let layer_data = match level {
            CryptoThreatLevel::Normal   => encrypt_normal(key, plaintext, aad)?,
            CryptoThreatLevel::Elevated => encrypt_elevated(key, plaintext, aad)?,
            CryptoThreatLevel::High     => encrypt_high(key, plaintext, aad)?,
            CryptoThreatLevel::Critical => encrypt_critical(key, plaintext, aad)?,
        };

        let mut out = Vec::with_capacity(2 + layer_data.len());
        out.push(ADAPTIVE_TAG);
        out.push(level as u8);
        out.extend_from_slice(&layer_data);
        Ok(out)
    }

    /// Decrypt — reads threat level from wire format, peels correct layers.
    ///
    /// The level is taken from the stored wire tag; the caller's current
    /// threat level does not affect decryption.
    pub fn decrypt_adaptive(
        &self,
        key: &[u8; 32],
        sealed: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if sealed.len() < 2 {
            return Err("adaptive blob too short".into());
        }
        let tag = sealed.first().copied().ok_or("missing tag byte")?;
        if tag != ADAPTIVE_TAG {
            return Err(format!("bad adaptive tag: 0x{tag:02X}"));
        }
        let level_byte = sealed.get(1).copied().ok_or("missing level byte")?;
        let level = CryptoThreatLevel::from_u8(level_byte);
        let payload = sealed.get(2..).ok_or("missing payload")?;

        match level {
            CryptoThreatLevel::Normal   => decrypt_normal(key, payload, aad),
            CryptoThreatLevel::Elevated => decrypt_elevated(key, payload, aad),
            CryptoThreatLevel::High     => decrypt_high(key, payload, aad),
            CryptoThreatLevel::Critical => decrypt_critical(key, payload, aad),
        }
    }
}

impl Default for AdaptiveCrypto {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

static ADAPTIVE_CRYPTO: LazyLock<AdaptiveCrypto> = LazyLock::new(AdaptiveCrypto::new);

/// Access the global `AdaptiveCrypto` singleton.
pub fn adaptive_crypto() -> &'static AdaptiveCrypto {
    &ADAPTIVE_CRYPTO
}

// ---------------------------------------------------------------------------
// Layer-key derivation (High / Critical)
// ---------------------------------------------------------------------------

/// Derive three independent 32-byte subkeys from a master key via HKDF-SHA512.
pub fn derive_layer_keys(master: &[u8; 32]) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let hk = Hkdf::<Sha512>::new(Some(b"MILNET-ADAPTIVE-LAYER-SALT-v1"), master);
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let mut k3 = [0u8; 32];
    hk.expand(b"MILNET-ADAPTIVE-LAYER1-v1", &mut k1).map_err(|e| {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand failed for adaptive layer1 key",
            &format!("{e}"),
            file!(), line!(), column!(), module_path!(),
        );
        format!("HKDF layer1: {e}")
    })?;
    hk.expand(b"MILNET-ADAPTIVE-LAYER2-v1", &mut k2).map_err(|e| {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand failed for adaptive layer2 key",
            &format!("{e}"),
            file!(), line!(), column!(), module_path!(),
        );
        format!("HKDF layer2: {e}")
    })?;
    hk.expand(b"MILNET-ADAPTIVE-LAYER3-v1", &mut k3).map_err(|e| {
        common::siem::emit_runtime_error(
            common::siem::category::CRYPTO_FAILURE,
            "HKDF-SHA512 expand failed for adaptive layer3 key",
            &format!("{e}"),
            file!(), line!(), column!(), module_path!(),
        );
        format!("HKDF layer3: {e}")
    })?;
    Ok((k1, k2, k3))
}

// ---------------------------------------------------------------------------
// Normal (level 0): single AEGIS-256
// ---------------------------------------------------------------------------

fn encrypt_normal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_aegis256(key, plaintext, aad)
}

fn decrypt_normal(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    decrypt_aegis256(key, payload, aad)
}

// ---------------------------------------------------------------------------
// Elevated (level 1): AEGIS-256 + HMAC-SHA512 double-auth tag
// ---------------------------------------------------------------------------

fn encrypt_elevated(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let ciphertext = encrypt_aegis256(key, plaintext, aad)?;

    // Append HMAC-SHA512(key, ciphertext) as an extra authentication tag.
    let mut mac = <Hmac::<Sha512> as Mac>::new_from_slice(key)
        .map_err(|e| format!("HMAC-SHA512 key error: {e}"))?;
    mac.update(&ciphertext);
    let hmac_tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(ciphertext.len() + 64);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&hmac_tag);
    Ok(out)
}

fn decrypt_elevated(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    // Last 64 bytes are the HMAC-SHA512 tag.
    if payload.len() < 64 {
        return Err("elevated payload too short for HMAC tag".into());
    }
    let split = payload.len() - 64;
    let ciphertext = payload.get(..split).ok_or("elevated: ciphertext slice OOB")?;
    let stored_tag = payload.get(split..).ok_or("elevated: tag slice OOB")?;

    // Verify HMAC before decryption (encrypt-then-MAC).
    let mut mac = <Hmac::<Sha512> as Mac>::new_from_slice(key)
        .map_err(|e| format!("HMAC-SHA512 key error: {e}"))?;
    mac.update(ciphertext);
    mac.verify_slice(stored_tag)
        .map_err(|_| "elevated: HMAC-SHA512 verification failed")?;

    decrypt_aegis256(key, ciphertext, aad)
}

// ---------------------------------------------------------------------------
// High (level 2): triple-layer AES-GCM → ChaCha20-Poly1305 → AEGIS-256
// ---------------------------------------------------------------------------

fn encrypt_high(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let (k1, k2, k3) = derive_layer_keys(key)?;

    // Layer 1 (inner): AES-256-GCM
    let layer1 = encrypt_aes256gcm(&k1, plaintext, aad)?;
    // Layer 2 (middle): ChaCha20-Poly1305
    let layer2 = encrypt_chacha20(&k2, &layer1, aad)?;
    // Layer 3 (outer): AEGIS-256
    let layer3 = encrypt_aegis256(&k3, &layer2, aad)?;

    Ok(layer3)
}

fn decrypt_high(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let (k1, k2, k3) = derive_layer_keys(key)?;

    // Peel outer: AEGIS-256
    let layer2 = decrypt_aegis256(&k3, payload, aad)?;
    // Peel middle: ChaCha20-Poly1305
    let layer1 = decrypt_chacha20(&k2, &layer2, aad)?;
    // Peel inner: AES-256-GCM
    decrypt_aes256gcm(&k1, &layer1, aad)
}

// ---------------------------------------------------------------------------
// Critical (level 3): ephemeral key + triple-layer
// ---------------------------------------------------------------------------
// Wire format for Critical payload:
//   encrypted_ephemeral_len (4 LE bytes) || encrypted_ephemeral || triple_layer(plaintext)

fn encrypt_critical(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    // Generate an ephemeral 32-byte key.
    let mut ephemeral_key = [0u8; 32];
    getrandom::getrandom(&mut ephemeral_key)
        .map_err(|e| format!("ephemeral key generation failed: {e}"))?;

    // Encrypt the ephemeral key with the master key (AEGIS-256).
    let enc_ephemeral = encrypt_aegis256(key, &ephemeral_key, b"MILNET-CRITICAL-EPH-v1")?;
    let enc_eph_len = u32::try_from(enc_ephemeral.len())
        .map_err(|_| "ephemeral ciphertext too large")?;

    // Triple-layer encrypt the plaintext with the ephemeral key.
    let triple = encrypt_high(&ephemeral_key, plaintext, aad)?;

    let mut out = Vec::with_capacity(4 + enc_ephemeral.len() + triple.len());
    out.extend_from_slice(&enc_eph_len.to_le_bytes());
    out.extend_from_slice(&enc_ephemeral);
    out.extend_from_slice(&triple);
    Ok(out)
}

fn decrypt_critical(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < 4 {
        return Err("critical payload too short for length prefix".into());
    }
    let len_bytes = payload.get(..4).ok_or("critical: length prefix OOB")?;
    let enc_eph_len = u32::from_le_bytes(
        len_bytes.try_into().map_err(|_| "critical: length bytes conversion failed")?,
    ) as usize;

    let enc_eph_end = 4_usize
        .checked_add(enc_eph_len)
        .ok_or("critical: enc_eph_len overflow")?;
    if payload.len() < enc_eph_end {
        return Err("critical: payload too short for encrypted ephemeral key".into());
    }

    let enc_ephemeral = payload.get(4..enc_eph_end).ok_or("critical: enc ephemeral slice OOB")?;
    let triple = payload.get(enc_eph_end..).ok_or("critical: triple slice OOB")?;

    // Recover the ephemeral key.
    let ephemeral_key_bytes =
        decrypt_aegis256(key, enc_ephemeral, b"MILNET-CRITICAL-EPH-v1")?;
    if ephemeral_key_bytes.len() != 32 {
        return Err("critical: recovered ephemeral key has wrong length".into());
    }
    let mut ephemeral_key = [0u8; 32];
    ephemeral_key.copy_from_slice(&ephemeral_key_bytes);

    // Decrypt the triple-layer data.
    decrypt_high(&ephemeral_key, triple, aad)
}

// ---------------------------------------------------------------------------
// Low-level cipher helpers (AEGIS-256, AES-256-GCM, ChaCha20-Poly1305)
// ---------------------------------------------------------------------------

fn encrypt_aegis256(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; AEGIS256_NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| format!("AEGIS-256 nonce generation failed: {e}"))?;

    let (ct, tag) = Aegis256::<AEGIS256_TAG_LEN>::new(key, &nonce).encrypt(plaintext, aad);

    let mut out = Vec::with_capacity(AEGIS256_NONCE_LEN + ct.len() + AEGIS256_TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn decrypt_aegis256(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let min = AEGIS256_NONCE_LEN + AEGIS256_TAG_LEN;
    if payload.len() < min {
        return Err(format!(
            "AEGIS-256 payload too short: {} (need {})",
            payload.len(),
            min
        ));
    }
    let nonce_slice = payload.get(..AEGIS256_NONCE_LEN).ok_or("AEGIS-256: nonce OOB")?;
    let rest = payload.get(AEGIS256_NONCE_LEN..).ok_or("AEGIS-256: rest OOB")?;
    let tag_off = rest.len() - AEGIS256_TAG_LEN;
    let ct  = rest.get(..tag_off).ok_or("AEGIS-256: ciphertext OOB")?;
    let tag_sl = rest.get(tag_off..).ok_or("AEGIS-256: tag OOB")?;

    let mut nonce = [0u8; AEGIS256_NONCE_LEN];
    nonce.copy_from_slice(nonce_slice);
    let mut tag = [0u8; AEGIS256_TAG_LEN];
    tag.copy_from_slice(tag_sl);

    Aegis256::<AEGIS256_TAG_LEN>::new(key, &nonce)
        .decrypt(ct, &tag, aad)
        .map_err(|e| format!("AEGIS-256 decryption failed: {e}"))
}

fn encrypt_aes256gcm(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("AES-256-GCM nonce generation failed: {e}"))?;

    let cipher = <Aes256Gcm as AesKeyInit>::new(GenericArray::from_slice(key));
    let nonce  = GcmNonce::from_slice(&nonce_bytes);
    let ct_tag = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(AES_GCM_NONCE_LEN + ct_tag.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct_tag);
    Ok(out)
}

fn decrypt_aes256gcm(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < AES_GCM_NONCE_LEN + 16 {
        return Err(format!(
            "AES-256-GCM payload too short: {}",
            payload.len()
        ));
    }
    let nonce_sl = payload.get(..AES_GCM_NONCE_LEN).ok_or("AES-GCM: nonce OOB")?;
    let ct_tag   = payload.get(AES_GCM_NONCE_LEN..).ok_or("AES-GCM: payload OOB")?;

    let cipher = <Aes256Gcm as AesKeyInit>::new(GenericArray::from_slice(key));
    let nonce  = GcmNonce::from_slice(nonce_sl);
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: ct_tag, aad })
        .map_err(|e| format!("AES-256-GCM decryption failed: {e}"))
}

fn encrypt_chacha20(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; CHACHA_NONCE_LEN];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| format!("ChaCha20 nonce generation failed: {e}"))?;

    let cipher = <ChaCha20Poly1305 as ChaChaKeyInit>::new(ChaChaKey::from_slice(key));
    let nonce  = ChaChaNonce::from_slice(&nonce_bytes);
    let ct_tag = cipher
        .encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
        .map_err(|e| format!("ChaCha20-Poly1305 encryption failed: {e}"))?;

    let mut out = Vec::with_capacity(CHACHA_NONCE_LEN + ct_tag.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct_tag);
    Ok(out)
}

fn decrypt_chacha20(key: &[u8; 32], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() < CHACHA_NONCE_LEN + 16 {
        return Err(format!(
            "ChaCha20-Poly1305 payload too short: {}",
            payload.len()
        ));
    }
    let nonce_sl = payload.get(..CHACHA_NONCE_LEN).ok_or("ChaCha20: nonce OOB")?;
    let ct_tag   = payload.get(CHACHA_NONCE_LEN..).ok_or("ChaCha20: payload OOB")?;

    let cipher = <ChaCha20Poly1305 as ChaChaKeyInit>::new(ChaChaKey::from_slice(key));
    let nonce  = ChaChaNonce::from_slice(nonce_sl);
    cipher
        .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ct_tag, aad })
        .map_err(|e| format!("ChaCha20-Poly1305 decryption failed: {e}"))
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

fn unix_timestamp_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("getrandom failed");
        k
    }

    #[test]
    fn test_threat_level_from_risk_score() {
        assert_eq!(CryptoThreatLevel::from_risk_score(0.1), CryptoThreatLevel::Normal);
        assert_eq!(CryptoThreatLevel::from_risk_score(0.4), CryptoThreatLevel::Elevated);
        assert_eq!(CryptoThreatLevel::from_risk_score(0.7), CryptoThreatLevel::High);
        assert_eq!(CryptoThreatLevel::from_risk_score(0.9), CryptoThreatLevel::Critical);
    }

    #[test]
    fn test_adaptive_normal_roundtrip() {
        let ac = AdaptiveCrypto::new();
        // Default level is Normal.
        assert_eq!(ac.current_level(), CryptoThreatLevel::Normal);
        let key = random_key();
        let pt = b"normal plaintext";
        let aad = b"aad-normal";
        let sealed = ac.encrypt_adaptive(&key, pt, aad).expect("encrypt failed");
        let recovered = ac.decrypt_adaptive(&key, &sealed, aad).expect("decrypt failed");
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn test_adaptive_elevated_roundtrip() {
        let ac = AdaptiveCrypto::new();
        ac.escalate_immediate(CryptoThreatLevel::Elevated);
        assert_eq!(ac.current_level(), CryptoThreatLevel::Elevated);

        let key = random_key();
        let pt  = b"elevated plaintext";
        let aad = b"aad-elevated";
        let sealed = ac.encrypt_adaptive(&key, pt, aad).expect("encrypt failed");

        // Wire level byte should be 1.
        assert_eq!(sealed.get(1).copied(), Some(CryptoThreatLevel::Elevated as u8));

        // Payload should have the 64-byte HMAC suffix.
        let payload_len = sealed.len() - 2;
        // AEGIS ciphertext len = nonce(32) + pt_len + tag(32); HMAC appends 64 more.
        assert!(payload_len > AEGIS256_NONCE_LEN + AEGIS256_TAG_LEN + 64);

        let recovered = ac.decrypt_adaptive(&key, &sealed, aad).expect("decrypt failed");
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn test_adaptive_high_triple_layer() {
        let ac = AdaptiveCrypto::new();
        ac.escalate_immediate(CryptoThreatLevel::High);
        assert_eq!(ac.current_level(), CryptoThreatLevel::High);

        let key = random_key();
        let pt  = b"top secret triple layer message";
        let aad = b"aad-high";
        let sealed = ac.encrypt_adaptive(&key, pt, aad).expect("encrypt failed");
        assert_eq!(sealed.get(1).copied(), Some(CryptoThreatLevel::High as u8));

        let recovered = ac.decrypt_adaptive(&key, &sealed, aad).expect("decrypt failed");
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn test_adaptive_critical_rekey() {
        let ac = AdaptiveCrypto::new();
        ac.escalate_immediate(CryptoThreatLevel::Critical);
        assert_eq!(ac.current_level(), CryptoThreatLevel::Critical);

        let key = random_key();
        let pt  = b"critical eyes only";
        let aad = b"aad-critical";
        let sealed = ac.encrypt_adaptive(&key, pt, aad).expect("encrypt failed");
        assert_eq!(sealed.get(1).copied(), Some(CryptoThreatLevel::Critical as u8));

        let recovered = ac.decrypt_adaptive(&key, &sealed, aad).expect("decrypt failed");
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn test_adaptive_escalation_immediate() {
        let ac = AdaptiveCrypto::new();
        assert_eq!(ac.current_level(), CryptoThreatLevel::Normal);
        ac.escalate_immediate(CryptoThreatLevel::High);
        assert_eq!(ac.current_level(), CryptoThreatLevel::High);
        // Attempting to escalate to Elevated should be a no-op (already higher).
        ac.escalate_immediate(CryptoThreatLevel::Elevated);
        assert_eq!(ac.current_level(), CryptoThreatLevel::High);
    }

    #[test]
    fn test_adaptive_escalation_debounce() {
        // With default debounce (10s), a single escalate() call should NOT
        // immediately change the level.
        std::env::set_var("MILNET_ADAPTIVE_DEBOUNCE_SECS", "10");
        let ac = AdaptiveCrypto::new();
        std::env::remove_var("MILNET_ADAPTIVE_DEBOUNCE_SECS");

        assert_eq!(ac.current_level(), CryptoThreatLevel::Normal);
        ac.escalate(CryptoThreatLevel::High);
        // Level should still be Normal — debounce period not yet elapsed
        assert_eq!(ac.current_level(), CryptoThreatLevel::Normal);

        // escalate_immediate bypasses debounce
        ac.escalate_immediate(CryptoThreatLevel::High);
        assert_eq!(ac.current_level(), CryptoThreatLevel::High);
    }

    #[test]
    fn test_adaptive_zero_debounce_escalates_immediately() {
        std::env::set_var("MILNET_ADAPTIVE_DEBOUNCE_SECS", "0");
        let ac = AdaptiveCrypto::new();
        std::env::remove_var("MILNET_ADAPTIVE_DEBOUNCE_SECS");

        ac.escalate(CryptoThreatLevel::Elevated);
        assert_eq!(ac.current_level(), CryptoThreatLevel::Elevated);
    }

    #[test]
    fn test_adaptive_deescalation_cooldown() {
        let ac = AdaptiveCrypto::new();
        ac.escalate_immediate(CryptoThreatLevel::High);
        // Immediately try to de-escalate — cooldown hasn't elapsed.
        ac.deescalate();
        // Level must remain High.
        assert_eq!(ac.current_level(), CryptoThreatLevel::High);
    }

    #[test]
    fn test_adaptive_cross_level_decrypt() {
        // Encrypt at High, then decrypt with a *different* AdaptiveCrypto at Normal.
        // Must succeed because the level is embedded in the wire format.
        let ac_high = AdaptiveCrypto::new();
        ac_high.escalate_immediate(CryptoThreatLevel::High);

        let ac_normal = AdaptiveCrypto::new();
        assert_eq!(ac_normal.current_level(), CryptoThreatLevel::Normal);

        let key = random_key();
        let pt  = b"cross level decrypt test";
        let aad = b"aad-cross";
        let sealed   = ac_high.encrypt_adaptive(&key, pt, aad).expect("encrypt failed");
        let recovered = ac_normal.decrypt_adaptive(&key, &sealed, aad).expect("decrypt failed");
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn test_adaptive_wire_format_tag() {
        let ac = AdaptiveCrypto::new();
        let key = random_key();
        let sealed = ac.encrypt_adaptive(&key, b"data", b"aad").expect("encrypt");
        assert_eq!(sealed.first().copied(), Some(ADAPTIVE_TAG));
        assert_eq!(ADAPTIVE_TAG, 0xAD);
    }

    #[test]
    fn test_derive_layer_keys_distinct() {
        let master = random_key();
        let (k1, k2, k3) = derive_layer_keys(&master).expect("derive_layer_keys");
        assert_ne!(k1, k2, "layer keys must be distinct");
        assert_ne!(k1, k3, "layer keys must be distinct");
        assert_ne!(k2, k3, "layer keys must be distinct");
    }
}
