// X-K: Library half of the audit-witness binary. Holds the request handling
// logic, domain-separated signing, and the persisted per-witness sequence
// chain so the bin and integration tests can both exercise it.
#![deny(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// FIPS 204 domain separator for audit-witness checkpoint signatures.
/// Exactly 32 bytes — the array type enforces it at compile time.
/// Any change to this constant breaks all previously emitted signatures.
pub const AUDIT_WITNESS_DOMAIN: &[u8; 32] = b"AUDIT-WITNESS-CHECKPOINT-v1\0\0\0\0\0";

/// Filename of the per-witness append-only sequence chain inside the data dir.
pub const WITNESS_SEQ_LOG_FILENAME: &str = "witness_seq.log";

/// Each on-disk record: seq (8) || hash (32) || chain_after (32).
pub const SEQ_RECORD_LEN: usize = 8 + 32 + 32;

/// Errors that can be observed by integration tests. The binary itself
/// converts open() failures into fatal exits with SIEM:CRITICAL events.
#[derive(Debug, thiserror::Error)]
pub enum WitnessSeqError {
    #[error("seq replayed or out of order: requested {requested}, last persisted {persisted}")]
    SeqReplay { requested: u64, persisted: u64 },
    #[error("seq log io: {0}")]
    Io(String),
    #[error("seq log corrupt: {0}")]
    Corrupt(String),
}

/// Persisted sequence state. The chain is append-only with each record's
/// `chain_after = SHA-256(prev_chain || seq_be || hash)`. On open() the chain
/// is recomputed end-to-end and any mismatch fails closed (Corrupt).
pub struct WitnessSeqState {
    last_seq: Option<u64>,
    last_chain: [u8; 32],
    log_path: PathBuf,
    /// Strictly serializes record() across threads even though the binary is
    /// single-threaded today. Defensive: an attacker who finds a second entry
    /// path must still pass the monotonic check under contention.
    _serial: Mutex<()>,
}

impl WitnessSeqState {
    /// Open the seq log at `<data_dir>/witness_seq.log`, creating the dir if
    /// missing, and re-verify the persisted chain. Returns Err on any
    /// integrity violation (size not aligned, chain mismatch, non-monotonic).
    pub fn open(data_dir: &Path) -> Result<Self, WitnessSeqError> {
        if !data_dir.exists() {
            std::fs::create_dir_all(data_dir)
                .map_err(|e| WitnessSeqError::Io(format!("mkdir {data_dir:?}: {e}")))?;
        }
        let log_path = data_dir.join(WITNESS_SEQ_LOG_FILENAME);
        let bytes = match std::fs::read(&log_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                return Err(WitnessSeqError::Io(format!("read {log_path:?}: {e}")));
            }
        };
        if bytes.len() % SEQ_RECORD_LEN != 0 {
            return Err(WitnessSeqError::Corrupt(format!(
                "seq log size {} not a multiple of record size {}",
                bytes.len(),
                SEQ_RECORD_LEN
            )));
        }

        let mut chain = [0u8; 32];
        let mut last_seq: Option<u64> = None;
        for (i, rec) in bytes.chunks_exact(SEQ_RECORD_LEN).enumerate() {
            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&rec[0..8]);
            let seq = u64::from_be_bytes(seq_bytes);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&rec[8..40]);
            let mut stored_chain = [0u8; 32];
            stored_chain.copy_from_slice(&rec[40..72]);

            if let Some(prev) = last_seq {
                if seq <= prev {
                    return Err(WitnessSeqError::Corrupt(format!(
                        "non-monotonic seq at record {i}: prev={prev} got={seq}"
                    )));
                }
            }
            let mut h = Sha256::new();
            h.update(chain);
            h.update(seq.to_be_bytes());
            h.update(hash);
            let computed: [u8; 32] = h.finalize().into();
            if !crypto::ct::ct_eq(&computed, &stored_chain) {
                return Err(WitnessSeqError::Corrupt(format!(
                    "chain mismatch at record {i}"
                )));
            }
            chain = computed;
            last_seq = Some(seq);
        }
        Ok(Self {
            last_seq,
            last_chain: chain,
            log_path,
            _serial: Mutex::new(()),
        })
    }

    /// Last persisted sequence number, or None if the log is empty.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Currently committed chain head. All zeros for an empty log.
    pub fn last_chain(&self) -> [u8; 32] {
        self.last_chain
    }

    /// Append a new (seq, hash) record. Rejects any seq that does not strictly
    /// exceed the persisted last seq (replay / equivocation). On success the
    /// 72-byte record is durably persisted (file fsync + parent dir fsync)
    /// before the function returns. Returns the new chain-after value.
    pub fn record(&mut self, seq: u64, hash: &[u8; 32]) -> Result<[u8; 32], WitnessSeqError> {
        // Hold the lock across the entire RMW so a parallel call cannot race
        // the read-of-last_seq with the write.
        let _guard = self._serial.lock().map_err(|_| {
            WitnessSeqError::Io("witness seq mutex poisoned".to_string())
        })?;
        if let Some(prev) = self.last_seq {
            if seq <= prev {
                return Err(WitnessSeqError::SeqReplay {
                    requested: seq,
                    persisted: prev,
                });
            }
        }
        let mut h = Sha256::new();
        h.update(self.last_chain);
        h.update(seq.to_be_bytes());
        h.update(hash);
        let new_chain: [u8; 32] = h.finalize().into();

        let mut rec = [0u8; SEQ_RECORD_LEN];
        rec[0..8].copy_from_slice(&seq.to_be_bytes());
        rec[8..40].copy_from_slice(hash);
        rec[40..72].copy_from_slice(&new_chain);

        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| WitnessSeqError::Io(format!("open {:?}: {e}", self.log_path)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        f.write_all(&rec)
            .map_err(|e| WitnessSeqError::Io(format!("write {:?}: {e}", self.log_path)))?;
        f.sync_all()
            .map_err(|e| WitnessSeqError::Io(format!("fsync {:?}: {e}", self.log_path)))?;
        drop(f);
        if let Some(parent) = self.log_path.parent() {
            if let Ok(d) = std::fs::File::open(parent) {
                let _ = d.sync_all();
            }
        }
        self.last_seq = Some(seq);
        self.last_chain = new_chain;
        Ok(new_chain)
    }
}

/// Build the 40-byte witness signing payload: `seq_be(8) || hash_32`.
/// The same composition is used by both signer and verifier; any change
/// here is a wire-protocol break.
pub fn build_witness_signing_payload(seq: u64, hash: &[u8; 32]) -> [u8; 40] {
    let mut p = [0u8; 40];
    p[0..8].copy_from_slice(&seq.to_be_bytes());
    p[8..40].copy_from_slice(hash);
    p
}

/// Compute the audit-side pre-hash that the witness signs over.
/// This MUST match the layout used by `common::witness::WitnessLog::add_signed_checkpoint`.
pub fn audit_pre_hash(audit_root: &[u8; 64], kt_root: &[u8; 64], seq: u64, ts: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(audit_root);
    h.update(kt_root);
    h.update(seq.to_be_bytes());
    h.update(ts.to_be_bytes());
    h.finalize().into()
}

/// Process a single line-protocol request. The state mutex enforces the
/// monotonic seq invariant. All branches return a complete `\n`-terminated
/// response string.
///
/// Wire protocol:
///   `HEALTH`                              -> `OK <pid> <unix-ts>\n`
///   `VK`                                  -> `VK <hex>\n`
///   `SIGN <decimal-seq> <hex-32-byte>`    -> `SIG <hex>\n` | `ERR ...\n`
pub fn process_request(
    request: &str,
    state: &Mutex<WitnessSeqState>,
    signing_key: &crypto::pq_sign::PqSigningKey,
    vk_hex: &str,
) -> String {
    if request == "HEALTH" {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        return format!("OK {} {}\n", std::process::id(), ts);
    }
    if request == "VK" {
        return format!("VK {vk_hex}\n");
    }
    if let Some(args) = request.strip_prefix("SIGN ") {
        let mut parts = args.splitn(2, ' ');
        let seq_str = match parts.next() {
            Some(s) if !s.is_empty() => s,
            _ => return "ERR malformed SIGN: expected `SIGN <seq> <hex32>`\n".to_string(),
        };
        let hex_hash = match parts.next() {
            Some(h) if !h.is_empty() => h,
            _ => return "ERR malformed SIGN: missing hash\n".to_string(),
        };
        let seq: u64 = match seq_str.parse() {
            Ok(n) => n,
            Err(e) => return format!("ERR seq parse: {e}\n"),
        };
        let hash_bytes = match hex::decode(hex_hash) {
            Ok(b) => b,
            Err(e) => return format!("ERR hex decode: {e}\n"),
        };
        if hash_bytes.len() != 32 {
            return format!("ERR expected 32-byte hash, got {}\n", hash_bytes.len());
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        // Atomically: monotonic check + chain append + sign. Holding the
        // mutex across the sign call also guarantees that two concurrent
        // requests with the same seq cannot both observe `seq > last_seq`.
        let mut st = match state.lock() {
            Ok(s) => s,
            Err(_) => return "ERR witness seq state poisoned\n".to_string(),
        };
        if let Err(e) = st.record(seq, &hash) {
            return match e {
                WitnessSeqError::SeqReplay { requested, persisted } => {
                    tracing::error!(
                        target: "siem",
                        severity = "CRITICAL",
                        action = "audit_witness.seq_replay_rejected",
                        requested,
                        persisted,
                        "audit-witness rejected SIGN with non-monotonic seq"
                    );
                    format!("ERR seq replayed: {requested} <= {persisted}\n")
                }
                WitnessSeqError::Io(s) => {
                    tracing::error!(
                        target: "siem",
                        severity = "CRITICAL",
                        action = "audit_witness.seq_log_io_failure",
                        error = %s,
                        "audit-witness seq log IO failure — refusing to sign"
                    );
                    format!("ERR seq io: {s}\n")
                }
                WitnessSeqError::Corrupt(s) => {
                    tracing::error!(
                        target: "siem",
                        severity = "CRITICAL",
                        action = "audit_witness.seq_log_corrupt",
                        error = %s,
                        "audit-witness seq log corrupt mid-runtime — refusing to sign"
                    );
                    format!("ERR seq corrupt: {s}\n")
                }
            };
        }
        drop(st);

        let payload = build_witness_signing_payload(seq, &hash);
        let sig = match crypto::pq_sign::pq_sign_raw_domain(
            signing_key,
            &payload,
            AUDIT_WITNESS_DOMAIN,
        ) {
            Ok(s) => s,
            Err(e) => return format!("ERR sign: {e}\n"),
        };
        return format!("SIG {}\n", hex::encode(&sig));
    }
    "ERR unknown command\n".to_string()
}

/// Verify a witness signature using the same domain tag and payload layout
/// as the signer. Exposed so downstream verifiers (e.g. `common/witness.rs`)
/// don't have to duplicate the FIPS 204 ctx encoding by hand.
pub fn verify_witness_signature(
    vk: &crypto::pq_sign::PqVerifyingKey,
    seq: u64,
    hash: &[u8; 32],
    sig: &[u8],
) -> bool {
    let payload = build_witness_signing_payload(seq, hash);
    crypto::pq_sign::pq_verify_raw_domain(vk, &payload, AUDIT_WITNESS_DOMAIN, sig)
}
