// SPDX-License-Identifier: AGPL-3.0-or-later
//! Records (batches of file operations) and chunks of big files (PROTOCOL.md sections 5 and 6).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};

use crate::crypto::{blob_epoch, KeyRing, NONCE_LEN};
use crate::descriptor::signer_of;
use crate::{Error, Result};

pub const CAPTION_PREFIX: &str = "tgs1:";
pub const INLINE_MAX: usize = 256 * 1024;
pub const RECORD_PAYLOAD_MAX: usize = 4 * 1024 * 1024;
pub const DEFAULT_CHUNK: usize = 32 * 1024 * 1024;
pub const MAX_ENTRIES_PER_RECORD: usize = 500;

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub author: String,
    pub seq: u64,
    pub ts: f64,
    /// Entries stay JSON: replay validates each one and skips bad ones.
    pub entries: Vec<Value>,
    pub payload: Vec<u8>,
    /// v2: the author's Ed25519 public key (b64); the signature was checked when decoding.
    pub signer: Option<String>,
}

const SIG_DOMAIN: &[u8] = b"tgsync/rec/v2";
const SIG_LEN: usize = 64;

/// What a v2 record signs: domain, the epoch it is sealed with, header and payload.
fn signed_bytes(epoch: u32, header: &[u8], payload: &[u8]) -> Vec<u8> {
    [SIG_DOMAIN, &epoch.to_be_bytes(), &(header.len() as u32).to_be_bytes(), header, payload].concat()
}

/// `signing: Some(key)` writes a v2 record signed by `key` (PROTOCOL.md section 12); `None` a v1 record.
pub fn encode_record(keys: &KeyRing, rec: &Record, nonce: &[u8; NONCE_LEN], signing: Option<&[u8; 32]>) -> Result<Vec<u8>> {
    let mut h = json!({"v": 1, "author": rec.author, "seq": rec.seq, "ts": rec.ts, "entries": rec.entries});
    if let Some(key) = signing {
        h["v"] = Value::from(2);
        h["signer"] = Value::from(signer_of(key));
    }
    let header = serde_json::to_vec(&h).unwrap();
    let mut plain = [&(header.len() as u32).to_be_bytes()[..], &header, &rec.payload].concat();
    if let Some(key) = signing {
        let msg = signed_bytes(keys.current_epoch()?, &header, &rec.payload);
        plain.extend_from_slice(&SigningKey::from_bytes(key).sign(&msg).to_bytes());
    }
    keys.seal(b"record", b"", &plain, nonce, None)
}

/// Open a record. A v2 record's signature must verify against its `signer` (who that signer
/// belongs to is checked by the replica, against the members at the record's position).
pub fn decode_record(keys: &KeyRing, blob: &[u8]) -> Result<Record> {
    let plain = keys.open(b"record", b"", blob)?;
    let bad = |m: &str| Error::Crypto(format!("malformed record: {m}"));
    if plain.len() < 4 {
        return Err(Error::Crypto("record too short".into()));
    }
    let hl = u32::from_be_bytes(plain[..4].try_into().unwrap()) as usize;
    if hl > plain.len() - 4 {
        return Err(Error::Crypto("record header length invalid".into()));
    }
    let header = &plain[4..4 + hl];
    let h: Value = serde_json::from_slice(header).map_err(|e| bad(&e.to_string()))?;
    let (mut payload, mut signer) = (&plain[4 + hl..], None);
    match h.get("v").and_then(Value::as_i64) {
        Some(1) => {}
        Some(2) => {
            if payload.len() < SIG_LEN {
                return Err(bad("signature missing"));
            }
            let (body, sig) = payload.split_at(payload.len() - SIG_LEN);
            let s = h.get("signer").and_then(Value::as_str).ok_or_else(|| bad("signer"))?;
            let pk: [u8; 32] = B64.decode(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| bad("signer"))?;
            let msg = signed_bytes(blob_epoch(blob)?, header, body);
            VerifyingKey::from_bytes(&pk)
                .and_then(|k| k.verify(&msg, &Signature::from_bytes(sig.try_into().unwrap())))
                .map_err(|_| Error::Crypto("record signature is invalid".into()))?;
            payload = body;
            signer = Some(s.to_owned());
        }
        _ => return Err(Error::Crypto(format!("unsupported record version {}", h.get("v").unwrap_or(&Value::Null)))),
    }
    let seq = h.get("seq").and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)));
    Ok(Record {
        author: h.get("author").and_then(Value::as_str).ok_or_else(|| bad("author"))?.to_owned(),
        seq: seq.ok_or_else(|| bad("seq"))?,
        ts: h.get("ts").and_then(Value::as_f64).ok_or_else(|| bad("ts"))?,
        entries: h.get("entries").and_then(Value::as_array).ok_or_else(|| bad("entries"))?.clone(),
        payload: payload.to_vec(),
        signer,
    })
}

pub fn chunk_ctx(file_id: &str, index: u32, count: u32) -> Vec<u8> {
    format!("{file_id}:{index}:{count}").into_bytes()
}

pub fn seal_chunk(keys: &KeyRing, file_id: &str, index: u32, count: u32, data: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    keys.seal(b"chunk", &chunk_ctx(file_id, index, count), data, nonce, None)
}

pub fn open_chunk(keys: &KeyRing, file_id: &str, index: u32, count: u32, blob: &[u8]) -> Result<Vec<u8>> {
    keys.open(b"chunk", &chunk_ctx(file_id, index, count), blob)
}
