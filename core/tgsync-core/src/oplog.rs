// SPDX-License-Identifier: AGPL-3.0-or-later
//! Records (batches of file operations) and chunks of big files (PROTOCOL.md sections 5 and 6).

use serde_json::{json, Value};

use crate::crypto::{KeyRing, NONCE_LEN};
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
}

pub fn encode_record(keys: &KeyRing, rec: &Record, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let header = serde_json::to_vec(&json!({
        "v": 1, "author": rec.author, "seq": rec.seq, "ts": rec.ts, "entries": rec.entries,
    }))
    .unwrap();
    let plain = [&(header.len() as u32).to_be_bytes()[..], &header, &rec.payload].concat();
    keys.seal(b"record", b"", &plain, nonce, None)
}

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
    let h: Value = serde_json::from_slice(&plain[4..4 + hl]).map_err(|e| bad(&e.to_string()))?;
    if h.get("v").and_then(Value::as_i64) != Some(1) {
        return Err(Error::Crypto(format!("unsupported record version {}", h.get("v").unwrap_or(&Value::Null))));
    }
    let seq = h.get("seq").and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)));
    Ok(Record {
        author: h.get("author").and_then(Value::as_str).ok_or_else(|| bad("author"))?.to_owned(),
        seq: seq.ok_or_else(|| bad("seq"))?,
        ts: h.get("ts").and_then(Value::as_f64).ok_or_else(|| bad("ts"))?,
        entries: h.get("entries").and_then(Value::as_array).ok_or_else(|| bad("entries"))?.clone(),
        payload: plain[4 + hl..].to_vec(),
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
