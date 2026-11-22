// SPDX-License-Identifier: AGPL-3.0-or-later
//! Invite codes and join requests (PROTOCOL.md section 7).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

use crate::{Error, Result};

pub const PREFIX: &str = "tgsync1-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub link: String,
    pub vault_id: String,
    pub fingerprint: String,
    pub api: Option<(i64, String)>,
}

pub fn encode_invite(inv: &Invite) -> String {
    let mut d = json!({"l": inv.link, "v": inv.vault_id, "f": inv.fingerprint});
    if let Some((id, hash)) = &inv.api {
        d["a"] = json!([id, hash]);
    }
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&d).unwrap()))
}

pub fn decode_invite(code: &str) -> Result<Invite> {
    let code: String = code.split_whitespace().collect();
    let body = code.strip_prefix(PREFIX).ok_or_else(|| {
        Error::Invite("that does not look like a tgsync invite code (should start with 'tgsync1-')".into())
    })?;
    let damaged = || Error::Invite("invite code is damaged (copy the whole thing)".into());
    let raw = URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| damaged())?;
    let d: Value = serde_json::from_slice(&raw).map_err(|_| damaged())?;
    let s = |k: &str| d.get(k).and_then(Value::as_str).map(str::to_owned).ok_or_else(damaged);
    let api = match d.get("a") {
        None => None,
        Some(a) => Some((
            a.get(0).and_then(Value::as_i64).ok_or_else(damaged)?,
            a.get(1).and_then(Value::as_str).ok_or_else(damaged)?.to_owned(),
        )),
    };
    Ok(Invite { link: s("l")?, vault_id: s("v")?, fingerprint: s("f")?, api })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub vault_id: String,
    pub recipient: String,
    pub name: String,
}

pub fn encode_request(vault_id: &str, recipient: &str, name: &str) -> Vec<u8> {
    let name: String = name.chars().take(40).collect();
    serde_json::to_vec(&json!({"v": 1, "vault": vault_id, "recipient": recipient, "name": name})).unwrap()
}

/// `None` for anything malformed: join requests come from untrusted senders.
pub fn decode_request(data: &[u8]) -> Option<JoinRequest> {
    let d: Value = serde_json::from_slice(data).ok()?;
    if d.get("v")?.as_i64()? != 1 {
        return None;
    }
    let recipient = d.get("recipient")?.as_str()?;
    if !recipient.starts_with("age1") {
        return None;
    }
    Some(JoinRequest {
        vault_id: d.get("vault")?.as_str()?.to_owned(),
        recipient: recipient.to_owned(),
        name: d.get("name").and_then(Value::as_str).unwrap_or("").chars().take(40).collect(),
    })
}
