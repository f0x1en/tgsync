// SPDX-License-Identifier: AGPL-3.0-or-later
//! Descriptors: who the members are, and the vault keys wrapped to each of them (PROTOCOL.md section 4).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::crypto::{mac, member_id, KeyRing, NONCE_LEN};
use crate::identity::{unwrap, wrap_for};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub recipient: String,
    pub name: String,
}

impl Member {
    pub fn id(&self) -> String {
        member_id(&self.recipient)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Descriptor {
    pub vault_id: String,
    pub epoch: u32,
    pub members: Vec<Member>,
    pub raw: Value,
}

/// Our identity: age secret + public recipient.
#[derive(Debug, Clone)]
pub struct Identity {
    pub secret: String,
    pub recipient: String,
}

impl Identity {
    pub fn id(&self) -> String {
        member_id(&self.recipient)
    }
}

fn err(m: impl Into<String>) -> Error {
    Error::Crypto(m.into())
}

fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            Value::Object(keys.into_iter().map(|k| (k.clone(), sorted(&m[k]))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
        _ => v.clone(),
    }
}

/// Canonical JSON = Python `json.dumps(sort_keys=True, separators=(",", ":"))`: sorted keys, no spaces,
/// non-ASCII as `\uXXXX` escapes (UTF-16 units). Python and JS sort keys by code point / UTF-16 unit;
/// both agree with byte order for the ASCII keys the protocol uses.
pub fn canon(v: &Value) -> String {
    let s = serde_json::to_string(&sorted(v)).unwrap();
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

fn sha(v: &Value) -> [u8; 32] {
    Sha256::digest(canon(v).as_bytes()).into()
}

fn keycheck(key: &[u8], vault_id: &str, epoch: u32) -> String {
    hex::encode(mac(key, &[b"descriptor", vault_id.as_bytes(), epoch.to_string().as_bytes()]))
}

/// Build a descriptor for `members` carrying every epoch key in `ring`.
/// `created` is unix seconds; `nonce` gives fresh random bytes (two nonces are drawn).
pub fn build(
    ring: &KeyRing,
    vault_id: &str,
    members: &[Member],
    proof_epoch: Option<u32>,
    created: i64,
    nonce: &mut dyn FnMut() -> [u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let epoch = ring.current_epoch()?;
    let mut keys = Map::new();
    for e in ring.epochs() {
        keys.insert(e.to_string(), Value::from(B64.encode(ring.key(e)?)));
    }
    let keys_payload = serde_json::to_vec(&json!({ "keys": keys })).unwrap();
    let roster: Vec<Value> =
        members.iter().map(|m| json!({"id": m.id(), "recipient": m.recipient, "name": m.name})).collect();
    let mut wrapped = vec![];
    for m in members {
        wrapped.push(json!({"id": m.id(), "wrapped": B64.encode(wrap_for(&m.recipient, &keys_payload)?)}));
    }
    let proof_epoch = proof_epoch.unwrap_or(epoch);
    let roster_blob = ring.seal(b"roster", vault_id.as_bytes(), &serde_json::to_vec(&roster).unwrap(), &nonce(), Some(epoch))?;
    let mut body = json!({
        "v": 1,
        "vault_id": vault_id,
        "epoch": epoch,
        "created": created,
        "proof_epoch": proof_epoch,
        "members": wrapped,
        "roster": B64.encode(roster_blob),
        "keycheck": keycheck(ring.key(epoch)?, vault_id, epoch),
    });
    let ctx = format!("{vault_id}:{epoch}");
    let proof = ring.seal(b"descproof", ctx.as_bytes(), &sha(&body), &nonce(), Some(proof_epoch))?;
    body["proof"] = Value::from(B64.encode(proof));
    Ok(canon(&body).into_bytes())
}

pub fn parse(data: &[u8]) -> Result<Value> {
    let d: Value = serde_json::from_slice(data).map_err(|e| err(format!("malformed descriptor: {e}")))?;
    for k in ["v", "vault_id", "epoch", "members", "roster", "proof", "proof_epoch", "keycheck"] {
        if d.get(k).is_none() {
            return Err(err(format!("malformed descriptor: missing {k}")));
        }
    }
    if d["v"].as_i64() != Some(1) {
        return Err(err(format!("unsupported descriptor version {}", d["v"])));
    }
    Ok(d)
}

fn b64d(v: &Value) -> Result<Vec<u8>> {
    v.as_str().and_then(|s| B64.decode(s).ok()).ok_or_else(|| err("bad base64"))
}

/// Validate a descriptor and merge its keys into `ring`.
/// `Ok(None)`: valid but excludes us (we were removed, or not added yet). `Err`: forged or inconsistent.
/// `trusted`: it was already validated when stored locally.
pub fn accept(data: &[u8], me: &Identity, ring: &mut KeyRing, expected_vault_id: Option<&str>, trusted: bool) -> Result<Option<Descriptor>> {
    let d = parse(data)?;
    let vault_id = d["vault_id"].as_str().ok_or_else(|| err("malformed descriptor: vault_id"))?.to_owned();
    if expected_vault_id.is_some_and(|v| !v.is_empty() && v != vault_id) {
        return Err(err("descriptor belongs to a different vault"));
    }
    let epoch = d["epoch"].as_u64().and_then(|e| u32::try_from(e).ok()).ok_or_else(|| err("malformed descriptor: epoch"))?;
    if !ring.is_empty() && epoch < ring.current_epoch()? {
        return Err(err("descriptor epoch is older than ours (replay?)"));
    }
    let my_id = me.id();
    let members = d["members"].as_array().ok_or_else(|| err("malformed descriptor: members"))?;
    let Some(mine) = members.iter().find(|m| m.get("id").and_then(Value::as_str) == Some(my_id.as_str())) else {
        return Ok(None);
    };
    let bad_keys = |m: String| err(format!("malformed wrapped keys: {m}"));
    let payload: Value = serde_json::from_slice(&unwrap(&me.secret, &b64d(&mine["wrapped"])?)?).map_err(|e| bad_keys(e.to_string()))?;
    let mut keys: Vec<(u32, Vec<u8>)> = vec![];
    for (e, k) in payload.get("keys").and_then(Value::as_object).ok_or_else(|| bad_keys("keys".into()))? {
        keys.push((e.parse().map_err(|_| bad_keys(e.clone()))?, b64d(k)?));
    }
    let Some((_, own)) = keys.iter().find(|(e, _)| *e == epoch) else {
        return Err(err("descriptor does not contain its own epoch key"));
    };
    let mut candidate = ring.clone();
    for (e, k) in &keys {
        candidate.add(*e, k)?; // conflicting key for a known epoch -> reject
    }
    if d["keycheck"].as_str() != Some(keycheck(own, &vault_id, epoch).as_str()) {
        return Err(err("descriptor keycheck mismatch"));
    }
    let proof_epoch = d["proof_epoch"].as_u64().ok_or_else(|| err("bad proof epoch"))?;
    if proof_epoch != u64::from(epoch) && proof_epoch + 1 != u64::from(epoch) {
        return Err(err("bad proof epoch"));
    }
    let verifier = if !trusted && !ring.is_empty() {
        if !ring.has(proof_epoch as u32) {
            return Err(err("descriptor proof uses a key we do not hold"));
        }
        &*ring
    } else {
        &candidate // joining: trust on first use (the invite's fingerprint is the check)
    };
    let mut body = d.clone();
    body.as_object_mut().unwrap().remove("proof");
    let digest = verifier.open(b"descproof", format!("{vault_id}:{epoch}").as_bytes(), &b64d(&d["proof"])?)?;
    if digest != sha(&body) {
        return Err(err("descriptor proof does not match body"));
    }
    *ring = candidate;
    let roster = b64d(&d["roster"])
        .and_then(|r| ring.open(b"roster", vault_id.as_bytes(), &r))
        .and_then(|plain| serde_json::from_slice::<Value>(&plain).map_err(|e| err(e.to_string())))
        .map_err(|e| err(format!("cannot read roster: {e}")))?;
    let members = roster
        .as_array()
        .ok_or_else(|| err("cannot read roster: not a list"))?
        .iter()
        .map(|r| {
            Ok(Member {
                recipient: r.get("recipient").and_then(Value::as_str).ok_or_else(|| err("cannot read roster: recipient"))?.to_owned(),
                name: r.get("name").and_then(Value::as_str).unwrap_or("").to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Some(Descriptor { vault_id, epoch, members, raw: d }))
}
