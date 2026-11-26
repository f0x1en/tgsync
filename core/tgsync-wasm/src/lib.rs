// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebAssembly API of the tgsync core for the Node CLI and the Obsidian plugin.
//! The boundary is JSON strings and byte arrays. Randomness comes from the caller: every call that
//! needs it takes a fresh 32-byte `seed` (from `crypto.getRandomValues`), so the core stays sans-IO.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tgsync_core::crypto::{fingerprint, short_code};
use tgsync_core::descriptor::Identity;
use tgsync_core::replica::Report;
use tgsync_core::sync::{Content, DiskOp, LocalFile, Push};
use tgsync_core::tree::Applied;
use tgsync_core::vault::Vault;
use tgsync_core::{invites, members, oplog};
use wasm_bindgen::prelude::*;

fn js(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

/// Deterministic stream of random bytes from one caller-provided seed. Never pass the same seed
/// twice (AES-GCM nonces come from it); `label` keeps different uses of one seed apart anyway.
struct Stream {
    seed: Vec<u8>,
    label: &'static str,
    n: u64,
}

impl Stream {
    fn new(seed: &[u8], label: &'static str) -> Result<Stream, JsError> {
        if seed.len() < 32 {
            return Err(js("seed must be at least 32 random bytes"));
        }
        Ok(Stream {
            seed: seed.to_vec(),
            label,
            n: 0,
        })
    }
    fn block(&mut self) -> [u8; 32] {
        self.n += 1;
        Sha256::new()
            .chain_update(b"tgsync/wasm-stream/v1\0")
            .chain_update(self.label.as_bytes())
            .chain_update([0u8])
            .chain_update(&self.seed)
            .chain_update(self.n.to_be_bytes())
            .finalize()
            .into()
    }
    fn nonce(&mut self) -> [u8; 12] {
        self.block()[..12].try_into().unwrap()
    }
    fn key(&mut self) -> [u8; 32] {
        self.block()
    }
    fn hex8(&mut self) -> String {
        hex::encode(&self.block()[..8])
    }
}

/// A message id or unix time from JS: a finite, non-negative whole number.
fn whole(x: f64, what: &str) -> Result<i64, JsError> {
    if x.is_finite() && x >= 0.0 && x.fract() == 0.0 && x < 9.0e15 {
        Ok(x as i64)
    } else {
        Err(js(format!("bad {what}: {x}")))
    }
}

/// A message kind: exactly one character.
fn kind_of(kind: &str) -> Result<char, JsError> {
    let mut c = kind.chars();
    match (c.next(), c.next()) {
        (Some(k), None) => Ok(k),
        _ => Err(js(format!("bad message kind {kind:?}"))),
    }
}

fn identity(secret: &str, recipient: &str, signing_hex: Option<String>) -> Result<Identity, JsError> {
    let mut me = Identity::new(secret, recipient);
    if let Some(h) = signing_hex {
        let k: [u8; 32] = hex::decode(h)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| js("signing key must be 64 hex chars"))?;
        me.signing = Some(k);
    }
    Ok(me)
}

fn applied_json(a: &Applied) -> Value {
    match a {
        Applied::Put(p) => json!(["put", p, null]),
        Applied::Noop(p) => json!(["noop", p, null]),
        Applied::Delete(p) => json!(["delete", p, null]),
        Applied::Mkdir(p) => json!(["mkdir", p, null]),
        Applied::Rmdir(p) => json!(["rmdir", p, null]),
        Applied::Conflict(p, c) => json!(["conflict", p, c]),
        Applied::Text(p) => json!(["text", p, null]),
    }
}

/// One folder's engine.
#[wasm_bindgen]
pub struct Engine {
    vault: Vault,
    report: Report,
    /// The planned record: (seq, plan, sealed yet).
    plan: Option<(u64, Push, bool)>,
    /// The folder listing of the push in progress, re-used when `planPush` is called with `null`.
    /// Dropped by anything that changes what is synced from the other side (a pull, materialize).
    listing: Option<BTreeMap<String, LocalFile>>,
}

#[wasm_bindgen]
impl Engine {
    /// `signing_hex`: our Ed25519 signing key (64 hex), `vault_id`: known vault id, if any.
    #[wasm_bindgen(constructor)]
    pub fn new(secret: &str, recipient: &str, signing_hex: Option<String>, vault_id: Option<String>) -> Result<Engine, JsError> {
        Ok(Engine {
            vault: Vault::new(identity(secret, recipient, signing_hex)?, vault_id),
            report: Report::default(),
            plan: None,
            listing: None,
        })
    }

    pub fn load(secret: &str, recipient: &str, signing_hex: Option<String>, state: &[u8]) -> Result<Engine, JsError> {
        let vault = Vault::load(identity(secret, recipient, signing_hex)?, state).map_err(js)?;
        Ok(Engine {
            vault,
            report: Report::default(),
            plan: None,
            listing: None,
        })
    }

    pub fn save(&self) -> Result<Vec<u8>, JsError> {
        self.vault.save().map_err(js)
    }

    // ------------------------------------------------------------------ status

    pub fn cursor(&self) -> f64 {
        self.vault.replica.cursor as f64
    }
    #[wasm_bindgen(js_name = hasKeys)]
    pub fn has_keys(&self) -> bool {
        self.vault.replica.has_keys()
    }
    pub fn blocked(&self) -> bool {
        self.vault.replica.blocked()
    }
    pub fn removed(&self) -> bool {
        self.vault.replica.removed
    }
    #[wasm_bindgen(js_name = vaultId)]
    pub fn vault_id(&self) -> Option<String> {
        self.vault.replica.vault_id.clone()
    }
    /// The vault key fingerprint to compare out of band (epoch 1, else the lowest held).
    pub fn fingerprint(&self) -> Option<String> {
        let k = &self.vault.replica.keys;
        let e = if k.has(1) { 1 } else { k.epochs().next()? };
        Some(fingerprint(k.key(e).ok()?))
    }
    /// JSON `{"members": [{id, name, recipient, signer, admin, owner}], "admins": [...] | null, "owners": [...] | null}`.
    pub fn members(&self) -> String {
        let r = &self.vault.replica;
        let admins = r.admins.clone().unwrap_or_default();
        let owners = r.owners.clone().unwrap_or_default();
        let list: Vec<Value> = r
            .members
            .iter()
            .map(|m| {
                json!({"id": m.id(), "name": m.name, "recipient": m.recipient, "signer": m.signer,
                           "admin": m.signer.as_ref().is_some_and(|s| admins.contains(s)),
                           "owner": m.signer.as_ref().is_some_and(|s| owners.contains(s))})
            })
            .collect();
        json!({"members": list, "admins": r.admins, "owners": r.owners}).to_string()
    }
    /// JSON of the tree: `{path: {sha, size, mtime, author, msg_id, doc}}`.
    pub fn tree(&self) -> String {
        let t: BTreeMap<&String, Value> = self.vault.replica.tree.nodes.iter().map(|(p, n)| (p, n.to_json())).collect();
        serde_json::to_string(&t).unwrap()
    }
    /// JSON `{path: sha}` of what was last synced.
    pub fn synced(&self) -> String {
        serde_json::to_string(&self.vault.synced).unwrap()
    }

    /// Text of a merged note.
    pub fn text(&self, path: &str) -> Option<String> {
        self.vault.replica.text(path)
    }

    // ------------------------------------------------------------------ pull

    #[wasm_bindgen(js_name = beginPass)]
    pub fn begin_pass(&mut self) {
        self.vault.replica.begin_pass();
    }
    #[wasm_bindgen(js_name = wantsBody)]
    pub fn wants_body(&self, kind: &str, id: f64) -> bool {
        match (kind_of(kind), whole(id, "message id")) {
            (Ok(k), Ok(id)) => self.vault.replica.wants_body(k, id),
            _ => false,
        }
    }
    /// Feed message `id` (in increasing id order, after `cursor()`). A message of a kind we do not
    /// know (even an empty or long one) is skipped, and the cursor moves past it.
    pub fn feed(&mut self, id: f64, kind: &str, body: &[u8]) -> Result<(), JsError> {
        let k = kind_of(kind).unwrap_or('?');
        self.vault.replica.feed(whole(id, "message id")?, k, body, &mut self.report);
        Ok(())
    }
    /// End of a pull: returns the report as JSON and queues our rejected edits for re-sending.
    #[wasm_bindgen(js_name = finishPull)]
    pub fn finish_pull(&mut self) -> String {
        self.listing = None;
        let rep = std::mem::take(&mut self.report);
        self.vault.pulled(&rep);
        json!({
            "applied": rep.applied.iter().map(|(id, i, ts, who, a)| json!([id, i, ts, who, applied_json(a)])).collect::<Vec<_>>(),
            "problems": rep.problems,
            "descriptors": rep.descriptors.len(),
            "resend": rep.resend.len(),
            "text_versions": rep.text_versions,
        })
        .to_string()
    }

    // ------------------------------------------------------------------ push

    /// Plan the next record from the folder listing `disk_json`:
    /// `{path: {"sha", "size", "mtime", "text"?: string, "bytes"?: b64, "blob"?: object, "dir"?: true, "keep"?: true}}`.
    /// `keep`: unchanged since the last sync (same sha as `synced()`), so no content is needed.
    /// Returns JSON `{"seq", "entries", "done"}` or `null` if there is nothing to send.
    /// `disk_json` null: plan the next record from the same listing (after `pushed`), so a push of
    /// many records parses the listing once.
    #[wasm_bindgen(js_name = planPush)]
    pub fn plan_push(&mut self, disk_json: Option<String>, seed: &[u8]) -> Result<JsValue, JsError> {
        self.plan = None; // a failed plan must not leave an older one behind
        if let Some(j) = disk_json {
            self.listing = Some(self.parse_listing(&j)?);
        }
        let listing = self
            .listing
            .as_ref()
            .ok_or_else(|| js("planPush(null) needs a listing given earlier in this push"))?;
        let mut s = Stream::new(seed, "plan")?;
        let (seq, push) = self.vault.plan_push(listing, &mut || s.hex8()).map_err(js)?;
        if push.is_empty() {
            return Ok(JsValue::NULL);
        }
        let out = json!({"seq": seq, "entries": push.entries, "done": push.done}).to_string();
        self.plan = Some((seq, push, false));
        Ok(JsValue::from_str(&out))
    }

    fn parse_listing(&self, disk_json: &str) -> Result<BTreeMap<String, LocalFile>, JsError> {
        let d: BTreeMap<String, Value> = serde_json::from_str(disk_json).map_err(js)?;
        let mut disk = BTreeMap::new();
        for (p, f) in d {
            let content = if f.get("dir").and_then(Value::as_bool) == Some(true) {
                Content::Dir
            } else if let Some(t) = f.get("text").and_then(Value::as_str) {
                Content::Text(t.to_owned())
            } else if let Some(b) = f.get("bytes").and_then(Value::as_str) {
                Content::Small(B64.decode(b).map_err(js)?)
            } else if let Some(blob) = f.get("blob") {
                Content::Big(blob.clone())
            } else if f.get("keep").and_then(Value::as_bool) == Some(true) {
                let sha = f.get("sha").and_then(Value::as_str).unwrap_or("");
                if self.vault.synced.get(&p).map(String::as_str) != Some(sha) {
                    return Err(js(format!("{p}: `keep` but it changed since the last sync")));
                }
                Content::Small(vec![])
            } else {
                return Err(js(format!("{p}: needs text, bytes, blob or dir")));
            };
            let sha = f
                .get("sha")
                .and_then(Value::as_str)
                .ok_or_else(|| js(format!("{p}: sha missing")))?
                .to_owned();
            let size = f["size"].as_u64().ok_or_else(|| js(format!("{p}: size missing")))?;
            let mtime = f["mtime"].as_f64().ok_or_else(|| js(format!("{p}: mtime missing")))?;
            disk.insert(p, LocalFile { sha, size, mtime, content });
        }
        Ok(disk)
    }

    /// Seal the planned record (sets the seq: save the engine before posting).
    #[wasm_bindgen(js_name = sealRecord)]
    pub fn seal_record(&mut self, ts: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let (seq, push, sealed) = self.plan.as_mut().ok_or_else(|| js("no planned push"))?;
        let nonce = Stream::new(seed, "record")?.nonce();
        let body = self.vault.seal_record(*seq, push, ts, &nonce).map_err(js)?;
        *sealed = true;
        Ok(body)
    }

    /// The record is posted: mark its files synced.
    pub fn pushed(&mut self) -> Result<(), JsError> {
        match self.plan.take() {
            Some((_, push, true)) => self.vault.pushed(&push),
            Some((seq, push, false)) => {
                self.plan = Some((seq, push, false));
                return Err(js("the planned record was not sealed (call sealRecord, then post it)"));
            }
            None => return Err(js("no planned push")),
        }
        Ok(())
    }

    #[wasm_bindgen(js_name = sealChunk)]
    pub fn seal_chunk(&self, file_id: &str, index: u32, count: u32, data: &[u8], seed: &[u8]) -> Result<Vec<u8>, JsError> {
        oplog::seal_chunk(
            &self.vault.replica.keys,
            file_id,
            index,
            count,
            data,
            &Stream::new(seed, "chunk")?.nonce(),
        )
        .map_err(js)
    }

    #[wasm_bindgen(js_name = openChunk)]
    pub fn open_chunk(&self, file_id: &str, index: u32, count: u32, blob: &[u8]) -> Result<Vec<u8>, JsError> {
        oplog::open_chunk(&self.vault.replica.keys, file_id, index, count, blob).map_err(js)
    }

    /// The payload of a record (small files ride in it; entries point into it with `inline`).
    #[wasm_bindgen(js_name = recordPayload)]
    pub fn record_payload(&self, record: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(oplog::decode_record(&self.vault.replica.keys, record).map_err(js)?.payload)
    }

    /// A record's header as JSON `{"author", "seq", "ts", "entries"}` (e.g. to restore an old version).
    #[wasm_bindgen(js_name = openRecord)]
    pub fn open_record(&self, record: &[u8]) -> Result<String, JsError> {
        let r = oplog::decode_record(&self.vault.replica.keys, record).map_err(js)?;
        Ok(json!({"author": r.author, "seq": r.seq, "ts": r.ts, "entries": r.entries}).to_string())
    }

    /// A note as it was at text sha `sha` (from `finishPull().text_versions`).
    #[wasm_bindgen(js_name = textAt)]
    pub fn text_at(&self, doc: &str, sha: &str) -> Option<String> {
        self.vault.replica.texts.text_at(doc, sha)
    }

    /// Last record seq we posted in this vault. The host also keeps it outside the folder (with the
    /// profile) and gives it back with `setSentSeq` after a re-join, so a fresh engine never reuses
    /// a seq whose record the group does not show yet.
    #[wasm_bindgen(js_name = sentSeq)]
    pub fn sent_seq(&self) -> f64 {
        self.vault.sent_seq as f64
    }

    #[wasm_bindgen(js_name = setSentSeq)]
    pub fn set_sent_seq(&mut self, seq: f64) -> Result<(), JsError> {
        self.vault.sent_seq = self.vault.sent_seq.max(whole(seq, "seq")? as u64);
        Ok(())
    }

    /// Our member id.
    #[wasm_bindgen(js_name = myId)]
    pub fn my_id(&self) -> String {
        self.vault.replica.me.id()
    }

    /// The vault keys, JSON `{"<epoch>": "<hex key>"}`, for a host that seals and opens big-file
    /// chunks itself with the platform's AES-GCM (hardware-accelerated; same format, PROTOCOL.md
    /// section 6). Keep them in memory only.
    #[wasm_bindgen(js_name = vaultKeys)]
    pub fn vault_keys(&self) -> String {
        let k = &self.vault.replica.keys;
        let m: BTreeMap<String, String> = k.epochs().map(|e| (e.to_string(), hex::encode(k.key(e).unwrap()))).collect();
        serde_json::to_string(&m).unwrap()
    }

    /// Key epoch new data is sealed with.
    pub fn epoch(&self) -> Option<u32> {
        self.vault.replica.keys.current_epoch().ok()
    }

    // ------------------------------------------------------------------ materialize

    /// `disk_json`: `{path: sha}` of the folder now. Returns JSON ops:
    /// `[{"op": "write", "path", "sha", "mtime", "text"?, "blob"}, {"op": "delete" | "mkdir" | "rmdir", "path"}]`.
    #[wasm_bindgen(js_name = planMaterialize)]
    pub fn plan_materialize(&mut self, disk_json: &str) -> Result<String, JsError> {
        let disk: BTreeMap<String, String> = serde_json::from_str(disk_json).map_err(js)?;
        let (ops, synced) = self.vault.plan_materialize(&disk);
        let ops: Vec<Value> = ops
            .into_iter()
            .map(|o| match o {
                DiskOp::Write {
                    path,
                    sha,
                    mtime,
                    text,
                    blob,
                } => json!({"op": "write", "path": path, "sha": sha, "mtime": mtime, "text": text, "blob": blob}),
                DiskOp::Delete { path } => json!({"op": "delete", "path": path}),
                DiskOp::Mkdir { path } => json!({"op": "mkdir", "path": path}),
                DiskOp::Rmdir { path } => json!({"op": "rmdir", "path": path}),
            })
            .collect();
        Ok(json!({"ops": ops, "synced": synced}).to_string())
    }

    /// The ops are done: `synced_json` is the `synced` map `planMaterialize` returned.
    pub fn materialized(&mut self, synced_json: &str) -> Result<(), JsError> {
        self.listing = None;
        self.vault.materialized(serde_json::from_str(synced_json).map_err(js)?);
        Ok(())
    }

    // ------------------------------------------------------------------ members (admins only)

    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(&self, recipient: &str, name: &str, signer: Option<String>, created: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut s = Stream::new(seed, "add")?;
        members::add(
            &self.vault.replica,
            recipient,
            name,
            signer.as_deref(),
            whole(created, "time")?,
            &mut || s.nonce(),
        )
        .map_err(js)
    }
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&self, target: &str, created: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut s = Stream::new(seed, "remove")?;
        let key = s.key();
        members::remove(&self.vault.replica, target, &key, whole(created, "time")?, &mut || s.nonce()).map_err(js)
    }
    #[wasm_bindgen(js_name = giveAdmin)]
    pub fn give_admin(&self, target: &str, created: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut s = Stream::new(seed, "give")?;
        members::give_admin(&self.vault.replica, target, whole(created, "time")?, &mut || s.nonce()).map_err(js)
    }
    #[wasm_bindgen(js_name = takeAdmin)]
    pub fn take_admin(&self, target: &str, created: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut s = Stream::new(seed, "take")?;
        members::take_admin(&self.vault.replica, target, whole(created, "time")?, &mut || s.nonce()).map_err(js)
    }
    #[wasm_bindgen(js_name = giveOwner)]
    pub fn give_owner(&self, target: &str, created: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut s = Stream::new(seed, "owner")?;
        members::give_owner(&self.vault.replica, target, whole(created, "time")?, &mut || s.nonce()).map_err(js)
    }
    #[wasm_bindgen(js_name = takeOwner)]
    pub fn take_owner(&self, target: &str, created: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut s = Stream::new(seed, "unowner")?;
        members::take_owner(&self.vault.replica, target, whole(created, "time")?, &mut || s.nonce()).map_err(js)
    }
    #[wasm_bindgen(js_name = dropAdmin)]
    pub fn drop_admin(&self, created: f64, seed: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut s = Stream::new(seed, "drop")?;
        members::drop_admin(&self.vault.replica, whole(created, "time")?, &mut || s.nonce()).map_err(js)
    }
}

/// A new vault's first descriptor. Returns JSON `{"vault_id", "descriptor": b64}`.
#[wasm_bindgen(js_name = createVault)]
pub fn create_vault(secret: &str, recipient: &str, signing_hex: &str, name: &str, created: f64, seed: &[u8]) -> Result<String, JsError> {
    let me = identity(secret, recipient, Some(signing_hex.to_owned()))?;
    let mut s = Stream::new(seed, "create")?;
    let vault_id = s.hex8();
    let key = s.key();
    let d = members::create(&me, name, &vault_id, &key, whole(created, "time")?, &mut || s.nonce()).map_err(js)?;
    Ok(json!({"vault_id": vault_id, "descriptor": B64.encode(d)}).to_string())
}

/// Ed25519 public key (b64) of a signing key (64 hex).
#[wasm_bindgen(js_name = signerOf)]
pub fn signer_of(signing_hex: &str) -> Result<String, JsError> {
    let k: [u8; 32] = hex::decode(signing_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| js("signing key must be 64 hex chars"))?;
    Ok(tgsync_core::descriptor::signer_of(&k))
}

#[wasm_bindgen(js_name = shortCode)]
pub fn short_code_of(recipient: &str) -> String {
    short_code(recipient)
}

/// JSON `{"link", "vault_id", "fingerprint", "api": [id, hash] | null}`.
#[wasm_bindgen(js_name = decodeInvite)]
pub fn decode_invite(code: &str) -> Result<String, JsError> {
    let i = invites::decode_invite(code).map_err(js)?;
    Ok(json!({"link": i.link, "vault_id": i.vault_id, "fingerprint": i.fingerprint, "api": i.api}).to_string())
}

#[wasm_bindgen(js_name = encodeInvite)]
pub fn encode_invite(
    link: &str,
    vault_id: &str,
    fingerprint: &str,
    api_id: Option<f64>,
    api_hash: Option<String>,
) -> Result<String, JsError> {
    let api = match (api_id, api_hash) {
        (Some(i), Some(h)) => Some((whole(i, "api id")?, h)),
        (None, None) => None,
        _ => return Err(js("give both the api id and the api hash, or neither")),
    };
    Ok(invites::encode_invite(&invites::Invite {
        link: link.into(),
        vault_id: vault_id.into(),
        fingerprint: fingerprint.into(),
        api,
    }))
}

#[wasm_bindgen(js_name = encodeJoinRequest)]
pub fn encode_join_request(vault_id: &str, recipient: &str, name: &str, signer: Option<String>) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&invites::encode_request(vault_id, recipient, name)).unwrap();
    if let Some(s) = signer {
        v["signer"] = Value::from(s);
    }
    serde_json::to_vec(&v).unwrap()
}

/// JSON `{"vault_id", "recipient", "name", "signer", "code"}` or `null` if malformed.
#[wasm_bindgen(js_name = decodeJoinRequest)]
pub fn decode_join_request(body: &[u8]) -> String {
    let signer = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("signer").and_then(Value::as_str).map(str::to_owned)); // checked when accepted
    match invites::decode_request(body) {
        Some(r) => json!({"vault_id": r.vault_id, "recipient": r.recipient, "name": r.name, "signer": signer,
                          "code": short_code(&r.recipient)})
        .to_string(),
        None => "null".into(),
    }
}
