// SPDX-License-Identifier: AGPL-3.0-or-later
//! Descriptors: who the members are, and the vault keys wrapped to each of them (PROTOCOL.md section 4).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::crypto::{mac, member_id, KeyRing, NONCE_LEN};
use crate::identity::{unwrap, wrap_for};
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub recipient: String,
    pub name: String,
    /// Ed25519 public key (b64), v2 vaults only.
    pub signer: Option<String>,
}

impl Member {
    pub fn new(recipient: &str, name: &str) -> Self {
        Member {
            recipient: recipient.into(),
            name: name.into(),
            signer: None,
        }
    }

    pub fn id(&self) -> String {
        member_id(&self.recipient)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Descriptor {
    pub vault_id: String,
    pub epoch: u32,
    pub members: Vec<Member>,
    /// v2: signer keys allowed to post the next descriptor. `None` for v1.
    pub admins: Option<Vec<String>>,
    /// v2: the admins who may also change admins and owners (PROTOCOL.md section 11). `None` for v1.
    pub owners: Option<Vec<String>>,
    pub raw: Value,
}

/// Our identity: age secret + public recipient, and (v2) an Ed25519 signing key.
#[derive(Debug, Clone)]
pub struct Identity {
    pub secret: String,
    pub recipient: String,
    pub signing: Option<[u8; 32]>,
}

impl Identity {
    pub fn new(secret: &str, recipient: &str) -> Self {
        Identity {
            secret: secret.into(),
            recipient: recipient.into(),
            signing: None,
        }
    }

    pub fn id(&self) -> String {
        member_id(&self.recipient)
    }

    /// Our signer public key (b64), if we have a signing key.
    pub fn signer(&self) -> Option<String> {
        self.signing.as_ref().map(signer_of)
    }
}

/// b64 Ed25519 public key for a signing key.
pub fn signer_of(signing: &[u8; 32]) -> String {
    B64.encode(SigningKey::from_bytes(signing).verifying_key().as_bytes())
}

const SIG_DOMAIN: &[u8] = b"tgsync/desc/v2";

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

/// What a descriptor says, without its proof: the same for an exact re-post and for one a member
/// sealed again with a fresh proof. `None` if it does not parse.
pub fn content_id(data: &[u8]) -> Option<[u8; 32]> {
    let mut d = parse(data).ok()?;
    d.as_object_mut()?.remove("proof");
    Some(sha(&d))
}

fn keycheck(key: &[u8], vault_id: &str, epoch: u32) -> String {
    hex::encode(mac(key, &[b"descriptor", vault_id.as_bytes(), epoch.to_string().as_bytes()]))
}

/// v2 signing: the admin and owner lists and the key that signs this descriptor. `owners: None`
/// writes no owner list (as older clients did): the previous one then carries over.
pub struct Signing<'a> {
    pub admins: &'a [String],
    pub owners: Option<&'a [String]>,
    pub key: &'a [u8; 32],
}

/// Who held which role just before a descriptor: what its signer may change depends on it.
#[derive(Clone, Copy)]
pub struct Roles<'a> {
    pub members: &'a [Member],
    pub admins: &'a [String],
    pub owners: &'a [String],
}

/// What [`check_v2`] found: the new admins and owners, and whether a plain admin (not an owner) signed.
struct V2 {
    admins: Vec<String>,
    owners: Vec<String>,
    plain_admin: bool,
}

fn key_list(v: &Value, what: &str) -> Result<Vec<String>> {
    v.as_array()
        .and_then(|a| a.iter().map(|x| x.as_str().map(str::to_owned)).collect())
        .ok_or_else(|| err(format!("malformed descriptor: {what}")))
}

fn same_set(a: &[String], b: &[String]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    a.dedup();
    b.sort();
    b.dedup();
    a == b
}

/// Build a descriptor for `members` carrying every epoch key in `ring`.
/// `signing: None` makes a v1 descriptor; `Some` a v2 one (PROTOCOL.md section 11).
/// `created` is unix seconds; `nonce` gives fresh random bytes (two nonces are drawn).
pub fn build(
    ring: &KeyRing,
    vault_id: &str,
    members: &[Member],
    proof_epoch: Option<u32>,
    created: i64,
    signing: Option<Signing>,
    nonce: &mut dyn FnMut() -> [u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let epoch = ring.current_epoch()?;
    let mut keys = Map::new();
    for e in ring.epochs() {
        keys.insert(e.to_string(), Value::from(B64.encode(ring.key(e)?)));
    }
    let keys_payload = serde_json::to_vec(&json!({ "keys": keys })).unwrap();
    let roster: Vec<Value> = members
        .iter()
        .map(|m| {
            let mut r = json!({"id": m.id(), "recipient": m.recipient, "name": m.name});
            if let Some(s) = &m.signer {
                r["signer"] = Value::from(s.clone());
            }
            r
        })
        .collect();
    let mut wrapped = vec![];
    for m in members {
        wrapped.push(json!({"id": m.id(), "wrapped": B64.encode(wrap_for(&m.recipient, &keys_payload)?)}));
    }
    let proof_epoch = proof_epoch.unwrap_or(epoch);
    let roster_blob = ring.seal(
        b"roster",
        vault_id.as_bytes(),
        &serde_json::to_vec(&roster).unwrap(),
        &nonce(),
        Some(epoch),
    )?;
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
    if let Some(sg) = &signing {
        let mut admins = sg.admins.to_vec();
        admins.sort();
        admins.dedup();
        body["v"] = Value::from(2);
        body["admins"] = Value::from(admins);
        if let Some(owners) = sg.owners {
            let mut owners = owners.to_vec();
            owners.sort();
            owners.dedup();
            body["owners"] = Value::from(owners);
        }
        body["signer"] = Value::from(signer_of(sg.key));
    }
    let ctx = format!("{vault_id}:{epoch}");
    let proof = ring.seal(b"descproof", ctx.as_bytes(), &sha(&body), &nonce(), Some(proof_epoch))?;
    body["proof"] = Value::from(B64.encode(proof));
    if let Some(sg) = &signing {
        let msg = [SIG_DOMAIN, canon(&body).as_bytes()].concat();
        body["sig"] = Value::from(B64.encode(SigningKey::from_bytes(sg.key).sign(&msg).to_bytes()));
    }
    Ok(canon(&body).into_bytes())
}

pub fn parse(data: &[u8]) -> Result<Value> {
    let d: Value = serde_json::from_slice(data).map_err(|e| err(format!("malformed descriptor: {e}")))?;
    let v = d.get("v").and_then(Value::as_i64);
    if v != Some(1) && v != Some(2) {
        return Err(err(format!(
            "unsupported descriptor version {}",
            d.get("v").unwrap_or(&Value::Null)
        )));
    }
    let mut need = vec!["vault_id", "epoch", "members", "roster", "proof", "proof_epoch", "keycheck"];
    if v == Some(2) {
        need.extend(["admins", "signer", "sig"]);
    }
    for k in need {
        if d.get(k).is_none() {
            return Err(err(format!("malformed descriptor: missing {k}")));
        }
    }
    Ok(d)
}

fn b64d(v: &Value) -> Result<Vec<u8>> {
    v.as_str().and_then(|s| B64.decode(s).ok()).ok_or_else(|| err("bad base64"))
}

/// v2: the signature must verify, and the signer must be an admin: of the vault's last accepted
/// v2 descriptor (`prev`), or of its own list when there is none yet (trust on first use). Then the
/// role rules (PROTOCOL.md section 11): an owner may change anything; a plain admin may add people,
/// remove plain members (or themselves) and drop their own admin, nothing else. With no owner list
/// the previous owners carry over; the vault's first v2 descriptor makes its signer the owner.
/// `enforce: false` (stored, already checked) only works out the roles.
fn check_v2(d: &Value, prev: Option<Roles>, enforce: bool) -> Result<V2> {
    let admins = key_list(&d["admins"], "admins")?;
    if admins.is_empty() {
        return Err(err("descriptor has no admins"));
    }
    let signer = d["signer"].as_str().ok_or_else(|| err("malformed descriptor: signer"))?;
    let pk: [u8; 32] = B64
        .decode(signer)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err("bad signer key"))?;
    let sig: [u8; 64] = b64d(&d["sig"])?.try_into().map_err(|_| err("bad signature"))?;
    let mut body = d.clone();
    body.as_object_mut().unwrap().remove("sig");
    let msg = [SIG_DOMAIN, canon(&body).as_bytes()].concat();
    VerifyingKey::from_bytes(&pk)
        .and_then(|k| k.verify(&msg, &Signature::from_bytes(&sig)))
        .map_err(|_| err("descriptor signature is invalid"))?;
    let allowed = prev.map_or(&admins[..], |p| p.admins);
    if !allowed.iter().any(|a| a == signer) {
        return Err(err("descriptor not signed by an admin"));
    }
    let listed = d.get("owners").map(|o| key_list(o, "owners")).transpose()?;
    let owners = listed.unwrap_or_else(|| prev.map_or_else(|| vec![signer.to_owned()], |p| p.owners.to_vec()));
    let plain_admin = prev.is_some_and(|p| !p.owners.iter().any(|o| o == signer));
    if enforce {
        if let (true, Some(p)) = (plain_admin, prev) {
            if !same_set(&owners, p.owners) {
                return Err(err("only an owner can change who the owners are"));
            }
            let without_me: Vec<String> = p.admins.iter().filter(|a| *a != signer).cloned().collect();
            if !same_set(&admins, p.admins) && !same_set(&admins, &without_me) {
                return Err(err("only an owner can make or unmake admins"));
            }
            // Members are listed by id in the clear, so even someone this leaves out can check it.
            let ids: Vec<&str> = d["members"]
                .as_array()
                .map(|a| a.iter().filter_map(|m| m.get("id").and_then(Value::as_str)).collect())
                .unwrap_or_default();
            for m in p.members {
                let gone = !ids.contains(&m.id().as_str());
                let admin = m.signer.as_ref().is_some_and(|s| p.admins.contains(s));
                if gone && admin && m.signer.as_deref() != Some(signer) {
                    return Err(err("an admin can only remove plain members, not other admins or owners"));
                }
            }
        }
        if owners.is_empty() {
            return Err(err("descriptor has no owners"));
        }
        if !owners.iter().all(|o| admins.contains(o)) {
            return Err(err("an owner is not an admin"));
        }
    }
    Ok(V2 { admins, owners, plain_admin })
}

/// A plain admin may not change the signing key of someone who stays (that would hand their name to
/// another key). Checked once the roster is readable.
fn check_kept_signers(v2: &Option<V2>, prev: Option<Roles>, members: &[Member], enforce: bool) -> Result<()> {
    if let (true, Some(V2 { plain_admin: true, .. }), Some(p)) = (enforce, v2, prev) {
        for m in members {
            if p.members.iter().any(|o| o.recipient == m.recipient && o.signer != m.signer) {
                return Err(err("only an owner can change a member's signing key"));
            }
        }
    }
    Ok(())
}

/// Validate a descriptor and merge its keys into `ring`.
/// `Ok(None)`: valid but excludes us (we were removed, or not added yet). `Err`: forged or inconsistent.
/// `trusted`: it was already validated when stored locally.
/// `prev`: roles of the vault's last accepted v2 descriptor, if any.
pub fn accept(
    data: &[u8],
    me: &Identity,
    ring: &mut KeyRing,
    expected_vault_id: Option<&str>,
    trusted: bool,
    prev: Option<Roles>,
) -> Result<Option<Descriptor>> {
    let d = parse(data)?;
    let v2 = d["v"].as_i64() == Some(2);
    let vault_id = d["vault_id"]
        .as_str()
        .ok_or_else(|| err("malformed descriptor: vault_id"))?
        .to_owned();
    if expected_vault_id.is_some_and(|v| !v.is_empty() && v != vault_id) {
        return Err(err("descriptor belongs to a different vault"));
    }
    let epoch = d["epoch"]
        .as_u64()
        .and_then(|e| u32::try_from(e).ok())
        .ok_or_else(|| err("malformed descriptor: epoch"))?;
    if !ring.is_empty() && epoch < ring.current_epoch()? {
        return Err(err("descriptor epoch is older than ours (replay?)"));
    }
    if prev.is_some() && !v2 {
        return Err(err("v1 descriptor in a vault that has admins"));
    }
    let roles = if v2 { Some(check_v2(&d, prev, !trusted)?) } else { None };
    let proof_epoch = d["proof_epoch"].as_u64().ok_or_else(|| err("bad proof epoch"))?;
    if proof_epoch != u64::from(epoch) && proof_epoch.checked_add(1) != Some(u64::from(epoch)) {
        return Err(err("bad proof epoch"));
    }
    let mut body = d.clone();
    body.as_object_mut().unwrap().remove("proof");
    body.as_object_mut().unwrap().remove("sig");
    let proof_ctx = format!("{vault_id}:{epoch}");
    let my_id = me.id();
    let members = d["members"].as_array().ok_or_else(|| err("malformed descriptor: members"))?;
    let Some(mine) = members.iter().find(|m| m.get("id").and_then(Value::as_str) == Some(my_id.as_str())) else {
        // Leaves us out. Believe that only if it is proven with a key we hold; otherwise anyone
        // who can post in the group could make us think we were removed.
        if !ring.is_empty() && !trusted {
            let proof_epoch = u32::try_from(proof_epoch).map_err(|_| err("bad proof epoch"))?;
            if !ring.has(proof_epoch) {
                return Err(err("descriptor proof uses a key we do not hold"));
            }
            let digest = ring.open(b"descproof", proof_ctx.as_bytes(), &b64d(&d["proof"])?)?;
            if digest != sha(&body) {
                return Err(err("descriptor proof does not match body"));
            }
        }
        return Ok(None);
    };
    let bad_keys = |m: String| err(format!("malformed wrapped keys: {m}"));
    let payload: Value = serde_json::from_slice(&unwrap(&me.secret, &b64d(&mine["wrapped"])?)?).map_err(|e| bad_keys(e.to_string()))?;
    let mut keys: Vec<(u32, Vec<u8>)> = vec![];
    for (e, k) in payload
        .get("keys")
        .and_then(Value::as_object)
        .ok_or_else(|| bad_keys("keys".into()))?
    {
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
    let verifier = if !trusted && !ring.is_empty() {
        if !ring.has(proof_epoch as u32) {
            return Err(err("descriptor proof uses a key we do not hold"));
        }
        &*ring
    } else {
        &candidate // joining: trust on first use (the invite's fingerprint is the check)
    };
    let digest = verifier.open(b"descproof", proof_ctx.as_bytes(), &b64d(&d["proof"])?)?;
    if digest != sha(&body) {
        return Err(err("descriptor proof does not match body"));
    }
    let roster = b64d(&d["roster"])
        .and_then(|r| candidate.open(b"roster", vault_id.as_bytes(), &r))
        .and_then(|plain| serde_json::from_slice::<Value>(&plain).map_err(|e| err(e.to_string())))
        .map_err(|e| err(format!("cannot read roster: {e}")))?;
    let members = roster
        .as_array()
        .ok_or_else(|| err("cannot read roster: not a list"))?
        .iter()
        .map(|r| {
            Ok(Member {
                recipient: r
                    .get("recipient")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err("cannot read roster: recipient"))?
                    .to_owned(),
                name: r.get("name").and_then(Value::as_str).unwrap_or("").to_owned(),
                signer: r.get("signer").and_then(Value::as_str).map(str::to_owned),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(r) = &roles {
        if !r.admins.iter().all(|a| members.iter().any(|m| m.signer.as_ref() == Some(a))) {
            return Err(err("an admin is not a member"));
        }
    }
    check_kept_signers(&roles, prev, &members, !trusted)?;
    *ring = candidate;
    let (admins, owners) = roles.map_or((None, None), |r| (Some(r.admins), Some(r.owners)));
    Ok(Some(Descriptor {
        vault_id,
        epoch,
        members,
        admins,
        owners,
        raw: d,
    }))
}

/// What one descriptor says about the vault: the key epoch and members from its log position on.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub epoch: u32,
    pub members: Vec<Member>,
    pub admins: Option<Vec<String>>,
    pub owners: Option<Vec<String>>,
}

impl Snapshot {
    /// Its roles, for checking the next descriptor (`None` in a v1 vault).
    pub fn roles(&self) -> Option<Roles<'_>> {
        Some(Roles {
            members: &self.members,
            admins: self.admins.as_deref()?,
            owners: self.owners.as_deref().unwrap_or(&[]),
        })
    }
}

/// Validate a descriptor with keys we already hold, whether or not it includes us, and read its
/// roster. Used to build the membership history every replica agrees on (records are checked against
/// the members and epoch at their position). `prev` = the last snapshot in the history.
pub fn inspect(data: &[u8], ring: &KeyRing, expected_vault_id: Option<&str>, prev: Option<&Snapshot>) -> Result<Snapshot> {
    let d = parse(data)?;
    let v2 = d["v"].as_i64() == Some(2);
    let vault_id = d["vault_id"].as_str().ok_or_else(|| err("malformed descriptor: vault_id"))?;
    if expected_vault_id.is_some_and(|v| !v.is_empty() && v != vault_id) {
        return Err(err("descriptor belongs to a different vault"));
    }
    let epoch = d["epoch"]
        .as_u64()
        .and_then(|e| u32::try_from(e).ok())
        .ok_or_else(|| err("malformed descriptor: epoch"))?;
    if prev.is_some_and(|p| epoch < p.epoch) {
        return Err(err("descriptor epoch is older than ours (replay?)"));
    }
    let prev_roles = prev.and_then(Snapshot::roles);
    if prev_roles.is_some() && !v2 {
        return Err(err("v1 descriptor in a vault that has admins"));
    }
    let roles = if v2 { Some(check_v2(&d, prev_roles, true)?) } else { None };
    let proof_epoch = d["proof_epoch"]
        .as_u64()
        .and_then(|e| u32::try_from(e).ok())
        .ok_or_else(|| err("bad proof epoch"))?;
    if proof_epoch != epoch && proof_epoch.checked_add(1) != Some(epoch) {
        return Err(err("bad proof epoch"));
    }
    let mut body = d.clone();
    body.as_object_mut().unwrap().remove("proof");
    body.as_object_mut().unwrap().remove("sig");
    let digest = ring.open(b"descproof", format!("{vault_id}:{epoch}").as_bytes(), &b64d(&d["proof"])?)?;
    if digest != sha(&body) {
        return Err(err("descriptor proof does not match body"));
    }
    if d["keycheck"].as_str() != Some(keycheck(ring.key(epoch)?, vault_id, epoch).as_str()) {
        return Err(err("descriptor keycheck mismatch"));
    }
    let roster: Value = serde_json::from_slice(&ring.open(b"roster", vault_id.as_bytes(), &b64d(&d["roster"])?)?)
        .map_err(|e| err(format!("cannot read roster: {e}")))?;
    let members = roster
        .as_array()
        .ok_or_else(|| err("cannot read roster: not a list"))?
        .iter()
        .map(|r| {
            Ok(Member {
                recipient: r
                    .get("recipient")
                    .and_then(Value::as_str)
                    .ok_or_else(|| err("cannot read roster: recipient"))?
                    .to_owned(),
                name: r.get("name").and_then(Value::as_str).unwrap_or("").to_owned(),
                signer: r.get("signer").and_then(Value::as_str).map(str::to_owned),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(r) = &roles {
        if !r.admins.iter().all(|a| members.iter().any(|m| m.signer.as_ref() == Some(a))) {
            return Err(err("an admin is not a member"));
        }
    }
    check_kept_signers(&roles, prev_roles, &members, true)?;
    let (admins, owners) = roles.map_or((None, None), |r| (Some(r.admins), Some(r.owners)));
    Ok(Snapshot { epoch, members, admins, owners })
}
