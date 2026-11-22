// SPDX-License-Identifier: AGPL-3.0-or-later
//! Changing who is in a vault: every change is a v2 descriptor signed by an admin (PROTOCOL.md
//! sections 4 and 11). Each function returns the descriptor bytes to post. Randomness (keys, nonces)
//! and the clock come from the caller.

use crate::crypto::{KeyRing, NONCE_LEN};
use crate::descriptor::{build, Identity, Member, Signing};
use crate::replica::Replica;
use crate::{Error, Result};

fn err(m: &str) -> Error {
    Error::Crypto(m.into())
}

fn me_as_member(me: &Identity, name: &str) -> Result<Member> {
    Ok(Member { recipient: me.recipient.clone(), name: name.into(), signer: Some(me.signer().ok_or_else(|| err("no signing key"))?) })
}

fn signed(ring: &KeyRing, vault_id: &str, members: &[Member], admins: &[String], me: &Identity, proof_epoch: Option<u32>,
          created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let key = me.signing.as_ref().ok_or_else(|| err("no signing key"))?;
    build(ring, vault_id, members, proof_epoch, created, Some(Signing { admins, key }), nonce)
}

/// Start a vault: `me` is the only member and admin. `vault_id`: 16 random hex chars; `key`: 32 random bytes.
pub fn create(me: &Identity, name: &str, vault_id: &str, key: &[u8; 32], created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let mut ring = KeyRing::new();
    ring.add(1, key)?;
    let admins = [me.signer().ok_or_else(|| err("no signing key"))?];
    signed(&ring, vault_id, &[me_as_member(me, name)?], &admins, me, None, created, nonce)
}

fn admin_state(r: &Replica) -> Result<(&str, Vec<String>)> {
    let vault_id = r.vault_id.as_deref().ok_or_else(|| err("vault id unknown"))?;
    let admins = r.admins.clone().ok_or_else(|| err("this vault has no admins (v1); it cannot be changed by the Rust core"))?;
    let me = r.me.signer().ok_or_else(|| err("no signing key"))?;
    if !admins.contains(&me) {
        return Err(err("only an admin can do that (run `tgsync members` to see who is)"));
    }
    if r.removed {
        return Err(err("you were removed from this vault"));
    }
    Ok((vault_id, admins))
}

/// Add a member (after comparing the short code of their join request).
pub fn add(r: &Replica, recipient: &str, name: &str, signer: Option<&str>, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, admins) = admin_state(r)?;
    if r.members.iter().any(|m| m.recipient == recipient) {
        return Err(err("already a member"));
    }
    if signer.is_none() {
        // Records must be signed (PROTOCOL.md section 12): without a key they could never write.
        return Err(err("their join request has no signing key; they need a current tgsync and must ask to join again"));
    }
    let mut members = r.members.clone();
    members.push(Member { recipient: recipient.into(), name: name.into(), signer: signer.map(str::to_owned) });
    signed(&r.keys, vault_id, &members, &admins, &r.me, None, created, nonce)
}

/// Remove a member by recipient, member id or name, and rotate to a new key (`new_key`: 32 random bytes).
/// They lose admin rights too. Refused for the last member or the last admin.
pub fn remove(r: &Replica, target: &str, new_key: &[u8; 32], created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, admins) = admin_state(r)?;
    let (gone, keep): (Vec<Member>, Vec<Member>) =
        r.members.iter().cloned().partition(|m| target == m.recipient || target == m.id() || target == m.name);
    if gone.is_empty() {
        return Err(err(&format!("no such member: {target}")));
    }
    if keep.is_empty() {
        return Err(err("refusing to remove the last member"));
    }
    let admins: Vec<String> = admins.into_iter().filter(|a| !gone.iter().any(|m| m.signer.as_ref() == Some(a))).collect();
    if admins.is_empty() {
        return Err(err("refusing to remove the last admin (give admin to someone first)"));
    }
    let mut ring = r.keys.clone();
    let old = ring.current_epoch()?;
    ring.add(old + 1, new_key)?;
    signed(&ring, vault_id, &keep, &admins, &r.me, Some(old), created, nonce)
}

/// Make a member an admin.
pub fn give_admin(r: &Replica, target: &str, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, mut admins) = admin_state(r)?;
    let m = r.members.iter().find(|m| target == m.recipient || target == m.id() || target == m.name)
        .ok_or_else(|| err(&format!("no such member: {target}")))?;
    let s = m.signer.clone().ok_or_else(|| err("that member has no signing key (they must join again with a current tgsync)"))?;
    if admins.contains(&s) {
        return Err(err("already an admin"));
    }
    admins.push(s);
    signed(&r.keys, vault_id, &r.members, &admins, &r.me, None, created, nonce)
}

/// Stop being an admin yourself. Refused if you are the last one.
pub fn drop_admin(r: &Replica, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, admins) = admin_state(r)?;
    let me = r.me.signer().unwrap();
    let admins: Vec<String> = admins.into_iter().filter(|a| *a != me).collect();
    if admins.is_empty() {
        return Err(err("you are the last admin (give admin to someone first)"));
    }
    signed(&r.keys, vault_id, &r.members, &admins, &r.me, None, created, nonce)
}
