// SPDX-License-Identifier: AGPL-3.0-or-later
//! Changing who is in a vault: every change is a v2 descriptor signed by an admin (PROTOCOL.md
//! sections 4 and 11). Each function returns the descriptor bytes to post. Randomness (keys, nonces)
//! and the clock come from the caller.

use base64::Engine;

use crate::crypto::{KeyRing, NONCE_LEN};
use crate::descriptor::{build, Identity, Member, Signing};
use crate::replica::Replica;
use crate::{Error, Result};

fn err(m: &str) -> Error {
    Error::Crypto(m.into())
}

fn me_as_member(me: &Identity, name: &str) -> Result<Member> {
    Ok(Member {
        recipient: me.recipient.clone(),
        name: name.into(),
        signer: Some(me.signer().ok_or_else(|| err("no signing key"))?),
    })
}

fn signed(
    ring: &KeyRing,
    vault_id: &str,
    members: &[Member],
    roles: (&[String], &[String]),
    me: &Identity,
    proof_epoch: Option<u32>,
    created: i64,
    nonce: &mut dyn FnMut() -> [u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let key = me.signing.as_ref().ok_or_else(|| err("no signing key"))?;
    let (admins, owners) = roles;
    build(
        ring,
        vault_id,
        members,
        proof_epoch,
        created,
        Some(Signing {
            admins,
            owners: Some(owners),
            key,
        }),
        nonce,
    )
}

/// Start a vault: `me` is the only member, admin and owner. `vault_id`: 16 random hex chars; `key`: 32 random bytes.
pub fn create(
    me: &Identity,
    name: &str,
    vault_id: &str,
    key: &[u8; 32],
    created: i64,
    nonce: &mut dyn FnMut() -> [u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let mut ring = KeyRing::new();
    ring.add(1, key)?;
    let admins = [me.signer().ok_or_else(|| err("no signing key"))?];
    signed(
        &ring,
        vault_id,
        &[me_as_member(me, name)?],
        (&admins, &admins),
        me,
        None,
        created,
        nonce,
    )
}

/// The one member `target` names (key, member id or name). Names are not unique: refuse if several match.
fn one_match<'a>(r: &'a Replica, target: &str) -> Result<&'a Member> {
    let hits: Vec<&Member> = r
        .members
        .iter()
        .filter(|m| target == m.recipient || target == m.id() || target == m.name)
        .collect();
    match hits.len() {
        0 => Err(err(&format!("no such member: {target}"))),
        1 => Ok(hits[0]),
        _ => Err(err(&format!(
            "several members match '{target}'; use a member id instead: {}",
            hits.iter().map(|m| m.id()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// A v1 vault (no admins, made by older clients): any member may change who is in, with unsigned
/// v1 descriptors, as v1 clients do (PROTOCOL.md sections 4 and 14). `None` for a v2 vault.
fn v1_state(r: &Replica) -> Result<Option<&str>> {
    if r.admins.is_some() {
        return Ok(None);
    }
    if r.removed || r.keys.is_empty() {
        return Err(err("you are not a member of this vault"));
    }
    Ok(Some(r.vault_id.as_deref().ok_or_else(|| err("vault id unknown"))?))
}

/// The vault as an admin sees it: (vault id, admins, owners, am I an owner).
fn admin_state(r: &Replica) -> Result<(&str, Vec<String>, Vec<String>, bool)> {
    let vault_id = r.vault_id.as_deref().ok_or_else(|| err("vault id unknown"))?;
    let admins = r
        .admins
        .clone()
        .ok_or_else(|| err("this vault was made by an older tgsync and has no admins (any member can add or remove people)"))?;
    let me = r.me.signer().ok_or_else(|| err("no signing key"))?;
    if !admins.contains(&me) {
        return Err(err("only an admin can do that"));
    }
    if r.removed {
        return Err(err("you were removed from this vault"));
    }
    let owners = r.owners.clone().unwrap_or_default();
    let owner = owners.contains(&me);
    Ok((vault_id, admins, owners, owner))
}

fn owner_only(owner: bool) -> Result<()> {
    if owner {
        Ok(())
    } else {
        Err(err("only an owner can do that"))
    }
}

/// Add a member (after comparing the short code of their join request).
pub fn add(
    r: &Replica,
    recipient: &str,
    name: &str,
    signer: Option<&str>,
    created: i64,
    nonce: &mut dyn FnMut() -> [u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    if let Some(vault_id) = v1_state(r)? {
        if r.members.iter().any(|m| m.recipient == recipient) {
            return Err(err("already a member"));
        }
        let mut members = r.members.clone();
        members.push(Member::new(recipient, name));
        return build(&r.keys, vault_id, &members, None, created, None, nonce);
    }
    let (vault_id, admins, owners, _) = admin_state(r)?;
    if r.members.iter().any(|m| m.recipient == recipient) {
        return Err(err("already a member"));
    }
    if signer.is_none() {
        // Records must be signed (PROTOCOL.md section 12): without a key they could never write.
        return Err(err(
            "their join request has no signing key; they need a current tgsync and must ask to join again",
        ));
    }
    let s = signer.unwrap();
    // The signer comes from an untrusted join request; the short code covers only the recipient.
    // It must be a real Ed25519 key and nobody else's (else the newcomer would look like that member,
    // e.g. an admin).
    let valid = base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .is_some_and(|k| ed25519_dalek::VerifyingKey::from_bytes(&k).is_ok());
    if !valid {
        return Err(err("their join request has a broken signing key; they must ask to join again"));
    }
    if r.members.iter().any(|m| m.signer.as_deref() == Some(s)) {
        return Err(err(
            "their join request uses another member's signing key; refusing (it may be an impersonation attempt)",
        ));
    }
    let mut members = r.members.clone();
    members.push(Member {
        recipient: recipient.into(),
        name: name.into(),
        signer: signer.map(str::to_owned),
    });
    signed(&r.keys, vault_id, &members, (&admins, &owners), &r.me, None, created, nonce)
}

/// Remove a member by recipient, member id or name, and rotate to a new key (`new_key`: 32 random bytes).
/// They lose admin and owner rights too. A plain admin may remove only plain members (or themselves).
/// Refused for the last member, admin or owner.
pub fn remove(r: &Replica, target: &str, new_key: &[u8; 32], created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    if let Some(vault_id) = v1_state(r)? {
        one_match(r, target)?;
        let keep: Vec<Member> = r
            .members
            .iter()
            .filter(|m| !(target == m.recipient || target == m.id() || target == m.name))
            .cloned()
            .collect();
        if keep.is_empty() {
            return Err(err("refusing to remove the last member"));
        }
        let mut ring = r.keys.clone();
        let old = ring.current_epoch()?;
        ring.add(old + 1, new_key)?;
        return build(&ring, vault_id, &keep, Some(old), created, None, nonce);
    }
    let (vault_id, admins, owners, owner) = admin_state(r)?;
    let me = r.me.signer();
    let t = one_match(r, target)?;
    if !owner && t.signer.as_ref().is_some_and(|s| admins.contains(s)) && t.signer != me {
        return Err(err("an admin can only remove plain members; an owner can remove admins"));
    }
    let (gone, keep): (Vec<Member>, Vec<Member>) = r
        .members
        .iter()
        .cloned()
        .partition(|m| target == m.recipient || target == m.id() || target == m.name);
    if gone.is_empty() {
        return Err(err(&format!("no such member: {target}")));
    }
    if keep.is_empty() {
        return Err(err("refusing to remove the last member"));
    }
    let admins: Vec<String> = admins
        .into_iter()
        .filter(|a| !gone.iter().any(|m| m.signer.as_ref() == Some(a)))
        .collect();
    if admins.is_empty() {
        return Err(err("refusing to remove the last admin (give admin to someone first)"));
    }
    let owners: Vec<String> = owners.into_iter().filter(|o| admins.contains(o)).collect();
    if owners.is_empty() {
        return Err(err("refusing to remove the last owner (make someone else an owner first)"));
    }
    let mut ring = r.keys.clone();
    let old = ring.current_epoch()?;
    ring.add(old + 1, new_key)?;
    signed(&ring, vault_id, &keep, (&admins, &owners), &r.me, Some(old), created, nonce)
}

fn signer_of_member(r: &Replica, target: &str) -> Result<String> {
    one_match(r, target)?
        .signer
        .clone()
        .ok_or_else(|| err("that member has no signing key (they must join again with a current tgsync)"))
}

/// Make a member an admin (owners only).
pub fn give_admin(r: &Replica, target: &str, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, mut admins, owners, owner) = admin_state(r)?;
    owner_only(owner)?;
    let s = signer_of_member(r, target)?;
    if admins.contains(&s) {
        return Err(err("already an admin"));
    }
    admins.push(s);
    signed(&r.keys, vault_id, &r.members, (&admins, &owners), &r.me, None, created, nonce)
}

/// Take admin (and owner) rights from a member: owners may do it to anyone, an admin only to
/// themselves. Refused for the last admin or owner.
pub fn take_admin(r: &Replica, target: &str, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, admins, owners, owner) = admin_state(r)?;
    let s = signer_of_member(r, target)?;
    if !owner && r.me.signer().as_ref() != Some(&s) {
        return Err(err("only an owner can take admin rights from someone else"));
    }
    if !admins.contains(&s) {
        return Err(err("not an admin"));
    }
    let admins: Vec<String> = admins.into_iter().filter(|a| *a != s).collect();
    let owners: Vec<String> = owners.into_iter().filter(|o| *o != s).collect();
    if admins.is_empty() {
        return Err(err("that is the last admin (make someone else an admin first)"));
    }
    if owners.is_empty() {
        return Err(err("that is the last owner (make someone else an owner first)"));
    }
    signed(&r.keys, vault_id, &r.members, (&admins, &owners), &r.me, None, created, nonce)
}

/// Make a member an owner (owners only); they become an admin too.
pub fn give_owner(r: &Replica, target: &str, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, mut admins, mut owners, owner) = admin_state(r)?;
    owner_only(owner)?;
    let s = signer_of_member(r, target)?;
    if owners.contains(&s) {
        return Err(err("already an owner"));
    }
    if !admins.contains(&s) {
        admins.push(s.clone());
    }
    owners.push(s);
    signed(&r.keys, vault_id, &r.members, (&admins, &owners), &r.me, None, created, nonce)
}

/// Take owner rights from a member, yourself included (owners only); they stay an admin.
/// Refused for the last owner.
pub fn take_owner(r: &Replica, target: &str, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    let (vault_id, admins, owners, owner) = admin_state(r)?;
    owner_only(owner)?;
    let s = signer_of_member(r, target)?;
    if !owners.contains(&s) {
        return Err(err("not an owner"));
    }
    let owners: Vec<String> = owners.into_iter().filter(|o| *o != s).collect();
    if owners.is_empty() {
        return Err(err("that is the last owner (make someone else an owner first)"));
    }
    signed(&r.keys, vault_id, &r.members, (&admins, &owners), &r.me, None, created, nonce)
}

/// Stop being an admin (and owner) yourself.
pub fn drop_admin(r: &Replica, created: i64, nonce: &mut dyn FnMut() -> [u8; NONCE_LEN]) -> Result<Vec<u8>> {
    take_admin(r, &r.me.recipient, created, nonce)
}
