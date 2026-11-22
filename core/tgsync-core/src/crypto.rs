// SPDX-License-Identifier: AGPL-3.0-or-later
//! Seal/open blobs, subkeys, mac, fingerprints (PROTOCOL.md section 2) and member ids (section 3).

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub const MAGIC: &[u8; 4] = b"TGS1";
pub const HEADER_LEN: usize = 8;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const OVERHEAD: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

fn err(m: impl Into<String>) -> Error {
    Error::Crypto(m.into())
}

pub fn subkey(root: &[u8; 32], purpose: &[u8], ctx: &[u8]) -> [u8; 32] {
    let info = [b"tgsync/v1/".as_slice(), purpose, b"\0", ctx].concat();
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, root)
        .expand(&info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

pub fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(&(p.len() as u32).to_be_bytes());
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// Human-comparable fingerprint of a vault key, e.g. `5970 4df4 306a 51c1 a846`.
pub fn fingerprint(key: &[u8]) -> String {
    let h = hex::encode(Sha256::digest([b"tgsync/fingerprint/v1".as_slice(), key].concat()));
    h.as_bytes()[..20]
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `hex(SHA256(recipient))[:16]`.
pub fn member_id(recipient: &str) -> String {
    hex::encode(Sha256::digest(recipient.as_bytes()))[..16].to_string()
}

/// First 8 hex chars of the member id as `xxxx-xxxx`, read aloud to confirm a join request.
pub fn short_code(recipient: &str) -> String {
    let m = member_id(recipient);
    format!("{}-{}", &m[..4], &m[4..8])
}

/// Epoch of a sealed blob, from its header.
pub fn blob_epoch(blob: &[u8]) -> Result<u32> {
    if blob.len() < HEADER_LEN {
        return Err(err("blob too short"));
    }
    if &blob[..4] != MAGIC {
        return Err(err("bad magic"));
    }
    Ok(u32::from_be_bytes(blob[4..8].try_into().unwrap()))
}

/// Vault keys by epoch. The highest epoch seals new data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyRing {
    keys: BTreeMap<u32, [u8; 32]>,
}

impl KeyRing {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn epochs(&self) -> impl Iterator<Item = u32> + '_ {
        self.keys.keys().copied()
    }

    pub fn current_epoch(&self) -> Result<u32> {
        self.keys.keys().next_back().copied().ok_or_else(|| err("keyring is empty"))
    }

    pub fn has(&self, epoch: u32) -> bool {
        self.keys.contains_key(&epoch)
    }

    pub fn key(&self, epoch: u32) -> Result<&[u8; 32]> {
        self.keys.get(&epoch).ok_or_else(|| err(format!("no key for epoch {epoch}")))
    }

    pub fn add(&mut self, epoch: u32, key: &[u8]) -> Result<()> {
        let key: [u8; 32] = key.try_into().map_err(|_| err("vault key must be 32 bytes"))?;
        match self.keys.get(&epoch) {
            Some(k) if *k != key => Err(err(format!("conflicting key for epoch {epoch}"))),
            _ => {
                self.keys.insert(epoch, key);
                Ok(())
            }
        }
    }

    /// Seal with `epoch` (the current one if `None`). `nonce` must be 12 fresh random bytes.
    pub fn seal(&self, purpose: &[u8], ctx: &[u8], plaintext: &[u8], nonce: &[u8; NONCE_LEN], epoch: Option<u32>) -> Result<Vec<u8>> {
        let ep = match epoch {
            Some(e) => e,
            None => self.current_epoch()?,
        };
        let header = [MAGIC.as_slice(), &ep.to_be_bytes()].concat();
        let aad = [header.as_slice(), purpose, b"\0", ctx].concat();
        let cipher = Aes256Gcm::new(&subkey(self.key(ep)?, purpose, ctx).into());
        let ct = cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| err("encryption failed"))?;
        Ok([header.as_slice(), nonce, &ct].concat())
    }

    pub fn open(&self, purpose: &[u8], ctx: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < OVERHEAD {
            return Err(err("blob too short"));
        }
        let epoch = blob_epoch(blob)?;
        let key = self.key(epoch)?;
        let (header, rest) = blob.split_at(HEADER_LEN);
        let (nonce, ct) = rest.split_at(NONCE_LEN);
        let aad = [header, purpose, b"\0", ctx].concat();
        Aes256Gcm::new(&subkey(key, purpose, ctx).into())
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
            .map_err(|_| err("authentication failed (tampered, wrong key or wrong context)"))
    }
}
