// SPDX-License-Identifier: AGPL-3.0-or-later
//! age X25519 wrap/unwrap of vault keys (PROTOCOL.md section 3).
//! Wrapping draws its ephemeral key from the OS random source (inside the age crate).

use std::io::{Read, Write};
use std::str::FromStr;

use crate::{Error, Result};

fn err(m: impl Into<String>) -> Error {
    Error::Crypto(m.into())
}

/// Encrypt `data` to one age recipient (binary format, not armored).
pub fn wrap_for(recipient: &str, data: &[u8]) -> Result<Vec<u8>> {
    let r = age::x25519::Recipient::from_str(recipient).map_err(|e| err(format!("bad age recipient: {e}")))?;
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient)).map_err(|e| err(format!("age: {e}")))?;
    let mut out = vec![];
    let mut w = enc.wrap_output(&mut out).map_err(|e| err(format!("age: {e}")))?;
    w.write_all(data).and_then(|_| w.finish()).map_err(|e| err(format!("age: {e}")))?;
    Ok(out)
}

/// Decrypt an age file with our `AGE-SECRET-KEY-1...` identity.
pub fn unwrap(secret: &str, data: &[u8]) -> Result<Vec<u8>> {
    let id = age::x25519::Identity::from_str(secret).map_err(|e| err(format!("bad age identity: {e}")))?;
    let dec = age::Decryptor::new(data).map_err(|e| err(format!("age: {e}")))?;
    let mut r = dec
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|e| err(format!("age: {e}")))?;
    let mut out = vec![];
    r.read_to_end(&mut out).map_err(|e| err(format!("age: {e}")))?;
    Ok(out)
}
