// SPDX-License-Identifier: AGPL-3.0-or-later
//! tgsync engine. Pure functions: no network, no clock, no randomness.
//! Callers pass in nonces, keys and timestamps. See PROTOCOL.md.

pub mod crypto;
pub mod descriptor;
pub mod identity;
pub mod invites;
pub mod members;
pub mod oplog;
pub mod paths;
pub mod replica;
pub mod sync;
pub mod text;
pub mod tree;
pub mod vault;

/// Every failure the engine reports. The message is meant for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Crypto(String),
    Path(String),
    Invite(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Crypto(m) | Error::Path(m) | Error::Invite(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
