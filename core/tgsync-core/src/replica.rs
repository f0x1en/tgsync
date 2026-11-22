// SPDX-License-Identifier: AGPL-3.0-or-later
//! One client's view of a vault, built by replaying the group's messages in id order
//! (PROTOCOL.md section 9). Sans-IO: the caller reads the group and feeds messages in.
//!
//! Caller loop (one pull):
//! ```text
//! for pass in 0..2 {
//!     replica.begin_pass();
//!     for msg in group.messages_after(replica.cursor) {
//!         let body = if replica.wants_body(msg.kind, msg.id) { group.fetch(msg.id) } else { vec![] };
//!         replica.feed(msg.id, msg.kind, &body, &mut report);
//!     }
//!     if !(replica.blocked() && replica.has_keys()) { break }   // pass 2: keys arrived late
//! }
//! ```

use std::collections::BTreeMap;

use serde_json::Value;

use crate::crypto::{blob_epoch, KeyRing};
use crate::descriptor::{self, Identity, Member, Snapshot};
use crate::oplog::decode_record;
use crate::tree::{Applied, Tree};

pub const KIND_DESCRIPTOR: char = 'd';
pub const KIND_RECORD: char = 'r';
pub const KIND_CHUNK: char = 'c';
pub const KIND_JOIN: char = 'j';

const STALE: &str = "record sealed with a key that was already replaced";

/// What one pull did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    /// (msg id, entry index, record ts, author, what happened). No-ops are left out.
    pub applied: Vec<(i64, usize, f64, String, Applied)>,
    /// (msg id, problem) for messages that were skipped.
    pub problems: Vec<(i64, String)>,
    /// Descriptors we accepted, to store locally and re-load with [`Replica::load_descriptor`].
    pub descriptors: Vec<(i64, Vec<u8>)>,
    /// Entries of OUR records that readers skip because they were sealed with a key that was
    /// already replaced. The caller must upload these entries again with the next push: same
    /// content (read it from the old record, which we can still open, not from disk) and same `base`.
    pub resend: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct Replica {
    pub me: Identity,
    pub vault_id: Option<String>,
    pub keys: KeyRing,
    pub members: Vec<Member>,
    /// Admins of the last accepted v2 descriptor (`None` until the vault has one).
    pub admins: Option<Vec<String>>,
    pub tree: Tree,
    /// Last message id fully processed.
    pub cursor: i64,
    /// Last record seq seen per author id.
    pub authors: BTreeMap<String, u64>,
    /// A descriptor dropped us after we had synced: stop applying records.
    pub removed: bool,
    /// We already wrote this vault to disk (a later exclusion means "removed", not "not added yet").
    pub active: bool,
    /// Membership history: (descriptor msg id, what it says). Same on every replica.
    pub history: Vec<(i64, Snapshot)>,
    /// Every descriptor seen, in order, not yet in `history` (we had no keys to check it yet).
    pending: Vec<(i64, Vec<u8>)>,
    /// Every descriptor seen, in order (to rebuild the history after a fresh re-join).
    all_descriptors: Vec<(i64, Vec<u8>)>,
    desc_seen: i64,
    blocked: bool,
}

impl Replica {
    pub fn new(me: Identity, vault_id: Option<String>) -> Self {
        Replica {
            me,
            vault_id,
            keys: KeyRing::new(),
            members: vec![],
            admins: None,
            tree: Tree::new(),
            cursor: 0,
            authors: BTreeMap::new(),
            removed: false,
            active: false,
            history: vec![],
            pending: vec![],
            all_descriptors: vec![],
            desc_seen: 0,
            blocked: false,
        }
    }

    pub fn has_keys(&self) -> bool {
        !self.keys.is_empty()
    }

    pub fn blocked(&self) -> bool {
        self.blocked
    }

    /// Next record seq for our own records.
    pub fn next_seq(&self) -> u64 {
        self.authors.get(&self.me.id()).copied().unwrap_or(0) + 1
    }

    /// Re-load a descriptor stored by an earlier pull (already validated then).
    pub fn load_descriptor(&mut self, data: &[u8]) {
        if let Ok(Some(d)) = descriptor::accept(data, &self.me, &mut self.keys, self.vault_id.as_deref(), true, self.admins.as_deref()) {
            self.members = d.members;
            if d.admins.is_some() {
                self.admins = d.admins;
            }
        }
    }

    /// Move descriptors from `pending` into the history once we hold keys to check them.
    fn flush_history(&mut self) {
        if !self.has_keys() {
            return;
        }
        for (id, data) in std::mem::take(&mut self.pending) {
            let prev = self.history.last().map(|(_, s)| s);
            if let Ok(snap) = descriptor::inspect(&data, &self.keys, self.vault_id.as_deref(), prev) {
                self.history.push((id, snap));
            }
        }
    }

    /// The vault as it was just before message `id`.
    pub fn snapshot_at(&self, id: i64) -> Option<&Snapshot> {
        self.history.iter().rev().find(|(at, _)| *at < id).map(|(_, s)| s)
    }

    /// In a vault with admins (v2), records must be signed by a member at their position and sealed
    /// with the newest key at that position (PROTOCOL.md section 12).
    fn check_record(&self, id: i64, body: &[u8], rec: &crate::oplog::Record) -> Result<(), &'static str> {
        let Some(snap) = self.snapshot_at(id) else { return Ok(()) };
        if snap.admins.is_none() {
            return Ok(()); // v1 vault: records are not signed
        }
        let Some(signer) = &rec.signer else { return Err("unsigned record in a vault that has admins") };
        if !snap.members.iter().any(|m| m.id() == rec.author && m.signer.as_ref() == Some(signer)) {
            return Err("record not signed by a member");
        }
        if blob_epoch(body).is_ok_and(|e| e < snap.epoch) {
            return Err(STALE);
        }
        Ok(())
    }

    pub fn begin_pass(&mut self) {
        self.blocked = false;
    }

    /// Does `feed` need this message's body? Saves downloads of records we would skip anyway.
    pub fn wants_body(&self, kind: char, id: i64) -> bool {
        match kind {
            KIND_DESCRIPTOR => id > self.desc_seen,
            KIND_RECORD => !self.removed && self.has_keys() && !self.blocked,
            _ => false,
        }
    }

    /// Process message `id` (ids must come in increasing order, starting after `cursor`).
    pub fn feed(&mut self, id: i64, kind: char, body: &[u8], rep: &mut Report) {
        match kind {
            KIND_DESCRIPTOR if id > self.desc_seen => {
                self.desc_seen = id;
                self.all_descriptors.push((id, body.to_vec()));
                self.pending.push((id, body.to_vec()));
                match descriptor::accept(body, &self.me, &mut self.keys, self.vault_id.as_deref(), false, self.admins.as_deref()) {
                    Ok(None) if self.has_keys() && !self.active => {
                        // Dropped before we ever synced: a later re-add is a fresh join.
                        self.keys = KeyRing::new();
                        self.members.clear();
                        self.admins = None;
                        self.history.clear();
                        self.pending = self.all_descriptors.clone();
                    }
                    Ok(None) => {
                        if self.has_keys() {
                            self.removed = true;
                        }
                    }
                    Ok(Some(d)) => {
                        self.vault_id.get_or_insert(d.vault_id);
                        self.members = d.members;
                        if d.admins.is_some() {
                            self.admins = d.admins;
                        }
                        rep.descriptors.push((id, body.to_vec()));
                    }
                    Err(e) => rep.problems.push((id, format!("rejected descriptor: {e}"))),
                }
                self.flush_history();
            }
            KIND_RECORD if !self.removed => {
                if !self.has_keys() || self.blocked {
                    self.blocked = true;
                    return;
                }
                match decode_record(&self.keys, body) {
                    Err(e) => {
                        if blob_epoch(body).is_ok_and(|ep| !self.keys.has(ep)) {
                            self.blocked = true; // sealed with a key we will get later
                            return;
                        }
                        rep.problems.push((id, format!("unreadable record: {e}")));
                    }
                    Ok(rec) => {
                        if let Err(why) = self.check_record(id, body, &rec) {
                            if why == STALE {
                                // Authentic but sealed with a replaced key: count its seq, apply nothing.
                                self.authors.insert(rec.author.clone(), rec.seq.max(self.authors.get(&rec.author).copied().unwrap_or(0)));
                                if rec.author == self.me.id() {
                                    rep.resend.extend(rec.entries.iter().cloned());
                                }
                            }
                            rep.problems.push((id, why.to_owned()));
                            self.cursor = id;
                            return;
                        }
                        let short: String = rec.author.chars().take(6).collect();
                        let prev = self.authors.get(&rec.author).copied().unwrap_or(0);
                        if rec.seq <= prev {
                            rep.problems.push((id, format!("replayed/duplicate record from {short} seq {}", rec.seq)));
                        } else {
                            if prev > 0 && rec.seq != prev + 1 {
                                rep.problems.push((id, format!("gap in {short}'s history: {prev} -> {} (message dropped?)", rec.seq)));
                            }
                            self.authors.insert(rec.author.clone(), rec.seq);
                            for (i, e) in rec.entries.iter().enumerate() {
                                match self.tree.apply_entry(e, &rec.author, rec.ts, id) {
                                    None | Some(Applied::Noop(_)) => {}
                                    Some(a) => rep.applied.push((id, i, rec.ts, rec.author.clone(), a)),
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        if !self.blocked {
            self.cursor = id;
        }
    }
}
