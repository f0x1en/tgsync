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
use crate::text::{sha_hex, TextEdit, Texts};
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
    pub resend: Vec<Resend>,
    /// For each note edit applied: (msg id, entry index, doc id, text sha after it). With
    /// `Texts::text_at` this gives every version of a note back (`tgsync restore`).
    pub text_versions: Vec<(i64, usize, String, String)>,
}

/// One of our entries to upload again, with the content bytes it pointed to (empty if none).
#[derive(Debug, Clone, PartialEq)]
pub struct Resend {
    pub entry: Value,
    pub bytes: Vec<u8>,
}

/// The inline bytes an entry points to in its record's payload.
fn inline_bytes<'a>(entry: &Value, payload: &'a [u8]) -> Option<&'a [u8]> {
    let inline = entry.get("blob")?.get("inline")?.as_array()?;
    let (off, len) = (inline.first()?.as_u64()? as usize, inline.get(1)?.as_u64()? as usize);
    payload.get(off..off.checked_add(len)?)
}

#[derive(Debug)]
pub struct Replica {
    pub me: Identity,
    pub vault_id: Option<String>,
    pub keys: KeyRing,
    pub members: Vec<Member>,
    /// Admins of the last accepted v2 descriptor (`None` until the vault has one).
    pub admins: Option<Vec<String>>,
    pub tree: Tree,
    /// Loro documents of text notes (PROTOCOL.md section 13).
    pub texts: Texts,
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
    /// `descriptor::content_id` of each of `all_descriptors` (to spot re-posts fast). Not saved.
    desc_ids: std::collections::HashSet<[u8; 32]>,
    /// Descriptors that included us, in order: re-reading them with our identity gives back the
    /// vault keys when the replica is loaded (keys are never saved).
    accepted: Vec<(i64, Vec<u8>)>,
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
            texts: Texts::default(),
            cursor: 0,
            authors: BTreeMap::new(),
            removed: false,
            active: false,
            history: vec![],
            pending: vec![],
            all_descriptors: vec![],
            desc_ids: Default::default(),
            accepted: vec![],
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
        if let Ok(Some(d)) = descriptor::accept(
            data,
            &self.me,
            &mut self.keys,
            self.vault_id.as_deref(),
            true,
            self.admins.as_deref(),
        ) {
            self.members = d.members;
            if d.admins.is_some() {
                self.admins = d.admins;
            }
        }
    }

    /// A `text` entry: import its Loro update, then place the note in the tree.
    fn apply_text(&mut self, e: &Value, payload: &[u8], author: &str, ts: f64, id: i64, rep: &mut Report) -> Option<Applied> {
        let path = crate::paths::normalize(e.get("path")?.as_str()?).ok()?;
        let doc = e.get("doc")?.as_str()?;
        if doc.is_empty() || doc.len() > 64 || e.get("blob")?.get("payload_msg").is_some() {
            return None;
        }
        let text = match self.texts.import(doc, inline_bytes(e, payload)?) {
            Ok(t) => t,
            Err(err) => {
                rep.problems.push((id, format!("{path}: {err}")));
                return None;
            }
        };
        let mtime = e.get("mtime").and_then(Value::as_f64).unwrap_or(ts);
        let applied = self.tree.apply_text(
            &path,
            doc,
            &sha_hex(&text),
            text.len() as i64,
            mtime,
            e.get("base").and_then(Value::as_str),
            author,
            ts,
            id,
        );
        if let Applied::Text(at) | Applied::Conflict(_, at) = &applied {
            self.texts.placed(doc, &path, at);
        }
        Some(applied)
    }

    /// Text of the note at `path`, if it is a merged text note.
    pub fn text(&self, path: &str) -> Option<String> {
        self.texts.text(self.tree.get(path)?.doc.as_deref()?)
    }

    /// Writer: the Loro update turning the version we last synced of `path` (text sha `base`) into
    /// `new_text`. `new_doc` (16 random hex) is used if this starts a new note; `peer` must be unique
    /// per update (e.g. derived from our id, the record seq and the entry index).
    pub fn prepare_text(&self, path: &str, base: Option<&str>, new_text: &str, new_doc: &str, peer: u64) -> crate::Result<TextEdit> {
        let doc = self
            .tree
            .get(path)
            .and_then(|n| n.doc.clone())
            .filter(|d| base.is_some_and(|b| self.texts.has_version(d, b)));
        // The note may have moved (conflict copy) or been deleted since: find its doc by version and path.
        let doc = doc.or_else(|| base.and_then(|b| self.texts.doc_with_version_at(b, path)));
        self.texts.prepare(doc.as_deref(), base, new_text, new_doc, peer)
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
        let Some(signer) = &rec.signer else {
            return Err("unsigned record in a vault that has admins");
        };
        if !snap
            .members
            .iter()
            .any(|m| m.id() == rec.author && m.signer.as_ref() == Some(signer))
        {
            return Err("record not signed by a member");
        }
        if blob_epoch(body).is_ok_and(|e| e < snap.epoch) {
            return Err(STALE);
        }
        Ok(())
    }

    /// Everything needed to continue later, as JSON bytes. Holds no keys: [`Replica::load`] gets them
    /// back by unwrapping the stored descriptors with our identity.
    pub fn save(&self) -> crate::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&self.save_value()?).unwrap())
    }

    /// [`Replica::save`] as JSON (to embed it without serializing twice).
    pub fn save_value(&self) -> crate::Result<Value> {
        use base64::Engine;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let msgs = |l: &[(i64, Vec<u8>)]| l.iter().map(|(i, b)| serde_json::json!([i, b64(b)])).collect::<Vec<_>>();
        let member = |m: &Member| serde_json::json!({"recipient": m.recipient, "name": m.name, "signer": m.signer});
        let history: Vec<Value> = self
            .history
            .iter()
            .map(|(i, s)| serde_json::json!([i, s.epoch, s.members.iter().map(member).collect::<Vec<_>>(), s.admins]))
            .collect();
        Ok(serde_json::json!({
            "v": 1, "vault_id": self.vault_id, "cursor": self.cursor, "authors": self.authors,
            "removed": self.removed, "active": self.active, "desc_seen": self.desc_seen,
            "accepted": msgs(&self.accepted), "all_descriptors": msgs(&self.all_descriptors), "pending": msgs(&self.pending),
            "history": history, "tree": self.tree.nodes.values().map(|n| n.to_json()).collect::<Vec<_>>(),
            "texts": self.texts.save()?,
        }))
    }

    pub fn load(me: Identity, data: &[u8]) -> crate::Result<Replica> {
        let v: Value = serde_json::from_slice(data).map_err(|_| crate::Error::Crypto("bad saved state".into()))?;
        Self::load_value(me, &v)
    }

    /// [`Replica::load`] from parsed JSON.
    pub fn load_value(me: Identity, v: &Value) -> crate::Result<Replica> {
        use base64::Engine;
        let bad = || crate::Error::Crypto("bad saved state".into());
        let msgs = |k: &str| -> crate::Result<Vec<(i64, Vec<u8>)>> {
            v.get(k)
                .and_then(Value::as_array)
                .ok_or_else(bad)?
                .iter()
                .map(|x| {
                    let b = x[1]
                        .as_str()
                        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                        .ok_or_else(bad)?;
                    Ok((x[0].as_i64().ok_or_else(bad)?, b))
                })
                .collect()
        };
        let member = |m: &Value| Member {
            recipient: m["recipient"].as_str().unwrap_or("").to_owned(),
            name: m["name"].as_str().unwrap_or("").to_owned(),
            signer: m["signer"].as_str().map(str::to_owned),
        };
        let mut r = Replica::new(me, v["vault_id"].as_str().map(str::to_owned));
        r.cursor = v["cursor"].as_i64().ok_or_else(bad)?;
        r.desc_seen = v["desc_seen"].as_i64().ok_or_else(bad)?;
        r.removed = v["removed"].as_bool().ok_or_else(bad)?;
        r.active = v["active"].as_bool().ok_or_else(bad)?;
        r.authors = v["authors"]
            .as_object()
            .ok_or_else(bad)?
            .iter()
            .map(|(k, s)| (k.clone(), s.as_u64().unwrap_or(0)))
            .collect();
        r.all_descriptors = msgs("all_descriptors")?;
        r.desc_ids = r.all_descriptors.iter().filter_map(|(_, b)| descriptor::content_id(b)).collect();
        r.pending = msgs("pending")?;
        for (_, d) in msgs("accepted")? {
            r.load_descriptor(&d);
        }
        r.accepted = msgs("accepted")?;
        for h in v["history"].as_array().ok_or_else(bad)? {
            let admins = h[3]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect());
            let members = h[2].as_array().ok_or_else(bad)?.iter().map(member).collect();
            r.history.push((
                h[0].as_i64().ok_or_else(bad)?,
                Snapshot {
                    epoch: h[1].as_u64().ok_or_else(bad)? as u32,
                    members,
                    admins,
                },
            ));
        }
        for n in v["tree"].as_array().ok_or_else(bad)? {
            r.tree.set(crate::tree::Node::from_json(n).ok_or_else(bad)?);
        }
        r.texts = Texts::load(&v["texts"])?;
        Ok(r)
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
                // A re-post of a descriptor already in the log (anyone can forward one) must not
                // count again: adding a member keeps the epoch, so the epoch alone cannot tell an
                // old one from a new one.
                let cid = descriptor::content_id(body);
                if cid.is_some_and(|c| !self.desc_ids.insert(c)) {
                    rep.problems.push((id, "rejected descriptor: a re-post of an earlier one".into()));
                } else {
                    self.all_descriptors.push((id, body.to_vec()));
                    self.pending.push((id, body.to_vec()));
                    match descriptor::accept(
                        body,
                        &self.me,
                        &mut self.keys,
                        self.vault_id.as_deref(),
                        false,
                        self.admins.as_deref(),
                    ) {
                        Ok(None) if self.has_keys() && !self.active => {
                            // Dropped before we ever synced: a later re-add is a fresh join.
                            self.keys = KeyRing::new();
                            self.members.clear();
                            self.admins = None;
                            self.history.clear();
                            self.pending = self.all_descriptors.clone();
                            self.accepted.clear();
                        }
                        Ok(None) => {
                            if self.has_keys() {
                                self.removed = true;
                            }
                        }
                        Ok(Some(d)) => {
                            self.accepted.push((id, body.to_vec()));
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
            }
            KIND_RECORD if !self.removed => {
                if !self.has_keys() || self.blocked {
                    self.blocked = true;
                    return;
                }
                match decode_record(&self.keys, body) {
                    Err(e) => {
                        // Not blocking here: once we hold keys, the descriptor with any newer key
                        // comes earlier in the log than records sealed with it. A record with an
                        // epoch we never got is junk; waiting for it would stop us for good.
                        rep.problems.push((id, format!("unreadable record: {e}")));
                    }
                    Ok(rec) => {
                        if let Err(why) = self.check_record(id, body, &rec) {
                            if why == STALE {
                                // Authentic but sealed with a replaced key: count its seq, apply nothing.
                                let prev = self.authors.get(&rec.author).copied().unwrap_or(0);
                                self.authors.insert(rec.author.clone(), rec.seq.max(prev));
                                // Ours, and not a replay of a record we already handled: send it again.
                                if rec.author == self.me.id() && rec.seq > prev {
                                    rep.resend.extend(rec.entries.iter().map(|e| Resend {
                                        entry: e.clone(),
                                        bytes: inline_bytes(e, &rec.payload).unwrap_or_default().to_vec(),
                                    }));
                                }
                            }
                            rep.problems.push((id, why.to_owned()));
                            self.cursor = id;
                            return;
                        }
                        let short: String = rec.author.chars().take(6).collect();
                        let prev = self.authors.get(&rec.author).copied().unwrap_or(0);
                        if rec.seq <= prev {
                            rep.problems
                                .push((id, format!("replayed/duplicate record from {short} seq {}", rec.seq)));
                        } else {
                            if prev > 0 && rec.seq != prev + 1 {
                                rep.problems
                                    .push((id, format!("gap in {short}'s history: {prev} -> {} (message dropped?)", rec.seq)));
                            }
                            self.authors.insert(rec.author.clone(), rec.seq);
                            for (i, e) in rec.entries.iter().enumerate() {
                                let applied = if e.get("op").and_then(Value::as_str) == Some("text") {
                                    let a = self.apply_text(e, &rec.payload, &rec.author, rec.ts, id, rep);
                                    if let Some(Applied::Text(p)) = &a {
                                        let n = self.tree.get(p).unwrap();
                                        rep.text_versions.push((id, i, n.doc.clone().unwrap(), n.sha.clone()));
                                    }
                                    a
                                } else {
                                    self.tree.apply_entry(e, &rec.author, rec.ts, id)
                                };
                                match applied {
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
