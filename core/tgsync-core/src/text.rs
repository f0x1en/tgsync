// SPDX-License-Identifier: AGPL-3.0-or-later
//! Text notes merged with the Loro CRDT (PROTOCOL.md section 13).
//!
//! Every text file lineage is one Loro document, named by a `doc` id. A `text` entry carries a Loro
//! update (only the new operations). Replay imports updates in log order, so every replica holds the
//! same documents: concurrent edits of one note merge instead of making a conflict copy.

use std::collections::BTreeMap;

use loro::{ExportMode, Frontiers, LoroDoc, UpdateOptions};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const TEXT: &str = "t";

fn err(m: impl Into<String>) -> Error {
    Error::Crypto(m.into())
}

pub fn sha_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Should a file be synced as a mergeable text note? Writers decide; readers follow the entry's op.
pub fn is_text_path(path: &str) -> bool {
    path.to_lowercase().ends_with(".md")
}

/// The Loro documents of one replica, plus for each (doc, text sha) the version that produced it,
/// so a writer can diff from the exact version it last synced.
#[derive(Default)]
pub struct Texts {
    docs: BTreeMap<String, LoroDoc>,
    versions: BTreeMap<(String, String), Vec<u8>>,
    /// Saved snapshot (base64) per doc, until the doc changes: saving a vault of thousands of notes
    /// re-exports only the notes that changed.
    saved: std::cell::RefCell<BTreeMap<String, String>>,
    /// doc -> (path of the entry that started it, path it was last placed at). Writers only use it
    /// to find a note's doc after it moved or was deleted; replay does not depend on it.
    paths: BTreeMap<String, (String, String)>,
}

impl std::fmt::Debug for Texts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Texts")
            .field("docs", &self.docs.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Same docs with the same operations and text, and the same version index (snapshot bytes may differ).
impl PartialEq for Texts {
    fn eq(&self, other: &Self) -> bool {
        self.versions == other.versions
            && self.docs.len() == other.docs.len()
            && self.docs.iter().zip(&other.docs).all(|((ia, a), (ib, b))| {
                ia == ib && a.oplog_vv() == b.oplog_vv() && a.get_text(TEXT).to_string() == b.get_text(TEXT).to_string()
            })
    }
}

/// An edit ready to send: the doc id and the Loro update bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEdit {
    pub doc: String,
    pub update: Vec<u8>,
}

impl Texts {
    /// Current text of a doc.
    pub fn text(&self, doc: &str) -> Option<String> {
        self.docs.get(doc).map(|d| d.get_text(TEXT).to_string())
    }

    pub fn doc_ids(&self) -> impl Iterator<Item = &String> {
        self.docs.keys()
    }

    /// The text of `doc` as it was when its sha was `sha` (a version seen during replay).
    pub fn text_at(&self, doc: &str, sha: &str) -> Option<String> {
        let f = Frontiers::decode(self.versions.get(&(doc.to_owned(), sha.to_owned()))?).ok()?;
        Some(self.docs.get(doc)?.fork_at(&f).ok()?.get_text(TEXT).to_string())
    }

    pub fn has_version(&self, doc: &str, sha: &str) -> bool {
        self.versions.contains_key(&(doc.to_owned(), sha.to_owned()))
    }

    /// Replay placed `doc` (from an entry for `entry_path`) at `at`.
    pub fn placed(&mut self, doc: &str, entry_path: &str, at: &str) {
        let e = self.paths.entry(doc.to_owned()).or_insert_with(|| (entry_path.to_owned(), at.to_owned()));
        e.1 = at.to_owned();
    }

    /// The doc of the note that was at `path` with text sha `sha`, after it moved (a conflict copy of
    /// `path`) or was deleted. Only docs that started at, or last were at, `path` count: two notes
    /// with the same text (e.g. both empty) are different notes.
    pub fn doc_with_version_at(&self, sha: &str, path: &str) -> Option<String> {
        self.versions
            .keys()
            .filter(|(_, s)| s == sha)
            .map(|(d, _)| d)
            .find(|d| self.paths.get(*d).is_some_and(|(origin, last)| origin == path || last == path))
            .cloned()
    }

    /// Save every doc (Loro snapshot) and the version index.
    pub fn save(&self) -> serde_json::Value {
        use base64::Engine;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let mut saved = self.saved.borrow_mut();
        let docs: Vec<_> = self
            .docs
            .iter()
            .map(|(id, d)| {
                let snap = saved
                    .entry(id.clone())
                    .or_insert_with(|| b64(&d.export(ExportMode::Snapshot).unwrap()));
                serde_json::json!([id, snap])
            })
            .collect();
        let versions: Vec<_> = self.versions.iter().map(|((d, s), f)| serde_json::json!([d, s, b64(f)])).collect();
        let paths: Vec<_> = self.paths.iter().map(|(d, (o, l))| serde_json::json!([d, o, l])).collect();
        serde_json::json!({"docs": docs, "versions": versions, "paths": paths})
    }

    pub fn load(v: &serde_json::Value) -> Result<Texts> {
        use base64::Engine;
        let bad = || err("bad saved text state");
        let unb64 = |x: &serde_json::Value| {
            x.as_str()
                .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                .ok_or_else(bad)
        };
        let mut t = Texts::default();
        for p in v.get("paths").and_then(|x| x.as_array()).into_iter().flatten() {
            if let (Some(d), Some(o), Some(l)) = (p[0].as_str(), p[1].as_str(), p[2].as_str()) {
                t.paths.insert(d.to_owned(), (o.to_owned(), l.to_owned()));
            }
        }
        for d in v.get("docs").and_then(|x| x.as_array()).ok_or_else(bad)? {
            let doc = LoroDoc::new();
            doc.import(&unb64(&d[1])?).map_err(|e| err(e.to_string()))?;
            let id = d[0].as_str().ok_or_else(bad)?.to_owned();
            if let Some(snap) = d[1].as_str() {
                t.saved.borrow_mut().insert(id.clone(), snap.to_owned());
            }
            t.docs.insert(id, doc);
        }
        for x in v.get("versions").and_then(|x| x.as_array()).ok_or_else(bad)? {
            let key = (x[0].as_str().ok_or_else(bad)?.to_owned(), x[1].as_str().ok_or_else(bad)?.to_owned());
            t.versions.insert(key, unb64(&x[2])?);
        }
        Ok(t)
    }

    /// Does doc `doc` already contain every operation of `update`? (Checks that an edit was merged.)
    pub fn contains(&self, doc: &str, update: &[u8]) -> bool {
        let Some(d) = self.docs.get(doc) else { return false };
        let copy = d.fork();
        let before = copy.oplog_vv();
        copy.import(update).is_ok_and(|st| st.pending.as_ref().is_none_or(|p| p.is_empty())) && copy.oplog_vv() == before
    }

    /// Replay: import an update. Returns the doc's text afterwards. Importing twice is harmless.
    pub fn import(&mut self, doc: &str, update: &[u8]) -> Result<String> {
        self.saved.get_mut().remove(doc);
        let new = !self.docs.contains_key(doc);
        let d = self.docs.entry(doc.to_owned()).or_default();
        // Pending = it needs operations this doc does not have (a record went missing): Loro would
        // keep it aside and change nothing, so it is not applied.
        let res = d.import(update).map_err(|e| format!("bad text update: {e}"));
        let res = res.and_then(|st| match st.pending {
            Some(p) if !p.is_empty() => Err("text update depends on edits that never arrived".to_owned()),
            _ => Ok(()),
        });
        if let Err(e) = res {
            if new {
                self.docs.remove(doc); // a bad update must not leave an empty doc behind
            }
            return Err(err(e));
        }
        let d = &self.docs[doc];
        let text = d.get_text(TEXT).to_string();
        self.versions.insert((doc.to_owned(), sha_hex(&text)), d.oplog_frontiers().encode());
        Ok(text)
    }

    /// Writer: the update that turns the version we last synced (`doc` at text sha `base`) into
    /// `new_text`. With no known base, a new doc `new_doc` is started (replay then treats it as a new
    /// file: a conflict copy if the path is taken). `peer` must be unique per update (derive it from
    /// author, seq and entry index).
    pub fn prepare(&self, doc: Option<&str>, base: Option<&str>, new_text: &str, new_doc: &str, peer: u64) -> Result<TextEdit> {
        let known = match (doc, base) {
            (Some(doc), Some(base)) => self.versions.get(&(doc.to_owned(), base.to_owned())).map(|f| (doc, f)),
            _ => None,
        };
        let (doc_id, fork) = match known {
            Some((doc, frontiers)) => {
                let f = Frontiers::decode(frontiers).map_err(|e| err(e.to_string()))?;
                let d = self.docs.get(doc).ok_or_else(|| err("saved state names a note that is missing"))?;
                (doc.to_owned(), d.fork_at(&f).map_err(|e| err(e.to_string()))?)
            }
            None => (new_doc.to_owned(), LoroDoc::new()),
        };
        fork.set_peer_id(peer).map_err(|e| err(e.to_string()))?;
        let from = fork.oplog_vv();
        fork.get_text(TEXT)
            .update(new_text, UpdateOptions::default())
            .map_err(|_| err("text diff timed out"))?;
        fork.commit();
        let update = fork.export(ExportMode::updates(&from)).map_err(|e| err(e.to_string()))?;
        Ok(TextEdit { doc: doc_id, update })
    }
}
