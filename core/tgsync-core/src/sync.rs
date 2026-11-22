// SPDX-License-Identifier: AGPL-3.0-or-later
//! Push and materialize as plans (PROTOCOL.md section 9). Sans-IO: the caller lists the folder,
//! the core says what to upload or write, the caller does it. The simulator drives the same code.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::oplog::{INLINE_MAX, MAX_ENTRIES_PER_RECORD, RECORD_PAYLOAD_MAX};
use crate::replica::{Replica, Resend};
use crate::text::is_text_path;
use crate::tree::DIR;
use crate::Result;

/// One file (or empty folder) in the local folder, as the caller read it.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalFile {
    /// hex SHA-256 of the bytes (`"dir"` for an empty folder).
    pub sha: String,
    pub size: u64,
    pub mtime: f64,
    pub content: Content,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// A note small enough to merge (`.md`, UTF-8, at most 256 KiB).
    Text(String),
    /// Bytes small enough to ride inside the record.
    Small(Vec<u8>),
    /// A big file whose chunks the caller already uploaded: its `blob` (section 5).
    Big(Value),
    /// An empty folder.
    Dir,
}

impl LocalFile {
    /// Build from file bytes: notes become `Text`, other small files `Small`.
    pub fn from_bytes(path: &str, bytes: Vec<u8>, mtime: f64) -> LocalFile {
        let sha = hex::encode(Sha256::digest(&bytes));
        let size = bytes.len() as u64;
        let content = if bytes.len() <= INLINE_MAX && is_text_path(path) {
            match String::from_utf8(bytes) {
                Ok(t) => Content::Text(t),
                Err(e) => Content::Small(e.into_bytes()),
            }
        } else {
            Content::Small(bytes)
        };
        LocalFile { sha, size, mtime, content }
    }
}

/// What one push sends: one record (entries + payload) and the files to mark synced afterwards.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Push {
    pub entries: Vec<Value>,
    pub payload: Vec<u8>,
    /// path -> sha to record as synced once the record is posted (`None`: no longer synced).
    pub done: Vec<(String, Option<String>)>,
    /// How many queued re-send entries this record carries (they leave the queue once it is posted).
    pub resent: usize,
}

impl Push {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn inline(&mut self, bytes: &[u8]) -> Value {
        self.payload.extend_from_slice(bytes);
        json!([self.payload.len() - bytes.len(), bytes.len()])
    }
}

/// Peer id of one text update: unique per (author, seq, entry index).
pub fn text_peer(author: &str, seq: u64, index: usize) -> u64 {
    let h = Sha256::digest(format!("{author}:{seq}:{index}").as_bytes());
    u64::from_be_bytes(h[..8].try_into().unwrap())
}

/// Plan the next record: entries to re-send first (old-key rejections), then every difference
/// between the folder (`disk`) and what was last synced (`synced`: path -> sha). One record holds at
/// most 500 entries and about 4 MiB of payload: the caller posts it, marks it pushed and plans again
/// until the plan is empty.
/// `seq` is the record's seq; `new_doc` gives a fresh 16-hex doc id for a new note.
pub fn plan_push(
    replica: &Replica,
    disk: &BTreeMap<String, LocalFile>,
    synced: &BTreeMap<String, String>,
    resend: &[Resend],
    seq: u64,
    new_doc: &mut dyn FnMut() -> String,
) -> Result<Push> {
    let mut push = Push::default();
    for r in resend {
        if push.entries.len() >= MAX_ENTRIES_PER_RECORD || push.payload.len() >= RECORD_PAYLOAD_MAX {
            break; // the rest waits for the next record
        }
        let mut e = r.entry.clone();
        if !r.bytes.is_empty() {
            e["blob"]["inline"] = push.inline(&r.bytes);
        }
        push.entries.push(e);
        push.resent += 1;
    }
    let me = replica.me.id();
    // A vault without admins is a protocol v1 vault (older clients may share it): notes go as plain
    // `put`s there, since v1 readers know no `text` entries.
    let v2 = replica.admins.is_some();
    let paths: BTreeSet<&String> = disk.keys().chain(synced.keys()).collect();
    for p in paths {
        let (now, then) = (disk.get(p), synced.get(p));
        if now.map(|f| &f.sha) == then {
            continue;
        }
        if push.entries.len() >= MAX_ENTRIES_PER_RECORD || push.payload.len() >= RECORD_PAYLOAD_MAX {
            break; // the rest goes in the next record
        }
        let mut base = then.cloned();
        // A file became a folder of the same name, or the other way round: remove the old kind first,
        // else replay keeps it (a folder never replaces a file) and the next pull writes it back.
        let was_dir = then.map(String::as_str) == Some(DIR);
        let is_dir = matches!(now.map(|f| &f.content), Some(Content::Dir));
        if let (Some(_), Some(_)) = (now, then) {
            if was_dir != is_dir {
                push.entries.push(if was_dir {
                    json!({"op": "rmdir", "path": p})
                } else {
                    json!({"op": "delete", "path": p, "base": base})
                });
                base = None;
            }
        }
        let entry = match now {
            None if then.map(String::as_str) == Some(DIR) => json!({"op": "rmdir", "path": p}),
            None => json!({"op": "delete", "path": p, "base": base}),
            Some(f) => match &f.content {
                Content::Dir => json!({"op": "mkdir", "path": p}),
                Content::Text(text) if !v2 => {
                    let inline = push.inline(text.as_bytes());
                    json!({"op": "put", "path": p, "sha": f.sha, "size": f.size, "mtime": f.mtime, "base": base,
                           "blob": {"file_id": file_id(&f.sha), "chunks": null, "inline": inline}})
                }
                Content::Text(text) => {
                    let peer = text_peer(&me, seq, push.entries.len());
                    let edit = replica.prepare_text(p, base.as_deref(), text, &new_doc(), peer)?;
                    let inline = push.inline(&edit.update);
                    json!({"op": "text", "path": p, "doc": edit.doc, "sha": f.sha, "size": f.size,
                           "mtime": f.mtime, "base": base, "blob": {"inline": inline}})
                }
                other => {
                    // Content the group already has (a rename, move or copy): re-use its blob.
                    let reuse = replica
                        .tree
                        .nodes
                        .values()
                        .find(|n| n.sha == f.sha && n.doc.is_none() && n.sha != DIR);
                    let blob = match (reuse, other) {
                        (Some(n), _) => Value::Object(n.blob.clone()),
                        (None, Content::Small(bytes)) => {
                            let inline = push.inline(bytes);
                            json!({"file_id": file_id(&f.sha), "chunks": null, "inline": inline})
                        }
                        (None, Content::Big(blob)) => blob.clone(),
                        _ => unreachable!(),
                    };
                    json!({"op": "put", "path": p, "sha": f.sha, "size": f.size, "mtime": f.mtime, "base": base, "blob": blob})
                }
            },
        };
        push.entries.push(entry);
        push.done.push((p.clone(), now.map(|f| f.sha.clone())));
    }
    Ok(push)
}

fn file_id(sha: &str) -> String {
    sha[..16.min(sha.len())].to_string()
}

/// One change to make in the local folder.
#[derive(Debug, Clone, PartialEq)]
pub enum DiskOp {
    /// Write the file. `text`: a merged note (write it as is). Otherwise fetch the bytes `blob` points
    /// to (inline in record `payload_msg`, or chunks) and check them against `sha` before writing.
    Write {
        path: String,
        sha: String,
        mtime: f64,
        text: Option<String>,
        blob: Map<String, Value>,
    },
    /// Delete the file (it was unchanged since the last sync).
    Delete {
        path: String,
    },
    Mkdir {
        path: String,
    },
    /// Remove the folder if it is empty.
    Rmdir {
        path: String,
    },
}

/// Plan writing the tree to the folder: write what changed remotely, never touch local edits not
/// pushed yet. `disk`: path -> sha of what is in the folder now. Returns the ops and the new
/// `synced` map to store once the ops are done.
pub fn plan_materialize(
    replica: &Replica,
    disk: &BTreeMap<String, String>,
    synced: &BTreeMap<String, String>,
) -> (Vec<DiskOp>, BTreeMap<String, String>) {
    let mut ops = vec![];
    let mut out = synced.clone();
    for n in replica.tree.nodes.values() {
        let (local, last) = (disk.get(&n.path), synced.get(&n.path));
        if local == Some(&n.sha) {
            out.insert(n.path.clone(), n.sha.clone());
        } else if local == last {
            // Unchanged here since the last sync (or new on both sides of nothing): take theirs.
            ops.push(if n.sha == DIR {
                DiskOp::Mkdir { path: n.path.clone() }
            } else {
                DiskOp::Write {
                    path: n.path.clone(),
                    sha: n.sha.clone(),
                    mtime: n.mtime,
                    text: replica.text(&n.path),
                    blob: n.blob.clone(),
                }
            });
            out.insert(n.path.clone(), n.sha.clone());
        }
    }
    for (p, last) in synced {
        if replica.tree.get(p).is_some() {
            continue;
        }
        if disk.get(p) == Some(last) {
            ops.push(if last == DIR {
                DiskOp::Rmdir { path: p.clone() }
            } else {
                DiskOp::Delete { path: p.clone() }
            });
        }
        out.remove(p);
    }
    (ops, out)
}
