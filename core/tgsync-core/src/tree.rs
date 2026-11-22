// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic replay of log entries into the file tree (PROTOCOL.md section 9).
//! Every client applies the same ordered log and reaches the same tree, conflict names included.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::paths::{conflict_name, conflict_name_tagged, normalize};

/// sha of a folder node.
pub const DIR: &str = "dir";

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub path: String,
    pub sha: String,
    pub size: i64,
    pub mtime: f64,
    /// `{"file_id", "chunks", "chunk_size", "inline", "payload_msg"}`; kept as JSON, it is passed through.
    pub blob: Map<String, Value>,
    pub author: String,
    pub msg_id: i64,
}

/// What one entry did. `Conflict(original, copy)`: the write landed at `copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    Put(String),
    Noop(String),
    Delete(String),
    Mkdir(String),
    Rmdir(String),
    Conflict(String, String),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tree {
    pub nodes: BTreeMap<String, Node>,
    /// lowercase path -> exact path, for case-insensitive clash checks.
    fold: BTreeMap<String, String>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, path: &str) -> Option<&Node> {
        self.nodes.get(path)
    }

    pub fn set(&mut self, node: Node) {
        self.fold.insert(node.path.to_lowercase(), node.path.clone());
        self.nodes.insert(node.path.clone(), node);
    }

    fn remove(&mut self, path: &str) {
        self.nodes.remove(path);
        let low = path.to_lowercase();
        if self.fold.get(&low).map(String::as_str) == Some(path) {
            self.fold.remove(&low);
        }
    }

    fn free_conflict_path(&self, path: &str, author: &str, ts: f64) -> String {
        let mut cand = conflict_name(path, author, ts);
        let short: String = author.chars().take(5).collect();
        let mut n = 2;
        while self.fold.contains_key(&cand.to_lowercase()) {
            cand = conflict_name_tagged(path, &format!("{short}{n}"), ts);
            n += 1;
        }
        cand
    }

    /// Apply one entry. `None` = ignored (malformed, unsafe path, or lost to a newer state).
    pub fn apply_entry(&mut self, entry: &Value, author: &str, ts: f64, msg_id: i64) -> Option<Applied> {
        let op = entry.get("op")?.as_str()?;
        let path = normalize(entry.get("path")?.as_str()?).ok()?;
        let cur_sha = self.nodes.get(&path).map(|n| n.sha.clone());
        let clash = self.fold.get(&path.to_lowercase()).cloned();
        let base = entry.get("base").and_then(Value::as_str);
        match op {
            "put" => {
                let sha = entry.get("sha")?.as_str()?.to_owned();
                let size = entry.get("size")?.as_f64()?.trunc() as i64;
                let mtime = match entry.get("mtime") {
                    None | Some(Value::Null) => ts,
                    Some(m) => m.as_f64()?,
                };
                let mut blob = entry.get("blob")?.as_object()?.clone();
                blob.entry("payload_msg").or_insert(Value::from(msg_id));
                let node = Node { path: path.clone(), sha, size, mtime, blob, author: author.to_owned(), msg_id };
                if clash.as_ref().is_some_and(|c| *c != path) {
                    return Some(self.conflict(node, author, ts));
                }
                match cur_sha {
                    Some(c) if c == node.sha => Some(Applied::Noop(path)),
                    None => {
                        self.set(node);
                        Some(Applied::Put(path))
                    }
                    Some(c) if Some(c.as_str()) == base => {
                        self.set(node);
                        Some(Applied::Put(path))
                    }
                    Some(_) => Some(self.conflict(node, author, ts)),
                }
            }
            "delete" => {
                // An edit beats a delete: only delete what the author saw.
                if cur_sha.is_some() && cur_sha.as_deref() == base {
                    self.remove(&path);
                    return Some(Applied::Delete(path));
                }
                None
            }
            "mkdir" => {
                if cur_sha.is_some() || clash.is_some() {
                    return None;
                }
                self.set(Node { path: path.clone(), sha: DIR.into(), size: 0, mtime: ts, blob: Map::new(), author: author.to_owned(), msg_id });
                Some(Applied::Mkdir(path))
            }
            "rmdir" => {
                if cur_sha.as_deref() == Some(DIR) {
                    self.remove(&path);
                    return Some(Applied::Rmdir(path));
                }
                None
            }
            _ => None,
        }
    }

    fn conflict(&mut self, mut node: Node, author: &str, ts: f64) -> Applied {
        let original = std::mem::take(&mut node.path);
        node.path = self.free_conflict_path(&original, author, ts);
        let copy = node.path.clone();
        self.set(node);
        Applied::Conflict(original, copy)
    }
}
