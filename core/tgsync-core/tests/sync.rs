// SPDX-License-Identifier: AGPL-3.0-or-later
//! Push and materialize plans (tgsync_core::sync).

use std::collections::BTreeMap;

use serde_json::json;
use tgsync_core::descriptor::Identity;
use tgsync_core::replica::Replica;
use tgsync_core::sync::{plan_materialize, plan_push, Content, DiskOp, LocalFile};
use tgsync_core::tree::Node;

fn me() -> Replica {
    Replica::new(Identity::new("AGE-SECRET-KEY-1X", "age1test"), None)
}

fn files(list: &[(&str, &[u8])]) -> BTreeMap<String, LocalFile> {
    list.iter().map(|(p, b)| (p.to_string(), LocalFile::from_bytes(p, b.to_vec(), 1.0))).collect()
}

fn no_doc() -> String {
    "0123456789abcdef".into()
}

#[test]
fn from_bytes_picks_text_only_for_utf8_notes() {
    assert!(matches!(LocalFile::from_bytes("a.md", b"hi".to_vec(), 0.0).content, Content::Text(_)));
    assert!(matches!(LocalFile::from_bytes("a.md", vec![0xff, 0xfe], 0.0).content, Content::Small(_)));
    assert!(matches!(LocalFile::from_bytes("a.png", b"hi".to_vec(), 0.0).content, Content::Small(_)));
}

#[test]
fn push_plans_new_changed_deleted_and_folders() {
    let r = me();
    let mut disk = files(&[("a.md", b"note"), ("b.bin", b"\x00\x01")]);
    disk.insert("empty".into(), LocalFile { sha: "dir".into(), size: 0, mtime: 0.0, content: Content::Dir });
    let mut synced = BTreeMap::new();
    synced.insert("gone.txt".to_string(), "aa".to_string());
    synced.insert("olddir".to_string(), "dir".to_string());
    let p = plan_push(&r, &disk, &synced, &[], 1, &mut no_doc).unwrap();
    let ops: Vec<(&str, &str)> = p.entries.iter().map(|e| (e["op"].as_str().unwrap(), e["path"].as_str().unwrap())).collect();
    assert_eq!(ops, [("text", "a.md"), ("put", "b.bin"), ("mkdir", "empty"), ("delete", "gone.txt"), ("rmdir", "olddir")]);
    assert_eq!(p.entries[1]["blob"]["inline"], json!([p.payload.len() - 2, 2]));
    assert_eq!(p.done.len(), 5);
    // Nothing changed: nothing to send.
    let synced: BTreeMap<String, String> = disk.iter().map(|(k, v)| (k.clone(), v.sha.clone())).collect();
    assert!(plan_push(&r, &disk, &synced, &[], 2, &mut no_doc).unwrap().is_empty());
}

#[test]
fn rename_reuses_the_blob_and_uploads_no_bytes() {
    let mut r = me();
    let f = LocalFile::from_bytes("old.bin", b"big content".to_vec(), 1.0);
    let blob = json!({"file_id": "x", "chunks": null, "inline": [0, 11], "payload_msg": 7});
    r.tree.set(Node { path: "old.bin".into(), sha: f.sha.clone(), size: 11, mtime: 1.0, blob: blob.as_object().unwrap().clone(),
                      author: "a".into(), msg_id: 7, doc: None });
    let disk = files(&[("new.bin", b"big content")]);
    let mut synced = BTreeMap::new();
    synced.insert("old.bin".to_string(), f.sha.clone());
    let p = plan_push(&r, &disk, &synced, &[], 1, &mut no_doc).unwrap();
    assert!(p.payload.is_empty(), "a rename sends no bytes");
    assert_eq!(p.entries[0]["blob"]["payload_msg"], 7);
}

#[test]
fn materialize_writes_remote_changes_but_never_local_edits() {
    let mut r = me();
    for (path, sha) in [("theirs.bin", "t2"), ("mine.bin", "r2"), ("new.bin", "n1")] {
        r.tree.set(Node { path: path.into(), sha: sha.into(), size: 1, mtime: 1.0, blob: Default::default(),
                          author: "a".into(), msg_id: 1, doc: None });
    }
    let disk: BTreeMap<String, String> =
        [("theirs.bin", "t1"), ("mine.bin", "m-local"), ("removed.bin", "x1")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    let synced: BTreeMap<String, String> =
        [("theirs.bin", "t1"), ("mine.bin", "r1"), ("removed.bin", "x1")].iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
    let (ops, out) = plan_materialize(&r, &disk, &synced);
    let what: Vec<String> = ops.iter().map(|o| match o {
        DiskOp::Write { path, .. } => format!("write {path}"),
        DiskOp::Delete { path } => format!("delete {path}"),
        other => format!("{other:?}"),
    }).collect();
    assert_eq!(what, ["write new.bin", "write theirs.bin", "delete removed.bin"]);
    assert_eq!(out.get("mine.bin").map(String::as_str), Some("r1"), "a local edit stays unsynced until pushed");
    assert_eq!(out.get("theirs.bin").map(String::as_str), Some("t2"));
    assert!(!out.contains_key("removed.bin"));
}
