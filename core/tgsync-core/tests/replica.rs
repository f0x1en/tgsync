// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replica behaviour, ported from tests/test_sync.py and tests/test_members.py (log level, no files).

use age::secrecy::ExposeSecret;
use serde_json::{json, Value};
use tgsync_core::crypto::KeyRing;
use tgsync_core::descriptor::{self, Identity, Member};
use tgsync_core::oplog::{encode_record, Record};
use tgsync_core::replica::{Replica, Report};
use tgsync_core::tree::Applied;

fn person() -> Identity {
    let id = age::x25519::Identity::generate();
    Identity { secret: id.to_string().expose_secret().to_string(), recipient: id.to_public().to_string() }
}

fn member(p: &Identity, name: &str) -> Member {
    Member { recipient: p.recipient.clone(), name: name.into() }
}

/// The group: an ordered list of (id, kind, body).
#[derive(Default)]
struct Group {
    msgs: Vec<(i64, char, Vec<u8>)>,
    n: u8,
}

impl Group {
    fn post(&mut self, kind: char, body: Vec<u8>) -> i64 {
        let id = self.msgs.len() as i64 + 1;
        self.msgs.push((id, kind, body));
        id
    }

    fn nonce(&mut self) -> [u8; 12] {
        self.n = self.n.wrapping_add(1);
        [self.n; 12]
    }

    fn descriptor(&mut self, ring: &KeyRing, members: &[Member], proof_epoch: Option<u32>) {
        let mut n = self.n;
        let data = descriptor::build(ring, "a1b2c3d4e5f60718", members, proof_epoch, 1, &mut || { n = n.wrapping_add(1); [n; 12] }).unwrap();
        self.n = n;
        self.post('d', data);
    }

    fn record(&mut self, ring: &KeyRing, author: &Identity, seq: u64, ts: f64, entries: Vec<Value>) -> i64 {
        let rec = Record { author: author.id(), seq, ts, entries, payload: vec![] };
        let nonce = self.nonce();
        let body = encode_record(ring, &rec, &nonce).unwrap();
        self.post('r', body)
    }

    fn pull(&self, r: &mut Replica) -> Report {
        let mut rep = Report::default();
        for _ in 0..2 {
            r.begin_pass();
            let cursor = r.cursor;
            for (id, kind, body) in self.msgs.iter().filter(|m| m.0 > cursor) {
                let body = if r.wants_body(*kind, *id) { body.as_slice() } else { &[] };
                r.feed(*id, *kind, body, &mut rep);
            }
            if !(r.blocked() && r.has_keys()) {
                break;
            }
        }
        r.active = true;
        rep
    }
}

fn put(path: &str, sha: &str, base: Option<&str>) -> Value {
    json!({"op": "put", "path": path, "sha": sha, "size": 1, "mtime": 1.0, "base": base,
           "blob": {"file_id": "00000000000000aa", "chunks": null, "inline": [0, 1]}})
}

fn ring1() -> KeyRing {
    let mut r = KeyRing::new();
    r.add(1, &[1u8; 32]).unwrap();
    r
}

/// alice + bob in one vault, both replicas pulled.
fn pair() -> (Group, KeyRing, Identity, Identity, Replica, Replica) {
    let (a, b) = (person(), person());
    let mut g = Group::default();
    let ring = ring1();
    g.descriptor(&ring, &[member(&a, "alice")], None);
    g.descriptor(&ring, &[member(&a, "alice"), member(&b, "bob")], None);
    let (mut ra, mut rb) = (Replica::new(a.clone(), None), Replica::new(b.clone(), None));
    g.pull(&mut ra);
    g.pull(&mut rb);
    (g, ring, a, b, ra, rb)
}

#[test]
fn roundtrip_and_concurrent_edit_makes_conflict_copy() {
    let (mut g, ring, a, b, mut ra, mut rb) = pair();
    g.record(&ring, &a, 1, 1000.0, vec![put("n.md", "s1", None)]);
    g.pull(&mut rb);
    assert_eq!(rb.tree.get("n.md").unwrap().sha, "s1");
    // Both edit from s1; alice's lands first, bob's becomes the conflict copy.
    g.record(&ring, &a, 2, 1060.0, vec![put("n.md", "sa", Some("s1"))]);
    g.record(&ring, &b, 1, 1061.0, vec![put("n.md", "sb", Some("s1"))]);
    g.pull(&mut ra);
    let rep = g.pull(&mut rb);
    assert!(matches!(rep.applied.last().unwrap().4, Applied::Conflict(_, _)));
    assert_eq!(ra.tree, rb.tree, "both replicas reach the same tree");
    assert_eq!(ra.tree.get("n.md").unwrap().sha, "sa");
    assert_eq!(ra.tree.nodes.values().filter(|n| n.sha == "sb").count(), 1);
}

#[test]
fn edit_beats_delete() {
    let (mut g, ring, a, b, mut ra, _) = pair();
    g.record(&ring, &a, 1, 1.0, vec![put("n.md", "s1", None)]);
    g.record(&ring, &a, 2, 2.0, vec![put("n.md", "s2", Some("s1"))]);
    g.record(&ring, &b, 1, 3.0, vec![json!({"op": "delete", "path": "n.md", "base": "s1"})]);
    g.pull(&mut ra);
    assert_eq!(ra.tree.get("n.md").unwrap().sha, "s2");
}

#[test]
fn tampered_record_is_rejected_not_applied() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    let id = g.record(&ring, &a, 1, 1.0, vec![put("n.md", "s1", None)]);
    let last = g.msgs[id as usize - 1].2.len() - 1;
    g.msgs[id as usize - 1].2[last] ^= 1;
    let rep = g.pull(&mut ra);
    assert!(ra.tree.get("n.md").is_none());
    assert!(rep.problems[0].1.starts_with("unreadable record"));
    assert_eq!(ra.cursor, id, "a bad record does not block the log");
}

#[test]
fn replayed_record_ignored() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    let id = g.record(&ring, &a, 1, 1.0, vec![put("n.md", "s1", None)]);
    g.record(&ring, &a, 2, 2.0, vec![json!({"op": "delete", "path": "n.md", "base": "s1"})]);
    let copy = g.msgs[id as usize - 1].2.clone();
    g.post('r', copy);
    let rep = g.pull(&mut ra);
    assert!(ra.tree.get("n.md").is_none(), "the replayed put must not bring the file back");
    assert!(rep.problems[0].1.contains("duplicate"));
}

#[test]
fn unsafe_paths_from_peer_are_ignored() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    g.record(&ring, &a, 1, 1.0, vec![put("../evil", "x", None), put(".tgsync/state", "x", None), put("ok.md", "x", None)]);
    g.pull(&mut ra);
    assert_eq!(ra.tree.nodes.keys().collect::<Vec<_>>(), ["ok.md"]);
}

#[test]
fn removed_member_cannot_read_new_data_but_others_can() {
    let (mut g, mut ring, a, _, mut ra, mut rb) = pair();
    ring.add(2, &[2u8; 32]).unwrap();
    g.descriptor(&ring, &[member(&a, "alice")], Some(1));
    g.record(&ring, &a, 1, 1.0, vec![put("secret.md", "s1", None)]);
    g.pull(&mut ra);
    g.pull(&mut rb);
    assert_eq!(ra.tree.get("secret.md").unwrap().sha, "s1");
    assert!(rb.removed);
    assert!(rb.tree.get("secret.md").is_none());
    assert!(!rb.keys.has(2));
}

#[test]
fn forged_descriptor_from_outsider_rejected() {
    let (mut g, _, a, _, mut ra, _) = pair();
    let mallory = person();
    let mut fake = KeyRing::new();
    fake.add(1, &[9u8; 32]).unwrap();
    g.descriptor(&fake, &[member(&a, "alice"), member(&mallory, "mallory")], None);
    let rep = g.pull(&mut ra);
    assert!(rep.problems[0].1.starts_with("rejected descriptor"));
    assert_eq!(ra.members.len(), 2);
    assert_eq!(ra.keys.key(1).unwrap(), &[1u8; 32]);
}

#[test]
fn late_joiner_receives_history_and_non_member_gets_nothing() {
    let a = person();
    let c = person();
    let mut g = Group::default();
    let ring = ring1();
    g.descriptor(&ring, &[member(&a, "alice")], None);
    g.record(&ring, &a, 1, 1.0, vec![put("old.md", "s1", None)]);
    let mut rc = Replica::new(c.clone(), None);
    g.pull(&mut rc);
    assert!(!rc.has_keys() && rc.tree.nodes.is_empty());
    assert_eq!(rc.cursor, 1, "records we cannot read yet stay ahead of the cursor");
    g.descriptor(&ring, &[member(&a, "alice"), member(&c, "carol")], None);
    g.pull(&mut rc);
    assert_eq!(rc.tree.get("old.md").unwrap().sha, "s1");
    assert_eq!(rc.cursor, 3);
}
