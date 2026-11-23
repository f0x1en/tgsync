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
    Identity::new(id.to_string().expose_secret(), &id.to_public().to_string())
}

fn member(p: &Identity, name: &str) -> Member {
    Member::new(&p.recipient, name)
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
        let data = descriptor::build(ring, "a1b2c3d4e5f60718", members, proof_epoch, 1, None, &mut || {
            n = n.wrapping_add(1);
            [n; 12]
        })
        .unwrap();
        self.n = n;
        self.post('d', data);
    }

    fn descriptor_v2(&mut self, ring: &KeyRing, members: &[Member], proof_epoch: Option<u32>, admins: &[String], key: &[u8; 32]) {
        let mut n = self.n;
        let signing = descriptor::Signing { admins, key };
        let data = descriptor::build(ring, "a1b2c3d4e5f60718", members, proof_epoch, 1, Some(signing), &mut || {
            n = n.wrapping_add(1);
            [n; 12]
        })
        .unwrap();
        self.n = n;
        self.post('d', data);
    }

    fn record(&mut self, ring: &KeyRing, author: &Identity, seq: u64, ts: f64, entries: Vec<Value>) -> i64 {
        self.record_with(ring, author, seq, ts, entries, vec![])
    }

    fn record_with(&mut self, ring: &KeyRing, author: &Identity, seq: u64, ts: f64, entries: Vec<Value>, payload: Vec<u8>) -> i64 {
        let rec = Record {
            author: author.id(),
            seq,
            ts,
            entries,
            payload,
            signer: None,
        };
        let nonce = self.nonce();
        let body = encode_record(ring, &rec, &nonce, author.signing.as_ref()).unwrap();
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
    g.record(
        &ring,
        &a,
        1,
        1.0,
        vec![put("../evil", "x", None), put(".tgsync/state", "x", None), put("ok.md", "x", None)],
    );
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

// ------------------------------------------------------------------ admins (PROTOCOL.md section 11)

fn admin_person(k: u8) -> Identity {
    let mut p = person();
    p.signing = Some([k; 32]);
    p
}

fn smember(p: &Identity, name: &str) -> Member {
    Member {
        signer: p.signer(),
        ..member(p, name)
    }
}

/// alice (admin) + bob in a v2 vault.
fn admin_pair() -> (Group, KeyRing, Identity, Identity, Replica, Replica) {
    let (a, b) = (admin_person(1), admin_person(2));
    let mut g = Group::default();
    let ring = ring1();
    let admins = [a.signer().unwrap()];
    g.descriptor_v2(&ring, &[smember(&a, "alice")], None, &admins, &[1; 32]);
    g.descriptor_v2(&ring, &[smember(&a, "alice"), smember(&b, "bob")], None, &admins, &[1; 32]);
    let (mut ra, mut rb) = (Replica::new(a.clone(), None), Replica::new(b.clone(), None));
    assert!(g.pull(&mut ra).problems.is_empty());
    assert!(g.pull(&mut rb).problems.is_empty());
    (g, ring, a, b, ra, rb)
}

#[test]
fn admin_vault_accepts_its_admin() {
    let (_, _, a, b, ra, rb) = admin_pair();
    assert_eq!(ra.admins, Some(vec![a.signer().unwrap()]));
    assert_eq!(rb.members.len(), 2);
    assert_eq!(rb.members[1].signer, b.signer());
}

#[test]
fn non_admin_member_cannot_change_members() {
    let (mut g, ring, a, b, mut ra, _) = admin_pair();
    let carol = admin_person(3);
    // bob holds the vault key (valid proof) but is not an admin.
    g.descriptor_v2(
        &ring,
        &[smember(&a, "alice"), smember(&b, "bob"), smember(&carol, "carol")],
        None,
        &[b.signer().unwrap()],
        &[2; 32],
    );
    let rep = g.pull(&mut ra);
    assert_eq!(rep.problems[0].1, "rejected descriptor: descriptor not signed by an admin");
    assert_eq!(ra.members.len(), 2);
}

#[test]
fn give_admin_then_drop_admin() {
    let (mut g, ring, a, b, mut ra, _) = admin_pair();
    let both = vec![a.signer().unwrap(), b.signer().unwrap()];
    let members = [smember(&a, "alice"), smember(&b, "bob")];
    g.descriptor_v2(&ring, &members, None, &both, &[1; 32]); // alice gives admin to bob
    g.descriptor_v2(&ring, &members, None, &[b.signer().unwrap()], &[2; 32]); // bob: alice drops out
    assert!(g.pull(&mut ra).problems.is_empty());
    assert_eq!(ra.admins, Some(vec![b.signer().unwrap()]));
    g.descriptor_v2(&ring, &members, None, &both, &[1; 32]); // alice is no longer allowed
    assert!(g.pull(&mut ra).problems[0].1.contains("not signed by an admin"));
}

#[test]
fn v1_descriptor_rejected_after_v2() {
    let (mut g, ring, a, b, mut ra, _) = admin_pair();
    g.descriptor(&ring, &[member(&a, "alice"), member(&b, "bob"), member(&person(), "x")], None);
    assert!(g.pull(&mut ra).problems[0].1.contains("v1 descriptor in a vault that has admins"));
}

#[test]
fn tampered_signature_rejected() {
    let (mut g, ring, a, b, mut ra, _) = admin_pair();
    g.descriptor_v2(
        &ring,
        &[smember(&a, "alice"), smember(&b, "bob")],
        None,
        &[a.signer().unwrap()],
        &[1; 32],
    );
    let last = g.msgs.len() - 1;
    let text = String::from_utf8(g.msgs[last].2.clone())
        .unwrap()
        .replace("\"created\":1", "\"created\":2");
    g.msgs[last].2 = text.into_bytes();
    assert!(g.pull(&mut ra).problems[0].1.contains("signature is invalid"));
}

#[test]
fn admin_must_be_a_member() {
    let (mut g, ring, a, b, mut ra, _) = admin_pair();
    let outsider = admin_person(9);
    g.descriptor_v2(
        &ring,
        &[smember(&a, "alice"), smember(&b, "bob")],
        None,
        &[a.signer().unwrap(), outsider.signer().unwrap()],
        &[1; 32],
    );
    assert!(g.pull(&mut ra).problems[0].1.contains("an admin is not a member"));
}

#[test]
fn forged_removal_does_not_remove_us() {
    // v1 and v2 alike: an outsider posts a descriptor without bob, proven with a key bob does not know.
    for v2 in [false, true] {
        let (mut g, _, a, _, _, mut rb) = if v2 { admin_pair() } else { pair() };
        let mut fake = KeyRing::new();
        fake.add(1, &[9u8; 32]).unwrap();
        fake.add(2, &[8u8; 32]).unwrap();
        if v2 {
            g.descriptor_v2(&fake, &[smember(&a, "alice")], Some(1), &[a.signer().unwrap()], &[1; 32]);
        } else {
            g.descriptor(&fake, &[member(&a, "alice")], Some(1));
        }
        let rep = g.pull(&mut rb);
        assert!(!rb.removed, "v2={v2}: a forged removal must not remove us");
        assert!(rep.problems[0].1.starts_with("rejected descriptor"), "v2={v2}: {:?}", rep.problems);
    }
}

#[test]
fn real_removal_in_admin_vault() {
    let (mut g, mut ring, a, _, mut ra, mut rb) = admin_pair();
    ring.add(2, &[2u8; 32]).unwrap();
    g.descriptor_v2(&ring, &[smember(&a, "alice")], Some(1), &[a.signer().unwrap()], &[1; 32]);
    assert!(g.pull(&mut ra).problems.is_empty());
    g.pull(&mut rb);
    assert!(rb.removed);
    assert_eq!(ra.members.len(), 1);
}

// ------------------------------------------------------------------ signed records (PROTOCOL.md section 12)

#[test]
fn removed_member_cannot_write() {
    let (mut g, mut ring, a, b, mut ra, _) = admin_pair();
    let old = ring.clone();
    ring.add(2, &[2u8; 32]).unwrap();
    g.descriptor_v2(&ring, &[smember(&a, "alice")], Some(1), &[a.signer().unwrap()], &[1; 32]);
    g.record(&old, &b, 1, 1.0, vec![put("spam.md", "x", None)]); // bob still has the old key
    let rep = g.pull(&mut ra);
    assert!(ra.tree.get("spam.md").is_none());
    assert_eq!(rep.problems[0].1, "record not signed by a member");
}

#[test]
fn stale_key_record_rejected_and_handed_back_to_its_writer() {
    let (mut g, mut ring, a, b, _, mut rb) = admin_pair();
    let carol = admin_person(3);
    let three = [smember(&a, "alice"), smember(&b, "bob"), smember(&carol, "carol")];
    g.descriptor_v2(&ring, &three, None, &[a.signer().unwrap()], &[1; 32]);
    g.pull(&mut rb);
    let old = ring.clone();
    ring.add(2, &[2u8; 32]).unwrap();
    g.descriptor_v2(&ring, &three[..2], Some(1), &[a.signer().unwrap()], &[1; 32]); // carol removed
                                                                                    // bob has not pulled the rotation and writes with the old key carol still holds.
    g.record(&old, &b, 1, 1.0, vec![put("n.md", "s1", None)]);
    let rep = g.pull(&mut rb);
    assert!(rb.tree.get("n.md").is_none());
    assert!(rep.problems[0].1.contains("already replaced"));
    assert_eq!(rep.resend.len(), 1, "bob's own entry comes back for re-sending");
    // Re-sent with the new key: applied.
    g.record(&ring, &b, 2, 2.0, rep.resend.iter().map(|r| r.entry.clone()).collect());
    g.pull(&mut rb);
    assert_eq!(rb.tree.get("n.md").unwrap().sha, "s1");
}

#[test]
fn unsigned_record_rejected_in_admin_vault() {
    let (mut g, ring, _, b, mut ra, _) = admin_pair();
    let mut unsigned = b.clone();
    unsigned.signing = None;
    g.record(&ring, &unsigned, 1, 1.0, vec![put("n.md", "s1", None)]);
    assert_eq!(g.pull(&mut ra).problems[0].1, "unsigned record in a vault that has admins");
}

#[test]
fn record_signed_by_someone_else_rejected() {
    let (mut g, ring, a, b, mut ra, _) = admin_pair();
    let mut forger = b.clone();
    forger.signing = a.signing; // alice's key, bob's name
    g.record(&ring, &forger, 1, 1.0, vec![put("n.md", "s1", None)]);
    assert_eq!(g.pull(&mut ra).problems[0].1, "record not signed by a member");
}

#[test]
fn late_joiner_agrees_with_old_member_on_rejected_records() {
    let (mut g, mut ring, a, b, mut ra, _) = admin_pair();
    let old = ring.clone();
    ring.add(2, &[2u8; 32]).unwrap();
    g.descriptor_v2(&ring, &[smember(&a, "alice")], Some(1), &[a.signer().unwrap()], &[1; 32]); // bob removed
    g.record(&old, &b, 1, 1.0, vec![put("late.md", "x", None)]);
    g.record(&ring, &a, 1, 2.0, vec![put("ok.md", "y", None)]);
    let dave = admin_person(4);
    g.descriptor_v2(
        &ring,
        &[smember(&a, "alice"), smember(&dave, "dave")],
        None,
        &[a.signer().unwrap()],
        &[1; 32],
    );
    let mut rd = Replica::new(dave, None);
    g.pull(&mut ra);
    g.pull(&mut rd);
    assert_eq!(rd.tree, ra.tree);
    assert_eq!(rd.tree.nodes.keys().collect::<Vec<_>>(), ["ok.md"]);
    assert_eq!(rd.history.len(), ra.history.len());
}

// ------------------------------------------------------------------ text notes (PROTOCOL.md section 13)

/// One text edit by `who` (replica `r` prepares it), sent as its own record.
fn text_edit(g: &mut Group, ring: &KeyRing, who: &Identity, r: &Replica, seq: u64, path: &str, base: Option<&str>, text: &str, doc: &str) {
    let peer = seq * 1000 + u64::from(who.id().as_bytes()[0]);
    let edit = r.prepare_text(path, base, text, doc, peer).unwrap();
    let n = edit.update.len();
    let e = json!({"op": "text", "path": path, "doc": edit.doc, "sha": tgsync_core::text::sha_hex(text), "size": text.len(),
                   "mtime": 1.0, "base": base, "blob": {"inline": [0, n]}});
    g.record_with(ring, who, seq, seq as f64, vec![e], edit.update);
}

#[test]
fn concurrent_note_edits_merge_without_conflict_copy() {
    let (mut g, ring, a, b, mut ra, mut rb) = pair();
    text_edit(&mut g, &ring, &a, &ra, 1, "n.md", None, "hello world", "d1");
    g.pull(&mut ra);
    g.pull(&mut rb);
    let base = tgsync_core::text::sha_hex("hello world");
    // Both edit the same version at once.
    text_edit(&mut g, &ring, &a, &ra, 2, "n.md", Some(&base), "hello brave world", "x");
    text_edit(&mut g, &ring, &b, &rb, 1, "n.md", Some(&base), "hello world!", "y");
    g.pull(&mut ra);
    let rep = g.pull(&mut rb);
    assert_eq!(ra.text("n.md").unwrap(), "hello brave world!");
    // Every version stays readable (for `tgsync restore`).
    let (_, _, doc, sha) = rep.text_versions.last().unwrap().clone();
    assert_eq!(rb.texts.text_at(&doc, &sha).unwrap(), "hello brave world!");
    assert_eq!(rb.texts.text_at(&doc, &base).unwrap(), "hello world");
    assert_eq!(ra.tree, rb.tree);
    assert_eq!(ra.tree.nodes.len(), 1, "no conflict copy");
}

#[test]
fn note_edit_beats_delete() {
    let (mut g, ring, a, b, mut ra, mut rb) = pair();
    text_edit(&mut g, &ring, &a, &ra, 1, "n.md", None, "one", "d1");
    g.pull(&mut ra);
    g.pull(&mut rb);
    let base = tgsync_core::text::sha_hex("one");
    g.record(&ring, &a, 2, 2.0, vec![json!({"op": "delete", "path": "n.md", "base": base})]);
    text_edit(&mut g, &ring, &b, &rb, 1, "n.md", Some(&base), "one two", "y");
    g.pull(&mut ra);
    assert_eq!(ra.text("n.md").unwrap(), "one two");
}

#[test]
fn two_new_notes_at_one_path_make_a_conflict_copy() {
    let (mut g, ring, a, b, mut ra, rb) = pair();
    text_edit(&mut g, &ring, &a, &ra, 1, "n.md", None, "from alice", "da");
    text_edit(&mut g, &ring, &b, &rb, 1, "n.md", None, "from bob", "db");
    g.pull(&mut ra);
    assert_eq!(ra.text("n.md").unwrap(), "from alice");
    let copy = ra.tree.nodes.keys().find(|p| p.contains("conflict")).unwrap().clone();
    assert_eq!(ra.text(&copy).unwrap(), "from bob");
    // Bob keeps editing his note: the edits follow it to the conflict copy.
    let mut rb = rb;
    g.pull(&mut rb);
    let base = tgsync_core::text::sha_hex("from bob");
    text_edit(&mut g, &ring, &b, &rb, 2, "n.md", Some(&base), "from bob, again", "z");
    g.pull(&mut ra);
    assert_eq!(ra.text(&copy).unwrap(), "from bob, again");
    assert_eq!(ra.text("n.md").unwrap(), "from alice");
}

#[test]
fn bad_text_update_is_skipped() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    let e =
        json!({"op": "text", "path": "n.md", "doc": "d1", "sha": "x", "size": 3, "mtime": 1.0, "base": null, "blob": {"inline": [0, 3]}});
    g.record_with(&ring, &a, 1, 1.0, vec![e], b"bad".to_vec());
    g.pull(&mut ra);
    assert!(ra.tree.get("n.md").is_none());
}

// ------------------------------------------------------------------ regressions from the code review

#[test]
fn note_edit_takes_over_a_plain_file_it_was_based_on() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    let big = "x".repeat(10);
    let sha = tgsync_core::text::sha_hex(&big);
    // n.md arrived as a plain put (e.g. it was too big to merge, or written by an older client).
    g.record(&ring, &a, 1, 1.0, vec![put("n.md", &sha, None)]);
    g.pull(&mut ra);
    // Now edited as a note, based on that version: it replaces the file, no conflict copy.
    text_edit(&mut g, &ring, &a, &ra, 2, "n.md", Some(&sha), "short now", "d9");
    g.pull(&mut ra);
    assert_eq!(ra.text("n.md").unwrap(), "short now");
    assert_eq!(ra.tree.nodes.len(), 1);
    // Not based on it: someone else's file, so a conflict copy as before.
    let (mut g, ring, a, b, mut ra, rb) = pair();
    g.record(&ring, &a, 1, 1.0, vec![put("m.md", &sha, None)]);
    text_edit(&mut g, &ring, &b, &rb, 1, "m.md", None, "bob's own", "db");
    g.pull(&mut ra);
    assert_eq!(ra.tree.nodes.len(), 2);
}

#[test]
fn a_replayed_old_key_record_is_not_sent_again() {
    let (mut g, mut ring, a, b, _, mut rb) = admin_pair();
    let carol = admin_person(3);
    let three = [smember(&a, "alice"), smember(&b, "bob"), smember(&carol, "carol")];
    g.descriptor_v2(&ring, &three, None, &[a.signer().unwrap()], &[1; 32]);
    g.pull(&mut rb);
    let old = ring.clone();
    ring.add(2, &[2u8; 32]).unwrap();
    g.descriptor_v2(&ring, &three[..2], Some(1), &[a.signer().unwrap()], &[1; 32]);
    let id = g.record(&old, &b, 1, 1.0, vec![put("n.md", "s1", None)]);
    assert_eq!(g.pull(&mut rb).resend.len(), 1);
    let copy = g.msgs[id as usize - 1].2.clone();
    g.post('r', copy); // someone posts it again
    assert_eq!(g.pull(&mut rb).resend.len(), 0, "the replay must not queue the old content again");
}

#[test]
fn a_bad_note_update_leaves_no_empty_doc() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    let e =
        json!({"op": "text", "path": "n.md", "doc": "dd", "sha": "x", "size": 3, "mtime": 1.0, "base": null, "blob": {"inline": [0, 3]}});
    g.record_with(&ring, &a, 1, 1.0, vec![e], b"bad".to_vec());
    g.pull(&mut ra);
    assert_eq!(ra.texts.doc_ids().count(), 0);
}

#[test]
fn a_huge_proof_epoch_is_rejected_not_a_crash() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    g.descriptor(&ring, &[member(&a, "alice")], None);
    let last = g.msgs.len() - 1;
    let mut d: Value = serde_json::from_slice(&g.msgs[last].2).unwrap();
    d["proof_epoch"] = json!(u64::MAX);
    g.msgs[last].2 = serde_json::to_vec(&d).unwrap();
    assert!(g.pull(&mut ra).problems[0].1.contains("bad proof epoch"));
}

#[test]
fn an_edit_never_lands_in_another_note_with_the_same_text() {
    let (mut g, ring, a, b, mut ra, mut rb) = pair();
    // Two empty notes: q.md (older doc id "d1") and p.md ("d2").
    text_edit(&mut g, &ring, &a, &ra, 1, "q.md", None, "", "d1");
    text_edit(&mut g, &ring, &a, &ra, 2, "p.md", None, "", "d2");
    g.pull(&mut ra);
    g.pull(&mut rb);
    let empty = tgsync_core::text::sha_hex("");
    // alice deletes p.md; bob (not having pulled that) types into his p.md.
    g.record(&ring, &a, 3, 3.0, vec![json!({"op": "delete", "path": "p.md", "base": empty})]);
    g.pull(&mut rb);
    text_edit(&mut g, &ring, &b, &rb, 1, "p.md", Some(&empty), "bob's words", "d3");
    g.pull(&mut ra);
    assert_eq!(ra.text("q.md").unwrap(), "", "q.md is untouched");
    assert_eq!(ra.text("p.md").unwrap(), "bob's words");
}

#[test]
fn a_note_update_missing_its_history_is_reported_not_applied() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    let w = Replica::new(a.clone(), None);
    // Prepare two edits in a row on a private copy, then post only the second.
    let mut w = w;
    g.pull(&mut w);
    let e1 = w.prepare_text("n.md", None, "one", "dz", 1).unwrap();
    w.texts.import("dz", &e1.update).unwrap();
    w.tree
        .apply_text("n.md", "dz", &tgsync_core::text::sha_hex("one"), 3, 1.0, None, "x", 1.0, 1);
    let e2 = w
        .prepare_text("n.md", Some(&tgsync_core::text::sha_hex("one")), "one two", "dz", 2)
        .unwrap();
    let n = e2.update.len();
    let e =
        json!({"op": "text", "path": "n.md", "doc": "dz", "sha": "x", "size": 7, "mtime": 1.0, "base": null, "blob": {"inline": [0, n]}});
    g.record_with(&ring, &a, 1, 1.0, vec![e], e2.update);
    let rep = g.pull(&mut ra);
    assert!(ra.tree.get("n.md").is_none());
    assert!(rep.problems.iter().any(|(_, w)| w.contains("never arrived")), "{:?}", rep.problems);
}

#[test]
fn files_cannot_pose_as_folders() {
    let (mut g, ring, a, _, mut ra, _) = pair();
    g.record(
        &ring,
        &a,
        1,
        1.0,
        vec![put("f.bin", "dir", None), json!({"op": "mkdir", "path": "d"})],
    );
    g.record(&ring, &a, 2, 2.0, vec![json!({"op": "delete", "path": "d", "base": "dir"})]);
    g.pull(&mut ra);
    assert!(ra.tree.get("f.bin").is_none());
    assert_eq!(ra.tree.get("d").unwrap().sha, "dir", "delete does not remove a folder");
}

#[test]
fn a_note_keeps_its_newest_256_versions() {
    use tgsync_core::text::{sha_hex, Texts};
    let mut t = Texts::default();
    let mut base: Option<String> = None;
    for i in 0..300u64 {
        let text = format!("version {i}");
        let edit = t.prepare(base.as_ref().map(|_| "d"), base.as_deref(), &text, "d", i + 1).unwrap();
        t.import("d", &edit.update).unwrap();
        base = Some(sha_hex(&text));
    }
    assert!(t.has_version("d", &sha_hex("version 299")));
    assert!(t.has_version("d", &sha_hex("version 44")));
    assert!(!t.has_version("d", &sha_hex("version 43")), "older versions are dropped");
    let back = Texts::load(&t.save()).unwrap();
    assert!(back == t);
    assert!(back.has_version("d", &sha_hex("version 44")) && !back.has_version("d", &sha_hex("version 43")));
}
