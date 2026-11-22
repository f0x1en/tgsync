// SPDX-License-Identifier: AGPL-3.0-or-later
//! Writes spec/vectors_v2.json: a fixed protocol v2 log (admins, signed records, merged notes,
//! rejected messages) and what each person's replica must make of it. Other implementations replay
//! the same log and compare. `cargo run -p tgsync-sim --bin make_vectors_v2` (bytes change each run:
//! age wrapping is randomized; the expectations do not).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use tgsync_core::crypto::KeyRing;
use tgsync_core::descriptor::{self, Identity, Member, Signing};
use tgsync_core::members;
use tgsync_core::oplog::{encode_record, Record};
use tgsync_core::replica::{Replica, Report};
use tgsync_core::sync::{plan_push, LocalFile};

struct Log {
    msgs: Vec<(char, Vec<u8>, String)>,
    n: u8,
}

impl Log {
    fn nonce(&mut self) -> [u8; 12] {
        self.n += 1;
        [self.n; 12]
    }
    fn post(&mut self, kind: char, body: Vec<u8>, what: &str) -> i64 {
        self.msgs.push((kind, body, what.into()));
        self.msgs.len() as i64
    }
    fn pull(&self, r: &mut Replica) -> Report {
        let mut rep = Report::default();
        r.begin_pass();
        for (i, (k, b, _)) in self.msgs.iter().enumerate() {
            let id = i as i64 + 1;
            if id > r.cursor {
                r.feed(id, *k, b, &mut rep);
            }
        }
        r.active = true;
        rep
    }
}

fn person(v: &Value, who: &str, k: u8) -> Identity {
    let mut p = Identity::new(v[who]["secret"].as_str().unwrap(), v[who]["recipient"].as_str().unwrap());
    p.signing = Some([k; 32]);
    p
}

type Map = std::collections::BTreeMap<String, String>;

/// A record from the owner of `r`: their folder `files` (path -> text) after writing `notes`,
/// planned like a real push.
fn record(log: &mut Log, r: &Replica, synced: &mut Map, files: &mut Map, notes: &[(&str, &str)], seq: u64, keys: &KeyRing) -> Vec<u8> {
    for (p, t) in notes {
        files.insert(p.to_string(), t.to_string());
    }
    let disk = files
        .iter()
        .map(|(p, t)| (p.clone(), LocalFile::from_bytes(p, t.as_bytes().to_vec(), 1.0)))
        .collect();
    let mut docs = 0;
    let push = plan_push(r, &disk, synced, &[], seq, &mut || {
        docs += 1;
        format!("{:016x}", seq * 100 + docs)
    })
    .unwrap();
    for (p, s) in &push.done {
        match s {
            Some(s) => synced.insert(p.clone(), s.clone()),
            None => synced.remove(p),
        };
    }
    let rec = Record {
        author: r.me.id(),
        seq,
        ts: 1_762_850_000.0 + seq as f64,
        entries: push.entries,
        payload: push.payload,
        signer: None,
    };
    encode_record(keys, &rec, &log.nonce(), r.me.signing.as_ref()).unwrap()
}

fn main() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/");
    let v1: Value = serde_json::from_str(&std::fs::read_to_string(format!("{root}vectors.json")).unwrap()).unwrap();
    let (a, b) = (person(&v1["identities"], "alice", 1), person(&v1["identities"], "bob", 2));
    let mut log = Log { msgs: vec![], n: 0 };
    let vid = "a1b2c3d4e5f60718";

    // 1-2: alice creates the vault (admin), adds bob.
    let d = members::create(&a, "alice", vid, &[0x11; 32], 1_762_850_000, &mut || log.nonce()).unwrap();
    log.post('d', d, "alice creates the vault; she is its admin");
    let mut ra = Replica::new(a.clone(), Some(vid.into()));
    log.pull(&mut ra);
    let d = members::add(&ra, &b.recipient, "bob", b.signer().as_deref(), 1_762_850_001, &mut || log.nonce()).unwrap();
    log.post('d', d, "alice adds bob");
    log.pull(&mut ra);
    let mut rb = Replica::new(b.clone(), Some(vid.into()));
    log.pull(&mut rb);

    // 3: bob (not an admin) tries to add someone: rejected.
    let mallory = age::x25519::Identity::generate().to_public().to_string();
    let mut people = rb.members.clone();
    people.push(Member::new(&mallory, "mallory"));
    let admins = [b.signer().unwrap()];
    let signing = Signing {
        admins: &admins,
        key: b.signing.as_ref().unwrap(),
    };
    let d = descriptor::build(&rb.keys, vid, &people, None, 1_762_850_002, Some(signing), &mut || log.nonce()).unwrap();
    log.post('d', d, "bob, not an admin, tries to add mallory: rejected");

    // 4-6: notes. alice writes n.md; then both edit it from the same version: merged.
    let (mut sa, mut fa, mut fb) = (Map::new(), Map::new(), Map::new());
    let ka = ra.keys.clone();
    let r = record(&mut log, &ra, &mut sa, &mut fa, &[("n.md", "hello world\n")], 1, &ka);
    log.post('r', r, "alice writes n.md");
    log.pull(&mut ra);
    log.pull(&mut rb);
    let mut sb = sa.clone();
    fb.clone_from(&fa);
    let r1 = record(&mut log, &ra, &mut sa, &mut fa, &[("n.md", "hello brave world\n")], 2, &ka);
    let r2 = record(&mut log, &rb, &mut sb, &mut fb, &[("n.md", "hello world!\n")], 1, &ka);
    log.post('r', r1, "alice edits n.md");
    log.post('r', r2, "bob edits n.md from the same version: merged");
    log.pull(&mut ra);
    log.pull(&mut rb);

    // 7: a record from bob signed with alice's key: rejected.
    let mut forger = b.clone();
    forger.signing = a.signing;
    let rf = Replica::new(forger, Some(vid.into()));
    let mut rf = rf;
    log.pull(&mut rf);
    let r = record(&mut log, &rf, &mut Map::new(), &mut Map::new(), &[("evil.md", "x")], 9, &ka);
    log.post('r', r, "a record in bob's name signed by someone else: rejected");

    // 8-9: alice gives bob admin, then drops her own.
    log.pull(&mut ra);
    let d = members::give_admin(&ra, "bob", 1_762_850_010, &mut || log.nonce()).unwrap();
    log.post('d', d, "alice gives admin to bob");
    log.pull(&mut ra);
    let d = members::drop_admin(&ra, 1_762_850_011, &mut || log.nonce()).unwrap();
    log.post('d', d, "alice stops being an admin");
    log.pull(&mut ra);
    log.pull(&mut rb);

    // 10-11: bob removes alice (key rotates); alice, not having pulled, writes with the old key.
    let d = members::remove(&rb, "alice", &[0x22; 32], 1_762_850_012, &mut || log.nonce()).unwrap();
    log.post('d', d, "bob removes alice; the key rotates");
    let r = record(&mut log, &ra, &mut sa, &mut fa, &[("late.md", "after removal")], 3, &ka);
    log.post('r', r, "alice writes with the old key after her removal: rejected");
    log.pull(&mut ra);
    log.pull(&mut rb);

    // Expectations, from fresh replicas (what a new client must compute).
    let expect = |me: &Identity| {
        let mut r = Replica::new(me.clone(), Some(vid.into()));
        let rep = log.pull(&mut r);
        json!({
            "removed": r.removed,
            "epoch": r.keys.current_epoch().ok(),
            "members": r.members.iter().map(|m| m.name.clone()).collect::<Vec<_>>(),
            "admins": r.admins.as_ref().map(|a| a.len()),
            "files": r.tree.nodes.iter().map(|(p, n)| (p.clone(), json!({"sha": n.sha, "text": r.text(p)}))).collect::<serde_json::Map<_, _>>(),
            "problems": rep.problems.iter().map(|(id, w)| json!([id, w])).collect::<Vec<_>>(),
        })
    };
    let out = json!({
        "note": "Generated by `cargo run -p tgsync-sim --bin make_vectors_v2`. Protocol v2 (PROTOCOL.md sections 11-13). \
                 Replay `log` in order (message id = index + 1) as alice and as bob; compare with `expect`.",
        "vault_id": vid,
        "signing_keys": {"alice": hex::encode([1u8; 32]), "bob": hex::encode([2u8; 32])},
        "log": log.msgs.iter().map(|(k, b, w)| json!({"kind": k.to_string(), "body_b64": B64.encode(b), "what": w})).collect::<Vec<_>>(),
        "expect": {"alice": expect(&a), "bob": expect(&b)},
    });
    std::fs::write(format!("{root}vectors_v2.json"), serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    println!("{}", serde_json::to_string_pretty(&out["expect"]).unwrap());
}
