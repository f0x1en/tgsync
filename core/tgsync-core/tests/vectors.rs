// SPDX-License-Identifier: AGPL-3.0-or-later
//! The Rust core must agree with spec/vectors.json (same file the Python and TS tests use).

use serde_json::Value;
use tgsync_core::crypto::{self, KeyRing};
use tgsync_core::{invites, oplog, paths};

fn v() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn x(v: &Value) -> Vec<u8> {
    hex::decode(s(v)).unwrap()
}

fn ring(epoch: u64, key: &Value) -> KeyRing {
    let mut r = KeyRing::new();
    r.add(epoch as u32, &x(key)).unwrap();
    r
}

#[test]
fn subkeys_mac_fingerprint() {
    let v = v();
    for t in v["subkey"].as_array().unwrap() {
        let key: [u8; 32] = x(&t["key"]).try_into().unwrap();
        let got = crypto::subkey(&key, s(&t["purpose"]).as_bytes(), s(&t["ctx"]).as_bytes());
        assert_eq!(hex::encode(got), s(&t["subkey"]));
    }
    for t in v["mac"].as_array().unwrap() {
        let parts: Vec<&[u8]> = t["parts"].as_array().unwrap().iter().map(|p| s(p).as_bytes()).collect();
        assert_eq!(hex::encode(crypto::mac(&x(&t["key"]), &parts)), s(&t["mac"]));
    }
    for t in v["fingerprint"].as_array().unwrap() {
        assert_eq!(crypto::fingerprint(&x(&t["key"])), s(&t["fingerprint"]));
    }
}

#[test]
fn seal_open() {
    let v = v();
    for t in v["seal"].as_array().unwrap() {
        let r = ring(t["epoch"].as_u64().unwrap(), &t["key"]);
        let (purpose, ctx) = (s(&t["purpose"]).as_bytes(), s(&t["ctx"]).as_bytes());
        assert_eq!(r.open(purpose, ctx, &x(&t["blob"])).unwrap(), x(&t["plaintext"]));
        // Sealing with the vector's nonce gives the vector's blob byte for byte.
        let nonce: [u8; 12] = x(&t["nonce"]).try_into().unwrap();
        assert_eq!(r.seal(purpose, ctx, &x(&t["plaintext"]), &nonce, None).unwrap(), x(&t["blob"]));
    }
    let mut r = KeyRing::new();
    for (e, k) in v["open_ring"].as_object().unwrap() {
        r.add(e.parse().unwrap(), &x(k)).unwrap();
    }
    for t in v["open_must_fail"].as_array().unwrap() {
        let res = r.open(s(&t["purpose"]).as_bytes(), s(&t["ctx"]).as_bytes(), &x(&t["blob"]));
        assert!(res.is_err(), "must fail: {}", t["why"]);
    }
}

#[test]
fn identities() {
    for i in v()["identities"].as_object().unwrap().values() {
        assert_eq!(crypto::member_id(s(&i["recipient"])), s(&i["id"]));
        assert_eq!(crypto::short_code(s(&i["recipient"])), s(&i["short_code"]));
    }
}

#[test]
fn record_and_chunk() {
    let v = v();
    let r = &v["record"];
    let rec = oplog::decode_record(&ring(r["epoch"].as_u64().unwrap(), &r["key"]), &x(&r["blob"])).unwrap();
    assert_eq!(rec.author, s(&r["author"]));
    assert_eq!(rec.seq, r["seq"].as_u64().unwrap());
    assert_eq!(rec.ts, r["ts"].as_f64().unwrap());
    assert_eq!(&Value::from(rec.entries), &r["entries"]);
    assert_eq!(rec.payload, x(&r["payload"]));
    let c = &v["chunk"];
    let (idx, count) = (c["index"].as_u64().unwrap() as u32, c["count"].as_u64().unwrap() as u32);
    let got = oplog::open_chunk(&ring(1, &c["key"]), s(&c["file_id"]), idx, count, &x(&c["blob"])).unwrap();
    assert_eq!(got, x(&c["data"]));
}

#[test]
fn invite_and_join_request() {
    let v = v();
    let i = &v["invite"];
    let inv = invites::decode_invite(s(&i["code"])).unwrap();
    assert_eq!(
        (inv.link.as_str(), inv.vault_id.as_str(), inv.fingerprint.as_str()),
        (s(&i["link"]), s(&i["vault_id"]), s(&i["fingerprint"]))
    );
    let api = inv.api.clone().unwrap();
    assert_eq!((api.0, api.1.as_str()), (i["api"][0].as_i64().unwrap(), s(&i["api"][1])));
    assert_eq!(invites::encode_invite(&inv), s(&i["code"]));
    let j = &v["join_request"];
    let req = invites::decode_request(s(&j["body"]).as_bytes()).unwrap();
    assert_eq!(
        (req.vault_id.as_str(), req.recipient.as_str(), req.name.as_str()),
        (s(&j["vault"]), s(&j["recipient"]), s(&j["name"]))
    );
}

#[test]
fn paths_and_conflict_names() {
    let v = v();
    for p in v["paths"].as_array().unwrap() {
        let got = paths::normalize(s(&p["in"]));
        if p["ok"].as_bool().unwrap() {
            assert_eq!(got.unwrap(), s(&p["out"]));
        } else {
            assert!(got.is_err(), "must reject {:?}", p["in"]);
        }
    }
    for c in v["conflict_name"].as_array().unwrap() {
        assert_eq!(
            paths::conflict_name(s(&c["path"]), s(&c["author"]), c["ts"].as_f64().unwrap()),
            s(&c["out"])
        );
    }
}

use tgsync_core::descriptor::{self, Identity};
use tgsync_core::tree::{Applied, Tree};

fn ident(v: &Value, who: &str) -> Identity {
    let i = &v["identities"][who];
    Identity::new(s(&i["secret"]), s(&i["recipient"]))
}

#[test]
fn descriptor_sequence() {
    let v = v();
    let d = &v["descriptors"];
    for who in ["alice", "bob"] {
        let me = ident(&v, who);
        let mut ring = KeyRing::new();
        let seq = d["sequence"].as_array().unwrap();
        let want = d[format!("expect_{who}")].as_array().unwrap();
        assert_eq!(seq.len(), want.len());
        for (data, want) in seq.iter().zip(want) {
            let got = descriptor::accept(s(data).as_bytes(), &me, &mut ring, Some(s(&d["vault_id"])), false, None).unwrap();
            if want == "excluded" {
                assert!(got.is_none(), "{who}: expected excluded");
            } else {
                let got = got.unwrap();
                assert_eq!(u64::from(got.epoch), want["epoch"].as_u64().unwrap());
                let names: Vec<&str> = got.members.iter().map(|m| m.name.as_str()).collect();
                let want_names: Vec<&str> = want["members"].as_array().unwrap().iter().map(s).collect();
                assert_eq!(names, want_names);
            }
        }
        if who == "alice" {
            assert_eq!(hex::encode(ring.key(2).unwrap()), s(&d["epoch2_key"]));
        }
    }
}

#[test]
fn forged_descriptor_rejected() {
    let v = v();
    let d = &v["descriptors"];
    let me = ident(&v, "alice");
    let mut ring = KeyRing::new();
    descriptor::accept(
        s(&d["sequence"][0]).as_bytes(),
        &me,
        &mut ring,
        Some(s(&d["vault_id"])),
        false,
        None,
    )
    .unwrap();
    let before = ring.clone();
    assert!(descriptor::accept(
        s(&d["forged_after_d1"]).as_bytes(),
        &me,
        &mut ring,
        Some(s(&d["vault_id"])),
        false,
        None
    )
    .is_err());
    assert_eq!(ring, before, "a rejected descriptor must not change the ring");
}

#[test]
fn descriptor_roundtrip() {
    let v = v();
    let (alice, bob) = (ident(&v, "alice"), ident(&v, "bob"));
    let mut ring = KeyRing::new();
    ring.add(1, &[7u8; 32]).unwrap();
    let members = [
        descriptor::Member::new(&alice.recipient, "alice ü"),
        descriptor::Member::new(&bob.recipient, "bob"),
    ];
    let mut n = 0u8;
    let mut nonce = || {
        n += 1;
        [n; 12]
    };
    let data = descriptor::build(&ring, "a1b2c3d4e5f60718", &members, None, 1_762_850_000, None, &mut nonce).unwrap();
    let mut bob_ring = KeyRing::new();
    let got = descriptor::accept(&data, &bob, &mut bob_ring, None, false, None).unwrap().unwrap();
    assert_eq!(got.members, members);
    assert_eq!(bob_ring, ring);
}

#[test]
fn replay() {
    let v = v();
    let rv = &v["replay"];
    let mut t = Tree::new();
    let mut results = vec![];
    for m in rv["log"].as_array().unwrap() {
        for e in m["entries"].as_array().unwrap() {
            let r = t.apply_entry(e, s(&m["author"]), m["ts"].as_f64().unwrap(), m["msg_id"].as_i64().unwrap());
            results.push(match r {
                None => Value::Null,
                Some(Applied::Put(p)) => serde_json::json!(["put", p, null]),
                Some(Applied::Noop(p)) => serde_json::json!(["noop", p, null]),
                Some(Applied::Delete(p)) => serde_json::json!(["delete", p, null]),
                Some(Applied::Mkdir(p)) => serde_json::json!(["mkdir", p, null]),
                Some(Applied::Rmdir(p)) => serde_json::json!(["rmdir", p, null]),
                Some(Applied::Conflict(p, c)) => serde_json::json!(["conflict", p, c]),
                Some(Applied::Text(p)) => serde_json::json!(["text", p, null]),
            });
        }
    }
    assert_eq!(Value::from(results), rv["results"]);
    let tree: serde_json::Map<String, Value> = t
        .nodes
        .iter()
        .map(|(p, n)| {
            (
                p.clone(),
                serde_json::json!({"sha": n.sha, "author": n.author, "msg_id": n.msg_id, "payload_msg": n.blob.get("payload_msg")}),
            )
        })
        .collect();
    assert_eq!(Value::from(tree), rv["tree"]);
}
