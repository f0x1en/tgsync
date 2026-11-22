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
    assert_eq!((inv.link.as_str(), inv.vault_id.as_str(), inv.fingerprint.as_str()), (s(&i["link"]), s(&i["vault_id"]), s(&i["fingerprint"])));
    let api = inv.api.clone().unwrap();
    assert_eq!((api.0, api.1.as_str()), (i["api"][0].as_i64().unwrap(), s(&i["api"][1])));
    assert_eq!(invites::encode_invite(&inv), s(&i["code"]));
    let j = &v["join_request"];
    let req = invites::decode_request(s(&j["body"]).as_bytes()).unwrap();
    assert_eq!((req.vault_id.as_str(), req.recipient.as_str(), req.name.as_str()), (s(&j["vault"]), s(&j["recipient"]), s(&j["name"])));
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
        assert_eq!(paths::conflict_name(s(&c["path"]), s(&c["author"]), c["ts"].as_f64().unwrap()), s(&c["out"]));
    }
}
