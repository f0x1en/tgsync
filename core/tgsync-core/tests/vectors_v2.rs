// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replays spec/vectors_v2.json (a fixed protocol v2 log) as alice and as bob and compares with the
//! expected result. Another implementation of protocol v2 must pass the same check.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use tgsync_core::descriptor::Identity;
use tgsync_core::replica::{Replica, Report};

fn load(name: &str) -> Value {
    let p = format!("{}/../../spec/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn v2_log_replays_to_the_expected_state() {
    let (v1, v2) = (load("vectors.json"), load("vectors_v2.json"));
    let vid = v2["vault_id"].as_str().unwrap();
    for who in ["alice", "bob"] {
        let i = &v1["identities"][who];
        let mut me = Identity::new(i["secret"].as_str().unwrap(), i["recipient"].as_str().unwrap());
        me.signing = Some(hex::decode(v2["signing_keys"][who].as_str().unwrap()).unwrap().try_into().unwrap());
        let mut r = Replica::new(me, Some(vid.into()));
        let mut rep = Report::default();
        r.begin_pass();
        for (n, m) in v2["log"].as_array().unwrap().iter().enumerate() {
            let body = B64.decode(m["body_b64"].as_str().unwrap()).unwrap();
            r.feed(n as i64 + 1, m["kind"].as_str().unwrap().chars().next().unwrap(), &body, &mut rep);
        }
        let got = json!({
            "removed": r.removed,
            "epoch": r.keys.current_epoch().ok(),
            "members": r.members.iter().map(|m| m.name.clone()).collect::<Vec<_>>(),
            "admins": r.admins.as_ref().map(|a| a.len()),
            "files": r.tree.nodes.iter().map(|(p, n)| (p.clone(), json!({"sha": n.sha, "text": r.text(p)}))).collect::<serde_json::Map<_, _>>(),
            "problems": rep.problems.iter().map(|(id, w)| json!([id, w])).collect::<Vec<_>>(),
        });
        assert_eq!(got, v2["expect"][who], "{who}");
    }
}
