// SPDX-License-Identifier: AGPL-3.0-or-later
//! Junk membership messages (anyone in the group can post them) must cost a replica linear time:
//! each is compared with all earlier ones to spot re-posts, which must be a set lookup, not a scan.
use std::time::Instant;

use tgsync_core::descriptor::Identity;
use tgsync_core::replica::{Replica, Report};

fn feed_junk(n: usize) -> f64 {
    let mut r = Replica::new(Identity::new("AGE-SECRET-KEY-1X", "age1test"), None);
    let mut rep = Report::default();
    let junk: Vec<Vec<u8>> = (0..n)
        .map(|i| format!(
            "{{\"v\":1,\"vault_id\":\"00\",\"epoch\":1,\"members\":[],\"roster\":\"\",\"proof\":\"\",\"proof_epoch\":0,\"keycheck\":\"{i}\"}}"
        ).into_bytes())
        .collect(); // well-formed enough to parse, then rejected
    let start = Instant::now();
    for (i, d) in junk.iter().enumerate() {
        r.feed(i as i64 + 1, 'd', d, &mut rep);
    }
    start.elapsed().as_secs_f64()
}

#[test]
fn junk_membership_messages_cost_linear_time() {
    feed_junk(500); // warm up
    let (small, big) = (feed_junk(2000), feed_junk(8000));
    assert!(
        big < 8.0 * small,
        "8000 junk messages: {:.0} ms, 2000: {:.0} ms",
        big * 1e3,
        small * 1e3
    );
}
