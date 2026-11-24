// SPDX-License-Identifier: AGPL-3.0-or-later
//! Applying a note edit must cost about what Loro's own import costs (a copy of the whole note per
//! edit once made it 4x slower in release builds). Measured against a plain Loro import of the same
//! updates in the same run, so it holds on any machine.
use std::time::Instant;

use loro::{ExportMode, LoroDoc};
use tgsync_core::text::Texts;

#[test]
fn applying_an_edit_costs_about_a_plain_loro_import() {
    let w = LoroDoc::new();
    w.set_peer_id(7).unwrap();
    let t = w.get_text("text");
    t.insert(0, &"lorem ipsum dolor sit amet ".repeat(800)).unwrap();
    w.commit();
    let mut updates = vec![];
    let mut vv = Default::default();
    for i in 0..1000 {
        t.insert((i * 7919) % t.len_unicode(), &format!("[edit {i}]")).unwrap();
        w.commit();
        updates.push(w.export(ExportMode::updates(&vv)).unwrap());
        vv = w.oplog_vv();
    }
    let plain = LoroDoc::new();
    let start = Instant::now();
    for u in &updates {
        plain.import(u).unwrap();
    }
    let loro_s = start.elapsed().as_secs_f64();
    let mut texts = Texts::default();
    let start = Instant::now();
    for u in &updates {
        texts.import("d0", u).unwrap();
    }
    let ours_s = start.elapsed().as_secs_f64();
    assert!(ours_s < 4.0 * loro_s, "1000 edits: {:.0} ms here, {:.0} ms in plain Loro", ours_s * 1e3, loro_s * 1e3);
}
