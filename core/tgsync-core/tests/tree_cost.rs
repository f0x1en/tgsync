// SPDX-License-Identifier: AGPL-3.0-or-later
//! Replaying notes must stay linear in their number (finding a note's path by scanning every file
//! once made replay quadratic). 4x the notes must cost far less than 16x the time, on any machine.
use std::time::Instant;

use tgsync_core::tree::Tree;

fn replay(n: usize) -> f64 {
    let mut t = Tree::new();
    let start = Instant::now();
    for i in 0..n {
        t.apply_text(&format!("n/{i}.md"), &format!("d{i}"), &format!("s{i}"), 1, 1.0, None, "a", 1.0, i as i64);
    }
    for i in 0..n {
        let (path, base) = (format!("n/{i}.md"), format!("s{i}"));
        t.apply_text(&path, &format!("d{i}"), &format!("t{i}"), 1, 1.0, Some(&base), "a", 2.0, (n + i) as i64);
    }
    start.elapsed().as_secs_f64()
}

#[test]
fn replaying_notes_stays_linear() {
    replay(500); // warm up
    let (small, big) = (replay(2000), replay(8000));
    assert!(big < 8.0 * small, "8000 notes: {:.0} ms, 2000 notes: {:.0} ms", big * 1e3, small * 1e3);
}
