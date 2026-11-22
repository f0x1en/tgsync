// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo run --release -p tgsync-sim --bin bench`: how fast the core is (no network, no disk).

use std::collections::BTreeMap;
use std::time::Instant;

use age::secrecy::ExposeSecret;
use serde_json::json;
use tgsync_core::crypto::KeyRing;
use tgsync_core::descriptor::Identity;
use tgsync_core::members;
use tgsync_core::oplog::{encode_record, open_chunk, seal_chunk, Record};
use tgsync_core::replica::{Replica, Report};
use tgsync_core::sync::{plan_push, LocalFile};

fn person(k: u8) -> Identity {
    let id = age::x25519::Identity::generate();
    let mut p = Identity::new(id.to_string().expose_secret(), &id.to_public().to_string());
    p.signing = Some([k; 32]);
    p
}

fn mbps(bytes: usize, t: Instant) -> f64 {
    bytes as f64 / 1e6 / t.elapsed().as_secs_f64()
}

fn main() {
    // 1. Sealing and opening 32 MiB chunks (AES-256-GCM).
    let mut ring = KeyRing::new();
    ring.add(1, &[7; 32]).unwrap();
    let chunk = vec![0x5a_u8; 32 << 20];
    let t = Instant::now();
    let sealed: Vec<Vec<u8>> = (0..8).map(|i| seal_chunk(&ring, "f", i, 8, &chunk, &[i as u8; 12]).unwrap()).collect();
    let seal = mbps(8 * chunk.len(), t);
    let t = Instant::now();
    for (i, s) in sealed.iter().enumerate() {
        open_chunk(&ring, "f", i as u32, 8, s).unwrap();
    }
    let open = mbps(8 * chunk.len(), t);
    println!("chunks: seal {seal:.0} MB/s, open {open:.0} MB/s (256 MiB in 32 MiB chunks)");

    // 2. Replaying the log: 2000 signed records of 25 small-file entries each (50 000 files).
    let a = person(1);
    let mut group: Vec<(i64, char, Vec<u8>)> = vec![];
    let mut n = 0u8;
    let d = members::create(&a, "a", "0011223344556677", &[3; 32], 0, &mut || { n = n.wrapping_add(1); [n; 12] }).unwrap();
    group.push((1, 'd', d));
    let mut writer = Replica::new(a.clone(), None);
    writer.feed(1, 'd', &group[0].2, &mut Report::default());
    for seq in 1..=2000u64 {
        let entries: Vec<_> = (0..25)
            .map(|i| json!({"op": "put", "path": format!("d{seq}/f{i}.bin"), "sha": format!("{seq:032x}{i:032x}"), "size": 10,
                            "mtime": 1.0, "base": null, "blob": {"file_id": "x", "chunks": null, "inline": [0, 10]}}))
            .collect();
        let rec = Record { author: a.id(), seq, ts: 1.0, entries, payload: vec![0; 250], signer: None };
        let id = group.len() as i64 + 1;
        group.push((id, 'r', encode_record(&writer.keys, &rec, &[seq as u8; 12], a.signing.as_ref()).unwrap()));
    }
    let t = Instant::now();
    let mut r = Replica::new(a.clone(), None);
    let mut rep = Report::default();
    for (id, k, b) in &group {
        r.feed(*id, *k, b, &mut rep);
    }
    let secs = t.elapsed().as_secs_f64();
    assert_eq!(r.tree.nodes.len(), 50_000);
    println!("replay: 2000 records / 50 000 files in {:.2} s ({:.0} records/s, {:.0} files/s), signatures checked",
             secs, 2000.0 / secs, 50_000.0 / secs);

    // 3. Saving and loading that replica.
    let t = Instant::now();
    let saved = r.save();
    let save_s = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let back = Replica::load(a.clone(), &saved).unwrap();
    println!("state: save {:.0} ms, load {:.0} ms, {:.1} MB for 50 000 files", save_s * 1e3, t.elapsed().as_secs_f64() * 1e3,
             saved.len() as f64 / 1e6);
    assert_eq!(back.tree.nodes.len(), 50_000);

    // 4. Text notes: 1000 successive edits of one 20 KB note, then two people editing at once.
    let mut text = "lorem ipsum dolor sit amet ".repeat(800);
    let mut group: Vec<(i64, char, Vec<u8>)> = vec![group[0].clone()];
    let mut w = Replica::new(a.clone(), None);
    w.feed(1, 'd', &group[0].2, &mut Report::default());
    let mut synced: BTreeMap<String, String> = BTreeMap::new();
    let (mut update_bytes, mut prepare_s, mut apply_s) = (0usize, 0.0, 0.0);
    for seq in 1..=1000u64 {
        let at = (seq as usize * 7919) % text.len();
        let at = (0..=at).rev().find(|i| text.is_char_boundary(*i)).unwrap();
        text.insert_str(at, &format!("[edit {seq}]"));
        let disk: BTreeMap<String, LocalFile> =
            [("note.md".to_string(), LocalFile::from_bytes("note.md", text.clone().into_bytes(), 1.0))].into();
        let t = Instant::now();
        let p = plan_push(&w, &disk, &synced, &[], seq, &mut || "00000000000000d0".into()).unwrap();
        prepare_s += t.elapsed().as_secs_f64();
        update_bytes += p.payload.len();
        let rec = Record { author: a.id(), seq, ts: 1.0, entries: p.entries.clone(), payload: p.payload.clone(), signer: None };
        let id = group.len() as i64 + 1;
        let body = encode_record(&w.keys, &rec, &[1; 12], a.signing.as_ref()).unwrap();
        let t = Instant::now();
        w.feed(id, 'r', &body, &mut Report::default());
        apply_s += t.elapsed().as_secs_f64();
        group.push((id, 'r', body));
        for (path, sha) in p.done {
            synced.insert(path, sha.unwrap());
        }
    }
    assert_eq!(w.text("note.md").unwrap(), text);
    println!("notes: 1000 edits of a {} KB note: diff+export {:.2} ms/edit, import {:.2} ms/edit, {} bytes/edit on the wire (vs {} KB whole file)",
             text.len() / 1000, prepare_s, apply_s, update_bytes / 1000, text.len() / 1000);
    let saved = w.save();
    println!("notes: state with that note's whole history: {:.0} KB", saved.len() as f64 / 1e3);
}
