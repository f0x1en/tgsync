// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic simulation: N clients share one fake Telegram group. A seed picks every action
//! and fault, so a failing seed replays exactly. Checks after the clients settle:
//! 1. every replica holds the same tree;
//! 2. every client's disk equals the tree;
//! 3. no delivered edit is silently lost: each put's content is still in the tree, or a later
//!    entry named it as `base` (its author saw it and replaced or deleted it on purpose);
//! 4. text notes (`.md`, merged with Loro): every edit a member uploaded is merged into its doc.

use std::collections::{BTreeMap, BTreeSet};

use age::secrecy::ExposeSecret;
use tgsync_core::descriptor::Identity;
use tgsync_core::members;
use tgsync_core::replica::{Replica, Report, KIND_DESCRIPTOR, KIND_RECORD};
use tgsync_core::sync::{Content, DiskOp, LocalFile};
use tgsync_core::text::{is_text_path, sha_hex};
use tgsync_core::tree::DIR;
use tgsync_core::vault::Vault;

/// What `base` is for a file with this content: text notes use the sha of the text, other files
/// use their content id directly (content ids stand in for sha-256 of file bytes).
fn base_of(path: &str, content: Option<&String>) -> Option<String> {
    content.map(|c| if c != DIR && is_text_path(path) { sha_hex(c) } else { c.clone() })
}

/// The files a replica's tree describes: path -> text (notes), content id (other files) or "dir".
fn contents(r: &Replica) -> BTreeMap<String, String> {
    r.tree
        .nodes
        .values()
        .map(|n| {
            (
                n.path.clone(),
                match &n.doc {
                    Some(d) => r.texts.text(d).unwrap(),
                    None => n.sha.clone(),
                },
            )
        })
        .collect()
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(' ').filter(|w| !w.is_empty())
}

/// How the simulated folder's content looks to the core: notes are text, other files stand in
/// as empty small files whose sha is their content id.
fn local_file(path: &str, content: &str) -> LocalFile {
    if content == DIR {
        LocalFile {
            sha: DIR.into(),
            size: 0,
            mtime: 0.0,
            content: Content::Dir,
        }
    } else if path == BIG {
        // A big file: its chunks went up before the record (here only the blob is simulated).
        let blob = serde_json::json!({"file_id": &content[..content.len().min(16)], "chunks": [], "chunk_size": 1, "inline": null});
        LocalFile {
            sha: content.to_owned(),
            size: 1 << 30,
            mtime: 0.0,
            content: Content::Big(blob),
        }
    } else if is_text_path(path) {
        LocalFile {
            sha: sha_hex(content),
            size: content.len() as u64,
            mtime: 0.0,
            content: Content::Text(content.to_owned()),
        }
    } else {
        LocalFile {
            sha: content.to_owned(),
            size: 1,
            mtime: 0.0,
            content: Content::Small(vec![]),
        }
    }
}

/// splitmix64: tiny, fast, good enough to drive a simulation.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.next_u64() % 100 < percent
    }
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.next_u64() as u8;
        }
        out
    }
}

/// Paths the clients fight over: case clashes, folders, names that need conflict copies.
const PATHS: &[&str] = &[
    "a.md",
    "A.md",
    "b.md",
    "notes/x.md",
    "notes/X.md",
    "notes/y.md",
    "img.png",
    "video.bin",
];
/// A big file (chunked upload): re-uses the blob when the same content appears again.
const BIG: &str = "video.bin";
/// Empty folders the clients create and remove.
const DIRS: &[&str] = &["empty", "ideas/later"];

struct Client {
    /// Replica, synced map, re-send queue, last seq: the state a real host saves per folder.
    vault: Vault,
    /// path -> content: the text of a note, or a content id that stands in for other file bytes.
    disk: BTreeMap<String, String>,
}

pub struct Sim {
    pub rng: Rng,
    pub trace: Vec<String>,
    group: Vec<(i64, char, Vec<u8>)>,
    clients: Vec<Client>,
    next_content: u64,
    clock: f64,
    /// Off while settling: the network is healthy at the end.
    faults: bool,
    /// (client, record msg id, path, content or None for a delete) for every change the client
    /// marked as uploaded.
    promised: Vec<(usize, i64, String, Option<String>)>,
    /// (client, record msg id at that time, path) for every local edit or delete.
    touched: Vec<(usize, i64, String)>,
    /// A protocol v1 vault (see `with_version`).
    v1: bool,
    /// Message ids of odd records (see `weird_record`): no edit in them has to survive.
    odd: BTreeSet<i64>,
    /// v1: notes travel as plain puts, so their text is looked up by sha when written back.
    texts_by_sha: BTreeMap<String, String>,
    /// (client, record msg id, doc, Loro update) for every note upload marked as done.
    text_promised: Vec<(usize, i64, String, Vec<u8>)>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub messages: usize,
    pub conflicts: usize,
    pub problems: usize,
    /// Records sealed with an older epoch than the newest the group had at that point
    /// (the writer had not pulled a key rotation yet).
    pub stale_epoch: usize,
}

/// An age identity derived from the seed, so member ids (and conflict-copy names) replay exactly.
fn person(rng: &mut Rng) -> Identity {
    use bech32::ToBase32;
    let secret = bech32::encode("age-secret-key-", rng.bytes::<32>().to_base32(), bech32::Variant::Bech32)
        .unwrap()
        .to_uppercase();
    let id: age::x25519::Identity = secret.parse().unwrap();
    let mut p = Identity::new(id.to_string().expose_secret(), &id.to_public().to_string());
    p.signing = Some(rng.bytes());
    p
}

impl Sim {
    pub fn new(seed: u64, n_clients: usize) -> Self {
        Self::with_version(seed, n_clients, false)
    }

    /// `v1`: a protocol v1 vault (no admins, unsigned records, notes sent as plain puts), as made by
    /// older clients; the core must keep it working the v1 way (PROTOCOL.md section 14).
    pub fn with_version(seed: u64, n_clients: usize, v1: bool) -> Self {
        let mut rng = Rng::new(seed);
        let people: Vec<Identity> = (0..n_clients).map(|_| person(&mut rng)).collect();
        let key = rng.bytes::<32>();
        let mut group = vec![];
        if v1 {
            let mut ring = tgsync_core::crypto::KeyRing::new();
            ring.add(1, &key).unwrap();
            let all: Vec<_> = people
                .iter()
                .enumerate()
                .map(|(i, p)| tgsync_core::descriptor::Member::new(&p.recipient, &format!("c{i}")))
                .collect();
            let d = tgsync_core::descriptor::build(&ring, "5eed5eed5eed5eed", &all, None, 0, None, &mut || rng.bytes()).unwrap();
            group.push((1, KIND_DESCRIPTOR, d));
        }
        let mut post = |d: Vec<u8>| {
            let id = group.len() as i64 + 1;
            group.push((id, KIND_DESCRIPTOR, d));
        };
        if !v1 {
            post(members::create(&people[0], "c0", "5eed5eed5eed5eed", &key, 0, &mut || rng.bytes()).unwrap());
        }
        // The admin adds everyone else (as it would after their join requests).
        let mut admin = Replica::new(people[0].clone(), None);
        let mut rep = Report::default();
        admin.feed(1, KIND_DESCRIPTOR, &group[0].2, &mut rep);
        for (i, p) in people.iter().enumerate().skip(1).filter(|_| !v1) {
            let d = members::add(&admin, &p.recipient, &format!("c{i}"), p.signer().as_deref(), 0, &mut || {
                rng.bytes()
            })
            .unwrap();
            let id = group.len() as i64 + 1;
            admin.feed(id, KIND_DESCRIPTOR, &d, &mut rep);
            group.push((id, KIND_DESCRIPTOR, d));
        }
        let clients = people
            .into_iter()
            .map(|p| Client {
                vault: Vault::new(p, None),
                disk: BTreeMap::new(),
            })
            .collect();
        Sim {
            rng,
            trace: vec![],
            group,
            clients,
            next_content: 0,
            clock: 1_762_850_000.0,
            faults: true,
            promised: vec![],
            touched: vec![],
            text_promised: vec![],
            v1,
            odd: BTreeSet::new(),
            texts_by_sha: BTreeMap::new(),
        }
    }

    fn post(&mut self, kind: char, body: Vec<u8>) {
        let id = self.group.len() as i64 + 1;
        self.group.push((id, kind, body));
    }

    /// One random action by one random client.
    pub fn step(&mut self) {
        self.clock += 1.0 + self.rng.below(120) as f64;
        let c = self.rng.below(self.clients.len());
        if self.clients.len() > 1 && self.rng.chance(3) {
            self.churn();
            return;
        }
        if self.rng.chance(3) {
            self.restart(c);
            return;
        }
        if self.faults && self.rng.chance(2) {
            self.garbage();
            return;
        }
        if self.faults && self.rng.chance(2) {
            self.weird_record(c);
            return;
        }
        match self.rng.below(10) {
            0..=2 => self.edit(c),
            3 => self.toggle_dir(c),
            4 => self.delete(c),
            5..=6 => self.push(c),
            _ => {
                self.pull(c, true);
            }
        }
    }

    /// The admin (c0) removes a member (new epoch key) or adds a removed one back.
    /// A re-added member joins afresh: new replica, nothing synced, files on disk kept.
    fn churn(&mut self) {
        self.pull(0, false);
        let k = 1 + self.rng.below(self.clients.len() - 1);
        let target = self.clients[k].vault.replica.me.recipient.clone();
        if self.clients[0].vault.replica.members.iter().any(|m| m.recipient == target) {
            let key = self.rng.bytes::<32>();
            let Sim { clients, rng, v1, .. } = self;
            let desc = if *v1 {
                let a = &clients[0].vault.replica;
                let mut ring = a.keys.clone();
                let old = ring.current_epoch().unwrap();
                ring.add(old + 1, &key).unwrap();
                let keep: Vec<_> = a.members.iter().filter(|m| m.recipient != target).cloned().collect();
                tgsync_core::descriptor::build(&ring, "5eed5eed5eed5eed", &keep, Some(old), 0, None, &mut || rng.bytes()).unwrap()
            } else {
                members::remove(&clients[0].vault.replica, &target, &key, 0, &mut || rng.bytes()).unwrap()
            };
            self.trace.push(format!("c0 removes c{k}"));
            self.post(KIND_DESCRIPTOR, desc);
        } else {
            self.churn_add(k);
        }
    }

    /// The admin adds c{k} back; c{k} joins afresh (new replica, nothing synced, files kept).
    fn churn_add(&mut self, k: usize) {
        let me = self.clients[k].vault.replica.me.clone();
        let Sim { clients, rng, v1, .. } = self;
        let desc = if *v1 {
            let a = &clients[0].vault.replica;
            let mut all = a.members.clone();
            all.push(tgsync_core::descriptor::Member::new(&me.recipient, &format!("c{k}")));
            tgsync_core::descriptor::build(&a.keys, "5eed5eed5eed5eed", &all, None, 0, None, &mut || rng.bytes()).unwrap()
        } else {
            members::add(
                &clients[0].vault.replica,
                &me.recipient,
                &format!("c{k}"),
                me.signer().as_deref(),
                0,
                &mut || rng.bytes(),
            )
            .unwrap()
        };
        self.clients[k].vault.replica = Replica::new(me, None);
        self.clients[k].vault.synced.clear();
        self.trace.push(format!("c0 adds c{k} back"));
        self.post(KIND_DESCRIPTOR, desc);
    }

    /// Someone in the group (not a member, or a buggy client) posts junk: random bytes, or a real
    /// message with bits flipped, under any kind. Replicas must skip it without panicking.
    fn garbage(&mut self) {
        let kind = ['d', 'r', 'c', 'j', 'x'][self.rng.below(5)];
        // (Copies flip bits only in the first 48 bytes: message bytes are not the same in every run,
        // because Loro's encoding is not byte-stable, so a position based on the length would make
        // the run differ.)
        let (body, what) = if self.rng.chance(50) || self.group.is_empty() {
            let n = self.rng.below(300);
            (
                (0..n).map(|_| self.rng.next_u64() as u8).collect::<Vec<u8>>(),
                format!("{n} random bytes"),
            )
        } else {
            let src = self.rng.below(self.group.len());
            let mut b = self.group[src].2.clone();
            for _ in 0..1 + self.rng.below(4) {
                let i = self.rng.below(48);
                if i < b.len() {
                    b[i] ^= 1 << self.rng.below(8);
                }
            }
            (b, format!("copy of msg {} with bits flipped", src + 1))
        };
        self.trace.push(format!("junk message, kind {kind}: {what}"));
        self.post(kind, body);
    }

    /// A member (buggy or hostile) posts a properly sealed and signed record whose entries are odd:
    /// wrong types, unsafe paths, out-of-range blobs, garbage note updates, unknown ops. Replay must
    /// skip what makes no sense, never panic, and every replica must still agree.
    fn weird_record(&mut self, c: usize) {
        let v = &self.clients[c].vault;
        if v.replica.removed || !v.replica.has_keys() {
            return;
        }
        let paths = ["a.md", "../x", ".tgsync/s", "CON.md", "w/", "", "notes/x.md", "img.png", "dir"];
        let mut entries = vec![];
        for _ in 0..1 + self.rng.below(4) {
            let p = paths[self.rng.below(paths.len())];
            let e = match self.rng.below(9) {
                0 => serde_json::json!({"op": "put", "path": p, "sha": 5, "size": "big", "blob": null}),
                1 => serde_json::json!({"op": "put", "path": p, "sha": "z", "size": -3, "mtime": "now", "base": 1, "blob": {}}),
                2 => serde_json::json!({"op": "text", "path": p, "doc": "", "blob": {"inline": [0, 99999]}}),
                3 => {
                    serde_json::json!({"op": "text", "path": p, "doc": "dd", "sha": "q", "size": 1, "base": null, "blob": {"inline": [0, 4]}})
                }
                4 => serde_json::json!({"op": "delete", "path": p, "base": "dir"}),
                5 => serde_json::json!({"op": "rmdir", "path": p}),
                6 => serde_json::json!({"op": "mkdir", "path": p}),
                7 => serde_json::json!({"op": "teleport", "path": p}),
                _ => serde_json::json!("not an object"),
            };
            entries.push(e);
        }
        let seq = v.next_seq();
        let rec = tgsync_core::oplog::Record {
            author: v.replica.me.id(),
            seq,
            ts: self.clock,
            entries,
            payload: b"junk".to_vec(),
            signer: None,
        };
        let nonce = self.rng.bytes();
        let body = tgsync_core::oplog::encode_record(&v.replica.keys, &rec, &nonce, v.replica.me.signing.as_ref()).unwrap();
        self.clients[c].vault.sent_seq = seq;
        self.trace.push(format!("c{c} posts an odd record (seq {seq})"));
        self.post(KIND_RECORD, body);
        self.odd.insert(self.group.len() as i64);
    }

    /// The program stops and starts again: the replica is saved and loaded back (keys come back
    /// from the stored descriptors, never from the saved state).
    fn restart(&mut self, c: usize) {
        let v = &self.clients[c].vault;
        let loaded = Vault::load(v.replica.me.clone(), &v.save()).unwrap();
        self.trace.push(format!("c{c} restarts"));
        self.clients[c].vault = loaded;
    }

    /// Create an empty folder, or remove it if it is there.
    fn toggle_dir(&mut self, c: usize) {
        let d = DIRS[self.rng.below(DIRS.len())].to_string();
        let disk = &mut self.clients[c].disk;
        let made = if disk.get(&d).map(String::as_str) == Some(DIR) {
            disk.remove(&d);
            false
        } else {
            disk.insert(d.clone(), DIR.into());
            true
        };
        self.trace
            .push(format!("c{c} {} folder {d}", if made { "makes" } else { "removes" }));
        self.touched.push((c, self.group.len() as i64, d));
    }

    fn edit(&mut self, c: usize) {
        let path = PATHS[self.rng.below(PATHS.len())].to_string();
        if self.clients[c].disk.get(&path).map(String::as_str) == Some(DIR) {
            return; // a folder of that name is there (e.g. from an odd record): no file can be written
        }
        if is_text_path(&path) {
            // Insert one new word at a random place.
            self.next_content += 1;
            let word = format!("k{}", self.next_content - 1);
            let mut ws: Vec<String> = self.clients[c]
                .disk
                .get(&path)
                .map(|t| words(t).map(str::to_owned).collect())
                .unwrap_or_default();
            let at = self.rng.below(ws.len() + 1);
            ws.insert(at, word.clone());
            self.trace.push(format!("c{c} edit {path}: insert {word} at {at}"));
            self.touched.push((c, self.group.len() as i64, path.clone()));
            let text = ws.join(" ");
            self.texts_by_sha.insert(sha_hex(&text), text.clone());
            self.clients[c].disk.insert(path, text);
            return;
        }
        // Sometimes write content that another client also wrote (same bytes, no conflict expected).
        let content = if self.next_content > 0 && self.rng.chance(10) {
            format!("k{}", self.rng.below(self.next_content as usize))
        } else {
            self.next_content += 1;
            format!("k{}", self.next_content - 1)
        };
        self.trace.push(format!("c{c} edit {path} = {content}"));
        self.touched.push((c, self.group.len() as i64, path.clone()));
        self.clients[c].disk.insert(path, content);
    }

    fn delete(&mut self, c: usize) {
        let paths: Vec<String> = self.clients[c].disk.keys().cloned().collect();
        if paths.is_empty() {
            return;
        }
        let path = paths[self.rng.below(paths.len())].clone();
        self.trace.push(format!("c{c} delete {path}"));
        self.touched.push((c, self.group.len() as i64, path.clone()));
        self.clients[c].disk.remove(&path);
    }

    /// Upload local changes as one record (planned by `tgsync_core::sync::plan_push`). Faults:
    /// Telegram refusing the upload (flood wait); crash after posting but before marking the files
    /// synced; Telegram delivering the same upload twice.
    fn push(&mut self, c: usize) {
        let Sim { clients, rng, .. } = self;
        let v = &clients[c].vault;
        if v.replica.removed || !v.replica.has_keys() {
            return;
        }
        let disk: BTreeMap<String, LocalFile> = clients[c]
            .disk
            .iter()
            .map(|(p, content)| (p.clone(), local_file(p, content)))
            .collect();
        let (seq, plan) = v.plan_push(&disk, &mut || hex8(rng.bytes::<8>())).unwrap();
        if plan.is_empty() {
            return;
        }
        if self.faults && self.rng.chance(5) {
            self.trace.push(format!("c{c} push refused (flood wait), nothing sent"));
            return;
        }
        let resent = self.clients[c].vault.resend.len();
        let text_docs: Vec<(String, Vec<u8>)> = plan
            .entries
            .iter()
            .skip(plan.resent) // re-sent entries were counted by the push that first sent them
            .filter(|e| e["op"] == "text")
            .map(|e| {
                let (off, len) = (
                    e["blob"]["inline"][0].as_u64().unwrap() as usize,
                    e["blob"]["inline"][1].as_u64().unwrap() as usize,
                );
                (e["doc"].as_str().unwrap().to_owned(), plan.payload[off..off + len].to_vec())
            })
            .collect();
        let nonce = self.rng.bytes();
        let body = self.clients[c].vault.seal_record(seq, &plan, self.clock, &nonce).unwrap();
        let twice = self.faults && self.rng.chance(3);
        let crash = self.faults && self.rng.chance(5);
        self.trace.push(format!(
            "c{c} push seq {seq} {} entries, {resent} sent again{}{} {}",
            plan.done.len(),
            if twice { " (delivered twice)" } else { "" },
            if crash { " (crash before marking synced)" } else { "" },
            plan.entries
                .iter()
                .map(|e| format!("{}:{}", e["op"].as_str().unwrap_or("?"), e["path"].as_str().unwrap_or("?")))
                .collect::<Vec<_>>()
                .join(" ")
        ));
        self.post(KIND_RECORD, body.clone());
        if twice {
            self.post(KIND_RECORD, body);
        }
        if crash {
            return;
        }
        let msg_id = self.group.len() as i64 - i64::from(twice);
        for (doc, update) in text_docs {
            self.text_promised.push((c, msg_id, doc, update));
        }
        for (p, _) in &plan.done {
            let content = self.clients[c].disk.get(p).cloned();
            self.promised.push((c, msg_id, p.clone(), content));
        }
        self.clients[c].vault.pushed(&plan);
    }

    /// Replay the log and write the tree to disk. `lag`: the newest messages may not be visible yet.
    fn pull(&mut self, c: usize, lag: bool) -> Report {
        let cursor = self.clients[c].vault.replica.cursor as usize;
        // Telegram may not show the newest few messages yet; it never hides old ones.
        let len = self.group.len();
        let visible = if lag && self.rng.chance(30) {
            len - self.rng.below((len - cursor).min(3) + 1)
        } else {
            len
        };
        let mut rep = Report::default();
        let r = &mut self.clients[c].vault.replica;
        for _ in 0..2 {
            r.begin_pass();
            let from = r.cursor as usize;
            for (id, kind, body) in &self.group[from..visible] {
                let body = if r.wants_body(*kind, *id) { body.as_slice() } else { &[] };
                r.feed(*id, *kind, body, &mut rep);
            }
            if !(r.blocked() && r.has_keys()) {
                break;
            }
        }
        self.trace.push(format!(
            "c{c} pull to msg {} ({} applied, {} to send again)",
            r.cursor,
            rep.applied.len(),
            rep.resend.len()
        ));
        // Our records that readers skip (sealed with a replaced key): queue them to upload again.
        self.clients[c].vault.pulled(&rep);
        self.materialize(c);
        rep
    }

    /// Write the tree to disk as the vault plans it.
    fn materialize(&mut self, c: usize) {
        let texts = &self.texts_by_sha;
        let cl = &mut self.clients[c];
        let disk: BTreeMap<String, String> = cl
            .disk
            .iter()
            .map(|(p, content)| (p.clone(), base_of(p, Some(content)).unwrap()))
            .collect();
        let (ops, synced) = cl.vault.plan_materialize(&disk);
        for op in ops {
            match op {
                DiskOp::Write { path, text: Some(t), .. } => cl.disk.insert(path, t),
                // v1: a note came as a plain put; its text is known by its sha.
                DiskOp::Write { path, sha, .. } if is_text_path(&path) => cl.disk.insert(path, texts.get(&sha).cloned().unwrap_or(sha)),
                DiskOp::Write { path, sha, .. } => cl.disk.insert(path, sha),
                DiskOp::Delete { path } => cl.disk.remove(&path),
                DiskOp::Mkdir { path } => cl.disk.insert(path, DIR.into()),
                DiskOp::Rmdir { path } => cl.disk.remove(&path),
            };
        }
        cl.vault.materialized(synced);
    }

    /// Everyone pushes and pulls until nothing moves, then check the invariants.
    pub fn settle_and_check(&mut self) -> Result<Stats, String> {
        self.trace.push("-- settle".into());
        self.faults = false;
        for k in 1..self.clients.len() {
            self.pull(0, false);
            self.pull(k, false); // learn whether we were removed
            let recipient = self.clients[k].vault.replica.me.recipient.clone();
            if !self.clients[0].vault.replica.members.iter().any(|m| m.recipient == recipient) {
                self.churn_add(k);
            } else if self.clients[k].vault.replica.removed {
                // Saw its removal but was added back since: the user runs `tgsync join` again.
                let me = self.clients[k].vault.replica.me.clone();
                self.clients[k].vault.replica = Replica::new(me, None);
                self.clients[k].vault.synced.clear();
                self.trace.push(format!("c{k} joins again"));
            }
        }
        for round in 0.. {
            let before = self.group.len();
            for c in 0..self.clients.len() {
                self.pull(c, false);
                self.push(c);
            }
            for c in 0..self.clients.len() {
                self.pull(c, false);
            }
            if self.group.len() == before {
                break;
            }
            if round > 20 {
                let mut why = vec![];
                for (i, cl) in self.clients.iter().enumerate() {
                    for (p, c) in &cl.disk {
                        let (sy, tr) = (cl.vault.synced.get(p), cl.vault.replica.tree.get(p).map(|n| &n.sha));
                        if base_of(p, Some(c)).as_ref() != sy {
                            why.push(format!("c{i} {p}: disk {c:?} synced {sy:?} tree {tr:?}"));
                        }
                    }
                }
                return Err(format!("clients never settle (they keep uploading):\n  {}", why.join("\n  ")));
            }
        }
        for (i, cl) in self.clients.iter().enumerate() {
            let back =
                Replica::load(cl.vault.replica.me.clone(), &cl.vault.replica.save()).map_err(|e| format!("c{i}: load failed: {e}"))?;
            let (a, b): (serde_json::Value, serde_json::Value) = (
                serde_json::from_slice(&cl.vault.replica.save()).unwrap(),
                serde_json::from_slice(&back.save()).unwrap(),
            );
            // Loro snapshot bytes are not stable when re-exported: compare notes by content instead.
            let differs: Vec<&String> = a.as_object().unwrap().keys().filter(|k| *k != "texts" && a[*k] != b[*k]).collect();
            if !differs.is_empty()
                || back.texts != cl.vault.replica.texts
                || back.keys != cl.vault.replica.keys
                || back.members != cl.vault.replica.members
            {
                return Err(format!("c{i}: saving and loading the replica changes {differs:?}"));
            }
        }
        let first = &self.clients[0].vault.replica.tree;
        for (i, cl) in self.clients.iter().enumerate() {
            if cl.vault.replica.tree != *first {
                let (a, b) = (&first.nodes, &cl.vault.replica.tree.nodes);
                let diff: Vec<String> = a
                    .keys()
                    .chain(b.keys())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .filter(|p| a.get(*p).map(|n| (&n.sha, n.msg_id)) != b.get(*p).map(|n| (&n.sha, n.msg_id)))
                    .map(|p| {
                        format!(
                            "{p}: c0 {:?} / c{i} {:?}",
                            a.get(p).map(|n| (&n.sha, n.msg_id)),
                            b.get(p).map(|n| (&n.sha, n.msg_id))
                        )
                    })
                    .collect();
                return Err(format!(
                    "c{i}'s tree differs from c0's (c{i} cursor {}, removed {}):\n  {}",
                    cl.vault.replica.cursor,
                    cl.vault.replica.removed,
                    diff.join("\n  ")
                ));
            }
            // v1 notes are plain puts: compare their text, known by sha.
            let tree: BTreeMap<String, String> = contents(&cl.vault.replica)
                .into_iter()
                .map(|(p, c)| {
                    let t = if is_text_path(&p) {
                        self.texts_by_sha.get(&c).cloned().unwrap_or(c)
                    } else {
                        c
                    };
                    (p, t)
                })
                .collect();
            let docs = |r: &Replica| r.texts.doc_ids().map(|d| (d.clone(), r.texts.text(d))).collect::<Vec<_>>();
            if docs(&cl.vault.replica) != docs(&self.clients[0].vault.replica) {
                return Err(format!("c{i}'s text notes differ from c0's"));
            }
            if cl.disk != tree {
                return Err(format!("c{i}'s disk differs from the tree:\n disk {:?}\n tree {:?}", cl.disk, tree));
            }
        }
        self.check_nothing_lost()
    }

    fn check_nothing_lost(&self) -> Result<Stats, String> {
        let mut stats = Stats {
            messages: self.group.len(),
            ..Default::default()
        };
        let in_tree: BTreeSet<&str> = self.clients[0].vault.replica.tree.nodes.values().map(|n| n.sha.as_str()).collect();
        // Replay once more, collecting every delivered (non-duplicate) entry.
        let mut r = Replica::new(self.clients[0].vault.replica.me.clone(), None);
        let mut rep = Report::default();
        let mut puts: Vec<(String, String)> = vec![];
        let mut bases: BTreeSet<(String, String)> = BTreeSet::new();
        for (id, kind, body) in &self.group {
            let before = r.authors.clone();
            r.feed(*id, *kind, body, &mut rep);
            // Applied = new seq and no problem other than a gap note for this message.
            // (Problems about single entries, e.g. a bad note update, do not reject the record.)
            let whole_record = |why: &str| {
                [
                    "unreadable record",
                    "replayed/duplicate",
                    "unsigned record",
                    "record not signed",
                    "record sealed with a key",
                ]
                .iter()
                .any(|p| why.starts_with(p))
            };
            let rejected = rep
                .problems
                .iter()
                .rev()
                .take_while(|(at, _)| at == id)
                .any(|(_, why)| whole_record(why));
            if *kind == KIND_RECORD && r.authors != before && !rejected && !self.odd.contains(id) {
                let rec = tgsync_core::oplog::decode_record(&r.keys, body).unwrap();
                for e in &rec.entries {
                    let Some(path) = e["path"].as_str().map(str::to_string) else {
                        continue;
                    }; // odd entries
                    if let Some(b) = e["base"].as_str() {
                        bases.insert((path.clone(), b.to_string()));
                    }
                    // Only puts replay can accept (odd ones may come back through a re-send).
                    let valid = e["size"].as_f64().is_some_and(|n| n >= 0.0) && e["sha"] != "dir" && e["blob"].is_object();
                    if let (true, true, Some(sha)) = (e["op"] == "put", valid, e["sha"].as_str()) {
                        puts.push((path, sha.to_string()));
                    }
                }
            }
        }
        stats.problems = rep.problems.len();
        stats.stale_epoch = rep.problems.iter().filter(|(_, why)| why.contains("already replaced")).count();
        stats.conflicts = rep
            .applied
            .iter()
            .filter(|a| matches!(a.4, tgsync_core::tree::Applied::Conflict(..)))
            .count();
        for (path, sha) in puts {
            // Knowingly replaced: someone later wrote this path with base = this content.
            // (A conflict copy's later edits use the copy's path, so also accept any path.)
            let replaced = bases.iter().any(|(_, b)| *b == sha);
            if !in_tree.contains(sha.as_str()) && !replaced {
                return Err(format!("edit lost: {path} = {sha} is nowhere in the tree and nobody replaced it"));
            }
        }
        // Every upload a client marked as done, while it was a member, must survive the same way
        // (this catches records that readers rejected, e.g. sealed with a replaced key, and never re-sent).
        for (c, msg_id, path, sha) in &self.promised {
            let Some(sha) = sha.as_ref().filter(|s| *s != DIR) else { continue };
            if is_text_path(path) && !self.v1 {
                continue; // checked below (notes merge in v2)
            }
            let me = self.clients[*c].vault.replica.me.id();
            let member = r.snapshot_at(*msg_id).is_some_and(|s| s.members.iter().any(|m| m.id() == me));
            // The same person changed or deleted this path on their own disk afterwards.
            let superseded = self.touched.iter().any(|(c2, m2, p2)| c2 == c && m2 >= msg_id && p2 == path);
            // (v1 notes: the tree and bases hold the sha of the text.)
            let id = if is_text_path(path) { sha_hex(sha) } else { sha.clone() };
            if member && !superseded && !in_tree.contains(id.as_str()) && !bases.iter().any(|(_, b)| *b == id) {
                let cl = &self.clients[*c];
                let puts_of_it: Vec<String> = self
                    .promised
                    .iter()
                    .filter(|p| p.0 == *c && p.2 == *path)
                    .map(|p| format!("msg {} {:?}", p.1, p.3))
                    .collect();
                return Err(format!(
                    "upload lost: c{c} marked {path} = {sha} (msg {msg_id}) as uploaded; it is gone. \
                    c{c} disk {:?}, synced {:?}, tree {:?}; c{c}'s uploads of {path}: {puts_of_it:?}",
                    cl.disk.get(path),
                    cl.vault.synced.get(path),
                    cl.vault.replica.tree.get(path).map(|n| &n.sha)
                ));
            }
        }
        // Text: every note edit a member uploaded is merged into its doc (all its Loro operations
        // are in the final doc). Edits re-sent after an old-key rejection count from the re-send.
        for (c, msg_id, doc, update) in &self.text_promised {
            let me = self.clients[*c].vault.replica.me.id();
            let member = r.snapshot_at(*msg_id).is_some_and(|s| s.members.iter().any(|m| m.id() == me));
            if member && !self.clients[0].vault.replica.texts.contains(doc, update) {
                return Err(format!(
                    "note edit lost: c{c}'s upload to doc {doc} (msg {msg_id}) is not in the final doc {:?}",
                    self.clients[0].vault.replica.texts.text(doc)
                ));
            }
        }
        Ok(stats)
    }
}

/// Run one seed. On failure the error holds the full action trace.
pub fn run(seed: u64, steps: usize) -> Result<Stats, String> {
    // Every fifth seed is an old (v1) vault.
    let mut sim = Sim::with_version(seed, 2 + (seed % 3) as usize, seed % 5 == 4);
    for _ in 0..steps {
        sim.step();
    }
    sim.settle_and_check()
        .map_err(|e| format!("seed {seed}: {e}\ntrace:\n  {}", sim.trace.join("\n  ")))
}

fn hex8(b: [u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn seeds_converge() {
        // Quick smoke run; `make sim` runs 10000 seeds in release mode.
        for seed in 0..40 {
            if let Err(e) = super::run(seed, 150) {
                panic!("{e}");
            }
        }
    }

    #[test]
    fn runs_cover_folders_and_big_files() {
        let mut sim = super::Sim::new(3, 3);
        for _ in 0..300 {
            sim.step();
        }
        sim.settle_and_check().unwrap();
        let t = sim.trace.join("\n");
        assert!(t.contains("makes folder") && t.contains("removes folder"), "no folder actions");
        assert!(t.contains("video.bin"), "no big-file actions");
        let tree = &sim.clients[0].vault.replica.tree;
        assert!(
            tree.nodes.values().any(|n| n.blob.get("chunks").is_some_and(|c| c.is_array())),
            "no big file in the tree"
        );
    }

    #[test]
    fn v1_vaults_run_the_v1_way() {
        let mut sim = super::Sim::with_version(4, 3, true);
        for _ in 0..300 {
            sim.step();
        }
        sim.settle_and_check().unwrap();
        let r = &sim.clients[0].vault.replica;
        assert!(r.admins.is_none(), "no admins in a v1 vault");
        assert_eq!(r.texts.doc_ids().count(), 0, "no merged notes in a v1 vault");
        assert!(
            r.tree.nodes.values().any(|n| n.path.ends_with(".md") && n.doc.is_none()),
            "notes are plain files"
        );
    }

    #[test]
    fn same_seed_same_run() {
        let trace = |seed| {
            let mut sim = super::Sim::new(seed, 3);
            for _ in 0..100 {
                sim.step();
            }
            sim.settle_and_check().unwrap();
            sim.trace.join("\n")
        };
        assert_eq!(trace(7), trace(7));
    }
}
