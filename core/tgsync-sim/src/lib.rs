// SPDX-License-Identifier: AGPL-3.0-or-later
//! Deterministic simulation: N clients share one fake Telegram group. A seed picks every action
//! and fault, so a failing seed replays exactly. Checks after the clients settle:
//! 1. every replica holds the same tree;
//! 2. every client's disk equals the tree;
//! 3. no delivered edit is silently lost: each put's content is still in the tree, or a later
//!    entry named it as `base` (its author saw it and replaced or deleted it on purpose).

use std::collections::{BTreeMap, BTreeSet};

use age::secrecy::ExposeSecret;
use serde_json::json;
use tgsync_core::crypto::KeyRing;
use tgsync_core::descriptor::{self, Identity, Member};
use tgsync_core::oplog::{encode_record, Record};
use tgsync_core::replica::{Replica, Report, KIND_DESCRIPTOR, KIND_RECORD};
use tgsync_core::tree::DIR;

/// splitmix64: tiny, fast, good enough to drive a simulation.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.next() as u8;
        }
        out
    }
}

/// Paths the clients fight over: case clashes, folders, names that need conflict copies.
const PATHS: &[&str] = &["a.md", "A.md", "b.md", "notes/x.md", "notes/X.md", "notes/y.md", "img.png"];

struct Client {
    replica: Replica,
    /// path -> content id. Content ids stand in for file bytes (the tree stores them as `sha`).
    disk: BTreeMap<String, String>,
    /// path -> content id at the last sync (what `base` is taken from).
    synced: BTreeMap<String, String>,
    /// Last seq we posted, saved before posting (write-ahead), so a crash never reuses a seq.
    sent_seq: u64,
    /// Entries of our records that readers rejected (old key): uploaded again, same content and base,
    /// with the next push. The content comes from the old record, not from disk.
    resend: Vec<serde_json::Value>,
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

fn member(p: &Identity, name: &str) -> Member {
    Member { signer: p.signer(), ..Member::new(&p.recipient, name) }
}

/// A v2 descriptor signed by the admin c0.
fn admin_descriptor(rng: &mut Rng, admin: &Identity, ring: &KeyRing, members: &[Member], proof_epoch: Option<u32>) -> Vec<u8> {
    let admins = [admin.signer().unwrap()];
    let signing = descriptor::Signing { admins: &admins, key: admin.signing.as_ref().unwrap() };
    descriptor::build(ring, "5eed5eed5eed5eed", members, proof_epoch, 0, Some(signing), &mut || rng.bytes()).unwrap()
}

impl Sim {
    pub fn new(seed: u64, n_clients: usize) -> Self {
        let mut rng = Rng::new(seed);
        let mut ring = KeyRing::new();
        ring.add(1, &rng.bytes::<32>()).unwrap();
        let people: Vec<Identity> = (0..n_clients).map(|_| person(&mut rng)).collect();
        let members: Vec<Member> =
            people.iter().enumerate().map(|(i, p)| member(p, &format!("c{i}"))).collect();
        let desc = admin_descriptor(&mut rng, &people[0], &ring, &members, None);
        let clients = people
            .into_iter()
            .map(|p| Client { replica: Replica::new(p, None), disk: BTreeMap::new(), synced: BTreeMap::new(), sent_seq: 0, resend: vec![] })
            .collect();
        Sim { rng, trace: vec![], group: vec![(1, KIND_DESCRIPTOR, desc)], clients, next_content: 0, clock: 1_762_850_000.0, faults: true, promised: vec![], touched: vec![] }
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
        match self.rng.below(10) {
            0..=3 => self.edit(c),
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
        let target = self.clients[k].replica.me.recipient.clone();
        let admin = &self.clients[0].replica;
        let mut ring = admin.keys.clone();
        let mut members = admin.members.clone();
        let proof_epoch = if members.iter().any(|m| m.recipient == target) {
            members.retain(|m| m.recipient != target);
            let old = ring.current_epoch().unwrap();
            ring.add(old + 1, &self.rng.bytes::<32>()).unwrap();
            self.trace.push(format!("c0 removes c{k} (epoch {})", old + 1));
            Some(old)
        } else {
            let me = self.clients[k].replica.me.clone();
            members.push(member(&me, &format!("c{k}")));
            self.clients[k].replica = Replica::new(me, None);
            self.clients[k].synced.clear();
            self.trace.push(format!("c0 adds c{k} back"));
            None
        };
        let admin = self.clients[0].replica.me.clone();
        let desc = admin_descriptor(&mut self.rng, &admin, &ring, &members, proof_epoch);
        self.post(KIND_DESCRIPTOR, desc);
    }

    fn churn_add(&mut self, k: usize) {
        let admin = &self.clients[0].replica;
        let (ring, mut members) = (admin.keys.clone(), admin.members.clone());
        let me = self.clients[k].replica.me.clone();
        members.push(member(&me, &format!("c{k}")));
        self.clients[k].replica = Replica::new(me, None);
        self.clients[k].synced.clear();
        self.trace.push(format!("c0 adds c{k} back"));
        let admin = self.clients[0].replica.me.clone();
        let desc = admin_descriptor(&mut self.rng, &admin, &ring, &members, None);
        self.post(KIND_DESCRIPTOR, desc);
    }

    fn edit(&mut self, c: usize) {
        let path = PATHS[self.rng.below(PATHS.len())].to_string();
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

    /// Upload local changes as one record. Faults: Telegram refusing the upload (flood wait); crash after posting but before marking the files
    /// synced; Telegram delivering the same upload twice.
    fn push(&mut self, c: usize) {
        let cl = &self.clients[c];
        if cl.replica.removed || !cl.replica.has_keys() {
            return;
        }
        let mut entries = cl.resend.clone();
        let mut done = vec![];
        let paths: BTreeSet<&String> = cl.disk.keys().chain(cl.synced.keys()).collect();
        for p in paths {
            let (now, then) = (cl.disk.get(p), cl.synced.get(p));
            if now == then {
                continue;
            }
            match now {
                Some(sha) => entries.push(json!({"op": "put", "path": p, "sha": sha, "size": 1, "mtime": self.clock,
                    "base": then, "blob": {"file_id": "0000000000000000", "chunks": null, "inline": [0, 0]}})),
                None => entries.push(json!({"op": "delete", "path": p, "base": then})),
            }
            done.push((p.clone(), now.cloned()));
        }
        if entries.is_empty() {
            return;
        }
        if self.faults && self.rng.chance(5) {
            self.trace.push(format!("c{c} push refused (flood wait), nothing sent"));
            return;
        }
        let resent = std::mem::take(&mut self.clients[c].resend).len();
        let cl = &self.clients[c];
        let seq = cl.sent_seq.max(cl.replica.next_seq() - 1) + 1;
        self.clients[c].sent_seq = seq;
        let me = &self.clients[c].replica.me;
        let rec = Record { author: me.id(), seq, ts: self.clock, entries, payload: vec![], signer: None };
        let body = encode_record(&self.clients[c].replica.keys, &rec, &self.rng.bytes(), me.signing.as_ref()).unwrap();
        let twice = self.faults && self.rng.chance(3);
        let crash = self.faults && self.rng.chance(5);
        self.trace.push(format!("c{c} push seq {seq} {} entries, {resent} sent again{}{}", done.len(),
            if twice { " (delivered twice)" } else { "" }, if crash { " (crash before marking synced)" } else { "" }));
        self.post(KIND_RECORD, body.clone());
        if twice {
            self.post(KIND_RECORD, body);
        }
        if crash {
            return;
        }
        let msg_id = self.group.len() as i64 - i64::from(twice);
        for (p, sha) in done {
            self.promised.push((c, msg_id, p.clone(), sha.clone()));
            match sha {
                Some(s) => self.clients[c].synced.insert(p, s),
                None => self.clients[c].synced.remove(&p),
            };
        }
    }

    /// Replay the log and write the tree to disk. `lag`: the newest messages may not be visible yet.
    fn pull(&mut self, c: usize, lag: bool) -> Report {
        let cursor = self.clients[c].replica.cursor as usize;
        // Telegram may not show the newest few messages yet; it never hides old ones.
        let len = self.group.len();
        let visible = if lag && self.rng.chance(30) { len - self.rng.below((len - cursor).min(3) + 1) } else { len };
        let mut rep = Report::default();
        let r = &mut self.clients[c].replica;
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
        self.trace.push(format!("c{c} pull to msg {} ({} applied, {} to send again)", r.cursor, rep.applied.len(), rep.resend.len()));
        // Our records that readers skip (sealed with a replaced key): queue them to upload again.
        self.clients[c].resend.extend(rep.resend.iter().cloned());
        self.materialize(c);
        rep
    }

    /// PROTOCOL.md section 9 "Materialize": write what changed, never clobber unpushed local edits.
    fn materialize(&mut self, c: usize) {
        let cl = &mut self.clients[c];
        if cl.replica.has_keys() {
            cl.replica.active = true;
        }
        let tree: BTreeMap<String, String> =
            cl.replica.tree.nodes.values().filter(|n| n.sha != DIR).map(|n| (n.path.clone(), n.sha.clone())).collect();
        for (p, sha) in &tree {
            let local = cl.disk.get(p);
            if local == Some(sha) {
                cl.synced.insert(p.clone(), sha.clone());
            } else if local == cl.synced.get(p) {
                cl.disk.insert(p.clone(), sha.clone());
                cl.synced.insert(p.clone(), sha.clone());
            }
        }
        let gone: Vec<String> = cl.synced.keys().filter(|p| !tree.contains_key(*p)).cloned().collect();
        for p in gone {
            if cl.disk.get(&p) == cl.synced.get(&p) {
                cl.disk.remove(&p);
            }
            cl.synced.remove(&p);
        }
    }

    /// Everyone pushes and pulls until nothing moves, then check the invariants.
    pub fn settle_and_check(&mut self) -> Result<Stats, String> {
        self.trace.push("-- settle".into());
        self.faults = false;
        for k in 1..self.clients.len() {
            self.pull(0, false);
            self.pull(k, false); // learn whether we were removed
            let recipient = self.clients[k].replica.me.recipient.clone();
            if !self.clients[0].replica.members.iter().any(|m| m.recipient == recipient) {
                self.churn_add(k);
            } else if self.clients[k].replica.removed {
                // Saw its removal but was added back since: the user runs `tgsync join` again.
                let me = self.clients[k].replica.me.clone();
                self.clients[k].replica = Replica::new(me, None);
                self.clients[k].synced.clear();
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
                return Err("clients never settle (they keep uploading)".into());
            }
        }
        let first = &self.clients[0].replica.tree;
        for (i, cl) in self.clients.iter().enumerate() {
            if cl.replica.tree != *first {
                let (a, b) = (&first.nodes, &cl.replica.tree.nodes);
                let diff: Vec<String> = a.keys().chain(b.keys()).collect::<BTreeSet<_>>().into_iter()
                    .filter(|p| a.get(*p).map(|n| (&n.sha, n.msg_id)) != b.get(*p).map(|n| (&n.sha, n.msg_id)))
                    .map(|p| format!("{p}: c0 {:?} / c{i} {:?}", a.get(p).map(|n| (&n.sha, n.msg_id)), b.get(p).map(|n| (&n.sha, n.msg_id))))
                    .collect();
                return Err(format!("c{i}'s tree differs from c0's (c{i} cursor {}, removed {}):\n  {}",
                    cl.replica.cursor, cl.replica.removed, diff.join("\n  ")));
            }
            let tree: BTreeMap<String, String> =
                cl.replica.tree.nodes.values().filter(|n| n.sha != DIR).map(|n| (n.path.clone(), n.sha.clone())).collect();
            if cl.disk != tree {
                return Err(format!("c{i}'s disk differs from the tree:\n disk {:?}\n tree {:?}", cl.disk, tree));
            }
        }
        self.check_nothing_lost()
    }

    fn check_nothing_lost(&self) -> Result<Stats, String> {
        let mut stats = Stats { messages: self.group.len(), ..Default::default() };
        let in_tree: BTreeSet<&str> = self.clients[0].replica.tree.nodes.values().map(|n| n.sha.as_str()).collect();
        // Replay once more, collecting every delivered (non-duplicate) entry.
        let mut r = Replica::new(self.clients[0].replica.me.clone(), None);
        let mut rep = Report::default();
        let mut puts: Vec<(String, String)> = vec![];
        let mut bases: BTreeSet<(String, String)> = BTreeSet::new();
        for (id, kind, body) in &self.group {
            let before = r.authors.clone();
            r.feed(*id, *kind, body, &mut rep);
            // Applied = new seq and no problem other than a gap note for this message.
            let rejected = rep.problems.last().is_some_and(|(at, why)| at == id && !why.starts_with("gap"));
            if *kind == KIND_RECORD && r.authors != before && !rejected {
                let rec = tgsync_core::oplog::decode_record(&r.keys, body).unwrap();
                for e in &rec.entries {
                    let path = e["path"].as_str().unwrap().to_string();
                    if let Some(b) = e["base"].as_str() {
                        bases.insert((path.clone(), b.to_string()));
                    }
                    if e["op"] == "put" {
                        puts.push((path, e["sha"].as_str().unwrap().to_string()));
                    }
                }
            }
        }
        stats.problems = rep.problems.len();
        stats.stale_epoch = rep.problems.iter().filter(|(_, why)| why.contains("already replaced")).count();
        stats.conflicts = rep.applied.iter().filter(|a| matches!(a.4, tgsync_core::tree::Applied::Conflict(..))).count();
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
            let Some(sha) = sha else { continue };
            let me = self.clients[*c].replica.me.id();
            let member = r.snapshot_at(*msg_id).is_some_and(|s| s.members.iter().any(|m| m.id() == me));
            // The same person changed or deleted this path on their own disk afterwards.
            let superseded = self.touched.iter().any(|(c2, m2, p2)| c2 == c && m2 >= msg_id && p2 == path);
            if member && !superseded && !in_tree.contains(sha.as_str()) && !bases.iter().any(|(_, b)| b == sha) {
                let cl = &self.clients[*c];
                let puts_of_it: Vec<String> = self.promised.iter().filter(|p| p.0 == *c && p.2 == *path).map(|p| format!("msg {} {:?}", p.1, p.3)).collect();
                return Err(format!("upload lost: c{c} marked {path} = {sha} (msg {msg_id}) as uploaded; it is gone. \
                    c{c} disk {:?}, synced {:?}, tree {:?}; c{c}'s uploads of {path}: {puts_of_it:?}",
                    cl.disk.get(path), cl.synced.get(path), cl.replica.tree.get(path).map(|n| &n.sha)));
            }
        }
        Ok(stats)
    }
}

/// Run one seed. On failure the error holds the full action trace.
pub fn run(seed: u64, steps: usize) -> Result<Stats, String> {
    let mut sim = Sim::new(seed, 2 + (seed % 3) as usize);
    for _ in 0..steps {
        sim.step();
    }
    sim.settle_and_check().map_err(|e| format!("seed {seed}: {e}\ntrace:\n  {}", sim.trace.join("\n  ")))
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
