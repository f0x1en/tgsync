// SPDX-License-Identifier: AGPL-3.0-or-later
//! Everything one folder needs between runs: the replica, what was last synced, edits to re-send,
//! and the last record seq we posted. Sans-IO; a host (Node CLI, Obsidian plugin, simulator) does
//! the reading and writing around it.
//!
//! Push: `plan_push` -> `seal_record` (sets the seq first, write-ahead) -> post -> `pushed`.
//! Pull: `replica` begin_pass / wants_body / feed, then `pulled`; then `plan_materialize` -> write
//! files -> `materialized`.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::crypto::NONCE_LEN;
use crate::descriptor::Identity;
use crate::oplog::{encode_record, Record};
use crate::replica::{Replica, Report, Resend};
use crate::sync::{plan_materialize, plan_push, DiskOp, LocalFile, Push};
use crate::{Error, Result};

#[derive(Debug)]
pub struct Vault {
    pub replica: Replica,
    /// path -> sha at the last sync (`base` of the next change).
    pub synced: BTreeMap<String, String>,
    /// Our entries readers rejected (sealed with a replaced key), to send with the next push.
    pub resend: Vec<Resend>,
    /// Last record seq we posted (saved before posting, so a crash never reuses a seq).
    pub sent_seq: u64,
}

impl Vault {
    pub fn new(me: Identity, vault_id: Option<String>) -> Self {
        Vault { replica: Replica::new(me, vault_id), synced: BTreeMap::new(), resend: vec![], sent_seq: 0 }
    }

    pub fn next_seq(&self) -> u64 {
        self.sent_seq.max(self.replica.next_seq() - 1) + 1
    }

    /// Plan the next record. Empty if nothing changed and nothing waits to be re-sent.
    pub fn plan_push(&self, disk: &BTreeMap<String, LocalFile>, new_doc: &mut dyn FnMut() -> String) -> Result<(u64, Push)> {
        if self.replica.removed || !self.replica.has_keys() {
            return Err(Error::Crypto("not a member of this vault (no keys)".into()));
        }
        let seq = self.next_seq();
        Ok((seq, plan_push(&self.replica, disk, &self.synced, &self.resend, seq, new_doc)?))
    }

    /// Seal the planned record. Records `seq` as used and drops the re-send queue (it is in this
    /// record): save the vault before posting.
    pub fn seal_record(&mut self, seq: u64, push: &Push, ts: f64, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
        let me = &self.replica.me;
        let rec = Record { author: me.id(), seq, ts, entries: push.entries.clone(), payload: push.payload.clone(), signer: None };
        let body = encode_record(&self.replica.keys, &rec, nonce, me.signing.as_ref())?;
        self.sent_seq = seq;
        self.resend.clear();
        Ok(body)
    }

    /// The record is posted: its files count as synced.
    pub fn pushed(&mut self, push: &Push) {
        for (p, sha) in &push.done {
            match sha {
                Some(s) => self.synced.insert(p.clone(), s.clone()),
                None => self.synced.remove(p),
            };
        }
    }

    /// After a pull: queue our rejected entries for re-sending.
    pub fn pulled(&mut self, rep: &Report) {
        self.resend.extend(rep.resend.iter().cloned());
    }

    /// `disk`: path -> sha of what is in the folder now.
    pub fn plan_materialize(&self, disk: &BTreeMap<String, String>) -> (Vec<DiskOp>, BTreeMap<String, String>) {
        plan_materialize(&self.replica, disk, &self.synced)
    }

    /// The ops are done: store the new synced map.
    pub fn materialized(&mut self, synced: BTreeMap<String, String>) {
        if self.replica.has_keys() {
            self.replica.active = true;
        }
        self.synced = synced;
    }

    pub fn save(&self) -> Vec<u8> {
        use base64::Engine;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let replica: Value = serde_json::from_slice(&self.replica.save()).unwrap();
        let resend: Vec<Value> = self.resend.iter().map(|r| json!([r.entry, b64(&r.bytes)])).collect();
        serde_json::to_vec(&json!({"v": 1, "replica": replica, "synced": self.synced, "resend": resend, "sent_seq": self.sent_seq})).unwrap()
    }

    pub fn load(me: Identity, data: &[u8]) -> Result<Vault> {
        use base64::Engine;
        let bad = || Error::Crypto("bad saved vault state".into());
        let v: Value = serde_json::from_slice(data).map_err(|_| bad())?;
        let replica = Replica::load(me, &serde_json::to_vec(&v["replica"]).unwrap())?;
        let synced = v["synced"].as_object().ok_or_else(bad)?.iter().map(|(k, s)| (k.clone(), s.as_str().unwrap_or("").to_owned())).collect();
        let mut resend = vec![];
        for r in v["resend"].as_array().ok_or_else(bad)? {
            let bytes = r[1].as_str().and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok()).ok_or_else(bad)?;
            resend.push(Resend { entry: r[0].clone(), bytes });
        }
        Ok(Vault { replica, synced, resend, sent_seq: v["sent_seq"].as_u64().ok_or_else(bad)? })
    }
}
