// SPDX-License-Identifier: AGPL-3.0-or-later
//! Member operations (tgsync_core::members) end to end through replicas.

use age::secrecy::ExposeSecret;
use tgsync_core::descriptor::Identity;
use tgsync_core::members;
use tgsync_core::replica::{Replica, Report};

fn person(k: u8) -> Identity {
    let id = age::x25519::Identity::generate();
    let mut p = Identity::new(id.to_string().expose_secret(), &id.to_public().to_string());
    p.signing = Some([k; 32]);
    p
}

struct Group(Vec<(i64, char, Vec<u8>)>, u8);

impl Group {
    fn post(&mut self, d: Vec<u8>) {
        let id = self.0.len() as i64 + 1;
        self.0.push((id, 'd', d));
    }
    fn n(&mut self) -> impl FnMut() -> [u8; 12] + '_ {
        move || {
            self.1 = self.1.wrapping_add(1);
            [self.1; 12]
        }
    }
    fn pull(&self, r: &mut Replica) -> Report {
        let mut rep = Report::default();
        r.begin_pass();
        let cursor = r.cursor;
        for (id, kind, body) in self.0.iter().filter(|m| m.0 > cursor) {
            r.feed(*id, *kind, body, &mut rep);
        }
        rep
    }
}

#[test]
fn create_add_give_drop_remove() {
    let (a, b, c) = (person(1), person(2), person(3));
    let mut g = Group(vec![], 0);
    let d = members::create(&a, "alice", "00112233aabbccdd", &[5; 32], 1, &mut g.n()).unwrap();
    g.post(d);
    let mut ra = Replica::new(a.clone(), None);
    g.pull(&mut ra);
    assert_eq!(ra.admins, Some(vec![a.signer().unwrap()]));

    let d = members::add(&ra, &b.recipient, "bob", b.signer().as_deref(), 2, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    let mut rb = Replica::new(b.clone(), None);
    g.pull(&mut rb);
    assert_eq!(rb.members.len(), 2);
    assert!(members::add(&rb, &c.recipient, "carol", None, 3, &mut g.n())
        .unwrap_err()
        .to_string()
        .contains("only an admin"));
    assert!(members::drop_admin(&ra, 3, &mut g.n())
        .unwrap_err()
        .to_string()
        .contains("last admin"));

    let d = members::give_owner(&ra, "bob", 3, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    g.pull(&mut rb);
    let d = members::drop_admin(&ra, 4, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    g.pull(&mut rb);
    assert_eq!(rb.admins, Some(vec![b.signer().unwrap()]));

    // bob (now the only admin and owner) removes alice: new key, alice is out.
    assert!(members::remove(&rb, "bob", &[6; 32], 5, &mut g.n())
        .unwrap_err()
        .to_string()
        .contains("last admin"));
    let d = members::remove(&rb, "alice", &[6; 32], 5, &mut g.n()).unwrap();
    g.post(d);
    let rep = g.pull(&mut ra);
    assert!(rep.problems.is_empty(), "{:?}", rep.problems);
    g.pull(&mut rb);
    assert_eq!(rb.members.len(), 1);
    assert!(rb.keys.has(2) && !ra.keys.has(2));
}

#[test]
fn ambiguous_names_are_refused() {
    let (a, b, c) = (person(1), person(2), person(3));
    let mut g = Group(vec![], 0);
    let d = members::create(&a, "alice", "00112233aabbccdd", &[5; 32], 1, &mut g.n()).unwrap();
    g.post(d);
    let mut ra = Replica::new(a.clone(), None);
    g.pull(&mut ra);
    for p in [&b, &c] {
        let d = members::add(&ra, &p.recipient, "phone", p.signer().as_deref(), 2, &mut g.n()).unwrap();
        g.post(d);
        g.pull(&mut ra);
    }
    let e = members::remove(&ra, "phone", &[6; 32], 3, &mut g.n()).unwrap_err().to_string();
    assert!(e.contains("several members match"), "{e}");
    assert!(members::remove(&ra, &b.id(), &[6; 32], 3, &mut g.n()).is_ok());
}

#[test]
fn vault_keeps_resends_until_posted_and_never_writes_unsigned_records() {
    use tgsync_core::replica::Resend;
    use tgsync_core::vault::Vault;
    let a = person(1);
    let mut g = Group(vec![], 0);
    let d = members::create(&a, "alice", "00112233aabbccdd", &[5; 32], 1, &mut g.n()).unwrap();
    g.post(d);
    let mut v = Vault::new(a.clone(), None);
    g.pull(&mut v.replica);
    v.resend.push(Resend {
        entry: serde_json::json!({"op": "mkdir", "path": "x"}),
        bytes: vec![],
    });
    let (seq, plan) = v.plan_push(&Default::default(), &mut || "0000000000000000".into()).unwrap();
    assert_eq!(plan.resent, 1);
    v.seal_record(seq, &plan, 1.0, &[1; 12]).unwrap();
    assert_eq!(v.resend.len(), 1, "kept until the record is posted");
    v.pushed(&plan);
    assert!(v.resend.is_empty());
    // An identity without a signing key cannot write in this (v2) vault.
    v.replica.me.signing = None;
    v.resend.push(Resend {
        entry: serde_json::json!({"op": "mkdir", "path": "y"}),
        bytes: vec![],
    });
    let (seq, plan) = v.plan_push(&Default::default(), &mut || "0000000000000000".into()).unwrap();
    assert!(v.seal_record(seq, &plan, 1.0, &[1; 12]).is_err());
}

#[test]
fn a_join_request_cannot_borrow_someone_elses_signing_key() {
    let (a, b) = (person(1), person(2));
    let mut g = Group(vec![], 0);
    let d = members::create(&a, "alice", "00112233aabbccdd", &[5; 32], 1, &mut g.n()).unwrap();
    g.post(d);
    let mut ra = Replica::new(a.clone(), None);
    g.pull(&mut ra);
    // bob's request claims alice's (the admin's) signer: refused.
    let e = members::add(&ra, &b.recipient, "bob", a.signer().as_deref(), 2, &mut g.n())
        .unwrap_err()
        .to_string();
    assert!(e.contains("another member's signing key"), "{e}");
    // A key that is not an Ed25519 public key: refused.
    let e = members::add(&ra, &b.recipient, "bob", Some("AAAA"), 2, &mut g.n())
        .unwrap_err()
        .to_string();
    assert!(e.contains("broken signing key"), "{e}");
    assert!(members::add(&ra, &b.recipient, "bob", b.signer().as_deref(), 2, &mut g.n()).is_ok());
}

#[test]
fn in_an_old_v1_vault_any_member_adds_and_removes() {
    use tgsync_core::crypto::KeyRing;
    use tgsync_core::descriptor::{build, Member};
    let (a, b, c) = (person(1), person(2), person(3));
    let mut g = Group(vec![], 0);
    let mut ring = KeyRing::new();
    ring.add(1, &[4; 32]).unwrap();
    let d = build(
        &ring,
        "00112233aabbccdd",
        &[Member::new(&a.recipient, "alice"), Member::new(&b.recipient, "bob")],
        None,
        1,
        None,
        &mut g.n(),
    )
    .unwrap();
    g.post(d);
    let mut rb = Replica::new(b.clone(), None);
    g.pull(&mut rb);
    assert!(rb.admins.is_none());
    // bob is not the creator, and there are no admins: v1 rules let him add carol and remove alice.
    let d = members::add(&rb, &c.recipient, "carol", None, 2, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut rb);
    assert_eq!(rb.members.len(), 3);
    let d = members::remove(&rb, "alice", &[5; 32], 3, &mut g.n()).unwrap();
    g.post(d);
    let mut ra = Replica::new(a.clone(), None);
    g.pull(&mut ra);
    g.pull(&mut rb);
    assert_eq!(rb.members.len(), 2);
    assert!(rb.keys.has(2) && !ra.keys.has(2), "the key rotated without alice");
    assert!(members::give_admin(&rb, "carol", 4, &mut g.n())
        .unwrap_err()
        .to_string()
        .contains("no admins"));
}

#[test]
fn a_reposted_old_descriptor_does_not_trap_someone_removed_and_re_added() {
    // Found by the simulator (seed 7342): bob is added, removed, then someone re-posts the old
    // descriptor that added him, then alice adds him back. Bob replays it all in one pull (a fresh
    // join) and must end with the newest key, not the old one from the re-post.
    let (a, b) = (person(1), person(2));
    let mut g = Group(vec![], 0);
    let d = members::create(&a, "alice", "00112233aabbccdd", &[5; 32], 1, &mut g.n()).unwrap();
    g.post(d);
    let mut ra = Replica::new(a.clone(), None);
    g.pull(&mut ra);
    let added = members::add(&ra, &b.recipient, "bob", b.signer().as_deref(), 2, &mut g.n()).unwrap();
    g.post(added.clone());
    g.pull(&mut ra);
    let d = members::remove(&ra, "bob", &[6; 32], 3, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    g.post(added); // the re-post
    g.pull(&mut ra);
    let d = members::add(&ra, &b.recipient, "bob", b.signer().as_deref(), 4, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    let mut rb = Replica::new(b.clone(), None);
    let rep = g.pull(&mut rb);
    assert!(rb.keys.has(2), "bob holds the newest key: {:?}", rep.problems);
    assert!(!rb.removed);
    assert_eq!(rb.members.len(), 2);
}

#[test]
fn a_reposted_add_does_not_undo_a_later_add() {
    // Adding someone keeps the epoch, so an old add re-posted later has a current epoch. It must
    // not bring back the member list it had (which would drop carol).
    let (a, b, c) = (person(1), person(2), person(3));
    let mut g = Group(vec![], 0);
    let d = members::create(&a, "alice", "00112233aabbccdd", &[5; 32], 1, &mut g.n()).unwrap();
    g.post(d);
    let mut ra = Replica::new(a.clone(), None);
    g.pull(&mut ra);
    let add_bob = members::add(&ra, &b.recipient, "bob", b.signer().as_deref(), 2, &mut g.n()).unwrap();
    g.post(add_bob.clone());
    g.pull(&mut ra);
    let d = members::add(&ra, &c.recipient, "carol", c.signer().as_deref(), 3, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    let mut rc = Replica::new(c.clone(), None);
    g.pull(&mut rc);
    rc.active = true; // carol has synced
    g.post(add_bob); // the re-post
    let rep = g.pull(&mut rc);
    g.pull(&mut ra);
    assert!(!rc.removed, "carol is still a member: {:?}", rep.problems);
    assert_eq!((ra.members.len(), rc.members.len()), (3, 3));
}

#[test]
fn owners_admins_and_plain_members() {
    use tgsync_core::descriptor::{build, Signing};
    let (a, b, c, d) = (person(1), person(2), person(3), person(4));
    let mut g = Group(vec![], 0);
    let msg = members::create(&a, "alice", "00112233aabbccdd", &[5; 32], 1, &mut g.n()).unwrap();
    g.post(msg);
    let mut ra = Replica::new(a.clone(), None);
    g.pull(&mut ra);
    assert_eq!(ra.owners, Some(vec![a.signer().unwrap()]), "the creator is the owner");
    for (p, n) in [(&b, "bob"), (&c, "carol"), (&d, "dave")] {
        let msg = members::add(&ra, &p.recipient, n, p.signer().as_deref(), 2, &mut g.n()).unwrap();
        g.post(msg);
        g.pull(&mut ra);
    }
    let msg = members::give_admin(&ra, "bob", 3, &mut g.n()).unwrap();
    g.post(msg);
    let (mut rb, mut rd) = (Replica::new(b.clone(), None), Replica::new(d.clone(), None));
    for r in [&mut ra, &mut rb, &mut rd] {
        g.pull(r);
    }
    // bob, a plain admin: no admins made or unmade, no owners touched, only plain members removed.
    let refuse = |e: tgsync_core::Error, what: &str| assert!(e.to_string().contains(what), "{e}");
    refuse(members::give_admin(&rb, "carol", 4, &mut g.n()).unwrap_err(), "only an owner");
    refuse(members::give_owner(&rb, "carol", 4, &mut g.n()).unwrap_err(), "only an owner");
    refuse(members::take_admin(&rb, "alice", 4, &mut g.n()).unwrap_err(), "only an owner");
    refuse(members::remove(&rb, "alice", &[6; 32], 4, &mut g.n()).unwrap_err(), "only remove plain members");
    let msg = members::remove(&rb, "carol", &[6; 32], 4, &mut g.n()).unwrap();
    g.post(msg);
    for r in [&mut ra, &mut rb, &mut rd] {
        assert!(g.pull(r).problems.is_empty());
        assert_eq!(r.members.len(), 3, "bob removed carol, a plain member");
    }

    // A modified client signs what the builders refuse: every replica rejects it.
    let (bs, as_) = (b.signer().unwrap(), a.signer().unwrap());
    let both = [as_.clone(), bs.clone()];
    let forged = |g: &mut Group, admins: &[String], owners: Option<&[String]>| {
        let sg = Signing { admins, owners, key: b.signing.as_ref().unwrap() };
        let msg = build(&rb.keys, "00112233aabbccdd", &rb.members, None, 5, Some(sg), &mut g.n()).unwrap();
        g.post(msg);
    };
    forged(&mut g, &both, Some(&[bs.clone()])); // bob makes himself the owner instead of alice
    forged(&mut g, &[bs.clone()], None); // bob takes alice's admin rights
    for r in [&mut ra, &mut rd] {
        let problems: Vec<String> = g.pull(r).problems.into_iter().map(|p| p.1).collect();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].contains("only an owner can change who the owners are"), "{problems:?}");
        assert!(problems[1].contains("only an owner can make or unmake admins"), "{problems:?}");
        assert_eq!(r.owners, Some(vec![as_.clone()]));
        assert_eq!(r.admins.as_ref().map(|x| x.len()), Some(2));
    }
    // Removing the owner with a new key: alice is not fooled into thinking she was removed.
    let mut ring = rb.keys.clone();
    ring.add(3, &[7; 32]).unwrap();
    let keep: Vec<_> = rb.members.iter().filter(|m| m.recipient != a.recipient).cloned().collect();
    let sg = Signing { admins: &[bs.clone()], owners: Some(&[bs.clone()]), key: b.signing.as_ref().unwrap() };
    let msg = build(&ring, "00112233aabbccdd", &keep, Some(2), 6, Some(sg), &mut g.n()).unwrap();
    g.post(msg);
    g.pull(&mut ra);
    assert!(!ra.removed && !ra.keys.has(3), "alice is still in");

    // Owners can make more owners; then either may step down, but never the last one.
    let msg = members::give_owner(&ra, "bob", 7, &mut g.n()).unwrap();
    g.post(msg);
    g.pull(&mut ra);
    g.pull(&mut rb);
    let msg = members::take_owner(&rb, "alice", 8, &mut g.n()).unwrap();
    g.post(msg);
    g.pull(&mut ra);
    g.pull(&mut rb);
    assert_eq!(ra.owners, Some(vec![bs.clone()]));
    refuse(members::remove(&ra, "bob", &[8; 32], 9, &mut g.n()).unwrap_err(), "only remove plain members");
    refuse(members::take_owner(&rb, "bob", 9, &mut g.n()).unwrap_err(), "last owner");
}
