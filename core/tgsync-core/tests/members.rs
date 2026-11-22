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
    assert!(members::add(&rb, &c.recipient, "carol", None, 3, &mut g.n()).unwrap_err().to_string().contains("only an admin"));
    assert!(members::drop_admin(&ra, 3, &mut g.n()).unwrap_err().to_string().contains("last admin"));

    let d = members::give_admin(&ra, "bob", 3, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    g.pull(&mut rb);
    let d = members::drop_admin(&ra, 4, &mut g.n()).unwrap();
    g.post(d);
    g.pull(&mut ra);
    g.pull(&mut rb);
    assert_eq!(rb.admins, Some(vec![b.signer().unwrap()]));

    // bob (now the only admin) removes alice: new key, alice is out.
    assert!(members::remove(&rb, "bob", &[6; 32], 5, &mut g.n()).unwrap_err().to_string().contains("last admin"));
    let d = members::remove(&rb, "alice", &[6; 32], 5, &mut g.n()).unwrap();
    g.post(d);
    let rep = g.pull(&mut ra);
    assert!(rep.problems.is_empty(), "{:?}", rep.problems);
    g.pull(&mut rb);
    assert_eq!(rb.members.len(), 1);
    assert!(rb.keys.has(2) && !ra.keys.has(2));
}
