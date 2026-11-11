// SPDX-License-Identifier: AGPL-3.0-or-later
// Formats, paths and replay must match spec/vectors.json (made by the Python reference).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { CryptoError, KeyRing, fromUtf8, hex, unhex, utf8 } from "../src/crypto.ts";
import { PathError, conflictName, normalize } from "../src/paths.ts";
import {
  acceptDescriptor, addMember, buildDescriptor, canon, decodeInvite, decodeJoinRequest, decodeRecord, encodeInvite,
  encodeRecord, openChunk, removeMember, type Identity,
} from "../src/protocol.ts";
import { Tree } from "../src/tree.ts";

const V = JSON.parse(readFileSync(new URL("../../spec/vectors.json", import.meta.url), "utf8"));
const ident = (who: string): Identity => {
  const i = V.identities[who];
  return { secret: i.secret, recipient: i.recipient, id: i.id };
};

test("canonical JSON is byte-identical to Python's", () => {
  for (const d of V.descriptors.sequence) assert.equal(canon(JSON.parse(d)), d);
  assert.equal(canon({ b: "ü😀\x7f", a: [1, { z: null, y: true }] }), '{"a":[1,{"y":true,"z":null}],"b":"\\u00fc\\ud83d\\ude00\x7f"}');
});

for (const who of ["alice", "bob"]) {
  test(`descriptor sequence as ${who}`, async () => {
    const ring = new KeyRing();
    const want = V.descriptors[`expect_${who}`];
    for (const [i, data] of V.descriptors.sequence.entries()) {
      const got = await acceptDescriptor(utf8(data), ident(who), ring, V.descriptors.vault_id);
      if (want[i] === "excluded") assert.equal(got, null);
      else {
        assert.equal(got!.epoch, want[i].epoch);
        assert.deepEqual(got!.members.map((m) => m.name), want[i].members);
      }
    }
    if (who === "alice") assert.equal(hex(ring.key(2)), V.descriptors.epoch2_key);
  });
}

test("forged descriptor is rejected", async () => {
  const ring = new KeyRing();
  await acceptDescriptor(utf8(V.descriptors.sequence[0]), ident("alice"), ring, V.descriptors.vault_id);
  await assert.rejects(acceptDescriptor(utf8(V.descriptors.forged_after_d1), ident("alice"), ring, V.descriptors.vault_id), CryptoError);
});

test("descriptors written by TS: create, add, remove", async () => {
  const vid = "00112233aabbccdd";
  const A = { recipient: V.identities.alice.recipient, name: "alice" }, B = { recipient: V.identities.bob.recipient, name: "bob" };
  const ring = new KeyRing(new Map([[1, unhex(V.subkey[0].key)]]));
  const d1 = await buildDescriptor(ring, vid, [A]);
  const d2 = await addMember(ring, vid, [A], B);
  const d3 = await removeMember(ring, vid, [A, B], "bob");
  const ra = new KeyRing(), rb = new KeyRing();
  for (const d of [d1, d2, d3]) await acceptDescriptor(d, ident("alice"), ra, vid);
  assert.equal(ra.current, 2);
  assert.equal(await acceptDescriptor(d1, ident("bob"), rb, vid), null);
  assert.equal((await acceptDescriptor(d2, ident("bob"), rb, vid))!.members.length, 2);
  assert.equal(await acceptDescriptor(d3, ident("bob"), rb, vid), null);
  assert.ok(!rb.has(2));
});

test("records and chunks", async () => {
  const r = V.record;
  const ring = new KeyRing(new Map([[r.epoch, unhex(r.key)]]));
  const rec = await decodeRecord(ring, unhex(r.blob));
  assert.deepEqual([rec.author, rec.seq, rec.ts, rec.entries, hex(rec.payload)], [r.author, r.seq, r.ts, r.entries, r.payload]);
  const again = await decodeRecord(ring, await encodeRecord(ring, rec));
  assert.deepEqual(again, rec);
  const c = V.chunk;
  assert.equal(hex(await openChunk(new KeyRing(new Map([[1, unhex(c.key)]])), c.file_id, c.index, c.count, unhex(c.blob))), c.data);
});

test("invite codes and join requests", () => {
  const i = V.invite;
  const inv = decodeInvite(i.code);
  assert.deepEqual([inv.link, inv.vaultId, inv.fingerprint, inv.api], [i.link, i.vault_id, i.fingerprint, i.api]);
  assert.equal(encodeInvite(inv), i.code);
  assert.equal(decodeInvite(` ${i.code.slice(0, 10)}\n${i.code.slice(10)} `).vaultId, i.vault_id);
  const j = V.join_request;
  assert.deepEqual(decodeJoinRequest(utf8(j.body)), { vaultId: j.vault, recipient: j.recipient, name: j.name, msgId: 0 });
  assert.equal(decodeJoinRequest(utf8('{"v":1,"vault":"x","recipient":"evil"}')), null);
});

test("paths and conflict names", () => {
  for (const p of V.paths) {
    if (p.ok) assert.equal(normalize(p.in), p.out, p.in);
    else assert.throws(() => normalize(p.in), PathError, JSON.stringify(p.in));
  }
  for (const c of V.conflict_name) assert.equal(conflictName(c.path, c.author, c.ts), c.out);
});

test("replay reaches the same results and tree", () => {
  const t = new Tree();
  const results: unknown[] = [];
  for (const m of V.replay.log) for (const e of m.entries) results.push(t.applyEntry(structuredClone(e), m.author, m.ts, m.msg_id));
  assert.deepEqual(results, V.replay.results);
  const tree: any = {};
  for (const [p, n] of [...t.nodes].sort(([a], [b]) => (a < b ? -1 : 1))) {
    tree[p] = { sha: n.sha, author: n.author, msg_id: n.msg_id, payload_msg: n.blob.payload_msg ?? null };
  }
  assert.deepEqual(tree, V.replay.tree);
  assert.equal(fromUtf8(utf8("ok")), "ok");
});
