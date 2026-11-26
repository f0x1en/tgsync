// SPDX-License-Identifier: AGPL-3.0-or-later
// The WebAssembly build of the core replays spec/vectors_v2.json to the same state as native Rust.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { w } from "../src/core.ts";

const load = (f: string) => JSON.parse(readFileSync(new URL(`../../spec/${f}`, import.meta.url), "utf8"));

test("WebAssembly core replays the v2 vectors like native Rust", () => {
  const v1 = load("vectors.json"), v2 = load("vectors_v2.json");
  for (const who of ["alice", "bob"]) {
    const id = v1.identities[who];
    const e = new w.Engine(id.secret, id.recipient, v2.signing_keys[who], v2.vault_id);
    e.beginPass();
    v2.log.forEach((m: any, i: number) => e.feed(i + 1, m.kind, Uint8Array.from(atob(m.body_b64), (c) => c.charCodeAt(0))));
    const rep = JSON.parse(e.finishPull());
    const want = v2.expect[who];
    const members = JSON.parse(e.members());
    assert.equal(e.removed(), want.removed, who);
    assert.equal(e.epoch() ?? null, want.epoch, who);
    assert.deepEqual(members.members.map((m: any) => m.name), want.members, who);
    assert.equal(members.admins === null || members.admins === undefined ? null : members.admins.length, want.admins, who);
    const tree = JSON.parse(e.tree());
    assert.deepEqual(Object.keys(tree).sort(), Object.keys(want.files).sort(), who);
    for (const [p, f] of Object.entries(want.files) as [string, any][]) {
      assert.equal(tree[p].sha, f.sha, `${who} ${p}`);
      assert.equal(e.text(p) ?? null, f.text, `${who} ${p}`);
    }
    assert.deepEqual(rep.problems, want.problems, who);
    e.free();
  }
});
