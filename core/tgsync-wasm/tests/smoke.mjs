// SPDX-License-Identifier: AGPL-3.0-or-later
// Smoke test of the WebAssembly build (run in CI after wasm-bindgen --target nodejs).
// Usage: node smoke.mjs <path to tgsync_wasm.js>
import assert from "node:assert/strict";
import { createHash, getRandomValues } from "node:crypto";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const w = createRequire(import.meta.url)(process.argv[2]);
const V = JSON.parse(readFileSync(new URL("../../../spec/vectors.json", import.meta.url), "utf8"));
const a = V.identities.alice;
const seed = () => getRandomValues(new Uint8Array(32));
const sha = (s) => createHash("sha256").update(s).digest("hex");
const signing = "01".repeat(32);

// The group: [kind, body] in id order (id = index + 1).
const group = [];
const created = JSON.parse(w.createVault(a.secret, a.recipient, signing, "alice", 1, seed()));
group.push(["d", Buffer.from(created.descriptor, "base64")]);

let e = new w.Engine(a.secret, a.recipient, signing, created.vault_id);
const pull = () => {
  e.beginPass();
  for (let i = e.cursor(); i < group.length; i++) {
    const [kind, body] = group[i];
    e.feed(i + 1, kind, e.wantsBody(kind, i + 1) ? body : new Uint8Array());
  }
  return JSON.parse(e.finishPull());
};

assert.deepEqual(pull().problems, []);
assert.ok(e.hasKeys());
assert.equal(JSON.parse(e.members()).members[0].admin, true);

const plan = JSON.parse(e.planPush(JSON.stringify({ "n.md": { sha: sha("hello"), size: 5, mtime: 1, text: "hello" } }), seed()));
assert.equal(plan.entries[0].op, "text");
group.push(["r", e.sealRecord(2, seed())]);
e.pushed();
const rep = pull();
assert.deepEqual(rep.problems, []);
assert.equal(e.text("n.md"), "hello");

const ops = JSON.parse(e.planMaterialize(JSON.stringify({ "n.md": sha("hello") })));
assert.deepEqual(ops.ops, []);

e = w.Engine.load(a.secret, a.recipient, signing, e.save());
assert.equal(e.text("n.md"), "hello");
assert.equal(w.shortCode(a.recipient), a.short_code);
console.log("wasm smoke test ok");
