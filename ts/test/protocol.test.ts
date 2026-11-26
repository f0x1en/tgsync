// SPDX-License-Identifier: AGPL-3.0-or-later
// What the host reads and writes itself (chunks, captions, invites through the core, paths) must match spec/vectors.json.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { KeyRing, hex, unhex } from "../src/crypto.ts";
import { PathError, normalize } from "../src/paths.ts";
import { caption, decodeInvite, encodeInvite, openChunk, parseCaption, sealChunk } from "../src/protocol.ts";

const V = JSON.parse(readFileSync(new URL("../../spec/vectors.json", import.meta.url), "utf8"));
test("chunks and captions", async () => {
  const c = V.chunk, ring = new KeyRing(new Map([[1, unhex(c.key)]]));
  assert.equal(hex(await openChunk(ring, c.file_id, c.index, c.count, unhex(c.blob))), c.data);
  const again = await sealChunk(ring, c.file_id, c.index, c.count, unhex(c.data));
  assert.equal(hex(await openChunk(ring, c.file_id, c.index, c.count, again)), c.data);
  assert.equal(parseCaption(caption("r")), "r");
  assert.equal(parseCaption("tgs1:rr"), null);
});

test("invite codes", () => {
  const i = V.invite;
  const inv = decodeInvite(i.code);
  assert.deepEqual([inv.link, inv.vaultId, inv.fingerprint, inv.api], [i.link, i.vault_id, i.fingerprint, i.api]);
  assert.equal(encodeInvite(inv), i.code);
  assert.equal(decodeInvite(` ${i.code.slice(0, 10)}\n${i.code.slice(10)} `).vaultId, i.vault_id);
  assert.throws(() => decodeInvite("hello"), /does not look like a tgsync invite/);
});

test("paths", () => {
  for (const p of V.paths) {
    if (p.ok) assert.equal(normalize(p.in), p.out, p.in);
    else assert.throws(() => normalize(p.in), PathError, JSON.stringify(p.in));
  }
});
