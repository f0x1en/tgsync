// SPDX-License-Identifier: AGPL-3.0-or-later
// The host's crypto (chunk sealing, member ids) must match spec/vectors.json (made by the Python reference).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { KeyRing, CryptoError, hex, memberId, subkey, unhex, utf8 } from "../src/crypto.ts";
import { w } from "../src/core.ts";

const V = JSON.parse(readFileSync(new URL("../../spec/vectors.json", import.meta.url), "utf8"));

test("subkeys", async () => {
  for (const s of V.subkey) assert.equal(hex(await subkey(unhex(s.key), utf8(s.purpose), utf8(s.ctx))), s.subkey);
});

test("seal gives the same bytes as Python; open reads them", async () => {
  for (const s of V.seal) {
    const ring = new KeyRing(new Map([[s.epoch, unhex(s.key)]]));
    assert.equal(hex(await ring.seal(s.purpose, utf8(s.ctx), unhex(s.plaintext), s.epoch, unhex(s.nonce))), s.blob);
    assert.equal(hex(await ring.open(s.purpose, utf8(s.ctx), unhex(s.blob))), s.plaintext);
  }
});

test("open rejects bad blobs", async () => {
  const ring = new KeyRing(new Map(Object.entries(V.open_ring).map(([e, k]) => [Number(e), unhex(k as string)])));
  for (const b of V.open_must_fail) {
    await assert.rejects(ring.open(b.purpose, utf8(b.ctx), unhex(b.blob)), CryptoError, b.why);
  }
});

test("member ids here and short codes from the core", async () => {
  for (const i of Object.values(V.identities) as any[]) {
    assert.equal(await memberId(i.recipient), i.id);
    assert.equal(w.shortCode(i.recipient), i.short_code);
  }
});
