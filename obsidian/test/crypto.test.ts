// SPDX-License-Identifier: AGPL-3.0-or-later
// The TS crypto must match spec/vectors.json (made by the Python reference).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  KeyRing, CryptoError, fingerprint, hex, mac, memberId, shortCode, subkey, unhex, unwrap, utf8, wrapFor,
} from "../src/crypto.ts";

const V = JSON.parse(readFileSync(new URL("../../spec/vectors.json", import.meta.url), "utf8"));

test("subkeys, mac, fingerprint", async () => {
  for (const s of V.subkey) assert.equal(hex(await subkey(unhex(s.key), utf8(s.purpose), utf8(s.ctx))), s.subkey);
  for (const m of V.mac) assert.equal(hex(await mac(unhex(m.key), ...m.parts.map(utf8))), m.mac);
  for (const f of V.fingerprint) assert.equal(await fingerprint(unhex(f.key)), f.fingerprint);
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

test("member ids, short codes, age wrap/unwrap", async () => {
  for (const i of Object.values(V.identities) as any[]) {
    assert.equal(await memberId(i.recipient), i.id);
    assert.equal(await shortCode(i.recipient), i.short_code);
    const w = await wrapFor(i.recipient, utf8("keys"));
    assert.equal(new TextDecoder().decode(await unwrap(i.secret, w)), "keys");
  }
});
