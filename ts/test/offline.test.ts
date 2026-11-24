// SPDX-License-Identifier: AGPL-3.0-or-later
// A dead network or proxy makes Telegram calls fail with a clear error instead of hanging (mtcute
// reconnects forever); a slow call on a working connection is never cut.
import assert from "node:assert/strict";
import { test } from "node:test";
import { watchConnection, whileReachable } from "../src/node/reachable.ts";

function fakeClient() {
  const fs: ((s: string) => void)[] = [];
  const tg = { onConnectionState: { add: (f: (s: string) => void) => { fs.push(f); } } };
  watchConnection(tg);
  return { tg, emit: (s: string) => fs.forEach((f) => f(s)) };
}
const never = new Promise<never>(() => {});
const later = <T>(ms: number, v: T) => new Promise<T>((ok) => setTimeout(() => ok(v), ms));

test("a call fails once Telegram is unreachable long enough", async () => {
  const { tg, emit } = fakeClient();
  emit("connecting");
  await assert.rejects(whileReachable(tg, never, 50), /no connection to Telegram/);
});

test("reconnecting in time keeps the call alive; a slow call on a live connection is not cut", async () => {
  const { tg, emit } = fakeClient();
  emit("connecting");
  setTimeout(() => emit("connected"), 20);
  assert.equal(await whileReachable(tg, later(150, "done"), 60), "done");
  const quiet = fakeClient(); // no state events at all: never cut
  assert.equal(await whileReachable(quiet.tg, later(120, "ok"), 30), "ok");
});
