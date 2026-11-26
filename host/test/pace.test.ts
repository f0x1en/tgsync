// SPDX-License-Identifier: AGPL-3.0-or-later
// Pace: a flood wait slows the account down; calm time brings it back to normal, never below.
import assert from "node:assert/strict";
import { test } from "node:test";
import { Pace } from "../src/node/pace.ts";

test("a flood wait doubles the slow-down; each calm 10 minutes halve it, down to normal", () => {
  const p = Pace.memory();
  assert.equal(p.now(), 1);
  p.flood(5);
  p.flood(5);
  assert.equal(p.now(), 4);
  assert.ok(p.until > Date.now(), "no calls until Telegram's wait is over");
  p.since -= 10 * 60_000;
  assert.equal(p.now(), 2);
  p.since -= 60 * 60_000;
  assert.equal(p.now(), 1, "back to the set speed, not lower");
});
