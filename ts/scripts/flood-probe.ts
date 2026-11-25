// SPDX-License-Identifier: AGPL-3.0-or-later
// Find where Telegram starts saying "flood wait", on REAL Telegram. Telegram publishes no limits.
//
// Makes a throwaway private group, then raises the rate of one kind of call step by step until the
// first flood wait: reads (the call each sync makes while idle) and sends (each upload). The group is
// deleted at the end. Every flood wait also lands in <tgsync config>/flood-waits.log.
//
//   npm run -s flood-probe -- --profile SPARE --spare
//
// Use a SPARE account you can lose: hammering Telegram can get an account limited or banned.
// It takes up to about 25 minutes (2 minutes per step).
import { InputMedia } from "@mtcute/core";
import { existsSync, readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { connect, createGroup, floodLogPath } from "../src/node/telegram.ts";

const { values: a } = parseArgs({ options: { profile: { type: "string" }, spare: { type: "boolean" }, step: { type: "string", default: "120" } } });
if (!a.profile || !a.spare) {
  console.log("usage: npm run -s flood-probe -- --profile SPARE --spare   (log in first: tgsync login --profile SPARE)\n" +
              "--spare confirms this is an account you can lose.");
  process.exit(2);
}
const STEP = Number(a.step) * 1000; // ms per rate
const READS = [6, 12, 30, 60, 120, 240, 480]; // calls per minute
const SENDS = [10, 15, 20, 30, 45, 60];

const sleep = (ms: number) => new Promise((ok) => setTimeout(ok, ms));
const logged = () => (existsSync(floodLogPath()) ? readFileSync(floodLogPath(), "utf8").split("\n").filter(Boolean).length : 0);

/** Call `fn` `perMin` times a minute for one step. -> the flood wait lines it caused (none: this rate is fine). */
async function step(perMin: number, fn: () => Promise<unknown>): Promise<string[]> {
  const before = logged(), end = Date.now() + STEP;
  while (Date.now() < end) {
    const t = Date.now();
    try { await fn(); } catch (e) { console.log(`    error: ${(e as Error).message}`); }
    if (logged() > before) break;
    await sleep(Math.max(0, 60_000 / perMin - (Date.now() - t)));
  }
  return logged() > before ? readFileSync(floodLogPath(), "utf8").split("\n").filter(Boolean).slice(before) : [];
}

async function ramp(what: string, rates: number[], fn: () => Promise<unknown>): Promise<string> {
  console.log(`\n== ${what}`);
  let ok = "none";
  for (const r of rates) {
    process.stdout.write(`  ${r}/min for ${STEP / 1000}s: `);
    const hit = await step(r, fn);
    if (hit.length) {
      console.log(`FLOOD WAIT  ${hit[0]}`);
      const s = Number(hit[0].split(" ").at(-1));
      console.log(`  waiting it out (${s}s)`);
      await sleep((s + 5) * 1000);
      return `${what}: fine at ${ok}/min, flood wait at ${r}/min (${s}s)`;
    }
    console.log("ok");
    ok = String(r);
  }
  return `${what}: no flood wait up to ${ok}/min`;
}

const tg = await connect(a.profile);
let chat: any = null;
const results: string[] = [];
try {
  [chat] = await createGroup(tg, "tgsync flood probe (delete me)");
  const doc = new Uint8Array(64);
  results.push(await ramp("reads (getHistory, newest message)", READS, () => tg.getHistory(chat.id, { limit: 1 })));
  results.push(await ramp("sends (64-byte document)", SENDS, () => tg.sendMedia(chat.id, InputMedia.document(doc, { fileName: "x.bin" }))));
} finally {
  if (chat) await tg.deleteSupergroup(chat.id).then(() => console.log("\nthrowaway group deleted"),
    (e) => console.log(`\ncould not delete the throwaway group (delete it by hand): ${e}`));
  await tg.destroy();
}
console.log("\n== result");
for (const r of results) console.log("  " + r);
console.log(`  all flood waits: ${floodLogPath()}`);
