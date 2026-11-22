// SPDX-License-Identifier: AGPL-3.0-or-later
// The plugin against a fake `tgsync` (canned --json answers) and a stub `obsidian` module.
// `npm test` bundles this file with `obsidian` aliased to ./obsidian-stub.ts.
import assert from "node:assert/strict";
import { appendFileSync, chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FileSystemAdapter, TFile, notices } from "obsidian";
import TgsyncPlugin from "../src/main.ts";

const dir = mkdtempSync(join(tmpdir(), "tgsync-plugin-"));

/** A fake tgsync: answers each command from `answers`, logs its arguments to `<path>.log`. */
function fakeCli(answers: Record<string, unknown>): string {
  const f = join(dir, `tgsync-${Math.random().toString(36).slice(2)}`);
  writeFileSync(`${f}.json`, JSON.stringify(answers));
  writeFileSync(f, `#!/usr/bin/env node
const fs = require("fs");
const a = JSON.parse(fs.readFileSync(${JSON.stringify(`${f}.json`)}, "utf8"));
fs.appendFileSync(${JSON.stringify(`${f}.log`)}, process.argv.slice(2).join(" ") + "\\n");
process.stdout.write(JSON.stringify(a[process.argv[3]] ?? { ok: false, error: "unknown command" }));
`);
  chmodSync(f, 0o755);
  return f;
}

async function start(cli: string, active: string | null = null) {
  const app: any = {
    vault: { adapter: new FileSystemAdapter("/vaults/team") },
    workspace: { on: () => ({}), onLayoutReady: () => {}, getActiveFile: () => (active ? new TFile(active) : null) },
  };
  const p: any = new TgsyncPlugin(app);
  await p.saveData({ cli, checkMinutes: 0 });
  await p.onload();
  return p;
}

const status = (incoming: unknown[], pending: unknown[] = []) => ({ ok: true, incoming, pending, online_error: null });

test("check: shows counts, names who changed what, warns about the open note and shared edits", async () => {
  notices.length = 0;
  const cli = fakeCli({ status: status(
    [{ op: "put", path: "plan.md", who: "bob", also_local: true }, { op: "put", path: "x.png", who: "carol", also_local: false }],
    [{ op: "put", path: "plan.md" }]) });
  const p = await start(cli, "x.png");
  await p.check(false);
  assert.equal(p.bars[0].text, "tgsync: 2 to pull, 1 to push");
  assert.ok(notices.some((n) => n.includes("2 changes from bob, carol")), notices.join("\n"));
  assert.ok(notices.some((n) => n.includes("you and someone else changed plan.md")));
  assert.ok(notices.some((n) => n.includes("carol changed this note")));
  assert.match(readFileSync(`${cli}.log`, "utf8"), /^--json status -C \/vaults\/team$/m);
  // The same changes again: no new notice (only when something new arrives, or when asked).
  const before = notices.length;
  await p.check(false);
  assert.equal(notices.length, before);
});

test("pull and push report what happened; errors and offline are shown", async () => {
  notices.length = 0;
  const cli = fakeCli({
    status: status([]),
    pull: { ok: true, report: { written: ["a.md", "b.md"], deleted: ["c.md"], pushed_paths: [], conflicts: [["d.bin", "d (conflict ab12cd 2026-11-23 0100).bin"]], skipped: [], problems: [] } },
    push: { ok: false, error: "you were removed from this vault" },
  });
  const p = await start(cli);
  await p.pull();
  assert.ok(notices.includes("tgsync: 2 updated, 1 deleted"), notices.join("\n"));
  assert.ok(notices.some((n) => n.includes("both changed d.bin")));
  assert.equal(p.bars[0].text, "tgsync: up to date");
  await p.push();
  assert.ok(notices.includes("tgsync: you were removed from this vault"));

  const off = await start(fakeCli({ status: { ok: true, incoming: null, pending: [{ op: "put", path: "a.md" }], online_error: "no network" } }));
  await off.check(true);
  assert.equal(off.bars[0].text, "tgsync: offline, 1 to push");
  const broken = await start(join(dir, "no-such-program"));
  await broken.check(true);
  assert.equal(broken.bars[0].text, "tgsync: error");
  assert.ok(notices.some((n) => n.startsWith("tgsync: could not run")));
});
