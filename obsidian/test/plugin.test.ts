// SPDX-License-Identifier: AGPL-3.0-or-later
// The plugin (engine inside) on a sandbox group, with a stub `obsidian` module. Alice uses the CLI
// (../ts/dist/tgsync.mjs, built by `npm test` in ts/); Bob uses Obsidian with the plugin.
// `npm test` bundles this file with `obsidian` aliased to ./obsidian-stub.ts.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FileSystemAdapter, MarkdownView, notices } from "obsidian";
import TgsyncPlugin from "../src/main.ts";

(globalThis as any).window = globalThis; // timers, as in the app
const CLI = join(__dirname, "..", "..", "ts", "dist", "tgsync.mjs");
const tmp = mkdtempSync(join(tmpdir(), "tgsync-plugin-"));
process.env.TGSYNC_SANDBOX = join(tmp, "sb"); // the plugin's engine finds bob's keys in the sandbox
delete process.env.TGSYNC_HOME;
const A = join(tmp, "alice"), B = join(tmp, "bob");

function cli(profile: string, ...args: string[]): any {
  const r = spawnSync("node", [CLI, "--json", ...args], { env: { ...process.env, TGSYNC_PROFILE: profile }, encoding: "utf8" });
  return JSON.parse(r.stdout);
}

// alice makes the vault; bob asks to join and is let in (as he will from the plugin later)
const inv = cli("alice", "new", A).invite;
cli("alice", "accept", cli("bob", "join", inv, B).code, "-C", A);
assert.equal(cli("bob", "join").state, "joined");

const editor = new MarkdownView();
const handlers: (() => void)[] = [];

async function start(folder: string, settings: object = {}) {
  const app: any = {
    vault: { adapter: new FileSystemAdapter(folder), on: (_ev: string, f: () => void) => { handlers.push(f); return {}; } },
    workspace: { onLayoutReady: () => {}, getLeavesOfType: () => [{ view: editor }] },
  };
  const p: any = new TgsyncPlugin(app);
  await p.saveData(settings);
  await p.onload();
  p.editDelay = 50;
  p.joinEvery = () => 0;
  return p;
}

test("sync downloads others' changes and uploads yours; quiet unless asked", async () => {
  const p = await start(B);
  writeFileSync(join(A, "from-alice.md"), "hello bob\n");
  cli("alice", "push", "-C", A);
  notices.length = 0;
  await p.sync(false);
  assert.equal(readFileSync(join(B, "from-alice.md"), "utf8"), "hello bob\n");
  assert.equal(p.state, "synced");
  assert.equal(p.bars[0].text, "✓ Synced");
  assert.deepEqual(notices, []); // automatic syncs say nothing
  assert.ok(editor.saved > 0, "open notes are saved before syncing");

  writeFileSync(join(B, "from-bob.md"), "hi alice\n");
  await p.sync(true);
  assert.ok(notices.some((n) => n.includes("1 uploaded")), notices.join("\n"));
  cli("alice", "pull", "-C", A);
  assert.equal(readFileSync(join(A, "from-bob.md"), "utf8"), "hi alice\n");
  await p.onunload();
});

test("an edit is uploaded by itself a moment later", async () => {
  const p = await start(B);
  const started: Promise<void>[] = [];
  const sync = p.sync.bind(p);
  p.sync = (loud: boolean) => { const r = sync(loud); started.push(r); return r; };
  writeFileSync(join(B, "typed.md"), "typed in Obsidian\n");
  for (const h of handlers) h(); // Obsidian reports the change
  await new Promise((r) => setTimeout(r, 150));
  assert.ok(started.length > 0, "the edit started a sync by itself");
  await Promise.all(started);
  cli("alice", "pull", "-C", A);
  assert.equal(readFileSync(join(A, "typed.md"), "utf8"), "typed in Obsidian\n");
  await p.onunload();
});

test("both changed one file: both versions kept and the user is told; notes merge", async () => {
  const p = await start(B);
  writeFileSync(join(A, "pic.bin"), "v1");
  writeFileSync(join(A, "plan.md"), "plan\n");
  cli("alice", "push", "-C", A);
  await p.sync(false);
  writeFileSync(join(A, "pic.bin"), "alice");
  writeFileSync(join(B, "pic.bin"), "bob");
  writeFileSync(join(A, "plan.md"), "plan\nalice's line\n");
  writeFileSync(join(B, "plan.md"), "bob's line\nplan\n");
  cli("alice", "push", "-C", A);
  notices.length = 0;
  await p.sync(false);
  assert.ok(notices.some((n) => n.includes("pic.bin was changed on two devices")), notices.join("\n"));
  const note = readFileSync(join(B, "plan.md"), "utf8");
  assert.ok(note.includes("alice's line") && note.includes("bob's line"), note);
  await p.onunload();
});

test("a terminal run holding the folder: skipped quietly, no error", async () => {
  const p = await start(B);
  writeFileSync(join(B, ".tgsync", "lock"), String(process.pid)); // held by "someone" alive
  notices.length = 0;
  await p.sync(false);
  assert.equal(p.state, "synced");
  assert.deepEqual(notices, []);
  writeFileSync(join(B, ".tgsync", "lock"), "999999999"); // gone: taken over
  await p.sync(false);
  assert.ok(!existsSync(join(B, ".tgsync", "lock")), "lock released after the sync");
  await p.onunload();
});

test("not a vault, and sync switched off", async () => {
  const plain = mkdtempSync(join(tmpdir(), "tgsync-plain-"));
  const p = await start(plain);
  await p.sync(false);
  assert.equal(p.state, "not set up");
  await p.onunload();
  const q = await start(B, { auto: false });
  q.schedule();
  assert.equal(q.bars[0].text, "Sync paused");
  await q.onunload();
});

test("start a vault in Obsidian; a friend asks to join and is let in with one click", async () => {
  const C = mkdtempSync(join(tmpdir(), "tgsync-carol-")), D = join(tmp, "dave");
  writeFileSync(join(C, "welcome.md"), "hi from carol\n");
  const p = await start(C);
  await p.setup.create();
  assert.ok(p.host.cfg(), "the vault is set up");
  await p.sync(false);
  const invite = await p.setup.invite();
  cli("dave", "join", invite, D);
  const asked: any[] = [];
  p.askAccept = (r: any) => asked.push(r);
  p.lastAsk = 0;
  await p.sync(false);
  assert.equal(asked.length, 1, "the owner is asked about the request");
  assert.match(asked[0].code, /^[0-9a-f]{4}-[0-9a-f]{4}$/, "with the asker's code");
  assert.match(p.bars[0].text, /1 waiting to join/, "the request waits in the status bar");
  await p.sync(false);
  assert.equal(asked.length, 1, "asked once; then it waits");
  assert.match((await p.setup.members()).members[0].name, /\([0-9a-f]{4}-[0-9a-f]{4}\)$/, "members show their code");
  assert.equal(cli("dave", "join").state, "waiting", "nobody is in before the owner says so");
  await p.setup.accept(asked[0]);
  p.decided(asked[0]);
  assert.doesNotMatch(p.bars[0].text, /waiting to join/);
  await assert.rejects(p.setup.accept(asked[0]), /no longer waiting/);
  assert.equal(cli("dave", "join").state, "joined");
  assert.equal(readFileSync(join(D, "welcome.md"), "utf8"), "hi from carol\n");
  p.lastAsk = 0;
  asked.length = 0;
  await p.sync(false);
  assert.equal(asked.length, 0, "nobody left waiting");
  await p.onunload();
});

test("join from Obsidian: shows the code, then joins by itself once let in", async () => {
  const E = mkdtempSync(join(tmpdir(), "tgsync-erin-"));
  writeFileSync(join(A, "for-erin.md"), "hello erin\n");
  cli("alice", "push", "-C", A);
  const p = await start(E);
  const w = await p.setup.join(cli("alice", "invite", "-C", A).invite);
  assert.ok(w?.code, "waiting, with a code to tell the owner");
  await p.sync(false);
  assert.equal(p.state, "waiting");
  assert.deepEqual(await p.setup.waiting(), w);
  cli("alice", "accept", w!.code, "-C", A);
  await p.sync(false);
  assert.equal(p.state, "synced");
  assert.equal(readFileSync(join(E, "for-erin.md"), "utf8"), "hello erin\n");
  assert.equal(await p.setup.waiting(), null);
  writeFileSync(join(E, "from-erin.md"), "hi\n");
  await p.sync(false);
  cli("alice", "pull", "-C", A);
  assert.equal(readFileSync(join(A, "from-erin.md"), "utf8"), "hi\n");
  await p.onunload();
});

test("an account named in the vault's settings is used for setup", async () => {
  const F = mkdtempSync(join(tmpdir(), "tgsync-frank-"));
  const p = await start(F, { account: "frank" });
  assert.equal(p.setup.profile(), "frank");
  await p.setup.create();
  assert.equal(p.host.cfg().profile, "frank");
  await p.onunload();
});

test("a refused request is not asked about again", async () => {
  const G = join(tmp, "gus");
  const asked: any[] = [];
  const q = await start(A); // alice, the admin, in Obsidian
  q.askAccept = (r: any) => asked.push(r);
  cli("gus", "join", cli("alice", "invite", "-C", A).invite, G);
  q.lastAsk = 0;
  await q.sync(false);
  assert.equal(asked.length, 1);
  await q.refuse(asked[0]);
  q.lastAsk = 0;
  await q.sync(false);
  assert.equal(asked.length, 1, "not asked again");
  assert.equal(cli("gus", "join").state, "waiting");
  await q.onunload();
});
