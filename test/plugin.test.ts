// SPDX-License-Identifier: AGPL-3.0-or-later
// The plugin (engine inside) on a sandbox group, with a stub `obsidian` module. Alice and Bob each
// use Obsidian with the plugin, each with their own tgsync account (the Account setting).
// `npm test` bundles this file with `obsidian` aliased to ./obsidian-stub.ts.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FileSystemAdapter, MarkdownView, notices } from "obsidian";
import TgsyncPlugin from "../src/main.ts";

(globalThis as any).window = globalThis; // timers, as in the app
const tmp = mkdtempSync(join(tmpdir(), "tgsync-plugin-"));
process.env.TGSYNC_SANDBOX = join(tmp, "sb"); // keys and the "Telegram group" live in the sandbox
delete process.env.TGSYNC_HOME;
const A = join(tmp, "alice"), B = join(tmp, "bob");

const editor = new MarkdownView();

async function start(folder: string, settings: object = {}) {
  const edits: (() => void)[] = []; // what Obsidian calls when a file changes
  const app: any = {
    vault: { adapter: new FileSystemAdapter(folder), on: (_ev: string, f: () => void) => { edits.push(f); return {}; } },
    workspace: { onLayoutReady: () => {}, getLeavesOfType: () => [{ view: editor }], getActiveFile: () => null },
  };
  const p: any = new TgsyncPlugin(app);
  await p.saveData(settings);
  await p.onload();
  p.editDelay = 50;
  p.joinEvery = () => 0;
  p.edits = edits;
  return p;
}

/** Two plugins (alice's, bob's); `fn` runs with both; both are closed after. */
async function both(fn: (a: any, b: any) => Promise<void>) {
  const a = await start(A, { account: "alice" }), b = await start(B, { account: "bob" });
  try { await fn(a, b); } finally { await a.onunload(); await b.onunload(); }
}

/** `admin` asks about requests now (not in 10 minutes). -> the requests it showed. */
async function requests(admin: any): Promise<any[]> {
  const asked: any[] = [];
  admin.askAccept = (r: any) => asked.push(r);
  admin.lastAsk = 0;
  await admin.sync(false);
  return asked;
}

test("alice starts a vault in Obsidian; bob asks to join, is let in with one click, and joins by himself", async () => {
  await both(async (a, b) => {
    mkdirSync(A, { recursive: true });
    writeFileSync(join(A, "welcome.md"), "hi from alice\n");
    await a.setup.create();
    assert.ok(a.host.cfg(), "the vault is set up");
    await a.sync(false);
    const w = await b.setup.join(await a.setup.invite());
    assert.match(w?.code ?? "", /^[0-9a-f]{4}-[0-9a-f]{4}$/, "waiting, with the code alice sees beside his name");
    await b.sync(false);
    assert.equal(b.state, "waiting");
    assert.deepEqual(await b.setup.waiting(), w);

    const asked = await requests(a);
    assert.equal(asked.length, 1, "alice is asked about the request");
    assert.equal(asked[0].code, w!.code, "with bob's code");
    assert.match(a.bars[0].text, /1 waiting to join/, "the request waits in the status bar");
    await a.sync(false);
    assert.equal(asked.length, 1, "asked once; then it waits");
    await b.sync(false);
    assert.equal(b.state, "waiting", "nobody is in before alice says so");

    await a.setup.accept(asked[0]);
    a.decided(asked[0]);
    assert.doesNotMatch(a.bars[0].text, /waiting to join/);
    await assert.rejects(a.setup.accept(asked[0]), /no longer waiting/);
    await b.sync(false);
    assert.equal(b.state, "synced", "joined by himself");
    assert.equal(readFileSync(join(B, "welcome.md"), "utf8"), "hi from alice\n");
    assert.equal(await b.setup.waiting(), null);
    assert.equal((await requests(a)).length, 0, "nobody left waiting");
    const names = (await a.setup.members()).members.map((m: any) => m.name);
    assert.ok(names.every((n: string) => /\([0-9a-f]{4}-[0-9a-f]{4}\)$/.test(n)), `members show their code: ${names}`);
  });
});

test("sync downloads others' changes and uploads yours; quiet unless asked", async () => {
  await both(async (a, b) => {
    writeFileSync(join(A, "from-alice.md"), "hello bob\n");
    await a.sync(false);
    notices.length = 0;
    await b.sync(false);
    assert.equal(readFileSync(join(B, "from-alice.md"), "utf8"), "hello bob\n");
    assert.equal(b.state, "synced");
    assert.equal(b.bars[0].text, "✓ Synced");
    assert.deepEqual(notices, []); // automatic syncs say nothing
    assert.ok(editor.saved > 0, "open notes are saved before syncing");

    writeFileSync(join(B, "from-bob.md"), "hi alice\n");
    await b.sync(true);
    assert.ok(notices.some((n) => n.includes("1 uploaded")), notices.join("\n"));
    await a.sync(false);
    assert.equal(readFileSync(join(A, "from-bob.md"), "utf8"), "hi alice\n");
  });
});

test("an edit is uploaded by itself a moment later", async () => {
  await both(async (a, b) => {
    const started: Promise<void>[] = [];
    const sync = b.sync.bind(b);
    b.sync = (loud: boolean) => { const r = sync(loud); started.push(r); return r; };
    writeFileSync(join(B, "typed.md"), "typed in Obsidian\n");
    for (const h of b.edits) h(); // Obsidian reports the change
    await new Promise((r) => setTimeout(r, 150));
    assert.ok(started.length > 0, "the edit started a sync by itself");
    await Promise.all(started);
    await a.sync(false);
    assert.equal(readFileSync(join(A, "typed.md"), "utf8"), "typed in Obsidian\n");
  });
});

test("both changed one file: both versions kept and the user is told; notes merge", async () => {
  await both(async (a, b) => {
    writeFileSync(join(A, "plan.md"), "plan\n");
    await a.sync(false);
    await b.sync(false);
    writeFileSync(join(A, "pic.bin"), "alice");
    writeFileSync(join(B, "pic.bin"), "bob");
    writeFileSync(join(A, "plan.md"), "plan\nalice's line\n");
    writeFileSync(join(B, "plan.md"), "bob's line\nplan\n");
    await a.sync(false);
    notices.length = 0;
    await b.sync(false);
    assert.ok(notices.some((n) => n.includes("pic.bin was changed on two devices")), notices.join("\n"));
    const note = readFileSync(join(B, "plan.md"), "utf8");
    assert.ok(note.includes("alice's line") && note.includes("bob's line"), note);
  });
});

test("older versions of a file come back", async () => {
  await both(async (a) => {
    writeFileSync(join(A, "draft.md"), "first\n");
    await a.sync(false);
    writeFileSync(join(A, "draft.md"), "second\n");
    await a.sync(false);
    const rows = await a.setup.versions("draft.md");
    assert.ok(rows.length >= 2, JSON.stringify(rows));
    await a.setup.restore("draft.md", rows[rows.length - 1].rev);
    assert.equal(readFileSync(join(A, "draft.md"), "utf8"), "first\n");
  });
});

test("another program holding the folder: skipped quietly, no error", async () => {
  await both(async (_a, b) => {
    writeFileSync(join(B, ".tgsync", "lock"), String(process.pid)); // held by "someone" alive
    notices.length = 0;
    await b.sync(false);
    assert.equal(b.state, "synced");
    assert.deepEqual(notices, []);
    writeFileSync(join(B, ".tgsync", "lock"), "999999999"); // gone: taken over
    await b.sync(false);
    assert.ok(!existsSync(join(B, ".tgsync", "lock")), "lock released after the sync");
  });
});

test("not a vault, and sync switched off", async () => {
  const plain = mkdtempSync(join(tmpdir(), "tgsync-plain-"));
  const p = await start(plain);
  await p.sync(false);
  assert.equal(p.state, "not set up");
  await p.onunload();
  const q = await start(B, { account: "bob", auto: false });
  q.schedule();
  assert.equal(q.bars[0].text, "Sync paused");
  await q.onunload();
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
  const G = mkdtempSync(join(tmpdir(), "tgsync-gus-"));
  await both(async (a) => {
    const g = await start(G, { account: "gus" });
    await g.setup.join(await a.setup.invite());
    const asked = await requests(a);
    assert.equal(asked.length, 1);
    await a.refuse(asked[0]);
    assert.equal((await requests(a)).length, 0, "not asked again");
    await g.sync(false);
    assert.equal(g.state, "waiting");
    await g.onunload();
  });
});

test("owners make admins and owners; an admin cannot touch the owner", async () => {
  await both(async (a, b) => {
    const list = await a.setup.members();
    assert.ok(list.owner, "the vault's creator is its owner");
    const bob = list.members.find((m: any) => !m.you), alice = list.members.find((m: any) => m.you);
    await a.setup.giveAdmin(bob.id);
    assert.ok((await b.setup.members()).admin, "bob is an admin now");
    await assert.rejects(b.setup.remove(alice.id), /only remove plain members/);
    await assert.rejects(b.setup.takeAdmin(alice.id), /only an owner/);
    await a.setup.takeAdmin(bob.id);
    assert.ok(!(await b.setup.members()).admin, "the owner took it back");
    await a.setup.giveOwner(bob.id);
    assert.ok((await b.setup.members()).owner, "two owners");
    await b.setup.takeOwner(bob.id);
    await b.setup.dropAdmin();
    assert.ok(!(await b.setup.members()).admin, "bob stepped down");
    await a.setup.remove(bob.id);
    assert.equal((await a.setup.members()).members.length, 1);
    await b.sync(false);
    assert.equal(b.state, "error");
    assert.match(b.lastError, /removed/);
  });
});
