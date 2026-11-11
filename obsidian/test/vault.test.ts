// SPDX-License-Identifier: AGPL-3.0-or-later
// The engine, two people on an in-memory group with real folders (ported from tests/test_sync.py).
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rename, rm, rmdir, stat, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { newIdentity } from "../src/crypto.ts";
import { makeIgnore, DEFAULT_IGNORE } from "../src/paths.ts";
import { NodeFiles } from "../src/node/files.ts";
import { FakeChannel } from "../src/transport.ts";
import { Vault } from "../src/vault.ts";

const V = JSON.parse(readFileSync(new URL("../../spec/vectors.json", import.meta.url), "utf8"));

class Peer {
  vault!: Vault;
  constructor(public root: string) {}
  async write(rel: string, data: string | Uint8Array) {
    await mkdir(dirname(join(this.root, rel)), { recursive: true });
    await writeFile(join(this.root, rel), data);
  }
  read = (rel: string) => readFile(join(this.root, rel), "utf8");
  exists = (rel: string) => stat(join(this.root, rel)).then(() => true, () => false);
  async files(dir = ""): Promise<string[]> {
    const out: string[] = [];
    for (const e of await readdir(join(this.root, dir), { withFileTypes: true })) {
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isDirectory()) { if (e.name !== ".tgsync") out.push(...await this.files(rel)); }
      else if (e.name !== ".tgsyncignore") out.push(rel);
    }
    return out.sort();
  }
}

async function pair(): Promise<{ a: Peer; b: Peer; ch: FakeChannel; cleanup: () => Promise<void> }> {
  const tmp = await mkdtemp(join(tmpdir(), "tgsync-ts-"));
  const ch = new FakeChannel();
  const a = new Peer(join(tmp, "alice")), b = new Peer(join(tmp, "bob"));
  const ia = await newIdentity(), ib = await newIdentity();
  await mkdir(a.root); await mkdir(b.root);
  a.vault = await Vault.create(new NodeFiles(a.root), ia, ch.transport(), "alice");
  await a.vault.addMember(ib.recipient, "bob");
  b.vault = await Vault.join(new NodeFiles(b.root), ib, ch.transport(), a.vault.vaultId!);
  return { a, b, ch, cleanup: () => rm(tmp, { recursive: true, force: true }) };
}

/** What the old `tgsync sync` did: push, then pull. */
async function sync(p: Peer) {
  const r = await p.vault.pushChanges();
  const r2 = await p.vault.pullChanges();
  return { ...r2, pushed_paths: r.pushed_paths, conflicts: [...r.conflicts, ...r2.conflicts] };
}

test("ignore rules match Python's", () => {
  assert.equal(DEFAULT_IGNORE, V.ignore.default);
  const ig = makeIgnore(V.ignore.extra);
  for (const c of V.ignore.cases) assert.equal(ig(c.path), c.ignored, c.path);
});

test("roundtrip, small files batched into one message, big file in chunks", async () => {
  const { a, b, ch, cleanup } = await pair();
  for (let i = 0; i < 50; i++) await a.write(`n/${i}.md`, `note ${i}`);
  const big = new Uint8Array(700_000).map((_, i) => i % 251);
  await a.write("big.bin", big);
  const before = ch.sent;
  await a.vault.pushChanges(300_000);
  assert.equal(ch.sent - before, 1 + 3); // one record for 51 entries + 3 chunks
  await b.vault.pullChanges();
  assert.deepEqual(await b.files(), await a.files());
  assert.deepEqual(new Uint8Array(await readFile(join(b.root, "big.bin"))), big);
  await cleanup();
});

test("pull uploads nothing, push touches no local files", async () => {
  const { a, b, ch, cleanup } = await pair();
  await b.write("draft.md", "mine");
  const before = ch.sent;
  await b.vault.pullChanges();
  assert.equal(ch.sent, before);
  await a.write("x.md", "from alice");
  await a.vault.pushChanges();
  await b.vault.pushChanges();
  assert.equal(await b.exists("x.md"), false);
  await a.vault.pullChanges();
  assert.equal(await a.read("draft.md"), "mine");
  await cleanup();
});

test("edits and deletes propagate", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("n.md", "1");
  await sync(a); await sync(b);
  await a.write("n.md", "2");
  await sync(a); await sync(b);
  assert.equal(await b.read("n.md"), "2");
  await unlink(join(b.root, "n.md"));
  await sync(b); await sync(a);
  assert.equal(await a.exists("n.md"), false);
  await cleanup();
});

test("both edit the same note: conflict copy, nothing lost", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("n.md", "base");
  await sync(a); await sync(b);
  await a.write("n.md", "alice edit");
  await b.write("n.md", "bob edit");
  await sync(a);
  const rb = await sync(b);
  await sync(a);
  assert.equal(rb.conflicts.length, 1);
  assert.deepEqual(await a.files(), await b.files());
  const all = await Promise.all((await a.files()).map((f) => a.read(f)));
  assert.ok(all.includes("alice edit") && all.includes("bob edit"));
  await cleanup();
});

test("an edit beats a delete", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("k.md", "v1");
  await sync(a); await sync(b);
  await unlink(join(a.root, "k.md"));
  await b.write("k.md", "bob kept working");
  await sync(a); await sync(b); await sync(a);
  assert.equal(await a.read("k.md"), "bob kept working");
  await cleanup();
});

test("rename uploads no content again", async () => {
  const { a, b, ch, cleanup } = await pair();
  await a.write("big.bin", new Uint8Array(300_000).fill(7));
  await sync(a); await sync(b);
  await mkdir(join(a.root, "moved"));
  await rename(join(a.root, "big.bin"), join(a.root, "moved/big.bin"));
  const before = ch.sent;
  await a.vault.pushChanges();
  assert.equal(ch.sent - before, 1);
  await sync(b);
  assert.deepEqual(await b.files(), ["moved/big.bin"]);
  await cleanup();
});

test("empty folders sync and delete", async () => {
  const { a, b, cleanup } = await pair();
  await mkdir(join(a.root, "ideas/later"), { recursive: true });
  await sync(a); await sync(b);
  assert.ok((await stat(join(b.root, "ideas/later"))).isDirectory());
  await rmdir(join(b.root, "ideas/later"));
  await sync(b); await sync(a);
  assert.equal(await a.exists("ideas/later"), false);
  await cleanup();
});

test("status warns when someone else changed your file; log says who", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("plan.md", "v1");
  await sync(a); await sync(b);
  await b.write("plan.md", "bob's idea");
  await a.write("plan.md", "alice's idea");
  await a.vault.pushChanges();
  await b.vault.fetchChanges();
  assert.deepEqual(await b.vault.incoming(), [{ op: "put", path: "plan.md", who: "alice", also_local: true }]);
  assert.equal(await b.read("plan.md"), "bob's idea");
  const log = await b.vault.log("plan.md");
  assert.deepEqual(log.map((r) => r.who), ["alice", "alice"]);
  await cleanup();
});

test("removed member cannot read new files; late joiner gets full history", async () => {
  const { a, b, ch, cleanup } = await pair();
  await a.write("old.md", "before");
  await sync(a); await sync(b);
  await a.vault.removeMember("bob");
  await a.write("secret.md", "after");
  await sync(a);
  await assert.rejects(b.vault.pullChanges(), /removed/);
  assert.equal(await b.exists("secret.md"), false);
  const c = new Peer(join(dirname(a.root), "carol"));
  await mkdir(c.root);
  const ic = await newIdentity();
  await a.vault.addMember(ic.recipient, "carol");
  c.vault = await Vault.join(new NodeFiles(c.root), ic, ch.transport(), a.vault.vaultId!);
  await c.vault.pullChanges();
  assert.deepEqual(await c.files(), ["old.md", "secret.md"]);
  await cleanup();
});

test("state survives reopening the vault", async () => {
  const { a, ch, cleanup } = await pair();
  await a.write("n.md", "x");
  await sync(a);
  const again = await Vault.open(new NodeFiles(a.root), a.vault.me, ch.transport());
  assert.equal(again.members.length, 2);
  assert.deepEqual((await again.status()).pending, []);
  await cleanup();
});
