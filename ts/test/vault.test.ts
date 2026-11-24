// SPDX-License-Identifier: AGPL-3.0-or-later
// The engine, two people on an in-memory group with real folders (ported from tests/test_sync.py).
import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rename, rm, rmdir, stat, unlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { newIdentity } from "../src/crypto.ts";
import { makeIgnore, DEFAULT_IGNORE } from "../src/paths.ts";
import { NodeFiles } from "../src/node/files.ts";
import { FakeChannel, OfflineError } from "../src/transport.ts";
import { Vault } from "../src/vault.ts";
import { w } from "../src/core.ts";
import { KIND } from "../src/protocol.ts";

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
  await a.vault.addMember(ib.recipient, "bob", w.signerOf(ib.signing));
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

test("both edit the same note: the edits merge, no conflict copy", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("n.md", "first line\nsecond line\n");
  await sync(a); await sync(b);
  await a.write("n.md", "first line, by alice\nsecond line\n");
  await b.write("n.md", "first line\nsecond line\nthird line, by bob\n");
  await sync(a);
  const rb = await sync(b);
  await sync(a);
  assert.equal(rb.conflicts.length, 0);
  assert.deepEqual(await a.files(), ["n.md"]);
  assert.equal(await a.read("n.md"), "first line, by alice\nsecond line\nthird line, by bob\n");
  assert.equal(await b.read("n.md"), await a.read("n.md"));
  await cleanup();
});

test("both edit the same binary file: conflict copy, nothing lost", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("n.bin", "base");
  await sync(a); await sync(b);
  await a.write("n.bin", "alice edit");
  await b.write("n.bin", "bob edit");
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
  await a.vault.addMember(ic.recipient, "carol", w.signerOf(ic.signing));
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

test("huge files stream: never read or written whole, verified byte for byte", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "tgsync-big-"));
  const ch = new FakeChannel();
  const A = join(tmp, "a"), B = join(tmp, "b");
  await mkdir(A); await mkdir(B);
  const whole: string[] = [];
  const spy = (root: string) => {
    const f = new NodeFiles(root);
    const read = f.read.bind(f), write = f.write.bind(f);
    f.read = async (p) => { const d = await read(p); if (d.length > 1_000_000) whole.push(`read ${p}`); return d; };
    f.write = async (p, d, m) => { if (d.length > 1_000_000) whole.push(`write ${p}`); return write(p, d, m); };
    return f;
  };
  const ia = await newIdentity(), ib = await newIdentity();
  const a = await Vault.create(spy(A), ia, ch.transport(), "a");
  await a.addMember(ib.recipient, "b", w.signerOf(ib.signing));
  const b = await Vault.join(spy(B), ib, ch.transport(), a.vaultId!);
  const big = new Uint8Array(5 * 1024 * 1024 + 123).map((_, i) => (i * 7919) % 256);
  await writeFile(join(A, "video.bin"), big);
  const rep = await a.pushChanges(1024 * 1024);
  assert.deepEqual(rep.pushed_paths.sort(), [".tgsyncignore", "video.bin"]);
  assert.equal([...ch.messages.values()].filter(([k]) => k === "c").length, 6);
  await b.pullChanges();
  assert.deepEqual(new Uint8Array(await readFile(join(B, "video.bin"))), big);
  assert.deepEqual((await b.status()).pending, []);
  assert.deepEqual(whole, []);
  await rm(tmp, { recursive: true, force: true });
});

test("only admins change members; admin rights pass on", async () => {
  const { a, b, ch, cleanup } = await pair();
  const ic = await newIdentity();
  await assert.rejects(b.vault.addMember(ic.recipient, "carol", w.signerOf(ic.signing)), /only an admin/);
  await a.vault.giveAdmin("bob");
  await b.vault.pull();
  assert.ok(b.vault.isAdmin);
  await b.vault.addMember(ic.recipient, "carol", w.signerOf(ic.signing));
  await a.vault.dropAdmin();
  await a.vault.pull();
  assert.ok(!a.vault.isAdmin);
  assert.deepEqual(a.vault.members.map((m) => [m.name, m.admin]), [["alice", false], ["bob", true], ["carol", false]]);
  const before = ch.sent;
  await assert.rejects(a.vault.removeMember("carol"), /only an admin/);
  assert.equal(ch.sent, before, "nothing was posted");
  await cleanup();
});

test("a push cut off by the network is simply retried; nothing is lost or doubled", async () => {
  const { a, b, ch, cleanup } = await pair();
  await a.write("x.md", "one\n");
  await a.write("y.bin", "two");
  const send = a.vault.transport.send;
  let fail = true;
  a.vault.transport.send = async (kind, data) => {
    if (kind === "r" && fail) { fail = false; throw new Error("network down"); }
    return send(kind, data);
  };
  await assert.rejects(a.vault.pushChanges(), /network down/);
  const again = await a.vault.pushChanges();
  assert.deepEqual(again.pushed_paths.sort(), [".tgsyncignore", "x.md", "y.bin"]);
  assert.deepEqual((await a.vault.pushChanges()).pushed_paths, []);
  await sync(b);
  assert.equal(await b.read("x.md"), "one\n");
  assert.equal(await b.read("y.bin"), "two");
  assert.deepEqual((await b.vault.status()).problems, []);
  await cleanup();
});

test("restore brings back an old version of a binary file from the group", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("pic.bin", "v1");
  await sync(a);
  await a.write("pic.bin", "v2");
  await sync(a);
  await sync(b);
  const vers = await b.vault.versions("pic.bin");
  assert.equal(vers.length, 2);
  await b.vault.restoreVersion("pic.bin", vers[1].rev);   // the older one
  assert.equal(await b.read("pic.bin"), "v1");
  await sync(b); await sync(a);
  assert.equal(await a.read("pic.bin"), "v1");
  await cleanup();
});

test("a synced file that cannot be read right now is never pushed as a delete", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("busy.md", "v1\n");
  await sync(a); await sync(b);
  await a.write("busy.md", "v2, being saved\n");
  const files: any = (a.vault as any).files;
  const read = files.read.bind(files);
  files.read = async (p: string) => { if (p === "busy.md") throw new Error("EBUSY: locked by another app"); return read(p); };
  const rep = await a.vault.pushChanges();
  assert.ok(rep.skipped.some((s) => s.startsWith("busy.md:")), JSON.stringify(rep.skipped));
  assert.ok(!rep.pushed_paths.includes("busy.md"));
  await sync(b);
  assert.equal(await b.read("busy.md"), "v1\n", "bob still has it");
  files.read = read;
  await sync(a); await sync(b);
  assert.equal(await b.read("busy.md"), "v2, being saved\n");
  await cleanup();
});

test("a note with a byte-order mark syncs", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("bom.md", "﻿hello\n");
  await sync(a); await sync(b);
  assert.equal(await b.read("bom.md"), "﻿hello\n");
  assert.deepEqual((await b.vault.status()).problems, []);
  await cleanup();
});

test("a file stored under a decomposed (NFD) name is read and kept, not deleted", async () => {
  const { a, b, cleanup } = await pair();
  const nfd = "café.md", nfc = "café.md";
  await a.write(nfd, "from a mac\n");
  await sync(a); await sync(b);
  assert.equal(await b.read(nfc), "from a mac\n");
  assert.deepEqual((await a.vault.pendingChanges()).map((c) => [c.op, c.path]), []);
  await a.write(nfd, "edited\n");
  await sync(a); await sync(b);
  assert.equal(await b.read(nfc), "edited\n");
  assert.ok(await a.exists(nfd));
  await cleanup();
});

test("a folder of the old TypeScript engine upgrades without uploading everything again", async () => {
  const { a, b, ch, cleanup } = await pair();
  await a.write("n.md", "note\n");
  await a.write("x.bin", "data");
  await sync(a); await sync(b);
  // Make bob's folder look like one the old engine wrote: only .tgsync/state.json, with its synced map.
  const synced: { [p: string]: [string, number, number, number] } = {};
  for (const p of ["n.md", "x.bin", ".tgsyncignore"]) {
    const st = await stat(join(b.root, p));
    synced[p] = [createHash("sha256").update(await readFile(join(b.root, p))).digest("hex"), st.size, st.mtimeMs, st.mtimeMs + 10_000];
  }
  await rm(join(b.root, ".tgsync"), { recursive: true });
  await mkdir(join(b.root, ".tgsync"));
  await writeFile(join(b.root, ".tgsync", "state.json"), JSON.stringify({ v: 1, vault_id: a.vault.vaultId, synced }));
  const v = await Vault.open(new NodeFiles(b.root), (b.vault as any).me, ch.transport());
  const before = ch.sent;
  const rep = await v.pushChanges();
  assert.deepEqual(rep.pushed_paths, []);
  assert.equal(ch.sent, before);
  await cleanup();
});

test("a re-joined folder continues the profile's record numbers (never reuses one)", async () => {
  const { a, ch, cleanup } = await pair();
  const seqs = new Map<string, number>();
  const me: any = (a.vault as any).me;
  me.seqs = { get: (v: string) => seqs.get(v) ?? 0, set: (v: string, n: number) => seqs.set(v, n) };
  await a.write("one.md", "1\n");
  await a.vault.pushChanges();
  const used = seqs.get(a.vault.vaultId!)!;
  assert.ok(used >= 1);
  // A fresh folder for the same person and vault (as after a re-join) starts from the stored seq.
  const dir = await mkdtemp(join(tmpdir(), "tgsync-rejoin-"));
  const v = await Vault.join(new NodeFiles(dir), me, ch.transport(), a.vault.vaultId!);
  assert.equal(v.engine.sentSeq(), used);
  await rm(dir, { recursive: true, force: true });
  await cleanup();
});

test("a join request posted again with someone else's signing key is refused", async () => {
  const { a, ch, cleanup } = await pair();
  const carol = await newIdentity(), mallory = await newIdentity();
  await Vault.postJoinRequest(ch.transport(), carol, a.vault.vaultId!, "carol");
  // mallory replays carol's key with her own signing key
  await Vault.postJoinRequest(ch.transport(), { ...carol, signing: mallory.signing }, a.vault.vaultId!, "carol");
  const reqs = await a.vault.pendingRequests();
  assert.equal(reqs.length, 1);
  assert.ok(reqs[0].conflict);
  await assert.rejects(a.vault.acceptRequest(reqs[0]), /different signing keys/);
  await cleanup();
});

test("losing the connection during a pull stops it with one error; the next pull finishes", async () => {
  const { a, b, ch, cleanup } = await pair();
  const big = new Uint8Array(300 * 1024).map((_, i) => (i * 7) % 251); // above INLINE_MAX: sent as chunks
  await a.write("big.bin", big);
  await a.write("big2.bin", big.slice(1));
  await a.write("n1.md", "one");
  await a.write("n2.md", "two");
  await a.vault.pushChanges();
  const t = (b.vault as any).transport;
  const fetch = t.fetch;
  let calls = 0;
  t.fetch = async (id: number) => {
    if (ch.messages.get(id)![0] === KIND.chunk) { calls++; throw new OfflineError("no connection to Telegram"); }
    return fetch(id);
  };
  await assert.rejects(b.vault.pullChanges(), OfflineError);
  assert.equal(calls, 1, "stopped at the first failure instead of trying every file");
  t.fetch = fetch;
  await b.vault.pullChanges();
  assert.deepEqual(await b.files(), ["big.bin", "big2.bin", "n1.md", "n2.md"]);
  assert.deepEqual(new Uint8Array(await readFile(join(b.root, "big.bin"))), big);
  assert.equal(await b.read("n2.md"), "two");
  await cleanup();
});

test("losing the connection during a push: pushing again finishes, nothing lost or doubled", async () => {
  const { a, b, ch, cleanup } = await pair();
  const big = new Uint8Array(300 * 1024).map((_, i) => (i * 13) % 251);
  await a.write("big.bin", big);
  await a.write("n1.md", "one");
  const t = (a.vault as any).transport;
  const send = t.send;
  let sent = 0;
  t.send = async (kind: string, data: Uint8Array) => {
    if (sent++ >= 1) throw new OfflineError("no connection to Telegram"); // the first message goes out
    return send(kind, data);
  };
  await assert.rejects(a.vault.pushChanges(), OfflineError);
  t.send = send;
  await a.vault.pushChanges();
  const again = await a.vault.pushChanges();
  assert.deepEqual(again.pushed_paths, [], "everything is up already");
  await b.vault.pullChanges();
  assert.deepEqual(await b.files(), ["big.bin", "n1.md"]);
  assert.deepEqual(new Uint8Array(await readFile(join(b.root, "big.bin"))), big);
  assert.equal(await b.read("n1.md"), "one");
  const records = [...ch.messages.values()].filter(([k]) => k === KIND.record).length;
  assert.ok(records <= 3, `records posted: ${records}`);
  await cleanup();
});

// Ported from the Python suite (tests/test_sync.py on main): host behaviors no other test covers.

test("the group sees only ciphertext: no file names or contents", async () => {
  const { a, ch, cleanup } = await pair();
  await a.write("secret-plans.md", "TOP SECRET LAUNCH CODES");
  await a.vault.pushChanges();
  const blob = Buffer.concat([...ch.messages.values()].filter(([k]) => k !== KIND.descriptor).map(([, d]) => d));
  assert.ok(!blob.includes("TOP SECRET") && !blob.includes("secret-plans"));
  await cleanup();
});

test("editor scratch files are not synced", async () => {
  const { a, b, cleanup } = await pair();
  for (const junk of [".note.md.swp", "note.md~", "4913", ".#lock", "#auto#", ".netrwhist"]) await a.write(junk, "junk");
  await a.write("note.md", "real");
  await sync(a); await sync(b);
  assert.deepEqual(await b.files(), ["note.md"]);
  await cleanup();
});

test("an edit with the same size and modification time is still detected", async () => {
  const { a, b, cleanup } = await pair();
  await a.write("n.md", "v1");
  await sync(a);
  const st = await stat(join(a.root, "n.md"));
  await a.write("n.md", "v2");
  await utimes(join(a.root, "n.md"), st.atime, st.mtime); // identical size and mtime
  await sync(a);
  await sync(b);
  assert.equal(await b.read("n.md"), "v2");
  await cleanup();
});

test("joining with the same files already on disk uploads only real differences", async () => {
  const { a, ch, cleanup } = await pair();
  await a.write("same.md", "shared text");
  await a.write("other.md", "alice's version");
  await sync(a);
  const c = new Peer(join(dirname(a.root), "carol"));
  await mkdir(c.root);
  await c.write("same.md", "shared text"); // e.g. re-joined in her old folder: files there, state fresh
  await c.write("other.md", "carol's own edit");
  const ic = await newIdentity();
  await a.vault.addMember(ic.recipient, "carol", w.signerOf(ic.signing));
  c.vault = await Vault.join(new NodeFiles(c.root), ic, ch.transport(), a.vault.vaultId!);
  await c.vault.pullChanges(); // as `tgsync join` does
  const rep = await c.vault.pushChanges();
  assert.ok(!rep.pushed_paths.includes("same.md"), "identical to the vault: not uploaded again");
  assert.ok(rep.pushed_paths.includes("other.md"), "a real difference is shared, not lost");
  assert.equal(await c.read("same.md"), "shared text");
  await cleanup();
});

test("a big upload cut off midway continues from where it stopped; changed parts are sent again", async () => {
  const { a, b, ch, cleanup } = await pair();
  const big = new Uint8Array(1_000_000).map((_, i) => (i * 31) % 251); // 1 MB in 100 KB chunks: 10 parts
  await a.write("big.bin", big);
  const t = (a.vault as any).transport;
  const send = t.send;
  let n = 0;
  t.send = async (kind: string, data: Uint8Array) => {
    if (kind === KIND.chunk && ++n > 6) throw new OfflineError("no connection to Telegram"); // 6 parts get out
    return send(kind, data);
  };
  await assert.rejects(a.vault.pushChanges(100_000), OfflineError);
  t.send = send;
  const before = [...ch.messages.values()].filter(([k]) => k === KIND.chunk).length;
  await a.vault.pushChanges(100_000);
  const after = [...ch.messages.values()].filter(([k]) => k === KIND.chunk).length;
  assert.equal(after - before, 4, "only the 4 missing parts were sent");
  await b.vault.pullChanges();
  assert.ok(Buffer.from(big).equals(await readFile(join(b.root, "big.bin"))));

  // cut off again, then the file is edited (new mtime): the old parts are not reused
  const big2 = big.map((x) => x ^ 1);
  await a.write("big.bin", big2);
  n = 0;
  t.send = async (kind: string, data: Uint8Array) => {
    if (kind === KIND.chunk && ++n > 6) throw new OfflineError("no connection to Telegram");
    return send(kind, data);
  };
  await assert.rejects(a.vault.pushChanges(100_000), OfflineError);
  t.send = send;
  const big3 = big2.slice();
  big3[250_000] ^= 0xff;
  await a.write("big.bin", big3);
  await utimes(join(a.root, "big.bin"), new Date(Date.now() + 5000), new Date(Date.now() + 5000)); // surely a new mtime
  const mid = [...ch.messages.values()].filter(([k]) => k === KIND.chunk).length;
  await a.vault.pushChanges(100_000);
  const end = [...ch.messages.values()].filter(([k]) => k === KIND.chunk).length;
  assert.equal(end - mid, 10, "a changed file is uploaded whole");
  await b.vault.pullChanges();
  assert.ok(Buffer.from(big3).equals(await readFile(join(b.root, "big.bin"))));
  assert.equal((a.vault as any).state.d.uploads, undefined, "nothing left to resume");
  await cleanup();
});

test("pushing with nothing changed reads no file; nor do files the last pull wrote", async () => {
  const { a, b, cleanup } = await pair();
  const past = new Date(Date.now() - 3600_000); // not "just modified": no re-hash for safety
  for (let i = 0; i < 20; i++) {
    await a.write(`n${i}.md`, `note ${i}`);
    await utimes(join(a.root, `n${i}.md`), past, past);
  }
  await a.write("x.bin", new Uint8Array(300 * 1024));
  await utimes(join(a.root, "x.bin"), past, past);
  await utimes(join(a.root, ".tgsyncignore"), past, past); // made by the vault just now
  await a.vault.pushChanges();
  const count = (p: Peer) => {
    const f = (p.vault as any).files;
    const n = { reads: 0 };
    const [read, readChunks] = [f.read.bind(f), f.readChunks.bind(f)];
    f.read = (path: string) => { if (!path.startsWith(".tgsync")) n.reads++; return read(path); };
    f.readChunks = (path: string, size: number) => { n.reads++; return readChunks(path, size); };
    return n;
  };
  const na = count(a);
  await a.vault.pushChanges();
  assert.equal(na.reads, 0, "an idle push read files");
  await utimes(join(b.root, ".tgsyncignore"), past, past); // made at join, same as alice's: not rewritten
  await b.vault.pullChanges();
  const nb = count(b);
  await b.vault.pushChanges();
  assert.equal(nb.reads, 0, "files the pull wrote were read again");
  await cleanup();
});
