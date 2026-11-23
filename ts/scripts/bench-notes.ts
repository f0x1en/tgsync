// SPDX-License-Identifier: AGPL-3.0-or-later
// Many small notes between two people through a sandbox group: first push, pull, then one edit.
// No Telegram, so this measures tgsync itself.   npm run bench-notes -- [notes, default 5000]
import { mkdir, mkdtemp, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newIdentity } from "../src/crypto.ts";
import { w } from "../src/core.ts";
import { NodeFiles } from "../src/node/files.ts";
import { DirTransport, PREFIX } from "../src/node/sandbox.ts";
import { Vault } from "../src/vault.ts";

const n = Number(process.argv[2] ?? 5000);
const tmp = await mkdtemp(join(tmpdir(), "tgsync-bench-notes-"));
const A = join(tmp, "alice"), B = join(tmp, "bob"), G = join(tmp, "group");
try {
  for (const d of [A, B, G]) await mkdir(d);
  for (let i = 0; i < n; i++) {
    await mkdir(join(A, `d${i % 50}`), { recursive: true });
    const f = join(A, `d${i % 50}`, `note${i}.md`);
    await writeFile(f, `# Note ${i}\n\n${"Some text. ".repeat(40)}\n`);
    // Written an hour ago, like a real vault (files changed in the last 2 s are always hashed again).
    await utimes(f, new Date(Date.now() - 3600_000), new Date(Date.now() - 3600_000));
  }
  const link = PREFIX + G;
  const ia = await newIdentity(), ib = await newIdentity();
  const a = await Vault.create(new NodeFiles(A), ia, new DirTransport(link), "alice");
  await a.addMember(ib.recipient, "bob", w.signerOf(ib.signing));
  const b = await Vault.join(new NodeFiles(B), ib, new DirTransport(link), a.vaultId!);
  const time = async (f: () => Promise<unknown>) => { const t = performance.now(); await f(); return (performance.now() - t) / 1000; };
  const push = await time(() => a.pushChanges());
  const pull = await time(() => b.pullChanges());
  await writeFile(join(A, "d7", "note7.md"), "# Note 7\n\nchanged\n");
  const push1 = await time(() => a.pushChanges());
  const pull1 = await time(() => b.pullChanges());
  const idle = await time(() => a.pushChanges()); // nothing changed: a scan only
  const ok = (await readFile(join(B, "d7", "note7.md"), "utf8")) === "# Note 7\n\nchanged\n";
  console.log(JSON.stringify({ notes: n, first_push_s: +push.toFixed(1), first_pull_s: +pull.toFixed(1),
    one_edit_push_s: +push1.toFixed(2), one_edit_pull_s: +pull1.toFixed(2), idle_push_s: +idle.toFixed(2), ok }));
  if (!ok) process.exitCode = 1;
} finally {
  await rm(tmp, { recursive: true, force: true });
}
