// SPDX-License-Identifier: AGPL-3.0-or-later
// The per-profile store of our last record number in each vault (it must survive a re-join).
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { appDir, seqStore } from "../src/node/home.ts";

test("record numbers: one file per vault, never go down, older seqs.json still counts", () => {
  const home = mkdtempSync(join(tmpdir(), "tgsync-home-"));
  process.env.TGSYNC_HOME = home;
  try {
    const s = seqStore("p");
    assert.equal(s.get("aa11"), 0);
    s.set("aa11", 5);
    s.set("aa11", 3); // never lower
    s.set("bb22", 9);
    assert.deepEqual([s.get("aa11"), s.get("bb22")], [5, 9]);
    writeFileSync(join(appDir("p"), "seqs.json"), JSON.stringify({ cc33: 7, aa11: 2 }));
    assert.deepEqual([seqStore("p").get("cc33"), seqStore("p").get("aa11")], [7, 5]);
    writeFileSync(join(appDir("p"), "seqs", "bb22"), "garbage");
    assert.throws(() => s.get("bb22"), /damaged/);
    assert.throws(() => s.get("../x"), /unexpected vault id/);
  } finally {
    delete process.env.TGSYNC_HOME;
    rmSync(home, { recursive: true, force: true });
  }
});

test("reading a small file in chunks does not allocate a whole chunk (hashing 20 000 notes stays fast)", async () => {
  const { NodeFiles } = await import("../src/node/files.ts");
  const dir = mkdtempSync(join(tmpdir(), "tgsync-files-"));
  try {
    writeFileSync(join(dir, "n.md"), "a small note");
    const parts: Uint8Array[] = [];
    for await (const p of new NodeFiles(dir).readChunks("n.md", 32 * 1024 * 1024)) parts.push(p);
    assert.equal(Buffer.concat(parts).toString(), "a small note");
    assert.ok(parts.every((p) => p.buffer.byteLength <= 64 * 1024), `buffer of ${parts[0].buffer.byteLength} bytes`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
