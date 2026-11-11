// SPDX-License-Identifier: AGPL-3.0-or-later
// Python CLI (alice) and the TypeScript engine (bob) share one sandbox group.
// Skipped when the repo's Python venv is missing.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { newIdentity, shortCode } from "../src/crypto.ts";
import { decodeInvite } from "../src/protocol.ts";
import { NodeFiles } from "../src/node/files.ts";
import { DirTransport } from "../src/node/sandbox.ts";
import { Vault } from "../src/vault.ts";

const REPO = new URL("../../", import.meta.url).pathname;
const PY = join(REPO, ".venv/bin/python");

test("Python CLI and TS engine on one sandbox group", { skip: !existsSync(PY) && "no Python venv" }, async () => {
  const tmp = await mkdtemp(join(tmpdir(), "tgsync-cross-"));
  const sb = join(tmp, "sb"), A = join(tmp, "alice"), B = join(tmp, "bob");
  const py = (...args: string[]) => {
    const env: NodeJS.ProcessEnv = { ...process.env, TGSYNC_SANDBOX: sb, TGSYNC_PROFILE: "alice" };
    delete env.TGSYNC_HOME;
    let out: string;
    try { out = execFileSync(PY, ["-m", "tgsync.cli", "--json", ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }
    catch (e: any) { out = e.stdout; }
    return JSON.parse(out);
  };
  try {
    const made = py("new", A, "--no-git");
    assert.ok(made.ok, JSON.stringify(made));
    const inv = decodeInvite(made.invite);
    const bob = await newIdentity();
    const tr = new DirTransport(inv.link);

    await Vault.postJoinRequest(tr, bob, inv.vaultId, "bob");
    assert.equal(py("accept", await shortCode(bob.recipient), "-C", A).accepted, "bob");

    await writeFile(join(A, "hello.md"), "hi from python\n");
    py("push", "-C", A);

    await mkdir(B);
    const v = await Vault.join(new NodeFiles(B), bob, tr, inv.vaultId);
    await v.pullChanges();
    assert.equal(await readFile(join(B, "hello.md"), "utf8"), "hi from python\n");

    await writeFile(join(B, "reply.md"), "hi from typescript\n");
    await mkdir(join(B, "empty"));
    await v.pushChanges();
    let out = py("pull", "-C", A);
    assert.ok(out.report.written.includes("reply.md") && out.report.written.includes("empty/"), JSON.stringify(out));
    assert.equal(await readFile(join(A, "reply.md"), "utf8"), "hi from typescript\n");

    await rename(join(B, "reply.md"), join(B, "renamed.md"));   // TS rename, no re-upload
    await writeFile(join(A, "hello.md"), "python edit\n");      // both edit hello.md
    await writeFile(join(B, "hello.md"), "typescript edit\n");
    py("push", "-C", A);
    await v.fetchChanges();
    assert.deepEqual((await v.incoming()).map((x) => [x.path, x.who, x.also_local]), [["hello.md", "alice", true]]);
    const pushed = await v.pushChanges();
    assert.equal(pushed.conflicts.length, 1);
    await v.pullChanges();
    out = py("pull", "-C", A);
    const status = py("status", "-C", A);
    assert.deepEqual(status.incoming, []);
    assert.deepEqual(status.pending, []);
    assert.equal(await readFile(join(A, "renamed.md"), "utf8"), "hi from typescript\n");
    assert.equal(existsSync(join(A, "reply.md")), false);

    py("remove", "bob", "--yes", "-C", A);                       // Python rotates the key; TS sees it
    await assert.rejects(v.pullChanges(), /removed/);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});
