// SPDX-License-Identifier: AGPL-3.0-or-later
// The Node CLI (dist/tgsync.mjs, built by `npm test`) on a sandbox group: restore from the group,
// log, bare `tgsync`. The full two-person story is sandbox.test.ts.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../dist/tgsync.mjs", import.meta.url));

test("restore brings back versions from the group; log and bare tgsync", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "tgsync-cli-"));
  const A = join(tmp, "alice");
  const run = (args: string[], input = "", cwd = tmp) => {
    const env: NodeJS.ProcessEnv = { ...process.env, TGSYNC_SANDBOX: join(tmp, "sb"), TGSYNC_PROFILE: "alice" };
    delete env.TGSYNC_HOME;
    const r = spawnSync("node", [BIN, ...args], { env, cwd, input, encoding: "utf8" });
    return { rc: r.status, out: r.stdout, err: r.stderr };
  };
  const json = (...args: string[]) => JSON.parse(run(["--json", ...args]).out);
  try {
    assert.ok(json("new", A).ok);
    for (const text of ["one", "two", "three"]) {
      await writeFile(join(A, "n.md"), text);
      assert.deepEqual(json("push", "-C", A).report.pushed_paths.filter((p: string) => p === "n.md"), ["n.md"]);
    }
    const log = json("log", "n.md", "-C", A).log;
    assert.deepEqual(log.map((r: any) => [r.op, r.who]), [["put", "alice"], ["put", "alice"], ["put", "alice"]]);

    // path given: pick a version
    const shown = run(["restore", "n.md", "-C", A], "3\n");           // oldest of three
    assert.equal(shown.rc, 0, shown.err);
    assert.match(shown.out, /Versions of n\.md/);
    assert.equal(await readFile(join(A, "n.md"), "utf8"), "one");

    // unsaved edits are never overwritten
    await writeFile(join(A, "n.md"), "not uploaded");
    const newest = /1\) (\d+\.\d+)/.exec(shown.out)![1];
    const refused = json("restore", "n.md", newest, "-C", A);
    assert.equal(refused.ok, false);
    assert.match(refused.error, /tgsync push/);
    assert.equal(await readFile(join(A, "n.md"), "utf8"), "not uploaded");
    json("push", "-C", A);

    // nothing given: pick a file, then a version
    const picked = run(["restore", "-C", A], "1\n2\n");
    assert.equal(picked.rc, 0, picked.err);
    assert.equal(await readFile(join(A, "n.md"), "utf8"), "three");     // second newest after "not uploaded"

    assert.match(json("restore", "n.md", "99.0", "-C", A).error, /not a version of n\.md/);
    assert.match(json("restore", "n.md", "-C", A).error, /--json never asks/);

    // bare tgsync: status inside a vault, help outside
    const inside = run([], "", A);
    assert.equal(inside.rc, 0, inside.err);
    assert.match(inside.out, /M n\.md/);
    const outside = run([]);
    assert.match(outside.out, /Commands:/);
    assert.match(outside.out, /tgsync new \./);

    // one run per folder: we wait for a live holder (here a process that ends after 3 s), and take
    // over a lock whose process is gone
    const lock = join(A, ".tgsync", "lock");
    // (detached, so the system collects it when it ends; a child of this blocked test would linger)
    const holder = spawnSync("node", ["-e", "const c = require('child_process').spawn(process.execPath, " +
      "['-e', 'setTimeout(() => {}, 3000)'], { detached: true, stdio: 'ignore' }); c.unref(); console.log(c.pid)"], { encoding: "utf8" });
    await writeFile(lock, holder.stdout.trim());
    const t0 = Date.now();
    assert.ok(json("push", "-C", A).ok);
    assert.ok(Date.now() - t0 >= 2000, "waited for the holder");
    await writeFile(lock, "999999999"); // no such process
    assert.ok(json("push", "-C", A).ok);
    assert.equal(await readFile(lock, "utf8").catch(() => "released"), "released");
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

// Ported from the Python suite (tests/test_invites_profiles.py on main).
test("helpful refusals: not a vault lists yours, a vault cannot be made twice, unsafe profile names", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "tgsync-cli-"));
  const run = (args: string[], profile = "alice") => {
    const env: NodeJS.ProcessEnv = { ...process.env, TGSYNC_SANDBOX: join(tmp, "sb"), TGSYNC_PROFILE: profile };
    delete env.TGSYNC_HOME;
    const r = spawnSync("node", [BIN, "--json", ...args], { env, cwd: tmp, input: "", encoding: "utf8" });
    return JSON.parse(r.stdout);
  };
  try {
    const A = join(tmp, "alice"), plain = join(tmp, "plain");
    assert.ok(run(["new", A]).ok);
    const twice = run(["new", A]);
    assert.equal(twice.ok, false);
    assert.match(twice.error, /already a tgsync vault/);
    const notVault = run(["status", "-C", plain]);
    assert.equal(notVault.ok, false);
    assert.match(notVault.error, /is not a tgsync vault/);
    assert.match(notVault.error, /Your vaults on this computer/);
    assert.ok(notVault.error.includes("alice"), notVault.error);
    const bad = run(["new", join(tmp, "b")], "../evil"); // a vault's own saved profile wins elsewhere
    assert.equal(bad.ok, false);
    assert.match(bad.error, /profile names may only use/);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});
