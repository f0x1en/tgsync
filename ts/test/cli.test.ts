// SPDX-License-Identifier: AGPL-3.0-or-later
// The Node CLI (dist/tgsync.mjs, built by `npm test`) on a sandbox group: restore from the group,
// log, bare `tgsync`. The full two-person story is tests/test_sandbox.py with TGSYNC_CLI (`make ts`).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const BIN = new URL("../dist/tgsync.mjs", import.meta.url).pathname;

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
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});
