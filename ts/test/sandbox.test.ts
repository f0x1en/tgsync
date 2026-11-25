// SPDX-License-Identifier: AGPL-3.0-or-later
// Two people, two processes, one sandbox group on disk: the whole CLI story offline, via --json.
// Runs dist/tgsync.mjs (built by `npm test`); TGSYNC_CLI="..." picks another program.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const CLI = process.env.TGSYNC_CLI ? process.env.TGSYNC_CLI.split(" ") : ["node", fileURLToPath(new URL("../dist/tgsync.mjs", import.meta.url))];

function tg(sandbox: string, profile: string, args: string[], cwd?: string): [any, number] {
  const env: NodeJS.ProcessEnv = { ...process.env, TGSYNC_SANDBOX: sandbox, TGSYNC_PROFILE: profile };
  delete env.TGSYNC_HOME;
  const r = spawnSync(CLI[0], [...CLI.slice(1), "--json", ...args], { env, cwd, encoding: "utf8" });
  return [JSON.parse(r.stdout), r.status!];
}

async function dirs() {
  const tmp = await mkdtemp(join(tmpdir(), "tgsync-sandbox-"));
  return { tmp, sb: join(tmp, "sb"), A: join(tmp, "alice"), B: join(tmp, "bob") };
}
const read = (p: string) => readFile(p, "utf8");

test("two people in the sandbox", async () => {
  const { sb, A, B } = await dirs();

  let [out, rc] = tg(sb, "alice", ["new", A, "--no-git"]);
  assert.ok(rc === 0 && out.ok && out.invite.startsWith("tgsync1-"), JSON.stringify(out));
  assert.ok(statSync(join(sb, "config", "alice")).isDirectory()); // keys live in the sandbox, not your real config

  [out] = tg(sb, "bob", ["join", out.invite, B, "--no-git"]);
  assert.equal(out.state, "waiting", JSON.stringify(out));
  const code = out.code;

  [out] = tg(sb, "alice", ["members", "-C", A]);
  assert.deepEqual(out.waiting.map((w: any) => w.code), [code]);
  [out, rc] = tg(sb, "alice", ["accept", code, "-C", A]);
  assert.ok(rc === 0 && out.accepted === "bob", JSON.stringify(out));

  [out] = tg(sb, "bob", ["join"]); // remembered: no code, folder or account needed
  assert.equal(out.state, "joined", JSON.stringify(out));

  await writeFile(join(A, "hello.md"), "hi bob\n");
  [out] = tg(sb, "alice", ["push", "-C", A]);
  assert.ok(out.report.pushed_paths.includes("hello.md"));
  [out] = tg(sb, "bob", ["pull", "-C", B]);
  assert.ok(out.report.written.includes("hello.md"));
  assert.equal(await read(join(B, "hello.md")), "hi bob\n");

  // removed, then asks to come back from the SAME folder with plain `tgsync join`
  [out, rc] = tg(sb, "alice", ["remove", "bob", "--yes", "-C", A]);
  assert.equal(rc, 0, JSON.stringify(out));
  await writeFile(join(A, "while_out.md"), "written while bob was out\n");
  tg(sb, "alice", ["push", "-C", A]);
  [out, rc] = tg(sb, "bob", ["pull", "-C", B]);
  assert.ok(rc === 1 && out.error.includes("tgsync join"), JSON.stringify(out));
  [out] = tg(sb, "bob", ["join"], B);
  assert.equal(out.state, "waiting", JSON.stringify(out));
  // The full member id works too (it settles a code two requests share).
  [out, rc] = tg(sb, "alice", ["accept", out.id ?? out.code, "-C", A]);
  assert.equal(rc, 0, JSON.stringify(out));
  [out] = tg(sb, "bob", ["join"], B);
  assert.equal(out.state, "joined", JSON.stringify(out));
  assert.equal(await read(join(B, "while_out.md")), "written while bob was out\n");
  assert.equal(await read(join(B, "hello.md")), "hi bob\n");
  assert.deepEqual(out.report.conflicts, []);
  assert.deepEqual(out.report.pushed_paths, []); // files he already had are not uploaded again
  assert.ok(readdirSync(join(B, ".tgsync")).some((n) => n.includes(".removed-"))); // old state kept, not deleted
});

test("json errors are json and never ask", async () => {
  const { tmp, sb } = await dirs();
  let [out, rc] = tg(sb, "alice", ["push", "-C", tmp]);
  assert.ok(rc === 1 && out.ok === false && out.error.includes("not a tgsync vault"), JSON.stringify(out));
  [out, rc] = tg(sb, "alice", ["join"]);
  assert.ok(rc === 1 && out.error.includes("Paste the invite line"), JSON.stringify(out));
});

test("status warns when someone else changed your file", async () => {
  const { sb, A, B } = await dirs();
  const inv = tg(sb, "alice", ["new", A, "--no-git"])[0].invite;
  const code = tg(sb, "bob", ["join", inv, B, "--no-git"])[0].code;
  tg(sb, "alice", ["accept", code, "-C", A]);
  tg(sb, "bob", ["join"]);
  await writeFile(join(A, "plan.md"), "v1\n");
  tg(sb, "alice", ["push", "-C", A]);
  tg(sb, "bob", ["pull", "-C", B]);

  await writeFile(join(B, "plan.md"), "bob's idea\n"); // bob edits, not uploaded yet
  await writeFile(join(A, "plan.md"), "alice's idea\n"); // meanwhile alice uploads her edit
  tg(sb, "alice", ["push", "-C", A]);

  let [out, rc] = tg(sb, "bob", ["status", "-C", B]);
  assert.ok(rc === 0 && out.online_error === null, JSON.stringify(out));
  assert.deepEqual(out.incoming, [{ op: "put", path: "plan.md", who: "alice", also_local: true }]);
  assert.deepEqual(out.pending, [{ op: "put", path: "plan.md" }]);
  assert.equal(await read(join(B, "plan.md")), "bob's idea\n"); // status never touches files

  [out] = tg(sb, "bob", ["status", "--offline", "-C", B]);
  assert.equal(out.incoming, null);
});
