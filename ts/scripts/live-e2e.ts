// SPDX-License-Identifier: AGPL-3.0-or-later
// Live two-person test against REAL Telegram, using two accounts you already logged in with.
//
// It creates a throwaway private group, walks through the whole story (invite, join request,
// approval, sync, conflict, delete-vs-edit, removal, re-join) with tiny files, then deletes the group.
//
//   npm run -s live                                   # profiles: default (owner) and b (friend)
//   npm run -s live -- --owner me --friend you [--keep DIR]
//
// It runs live/tgsync.mjs (`make live` copies the build there, so `npm test` can rebuild meanwhile);
// TGSYNC_CLI="..." picks another program. The group is deleted at the end through the owner's login.
// Not part of CI (needs real accounts). Takes a few minutes because the rate limiter spaces sends.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { parseArgs } from "node:util";
import { connect, resolveChat } from "../src/node/telegram.ts";

const FAILS: string[] = [];
const LOG_LINE = /^\d{4}-\d\d-\d\dT\S+ \[(VRB|DBG|INF|WRN|ERR)\] /; // TGSYNC_DEBUG lines
const TIMEOUT = 120; // seconds; no tiny-file command needs this long
const ROOT = join(import.meta.dirname, "..", ".."); // bundled into ts/.test-out/
const CLI = process.env.TGSYNC_CLI ? process.env.TGSYNC_CLI.split(" ") : ["node", join(ROOT, "ts", "live", "tgsync.mjs")];

function check(cond: boolean, what: string) {
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${what}`);
  if (!cond) FAILS.push(what);
}

function tg(args: string[], expectOk = true): string {
  const t = Date.now();
  const env = { ...process.env, TGSYNC_DEBUG: "1" }; // timestamped Telegram calls: a hang shows where it stopped
  const r = spawnSync(CLI[0], [...CLI.slice(1), ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: TIMEOUT * 1000 });
  const full = ((r.stdout ?? "") + (r.stderr ?? "")).trim();
  if (r.error || r.signal) {
    console.log(`  $ tgsync ${args.join(" ")}   [killed after ${TIMEOUT}s]`);
    check(false, `command hung: tgsync ${args.join(" ")}\n${full}`);
    return full;
  }
  const out = full.split("\n").filter((x) => !LOG_LINE.test(x)).join("\n"); // checks read tgsync's own words only
  console.log(`  $ tgsync ${args.join(" ")}   [${Math.round((Date.now() - t) / 1000)}s]`);
  if (expectOk && r.status !== 0) check(false, `command failed: tgsync ${args.join(" ")}\n${full}`);
  return out;
}

/** Upload yours, then download others'. */
const sync = (folder: string) => tg(["push", "-C", folder]) + "\n" + tg(["pull", "-C", folder]);

function files(d: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!existsSync(d)) return out;
  for (const e of readdirSync(d, { recursive: true, withFileTypes: true })) {
    const p = join(e.parentPath, e.name);
    const rel = relative(d, p).split(sep).join("/");
    if (e.isFile() && !rel.split("/").includes(".tgsync") && e.name !== ".tgsyncignore") out[rel] = readFileSync(p, "latin1");
  }
  return Object.fromEntries(Object.entries(out).sort());
}
const same = (a: object, b: object) => JSON.stringify(a) === JSON.stringify(b);
const write = (p: string, s: string | Buffer) => writeFileSync(p, s);

async function main(): Promise<number> {
  const { values: a } = parseArgs({ options: { owner: { type: "string", default: "default" }, friend: { type: "string", default: "b" }, keep: { type: "string" } } });
  if (a.keep) mkdirSync(a.keep, { recursive: true });
  const tmp = mkdtempSync(join(a.keep ?? tmpdir(), "tgsync-e2e-"));
  const A = join(tmp, `tgsync-e2e-${Math.floor(Date.now() / 1000)}`), B = join(tmp, "friend"), B2 = join(tmp, "friend_again");
  let chat: any = null;
  try {
    console.log("\n== 1. owner creates a vault in a brand-new private group");
    let out = tg(["new", A, "--profile", a.owner!]);
    const m = /tgsync1-[A-Za-z0-9_-]+/.exec(out);
    check(!!m, "invite code printed");
    if (!m) return 1;
    const code = m[0];
    chat = JSON.parse(readFileSync(join(A, ".tgsync", "config.json"), "utf8"));

    console.log("\n== 2. friend asks to join (cannot read anything yet)");
    out = tg(["join", code, B, "--profile", a.friend!, "--name", "friend"]);
    let c = /code: ([0-9a-f]{4}-[0-9a-f]{4})/.exec(out);
    check(!!c && out.includes("Then you run:  cd ") && out.includes("tgsync join"), "friend got a short code and is waiting");
    check(Object.keys(files(B)).length === 0, "friend has no files before approval");
    if (!c) return 1;
    const short = c[1];

    console.log("\n== 3. owner sees the request and accepts by typing the code");
    out = tg(["members", "-C", A]);
    check(out.includes(short), "the members list shows the friend's waiting code");
    check(tg(["accept", "0000-0000", "-C", A], false).includes("nobody is waiting"), "accepting a wrong code is refused");
    tg(["accept", short, "-C", A]);
    out = tg(["members", "-C", A]);
    check(out.includes("friend") && !out.includes("waiting"), "friend is a member and no longer waiting");

    console.log("\n== 4. owner shares a note; friend pulls it");
    write(join(A, "welcome.md"), "hello friend\n");
    mkdirSync(join(A, "notes"));
    write(join(A, "notes", "idea.md"), "an idea\n");
    out = sync(A);
    check(out.includes("Uploaded") && out.includes("  welcome.md"), "push lists the uploaded files");
    out = tg(["join", code, B, "--profile", a.friend!]);
    check(out.includes("Joined"), "friend finishes joining after approval");
    check(same(files(B), files(A)), "friend received exactly the owner's files");

    console.log("\n== 4b. pull only downloads, push only uploads");
    write(join(A, "from_owner.md"), "pushed by owner\n");
    write(join(B, "draft.md"), "friend draft\n");
    out = tg(["push", "-C", A]);
    check(out.includes("Uploaded") && out.includes("  from_owner.md"), "owner's push lists the uploaded file");
    out = tg(["pull", "-C", B]);
    check(out.includes("Downloaded") && out.includes("  from_owner.md") && existsSync(join(B, "from_owner.md")), "friend's pull downloads it");
    check(!out.includes("draft.md"), "friend's pull does not upload the local draft");
    tg(["pull", "-C", A]);
    check(!existsSync(join(A, "draft.md")), "owner does not get the draft before the friend pushes");
    out = tg(["push", "-C", B]);
    check(out.includes("Uploaded") && out.includes("  draft.md"), "friend's push lists the draft");
    tg(["pull", "-C", A]);
    check(files(A)["draft.md"] === "friend draft\n", "owner's pull downloads the draft");
    check(same(files(A), files(B)), "folders identical after push/pull");

    console.log("\n== 5. both edit the same note (and the same binary file): nothing is lost");
    write(join(A, "shared.md"), "base\n");
    write(join(A, "shared.bin"), Buffer.from("base\0"));
    sync(A);
    sync(B);
    write(join(A, "shared.md"), "owner edit\n");
    write(join(B, "shared.md"), "friend edit\n");
    write(join(A, "shared.bin"), Buffer.from("owner\0"));
    write(join(B, "shared.bin"), Buffer.from("friend\0"));
    sync(A);
    sync(B);
    sync(A);
    check(same(files(A), files(B)), "both folders are identical after syncing");
    const merged = files(A)["shared.md"] ?? "";
    check(merged.includes("owner edit") && merged.includes("friend edit"), "the note holds both edits (merged)");
    const copies = Object.keys(files(A)).filter((p) => p.startsWith("shared (conflict"));
    check(!copies.some((p) => p.endsWith(".md")), "the note made no conflict copy");
    check(copies.filter((p) => p.endsWith(".bin")).length === 1, "the binary file kept both versions (one conflict copy)");

    console.log("\n== 6. owner deletes a note while friend edits it: the edit wins");
    write(join(A, "keep.md"), "v1\n");
    sync(A);
    sync(B);
    unlinkSync(join(A, "keep.md"));
    write(join(B, "keep.md"), "friend kept working\n");
    sync(A);
    sync(B);
    sync(A);
    check(files(A)["keep.md"] === "friend kept working\n", "edited note survived the delete on the owner's side");
    check(same(files(A), files(B)), "folders identical again");

    console.log("\n== 7. owner removes the friend: new files stay private");
    tg(["remove", "friend", "--yes", "-C", A]);
    write(join(A, "secret.md"), "after removal\n");
    sync(A);
    out = tg(["pull", "-C", B], false);
    check(out.includes("removed"), "friend's pull is refused with a clear message");
    check(!existsSync(join(B, "secret.md")), "friend never received the new file");

    console.log("\n== 8. friend asks again and is let back in with full history");
    out = tg(["join", code, B2, "--profile", a.friend!, "--name", "friend"]);
    c = /code: ([0-9a-f]{4}-[0-9a-f]{4})/.exec(out);
    check(!!c, "friend gets a new short code");
    if (c) {
      tg(["accept", c[1], "-C", A]);
      out = tg(["join", code, B2, "--profile", a.friend!]);
      check(out.includes("Joined"), "friend rejoined");
      check(same(files(B2), files(A)), "friend has everything, including files written while removed");
    }

    console.log("\n== 9. health check");
    out = tg(["status", "--check", "-C", A], false);
    check(out.includes("all good"), "status --check passes for the owner");
  } finally {
    console.log("\n== cleanup");
    if (chat) {
      try {
        const t = await connect(a.owner!); // only the group's creator can delete it
        try {
          await t.deleteSupergroup(await resolveChat(t, String(chat.chat), chat.chat_peer));
          console.log("  throwaway group deleted");
        } finally {
          await t.destroy();
        }
      } catch (e) {
        console.log(`  could not delete the throwaway group (delete it by hand): ${e}`);
      }
    }
    if (a.keep) console.log(`  kept the test folders in ${tmp}`);
    else rmSync(tmp, { recursive: true, force: true });
  }
  console.log(`\n${FAILS.length ? `${FAILS.length} FAILED` : "ALL PASSED"}`);
  for (const f of FAILS) console.log("  - " + f.split("\n")[0]);
  return FAILS.length ? 1 : 0;
}

process.exit(await main());
