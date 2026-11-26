// SPDX-License-Identifier: AGPL-3.0-or-later
// Live two-person test against REAL Telegram, through the plugin's own setup and sync code, with
// two accounts already logged in (tgsync settings in Obsidian, Advanced → Account).
//
// It makes a throwaway private group, then: start, invite, ask to join, let in, join, sync both
// ways, remove; then deletes the group. Tiny files; a few minutes because sends are paced.
//
//   npm run -s live                                  # accounts: default (owner) and b (friend)
//   npm run -s live -- --owner me --friend you [--keep]
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { VaultHost } from "../../ts/src/node/host.ts";
import { connect, resolveChat } from "../../ts/src/node/telegram.ts";
import { VaultSetup } from "../src/setup.ts";

const { values: a } = parseArgs({ options: { owner: { type: "string", default: "default" }, friend: { type: "string", default: "b" }, keep: { type: "boolean" } } });
const tmp = mkdtempSync(join(tmpdir(), "tgsync-live-"));
const A = join(tmp, "owner"), B = join(tmp, "friend");
const hostA = new VaultHost(A), hostB = new VaultHost(B);
const owner = new VaultSetup(A, hostA, () => a.owner!), friend = new VaultSetup(B, hostB, () => a.friend!);
const step = (s: string) => console.log(`== ${s}`);
let failed = false;

try {
  step("owner starts a vault");
  mkdirSync(A, { recursive: true });
  writeFileSync(join(A, "hello.md"), "hello\n");
  await owner.create();
  await hostA.use((v) => v.pushChanges());

  step("friend asks to join; owner lets them in; friend joins by itself");
  const w = await friend.join(await owner.invite());
  assert.ok(w, "friend waits to be let in");
  const reqs = await hostA.use((v) => v.pendingRequests());
  assert.equal(reqs.length, 1, "owner sees one request");
  await owner.accept(reqs[0]);
  assert.equal(await friend.join(), null, "joined");
  assert.equal(readFileSync(join(B, "hello.md"), "utf8"), "hello\n");

  step("sync both ways");
  writeFileSync(join(B, "from-friend.md"), "hi\n");
  await hostB.use((v) => v.pushChanges());
  await hostA.use((v) => v.pullChanges());
  assert.equal(readFileSync(join(A, "from-friend.md"), "utf8"), "hi\n");

  step("owner removes the friend");
  const them = (await owner.members()).members.find((m) => !m.you)!;
  await owner.remove(them.id);
  await assert.rejects(hostB.use((v) => v.pullChanges()), /removed/);
  console.log("ALL PASSED");
} catch (e) {
  failed = true;
  console.log(`FAILED: ${(e as Error).stack ?? e}`);
} finally {
  await hostA.close();
  await hostB.close();
  const cfg = hostA.cfg();
  if (cfg) {
    const tg = await connect(a.owner!); // only the group's creator can delete it
    try {
      await tg.deleteSupergroup(await resolveChat(tg, String(cfg.chat), cfg.chat_peer as string | undefined));
      console.log("throwaway group deleted");
    } catch (e) {
      console.log(`could not delete the throwaway group (delete it by hand): ${e}`);
    } finally { await tg.destroy(); }
  }
  if (a.keep) console.log(`kept the test folders in ${tmp}`);
  else rmSync(tmp, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);
