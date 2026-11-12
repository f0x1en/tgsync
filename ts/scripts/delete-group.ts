// SPDX-License-Identifier: AGPL-3.0-or-later
// Test helper for scripts/live_e2e.py: delete a vault's Telegram group with the Node login.
// Only the group's creator can do this. Not a user command.
//   npm run -s delete-group -- PROFILE VAULT_FOLDER
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { connect, resolveChat } from "../src/node/telegram.ts";

const [profile, vault] = process.argv.slice(2);
if (!profile || !vault) throw new Error("usage: delete-group PROFILE VAULT_FOLDER");
const cfg = JSON.parse(readFileSync(join(vault, ".tgsync", "config.json"), "utf8"));
const tg = await connect(profile);
try {
  await tg.deleteSupergroup(await resolveChat(tg, String(cfg.chat), cfg.chat_peer));
  console.log("  throwaway group deleted");
} finally {
  await tg.destroy();
}
