// SPDX-License-Identifier: AGPL-3.0-or-later
// A vault folder kept open by a long-running program (the Obsidian plugin): one Telegram
// connection for its whole life; the vault itself is opened fresh, under the folder lock, for each
// operation, so another window's run in between is never overwritten by stale state.
import type { TelegramClient } from "@mtcute/core/client.js";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { INTERNAL_DIR } from "../paths.ts";
import { OfflineError, TransportError, type Transport } from "../transport.ts";
import { Vault } from "../vault.ts";
import { NodeFiles } from "./files.ts";
import { loadIdentity } from "./home.ts";
import { takeLock } from "./lock.ts";
import { DirTransport, PREFIX } from "./sandbox.ts";
import { TelegramTransport, connect, resolveChat, savedPeer } from "./telegram.ts";

interface Cfg { chat: string; chat_peer?: string; profile?: string; [k: string]: unknown }

export class VaultHost {
  private tg: TelegramClient | null = null;
  private tr: Transport | null = null;

  constructor(readonly dir: string) {}

  private cfgPath() { return join(this.dir, INTERNAL_DIR, "config.json"); }

  /** null if this folder is not a tgsync vault. */
  cfg(): Cfg | null {
    try { return JSON.parse(readFileSync(this.cfgPath(), "utf8")); } catch { return null; }
  }

  private async transport(cfg: Cfg): Promise<Transport> {
    if (this.tr) return this.tr;
    const chat = String(cfg.chat);
    if (chat.startsWith(PREFIX)) return (this.tr = new DirTransport(chat));
    this.tg ??= await connect(cfg.profile ?? "default");
    const t = new TelegramTransport(this.tg, await resolveChat(this.tg, chat, cfg.chat_peer));
    const peer = savedPeer(t.chat); // find the group without its link next time
    if (peer && cfg.chat_peer !== peer) writeFileSync(this.cfgPath(), JSON.stringify({ ...cfg, chat_peer: peer }, null, 2));
    return (this.tr = t);
  }

  /** Run `fn` on the vault, under the folder lock (LockBusy if another tgsync holds it). A lost
   *  connection is dropped, so the next call connects again. */
  async use<T>(fn: (v: Vault) => Promise<T>): Promise<T> {
    const cfg = this.cfg();
    if (!cfg) throw new TransportError("this folder is not a tgsync vault");
    const release = await takeLock(this.dir, 0);
    try {
      const tr = await this.transport(cfg);
      const v = await Vault.open(new NodeFiles(this.dir), await loadIdentity(cfg.profile ?? "default"), tr);
      return await fn(v);
    } catch (e) {
      if (e instanceof OfflineError || e instanceof TransportError) await this.close();
      throw e;
    } finally {
      release();
    }
  }

  async close(): Promise<void> {
    const tg = this.tg;
    this.tg = null;
    this.tr = null;
    await tg?.destroy().catch(() => {});
  }
}
