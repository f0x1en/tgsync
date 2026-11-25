// SPDX-License-Identifier: AGPL-3.0-or-later
// Setting this vault up from inside Obsidian: log in to Telegram, start a vault or join one, invite,
// let people in. No questions or windows here (ui.ts does those), so the tests can drive it.
import { resolve } from "node:path";
import { memberId, shortCode } from "../../ts/src/crypto.ts";
import { NodeFiles } from "../../ts/src/node/files.ts";
import { currentProfile, mem, newSandboxGroup, sandboxRoot } from "../../ts/src/node/home.ts";
import type { VaultHost } from "../../ts/src/node/host.ts";
import { takeLock } from "../../ts/src/node/lock.ts";
import {
  SetupError, checkJoinFolder, createVault, ensureIdentity, findRequest, inviteLine, joinStep, openGroup,
} from "../../ts/src/node/setup.ts";
import {
  connect, createGroup, hasLogin, interactiveLogin, loadCreds, parseProxy, saveCreds, type LoginPrompts,
} from "../../ts/src/node/telegram.ts";
import { decodeInvite, type JoinRequest } from "../../ts/src/protocol.ts";

type TelegramClient = Awaited<ReturnType<typeof connect>>;

declare const TGSYNC_API: [number, string] | null | undefined; // set by esbuild.config.mjs
/** The Telegram API key this build ships with, if any. */
export const SHARED_API: [number, string] | null = typeof TGSYNC_API !== "undefined" ? TGSYNC_API : null;

/** "Use my own" values from the plugin's Advanced settings (empty: use the shared key / no proxy). */
export interface Advanced { apiId: string; apiHash: string; proxy: string }

export interface Waiting { code: string; id: string }

export class VaultSetup {
  constructor(readonly dir: string, private host: VaultHost) {}

  private get sandbox(): boolean { return sandboxRoot() !== null; }

  /** The tgsync account this vault uses (or will use). */
  profile(): string {
    return this.host.cfg()?.profile ?? this.joinEntry()?.profile ?? currentProfile();
  }

  loggedIn(): boolean { return this.sandbox || hasLogin(this.profile()); }

  /** Log in to Telegram: the window asks for phone, code and 2FA password. -> "Name (@user)". */
  async login(adv: Advanced, ask: LoginPrompts): Promise<string> {
    const profile = this.profile(), saved = loadCreds(profile);
    const own: [number, string] | null = adv.apiId.trim() && adv.apiHash.trim() ? [Number(adv.apiId), adv.apiHash.trim()] : null;
    if (own && (!Number.isInteger(own[0]) || own[0] <= 0)) throw new SetupError("The API id is a number (from my.telegram.org → API development tools).");
    const api = own ?? SHARED_API ?? (saved ? [saved.api_id, saved.api_hash] as [number, string] : null);
    if (!api) throw new SetupError("This build has no Telegram API key. Enter your own under Advanced (my.telegram.org → API development tools).");
    const proxy = adv.proxy.trim() || saved?.proxy || null;
    try { parseProxy(proxy); } catch (e) { throw new SetupError(`Proxy: ${(e as Error).message}`); }
    const creds = { api_id: api[0], api_hash: api[1], proxy };
    saveCreds(profile, creds);
    return interactiveLogin(profile, creds, ask);
  }

  /** Run `fn` with a Telegram connection (null in the sandbox), under the folder's lock. */
  private async online<T>(fn: (tg: TelegramClient | null) => Promise<T>): Promise<T> {
    const release = await takeLock(this.dir, 0);
    let tg: TelegramClient | null = null;
    try {
      if (!this.sandbox) tg = await connect(this.profile());
      return await fn(tg);
    } finally {
      await tg?.destroy().catch(() => {});
      release();
    }
  }

  private async name(tg: TelegramClient | null): Promise<string> {
    return (tg && (await tg.getMe()).firstName) || this.profile();
  }

  /** Start a new vault here: a private Telegram group named after the vault; files here are uploaded. */
  async create(): Promise<void> {
    if (this.host.cfg()) throw new SetupError("This vault is already set up.");
    const profile = this.profile();
    await this.online(async (tg) => {
      const [ident] = await ensureIdentity(profile);
      const title = this.dir.split(/[\\/]/).pop() || "tgsync vault";
      const link = tg ? (await createGroup(tg, title))[1] : newSandboxGroup();
      const tr = await openGroup(link, tg);
      try {
        const { v } = await createVault({ folder: this.dir, files: new NodeFiles(this.dir), ident, tr, profile, chat: link, link, name: await this.name(tg) });
        v.engine.free(); // syncing opens the vault afresh each time
      } finally { if (!tg) await tr.close(); }
    });
  }

  /** The join this vault waits on (asked, not let in yet), if any. */
  private joinEntry() {
    const here = resolve(this.dir);
    return Object.values(mem().joins ?? {}).find((j) => j.folder === here) ?? null;
  }

  /** Waiting to be let in: the code to tell the owner. null if not waiting. */
  async waiting(): Promise<Waiting | null> {
    const j = this.joinEntry();
    if (!j || this.host.cfg()) return null;
    const [ident] = await ensureIdentity(j.profile);
    return { code: await shortCode(ident.recipient), id: ident.id };
  }

  /** Join with an invite line (pasted, or the saved one). -> the code to tell the owner while
   *  waiting; null once joined (files downloaded). */
  async join(line?: string): Promise<Waiting | null> {
    const code = (line ?? this.joinEntry()?.code ?? "").trim().replace(/^tgsync join\s+/, "");
    if (!code) throw new SetupError("Paste the invite your friend sent you.");
    let inv;
    try { inv = decodeInvite(code); } catch (e) { throw new SetupError((e as Error).message); }
    const profile = this.profile();
    const same = await checkJoinFolder(this.dir, inv.vaultId);
    return this.online(async (tg) => {
      const [ident] = await ensureIdentity(profile);
      const tr = await openGroup(inv.link, tg);
      try {
        const r = await joinStep({
          folder: this.dir, files: async () => new NodeFiles(this.dir), ident, tr, profile, inv, code, same,
          who: () => this.name(tg),
        });
        if (r.state === "joined") { r.v.engine.free(); return null; }
        return { code: r.code, id: r.id };
      } finally { if (!tg) await tr.close(); }
    });
  }

  /** The invite line to send a friend (copied by the settings tab). */
  invite(): Promise<string> {
    return this.host.use((v) => inviteLine(v, this.dir, this.host.cfg()! as any));
  }

  /** Members, and people waiting to be let in (only admins can let them in). */
  members() {
    return this.host.use(async (v) => ({
      admin: v.isAdmin,
      members: v.members.map((m) => ({ name: m.name || m.recipient.slice(0, 12), admin: !!m.admin, you: m.recipient === v.me.recipient })),
      waiting: v.isAdmin ? await v.pendingRequests() : [],
    }));
  }

  /** Let `req` in if `typed` is the code (or full id) their tgsync shows them. */
  async accept(req: JoinRequest, typed: string): Promise<void> {
    const want = typed.trim().toLowerCase();
    if (want !== await shortCode(req.recipient) && want !== await memberId(req.recipient)) {
      throw new SetupError(`That is not ${req.name || "their"} code. Ask them to read you the code their tgsync shows.`);
    }
    await this.host.use(async (v) => {
      const hit = await findRequest(v, want); // refuses when someone else posted a request with the same code
      await v.acceptRequest(hit);
    });
  }
}
