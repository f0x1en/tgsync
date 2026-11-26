// SPDX-License-Identifier: AGPL-3.0-or-later
// Setting a vault folder up: start a vault, ask to join one and finish joining, invite, accept.
// Used by the Obsidian plugin (obsidian/src/setup.ts); nothing here asks questions or prints.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { shortCode } from "../crypto.ts";
import { INTERNAL_DIR } from "../paths.ts";
import { encodeInvite, type Identity, type Invite } from "../protocol.ts";
import type { Transport } from "../transport.ts";
import { ENGINE_FILE, LOCAL_FILE, OLD_STATE, Vault, type Report } from "../vault.ts";
import type { NodeFiles } from "./files.ts";
import { initIdentity, isSandboxLink, loadIdentity, mem, memSave, sandboxRoot } from "./home.ts";
import { DirTransport, PREFIX } from "./sandbox.ts";
import { TelegramTransport, exportInvite, resolveChat, savedPeer } from "./telegram.ts";
import type { TelegramClient } from "@mtcute/core/client.js";

/** A problem the user can fix; its message says how. */
export class SetupError extends Error {}

/** Path as you would type it: ~/x instead of /home/you/x. */
export function short(p: string): string {
  const abs = resolve(p), rel = relative(homedir(), abs);
  return rel && !rel.startsWith("..") && !rel.startsWith(sep) ? "~/" + rel.split(sep).join("/") : abs;
}

// ------------------------------------------------------------------ vault folders
export interface Cfg { chat: string; chat_peer?: string; profile: string; invite?: string; code?: string; [k: string]: unknown }

export const cfgPath = (vault: string) => join(vault, INTERNAL_DIR, "config.json");

export function saveCfg(vault: string, cfg: Cfg): void {
  mkdirSync(join(vault, INTERNAL_DIR), { recursive: true });
  writeFileSync(cfgPath(vault), JSON.stringify(cfg, null, 2));
}

/** A folder of the old Python CLI keeps its state in `.tgsync/state.db` (SQLite). Write what the
 *  engine needs from it (vault id, what was synced, our last record number) as `.tgsync/state.json`,
 *  the format `Vault.open` already takes over; otherwise every file looks changed on both sides. */
export function fromPythonState(folder: string): void {
  const db = join(folder, INTERNAL_DIR, "state.db");
  if (!existsSync(db) || existsSync(join(folder, ENGINE_FILE)) || existsSync(join(folder, OLD_STATE))) return;
  let sqlite: any;
  try { sqlite = createRequire(import.meta.url)("node:sqlite"); } catch {
    throw new SetupError(`${short(folder)} was made by the old tgsync; reading it needs Node 22.13 or newer (you have ${process.version})`);
  }
  const d = new sqlite.DatabaseSync(db, { readOnly: true });
  try {
    const kv = (k: string) => (d.prepare("SELECT v FROM kv WHERE k=?").get(k) as any)?.v ?? null;
    const cols = (d.prepare("PRAGMA table_info(synced)").all() as any[]).map((c) => c.name);
    const obs = cols.includes("observed_ns") ? "observed_ns" : "0";
    const synced: { [p: string]: [string, number, number, number] } = {};
    // times in ms (nanoseconds do not fit a JavaScript number)
    for (const r of d.prepare(`SELECT path, sha, size, mtime_ns / 1e6 AS m, ${obs} / 1e6 AS o FROM synced`).all() as any[]) {
      synced[r.path] = [r.sha, r.size, r.m, r.o];
    }
    const authors = Object.fromEntries((d.prepare("SELECT author, seq FROM authors").all() as any[]).map((r) => [r.author, Number(r.seq)]));
    writeFileSync(join(folder, OLD_STATE), JSON.stringify({ v: 1, vault_id: kv("vault_id"), synced, authors }));
  } finally {
    d.close();
  }
}

/** -> [vault id, were we removed from it] for a vault folder; [null, false] if none. */
export async function vaultAt(folder: string): Promise<[string | null, boolean]> {
  fromPythonState(folder);
  for (const [file, pick] of [[ENGINE_FILE, (d: any) => d.replica], [OLD_STATE, (d: any) => d]] as const) {
    if (!existsSync(join(folder, file))) continue;
    try {
      const d = pick(JSON.parse(readFileSync(join(folder, file), "utf8")));
      return [d.vault_id ?? null, !!d.removed];
    } catch {
      if (file === ENGINE_FILE) throw new SetupError(`${short(folder)}/${ENGINE_FILE} is damaged; move it away and join the vault there again`);
      continue;
    }
  }
  return [null, false];
}

// ------------------------------------------------------------------ keys and groups
/** The profile's key; made on first use. -> [identity, was it just made]. */
export async function ensureIdentity(profile: string): Promise<[Identity, boolean]> {
  try { return [await loadIdentity(profile), false]; } catch {
    return [await initIdentity(profile), true];
  }
}

/** The group behind a link, real or sandbox. `tg` is null in the sandbox. */
export async function openGroup(ref: string, tg: TelegramClient | null, peer?: string): Promise<Transport> {
  if (isSandboxLink(ref)) {
    if (sandboxRoot() === null) { // its keys live in the sandbox config dir
      const base = resolve(ref.slice(PREFIX.length), "..", "..");
      throw new SetupError(`This is a sandbox vault. First run:  export TGSYNC_SANDBOX=${base}`);
    }
    if (!existsSync(ref.slice(PREFIX.length))) throw new SetupError(`sandbox group ${ref.slice(PREFIX.length)} does not exist (was the sandbox deleted?)`);
    return new DirTransport(ref);
  }
  if (!tg) throw new SetupError("this vault's group is on Telegram, but TGSYNC_SANDBOX is set; unset it first");
  return new TelegramTransport(tg, await resolveChat(tg, ref, peer));
}

/** The invite line for a vault we are a member of (never one without a key fingerprint). */
function inviteFor(v: Vault, link: string): string {
  const fp = v.fingerprint();
  if (v.removed || !v.hasKeys || !v.vaultId || !fp) throw new SetupError("This folder has no vault keys (were you removed?), so it cannot invite anyone.");
  return encodeInvite({ link, vaultId: v.vaultId, fingerprint: fp, api: null });
}

// ------------------------------------------------------------------ start, invite
/** Start a vault in `folder` on the group `chat` (link, if it can be shared). Saves the folder's config. */
export async function createVault(a: {
  folder: string; files: NodeFiles; ident: Identity; tr: Transport; profile: string; chat: string; link: string | null; name: string;
}): Promise<Vault> {
  const v = await Vault.create(a.files, a.ident, a.tr, a.name);
  const cfg: Cfg = { chat: a.chat, profile: a.profile };
  if (a.link) cfg.invite = a.link;
  if (a.tr instanceof TelegramTransport) cfg.chat_peer = savedPeer(a.tr.chat);
  saveCfg(a.folder, cfg);
  return v;
}

/** The invite line for an open vault: its saved group link, else a new one. */
export async function inviteLine(v: Vault, folder: string, cfg: Cfg): Promise<string> {
  await v.pull();
  const tr = v.transport;
  const use = cfg.invite ?? (tr instanceof TelegramTransport ? await exportInvite(tr.tg, tr.chat) : String(cfg.chat));
  if (cfg.invite !== use) { cfg.invite = use; saveCfg(folder, cfg); }
  return inviteFor(v, use);
}

// ------------------------------------------------------------------ join
/** Can `folder` take vault `vaultId`? -> true if this vault is already there (back in after a removal?). */
export async function checkJoinFolder(folder: string, vaultId: string): Promise<boolean> {
  const [vid] = await vaultAt(folder);
  const same = existsSync(cfgPath(folder)) && vid === vaultId;
  if (existsSync(cfgPath(folder)) && !same) {
    throw new SetupError(`${short(folder)} already syncs a different vault. Open an empty vault in Obsidian and join from there.`);
  }
  return same;
}

export type JoinResult =
  | { state: "waiting"; who: string; code: string; id: string }
  | { state: "joined"; v: Vault; report: Report };

/** One step of joining: before they accept us, post a join request (and remember it); after, join
 *  and download the files. `same`: from checkJoinFolder. `files` takes the folder's lock. */
export async function joinStep(a: {
  folder: string; files: () => Promise<NodeFiles>; ident: Identity; tr: Transport; profile: string;
  inv: Invite; code: string; same: boolean; who: () => Promise<string>;
}): Promise<JoinResult> {
  const { folder, ident, tr, inv } = a;
  let rejoin = false;
  if (a.same) { // catch up first: this folder may not know yet that we were removed
    const old = await Vault.open(await a.files(), ident, tr);
    await old.pull();
    rejoin = old.removed;
    old.engine.free(); // its state files are moved aside below; this object must not save them again
    if (!rejoin) throw new SetupError(`You already joined this vault in ${short(folder)}.`);
  }
  const found = await Vault.discover(tr, ident);
  if (!found.has(inv.vaultId)) {
    const who = await a.who();
    await Vault.postJoinRequest(tr, ident, inv.vaultId, who);
    const m = mem();
    (m.joins ??= {})[inv.vaultId] = { code: a.code, profile: a.profile, folder: resolve(folder) };
    memSave(m);
    return { state: "waiting", who, code: await shortCode(ident.recipient), id: ident.id };
  }
  if (found.get(inv.vaultId)!.replace(/ /g, "") !== inv.fingerprint.replace(/ /g, "")) {
    throw new SetupError("KEY FINGERPRINT MISMATCH between the invite and the vault - refusing to join");
  }
  if (rejoin) { // start the vault state fresh; the old one is kept next to it, files stay
    const stamp = Math.floor(Date.now() / 1000);
    for (const f of [ENGINE_FILE, LOCAL_FILE, OLD_STATE]) {
      const st = join(folder, f);
      if (existsSync(st)) renameSync(st, `${st}.removed-${stamp}`);
    }
  }
  mkdirSync(folder, { recursive: true });
  const v = await Vault.join(await a.files(), ident, tr, inv.vaultId);
  saveCfg(folder, { chat: inv.link, chat_peer: tr instanceof TelegramTransport ? savedPeer(tr.chat) : undefined,
                    profile: a.profile, invite: inv.link, code: a.code });
  const m = mem();
  if (m.joins?.[inv.vaultId]) { delete m.joins[inv.vaultId]; memSave(m); }
  return { state: "joined", v, report: await v.pullChanges() };
}
