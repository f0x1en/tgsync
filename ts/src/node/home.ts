// SPDX-License-Identifier: AGPL-3.0-or-later
// This computer's tgsync data: profiles (one age key + Telegram login each), remembered input,
// and the sandbox switch. Same layout as the Python CLI, so existing keys keep working.
import { identityToRecipient } from "age-encryption";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { memberId, newIdentity } from "../crypto.ts";
import type { Identity } from "../protocol.ts";
import { PREFIX } from "./sandbox.ts";

export class HomeError extends Error {}

const expand = (p: string) => (p === "~" || p.startsWith("~/") ? join(homedir(), p.slice(1)) : p);

/** Sandbox root (TGSYNC_SANDBOX), or null for real Telegram. */
export function sandboxRoot(): string | null {
  const v = process.env.TGSYNC_SANDBOX;
  return v ? resolve(expand(v)) : null;
}

export const isSandboxLink = (ref: string) => ref.startsWith(PREFIX);

/** A new, empty sandbox group -> its link. */
export function newSandboxGroup(): string {
  const d = join(sandboxRoot()!, "groups", randomBytes(4).toString("hex"));
  mkdirSync(d, { recursive: true });
  return PREFIX + d;
}

/** Where profiles live (platformdirs.user_config_dir("tgsync") in the Python CLI). */
function configDir(): string {
  if (process.platform === "win32") return join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "tgsync");
  if (process.platform === "darwin") return join(homedir(), "Library", "Application Support", "tgsync");
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "tgsync");
}

export function rootDir(): string {
  const sb = sandboxRoot();
  const d = process.env.TGSYNC_HOME || (sb ? join(sb, "config") : configDir()); // sandbox keys never mix with real ones
  mkdirSync(d, { recursive: true });
  return d;
}

export function checkProfileName(name: string): string {
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) throw new HomeError("profile names may only use letters, digits, '_' and '-' (max 32)");
  return name;
}

export function listProfiles(): string[] {
  const root = rootDir();
  return readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory() && (existsSync(join(root, e.name, "identity.age-key")) || existsSync(join(root, e.name, "telegram.json"))))
    .map((e) => e.name).sort();
}

export const currentProfile = () => checkProfileName(process.env.TGSYNC_PROFILE || "default");

export function appDir(profile: string): string {
  const d = join(rootDir(), checkProfileName(profile));
  mkdirSync(d, { recursive: true, mode: 0o700 });
  try { chmodSync(d, 0o700); } catch { /* Windows: per-user ACLs */ }
  return d;
}

export async function loadIdentity(profile: string): Promise<Identity> {
  const p = join(appDir(profile), "identity.age-key");
  if (!existsSync(p)) throw new HomeError(`no identity for profile '${profile}'; log in from tgsync's settings in Obsidian`);
  const secret = readFileSync(p, "utf8").trim().split("\n").at(-1)!.trim();
  const recipient = await identityToRecipient(secret);
  return { secret, recipient, id: await memberId(recipient), signing: signingKey(profile), seqs: seqStore(profile) };
}

/** `<profile>/seqs/<vault id>`: the last record seq we posted in that vault (kept outside the folder,
 *  so a re-join never reuses one). One file per vault: two tgsync runs in different vaults never
 *  write the same file. `<profile>/seqs.json` (older versions: all vaults in one file) is still read. */
export function seqStore(profile: string): NonNullable<Identity["seqs"]> {
  const dir = join(appDir(profile), "seqs");
  const old = join(appDir(profile), "seqs.json");
  const damaged = (p: string) => new HomeError(`${p} is damaged; it keeps record numbers safe after a re-join. Remove it only if you have not re-joined a vault since`);
  const fileOf = (v: string) => {
    if (!/^[0-9a-f]{1,64}$/.test(v)) throw new HomeError(`unexpected vault id ${JSON.stringify(v)}`);
    return join(dir, v);
  };
  const readNum = (p: string): number => {
    if (!existsSync(p)) return 0;
    const n = Number(readFileSync(p, "utf8").trim());
    if (!Number.isSafeInteger(n) || n < 0) throw damaged(p);
    return n;
  };
  const readOld = (v: string): number => {
    if (!existsSync(old)) return 0;
    try { return JSON.parse(readFileSync(old, "utf8"))[v] ?? 0; } catch { throw damaged(old); }
  };
  const get = (v: string) => Math.max(readNum(fileOf(v)), readOld(v));
  return {
    get,
    set: (v, seq) => {
      if (get(v) >= seq) return;
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      const tmp = `${fileOf(v)}.${process.pid}.tmp`; // write, then rename: never half a file
      writeFileSync(tmp, String(seq), { mode: 0o600 });
      renameSync(tmp, fileOf(v));
    },
  };
}

/** The profile's Ed25519 signing key (64 hex), made on first use. Never leaves this computer. */
function signingKey(profile: string): string {
  const p = join(appDir(profile), "signing.key");
  if (!existsSync(p)) {
    try { writeFileSync(p, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "wx" }); }
    catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e; } // another tgsync made it just now
  }
  const key = readFileSync(p, "utf8").trim();
  if (!/^[0-9a-f]{64}$/.test(key)) throw new HomeError(`${p} is not a signing key (64 hex characters); it may be damaged`);
  return key;
}

export async function initIdentity(profile: string): Promise<Identity> {
  const p = join(appDir(profile), "identity.age-key");
  if (existsSync(p)) throw new HomeError(`identity already exists at ${p}`);
  const ident = await newIdentity();
  writeFileSync(p, `# public key: ${ident.recipient}\n${ident.secret}\n`, { mode: 0o600, flag: "wx" });
  return { ...ident, signing: signingKey(profile), seqs: seqStore(profile) };
}

// Join requests this computer sent (invite line, account, folder): the folder finishes joining by
// itself once let in.
export interface Remembered { joins?: { [vaultId: string]: { code: string; profile: string; folder: string } } }

const memPath = () => join(rootDir(), "remembered.json");

export function mem(): Remembered {
  try { return JSON.parse(readFileSync(memPath(), "utf8")); } catch { return {}; }
}

export function memSave(m: Remembered): void {
  writeFileSync(memPath(), JSON.stringify(m, null, 2));
}
