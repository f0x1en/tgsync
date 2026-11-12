// SPDX-License-Identifier: AGPL-3.0-or-later
// The tgsync command line, on the TypeScript engine. Same commands, output and --json contract
// as the Python CLI (HACKING.md). Talks to Telegram, or to a sandbox group (TGSYNC_SANDBOX).
//
//   tgsync              what changed, yours and others' (same as `tgsync status`)
//   tgsync pull / push  download others' changes / upload yours
//   tgsync log          who changed what and when
//   tgsync restore      bring back an older version of a file (from the group)
//   tgsync new DIR      start a vault        tgsync join CODE   join one
//   tgsync invite / members / accept CODE / remove NAME
//   tgsync --json ...   one JSON object on stdout, for scripts and plugins
import { existsSync, readFileSync, readdirSync, renameSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, relative, resolve, sep } from "node:path";
import { createInterface } from "node:readline/promises";
import { parseArgs, type ParseArgsConfig } from "node:util";
import { fingerprint, memberId, shortCode } from "../crypto.ts";
import { INTERNAL_DIR, normalize } from "../paths.ts";
import { decodeInvite, encodeInvite, type Identity } from "../protocol.ts";
import { State, STATE_FILE } from "../state.ts";
import type { Transport } from "../transport.ts";
import { Vault, type Incoming, type Report } from "../vault.ts";
import { NodeFiles } from "../node/files.ts";
import {
  checkProfileName, currentProfile, initIdentity, isSandboxLink, listProfiles, loadIdentity, mem, memSave,
  newSandboxGroup, sandboxRoot,
} from "../node/home.ts";
import { DirTransport, PREFIX } from "../node/sandbox.ts";
import {
  NotLoggedIn, TelegramTransport, connect, createGroup, exportInvite, interactiveLogin, loadCreds, parseProxy,
  resolveChat, saveCreds, savedPeer, type Creds, type LoginPrompts,
} from "../node/telegram.ts";
import type { TelegramClient } from "@mtcute/core/client.js";

const VERSION = "0.3.0";

class CliError extends Error {}

// ------------------------------------------------------------------ output and --json mode
// `tgsync --json <command>` prints exactly one JSON object on stdout ({"ok": true, ...} or
// {"ok": false, "error": "..."}) and never asks questions. Human messages go to stderr then.
let JSON_MODE = false;
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const yellow = paint("33"), red = paint("31"), bold = paint("1");

const echo = (s = "") => process.stdout.write(s + "\n");
const err = (s: string) => process.stderr.write(s + "\n");
const info = (s: string) => (JSON_MODE ? err(s) : echo(s));
const say = (s: string) => err("  ... " + s);

function emit(data: object, text: () => void): void {
  if (JSON_MODE) echo(JSON.stringify({ ok: true, ...data }));
  else text();
}

// One reader for all questions, so piped answers ("1\n2\n") are not lost between prompts.
let lines: AsyncIterator<string> | null = null;

async function ask(question: string, flag: string, def?: string): Promise<string> {
  if (JSON_MODE) throw new CliError(`${question}? (--json never asks; pass ${flag})`);
  process.stdout.write(def !== undefined ? `${question} [${def}]: ` : `${question}: `);
  lines ??= createInterface({ input: process.stdin, terminal: false })[Symbol.asyncIterator]();
  const next = await lines.next();
  if (next.done) throw new CliError(`no answer to "${question}" (input closed); pass ${flag}`);
  if (!process.stdin.isTTY) echo(next.value);
  return next.value.trim() || def || "";
}

async function askNumber(question: string, max: number, def: number, flag: string): Promise<number> {
  for (;;) {
    const n = Number(await ask(question, flag, String(def)));
    if (Number.isInteger(n) && n >= 1 && n <= max) return n;
    echo(`Error: ${n} is not in the range 1<=x<=${max}.`);
  }
}

function printLines(sym: string, paths: string[], limit = 15): void {
  for (const p of paths.slice(0, limit)) echo(`  ${sym} ${p}`);
  if (paths.length > limit) echo(`  ${sym} ... and ${paths.length - limit} more`);
}

const summary = (r: Report) => `pushed ${r.pushed} change(s), applied ${r.applied_remote} remote op(s), ` +
  `wrote ${r.written.length}, deleted ${r.deleted.length}, ${r.conflicts.length} conflict(s), ` +
  `${r.skipped.length} skipped, ${r.problems.length} problem(s)`;

function printReport(r: Report): void {
  echo(summary(r));
  printLines("^", r.pushed_paths); // uploaded
  printLines("v", r.written); // downloaded / updated here
  printLines("x", r.deleted); // deleted here
  for (const [a, b] of r.conflicts) echo(yellow(`  conflict: ${a} -> kept both, other copy at ${b}`));
  for (const s of r.skipped) echo(yellow(`  skipped: ${s}`));
  for (const p of r.problems) err(red(`  problem: ${p}`));
}

/** Path as you would type it: ~/x instead of /home/you/x. */
function short(p: string): string {
  const abs = resolve(p), rel = relative(homedir(), abs);
  return rel && !rel.startsWith("..") && !rel.startsWith(sep) ? "~/" + rel.split(sep).join("/") : abs;
}

const expand = (p: string) => (p === "~" || p.startsWith("~/") ? join(homedir(), p.slice(1)) : p);

// ------------------------------------------------------------------ vault folders
interface Cfg { chat: string; chat_peer?: string; profile: string; invite?: string; code?: string; [k: string]: unknown }

const cfgPath = (vault: string) => join(vault, INTERNAL_DIR, "config.json");

function loadCfg(vault: string, cmd: string): Cfg {
  if (!existsSync(cfgPath(vault))) throw notAVault(vault, cmd);
  rememberVault(vault);
  return JSON.parse(readFileSync(cfgPath(vault), "utf8"));
}

function saveCfg(vault: string, cfg: Cfg): void {
  mkdirSync(join(vault, INTERNAL_DIR), { recursive: true });
  writeFileSync(cfgPath(vault), JSON.stringify(cfg, null, 2));
}

function rememberVault(vault: string): void {
  const m = mem(), path = resolve(vault), old = m.vaults ?? [];
  m.vaults = [...old.filter((v) => v !== path && existsSync(cfgPath(v))), path];
  if (JSON.stringify(m.vaults) !== JSON.stringify(old)) memSave(m);
}

const knownVaults = () => (mem().vaults ?? []).filter((v) => existsSync(cfgPath(v)));

/** -> [vault id, were we removed from it] for a vault folder; [null, false] if none. */
async function vaultAt(folder: string): Promise<[string | null, boolean]> {
  if (!existsSync(join(folder, STATE_FILE))) return [null, false];
  const st = await State.load(new NodeFiles(folder));
  return [st.d.vault_id, st.d.removed];
}

function notAVault(vault: string, cmd = "status"): CliError {
  const lines = [`${short(vault)} is not a tgsync vault.`];
  const known = knownVaults();
  if (known.length) {
    lines.push("Your vaults on this computer:");
    for (const v of known) lines.push(`  cd ${short(v)} && tgsync ${cmd}`);
  }
  if (Object.keys(mem().joins ?? {}).length) lines.push("You asked to join a vault. When they have accepted you:  tgsync join");
  lines.push("Join a friend's vault into this folder:  tgsync join <invite line> .");
  lines.push("Start a new vault in this folder:        tgsync new .");
  return new CliError(lines.join("\n"));
}

// ------------------------------------------------------------------ Telegram or sandbox
// Everything that connects goes through here, so commands never care which one they talk to.
const OPEN: Transport[] = []; // closed when the command ends

async function hidden(question: string): Promise<string> {
  if (!process.stdin.isTTY || lines) return ask(question, "a terminal");
  process.stdout.write(`${question}: `);
  return new Promise((ok, no) => {
    let buf = "";
    const onData = (d: Buffer) => {
      for (const ch of d.toString("utf8")) {
        if (ch === "\r" || ch === "\n") { done(); ok(buf); return; }
        if (ch === "\u0003") { done(); no(new CliError("Aborted!")); return; }
        if (ch === "\u007f" || ch === "\b") buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    const done = () => { process.stdin.off("data", onData); process.stdin.setRawMode(false); process.stdin.pause(); echo(); };
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

const LOGIN: LoginPrompts = {
  phone: () => ask("Your phone number (international format, e.g. +491701234567)", "a terminal"),
  code: () => ask("The login code Telegram just sent you (in the Telegram app)", "a terminal"),
  password: () => hidden("Your Telegram 2FA password"),
};

/** Connect; if the Telegram session is missing or revoked, log in again right here (terminal only). */
async function connectOrRelogin(profile: string): Promise<TelegramClient> {
  try {
    return await connect(profile);
  } catch (e) {
    if (!(e instanceof NotLoggedIn) || JSON_MODE || !process.stdin.isTTY) throw e;
    info("Your Telegram session is missing or expired; logging in again.");
    info("Logged in as " + await interactiveLogin(profile, loadCreds(profile)!, LOGIN));
    return connect(profile);
  }
}

/** The group behind a link, real or sandbox. `tg` is null in the sandbox. */
async function transportFor(ref: string, tg: TelegramClient | null, peer?: string): Promise<Transport> {
  let tr: Transport;
  if (isSandboxLink(ref)) {
    if (sandboxRoot() === null) { // its keys live in the sandbox config dir
      const base = resolve(ref.slice(PREFIX.length), "..", "..");
      throw new CliError(`This is a sandbox vault. First run:  export TGSYNC_SANDBOX=${base}`);
    }
    if (!existsSync(ref.slice(PREFIX.length))) throw new CliError(`sandbox group ${ref.slice(PREFIX.length)} does not exist (was the sandbox deleted?)`);
    tr = new DirTransport(ref);
  } else {
    if (!tg) throw new CliError("this vault's group is on Telegram, but TGSYNC_SANDBOX is set; unset it first");
    let chat;
    try { chat = await resolveChat(tg, ref, peer); } catch (e) {
      await tg.destroy().catch(() => {}); // else the open connection keeps the process alive
      throw e;
    }
    const t = new TelegramTransport(tg, chat);
    t.log = err;
    tr = t;
  }
  OPEN.push(tr);
  return tr;
}

async function openVault(vault: string, cmd: string): Promise<[Vault, Cfg]> {
  const cfg = loadCfg(vault, cmd);
  const profile = cfg.profile ?? "default";
  const chat = String(cfg.chat);
  const tg = isSandboxLink(chat) ? null : await connectOrRelogin(profile);
  const tr = await transportFor(chat, tg, cfg.chat_peer);
  savePeer(vault, cfg, tr);
  const v = await Vault.open(new NodeFiles(resolve(vault)), await loadIdentity(profile), tr);
  v.notify = say;
  return [v, cfg];
}

/** Keep the group's id and access hash next to its link, so later runs find the group without the link. */
function savePeer(vault: string, cfg: Cfg, tr: Transport): void {
  const peer = tr instanceof TelegramTransport ? savedPeer(tr.chat) : undefined;
  if (peer && cfg.chat_peer !== peer) { cfg.chat_peer = peer; saveCfg(vault, cfg); }
}

/** Load or collect Telegram API credentials for a profile and save them (with the proxy). */
async function credsFor(profile: string, proxy?: string, api?: [number, string] | null): Promise<Creds> {
  const saved = loadCreds(profile);
  if (!api && process.env.TGSYNC_API_ID && process.env.TGSYNC_API_HASH) api = [Number(process.env.TGSYNC_API_ID), process.env.TGSYNC_API_HASH];
  let creds: Creds;
  if (api) creds = { api_id: api[0], api_hash: api[1].trim(), proxy: saved?.proxy ?? null };
  else if (saved) creds = saved;
  else {
    if (!JSON_MODE) {
      echo("Ask a teammate for their api_id/api_hash (the same pair works for everyone),\n" +
           "or create one at https://my.telegram.org -> API development tools");
    }
    const id = Number(await ask("api_id", "--api-id/--api-hash or TGSYNC_API_ID/TGSYNC_API_HASH"));
    if (!Number.isInteger(id) || id <= 0) throw new CliError("api_id is a number");
    creds = { api_id: id, api_hash: (await ask("api_hash", "--api-hash")).trim(), proxy: null };
  }
  if (proxy !== undefined) creds.proxy = proxy.toLowerCase() === "none" ? null : proxy;
  parseProxy(creds.proxy); // fails early on a bad proxy
  saveCreds(profile, creds);
  return creds;
}

/** Make sure the profile has a key (and, for Telegram, credentials and a login). Client is null in the sandbox. */
async function ensureReady(profile: string, api: [number, string] | null, proxy?: string): Promise<[Identity, TelegramClient | null]> {
  let ident: Identity;
  try { ident = await loadIdentity(profile); } catch {
    ident = await initIdentity(profile);
    info(`Created a new key for account '${profile}'.`);
  }
  if (sandboxRoot() !== null) return [ident, null];
  const creds = await credsFor(profile, proxy, api);
  try {
    return [ident, await connect(profile)];
  } catch (e) {
    if (!(e instanceof NotLoggedIn)) throw e;
    if (JSON_MODE) throw new CliError(`Telegram login needed for account '${profile}'; run the same command once in a terminal without --json`);
    info(`Logging in to Telegram for account '${profile}'...`);
    info("Logged in as " + await interactiveLogin(profile, creds, LOGIN));
    return [ident, await connect(profile)];
  }
}

/** Pick the account for new/join: explicit > TGSYNC_PROFILE > only one saved > ask > 'default'. */
async function chooseProfile(explicit?: string): Promise<string> {
  explicit = explicit || process.env.TGSYNC_PROFILE;
  if (explicit) return checkProfileName(explicit);
  const profiles = listProfiles();
  if (!profiles.length) return "default";
  if (profiles.length === 1) return profiles[0];
  if (JSON_MODE) throw new CliError(`Which account? (--json never asks; pass --profile, one of: ${profiles.join(", ")})`);
  const cur = currentProfile();
  echo("Which account should this vault use?");
  profiles.forEach((name, i) => echo(`  ${i + 1}) ${name}`));
  echo(`  ${profiles.length + 1}) a new account`);
  const n = await askNumber("Choose", profiles.length + 1, profiles.includes(cur) ? profiles.indexOf(cur) + 1 : 1, "--profile");
  return n === profiles.length + 1 ? checkProfileName(await ask("Name for the new account", "--profile")) : profiles[n - 1];
}

// ------------------------------------------------------------------ commands
type Opts = { [k: string]: string | boolean | undefined };
interface Command {
  help: string;
  usage: string;
  options: ParseArgsConfig["options"];
  run(args: string[], o: Opts): Promise<void>;
}

const VAULT_OPT = { vault: { type: "string", short: "C", default: "." } } as const;
const PROFILE_OPT = { profile: { type: "string" }, proxy: { type: "string" } } as const;

function reportCmd(help: string, what: "pullChanges" | "pushChanges"): Command {
  return {
    help, usage: "[-C VAULT]", options: VAULT_OPT,
    async run(_a, o) {
      const [v] = await openVault(o.vault as string, what === "pullChanges" ? "pull" : "push");
      const rep = await v[what]();
      emit({ report: rep }, () => printReport(rep));
    },
  };
}

const COMMANDS: { [name: string]: Command } = {
  new: {
    help: "Start a new vault in FOLDER (makes a private Telegram group, key and login as needed).",
    usage: "FOLDER [--chat LINK] [--name NAME] [--profile P]",
    options: { chat: { type: "string" }, name: { type: "string", default: "" }, "no-git": { type: "boolean" },
               "api-id": { type: "string" }, "api-hash": { type: "string" }, ...PROFILE_OPT },
    async run([folder], o) {
      if (!folder) throw new CliError("Missing argument 'FOLDER'.");
      folder = expand(folder);
      if (existsSync(cfgPath(folder))) { // check before making a group
        throw new CliError(`${short(folder)} is already a tgsync vault. To use it:  cd ${short(folder)} && tgsync\n` +
          "To start another vault, pick a new folder:  tgsync new ~/vaults/NAME");
      }
      const profile = await chooseProfile(o.profile as string | undefined);
      const api: [number, string] | null = o["api-id"] && o["api-hash"] ? [Number(o["api-id"]), o["api-hash"] as string] : null;
      const [ident, tg] = await ensureReady(profile, api, o.proxy as string | undefined);
      let chat: string, link: string | null = null;
      if (o.chat) chat = o.chat as string;
      else if (!tg) chat = link = newSandboxGroup();
      else chat = link = (await createGroup(tg, basename(resolve(folder)) || "tgsync vault"))[1];
      const tr = await transportFor(chat, tg); // the group is found by its link from now on
      mkdirSync(folder, { recursive: true });
      const v = await Vault.create(new NodeFiles(resolve(folder)), ident, tr, (o.name as string) || profile);
      const cfg: Cfg = { chat, profile };
      if (link) cfg.invite = link;
      if (tr instanceof TelegramTransport) cfg.chat_peer = savedPeer(tr.chat);
      saveCfg(folder, cfg);
      rememberVault(folder);
      const code = link ? encodeInvite({ link, vaultId: v.vaultId!, fingerprint: await fingerprint(v.keys.key(1)), api: null }) : null;
      emit({ folder: resolve(folder), profile, vault_id: v.vaultId, invite: code }, () => {
        echo(`Vault ready in ${short(folder)} (account '${profile}').\n`);
        echo(`  cd ${short(folder)}`);
        echo("  tgsync          sync your changes (run it inside the folder)");
        if (code) {
          echo("\nTo add a friend, send them this line:\n");
          echo(`  tgsync join ${code}\n`);
          echo("They get a short code like ab12-cd34 and tell it to you. Then, in the vault folder:\n" +
               "  tgsync accept ab12-cd34\n(`tgsync invite` prints the line again later.)");
        } else echo("Make an invite for friends with:  tgsync invite --link <group link>");
      });
    },
  },

  join: {
    help: "Join a vault from an invite code. After they accept you, run plain `tgsync join` again.",
    usage: "[CODE] [FOLDER] [--name NAME] [--profile P]",
    options: { name: { type: "string" }, "no-git": { type: "boolean" }, ...PROFILE_OPT },
    async run([code, folder], o) {
      const joins = mem().joins ?? {};
      if (code === undefined && !Object.keys(joins).length) { // removed from the vault here? its saved line asks again
        const here = folder ?? process.cwd();
        if (existsSync(cfgPath(here)) && (await vaultAt(here))[1]) [code, folder] = [loadCfg(here, "join").code!, here];
      }
      if (code === undefined) {
        const all = Object.values(joins);
        if (!all.length) throw new CliError("Paste the invite line your friend sent you, e.g.\n  tgsync join tgsync1-...  [FOLDER]");
        if (all.length > 1) throw new CliError("You are waiting on several vaults; run one of these:\n" + all.map((j) => `  tgsync join ${j.code}`).join("\n"));
        code = all[0].code;
      }
      let inv;
      try { inv = decodeInvite(code); } catch (e) { throw new CliError((e as Error).message); }
      const saved = joins[inv.vaultId];
      if (folder === undefined && saved?.folder) folder = saved.folder;
      if (folder === undefined && (await vaultAt(process.cwd()))[0] === inv.vaultId) folder = process.cwd(); // already here
      if (folder === undefined) {
        const def = readdirSync(process.cwd()).length ? `~/vaults/${inv.vaultId.slice(0, 6)}` : ".";
        folder = await ask("Folder for the vault", "FOLDER", def);
      }
      folder = expand(folder);
      const [vid] = await vaultAt(folder);
      const same = existsSync(cfgPath(folder)) && vid === inv.vaultId; // this vault is already here: back in?
      if (existsSync(cfgPath(folder)) && !same) {
        throw new CliError(`${short(folder)} already holds a different tgsync vault. Pick an empty or new folder, e.g.:\n` +
          `  tgsync join <invite line> ~/vaults/${inv.vaultId.slice(0, 6)}`);
      }
      const profile = await chooseProfile((o.profile as string | undefined) ?? saved?.profile);
      const [ident, tg] = await ensureReady(profile, inv.api, o.proxy as string | undefined);
      const tr = await transportFor(inv.link, tg);
      let rejoin = false;
      if (same) { // catch up first: this folder may not know yet that we were removed
        const old = await Vault.open(new NodeFiles(resolve(folder)), ident, tr);
        await old.pull();
        rejoin = old.removed;
        if (!rejoin) throw new CliError(`You already joined this vault in ${short(folder)}. To use it:  cd ${short(folder)} && tgsync`);
      }
      const found = await Vault.discover(tr, ident);
      if (!found.has(inv.vaultId)) {
        const who = (o.name as string | undefined) || profile;
        await Vault.postJoinRequest(tr, ident, inv.vaultId, who);
        const m = mem();
        (m.joins ??= {})[inv.vaultId] = { code, profile, folder: resolve(folder) };
        memSave(m);
        const sc = await shortCode(ident.recipient);
        emit({ state: "waiting", code: sc, folder: resolve(folder) }, () => {
          echo(`Join request sent as '${who}'. Files will go in ${short(folder!)}.`);
          echo(bold(`Tell the person who invited you this code: ${sc}`));
          echo(`They run:  tgsync accept ${sc}`);
          echo("Then you run:  tgsync join     (no need to paste the line again; any time, no hurry)");
        });
        return;
      }
      if (found.get(inv.vaultId)!.replace(/ /g, "") !== inv.fingerprint.replace(/ /g, "")) {
        throw new CliError("KEY FINGERPRINT MISMATCH between the invite and the vault - refusing to join");
      }
      if (rejoin) { // start the vault state fresh; the old one is kept next to it, files stay
        const st = join(folder, STATE_FILE);
        renameSync(st, `${st}.removed-${Math.floor(Date.now() / 1000)}`);
      }
      mkdirSync(folder, { recursive: true });
      const v = await Vault.join(new NodeFiles(resolve(folder)), ident, tr, inv.vaultId);
      v.notify = say;
      saveCfg(folder, { chat: inv.link, chat_peer: tr instanceof TelegramTransport ? savedPeer(tr.chat) : undefined,
                        profile, invite: inv.link, code });
      rememberVault(folder);
      const m = mem();
      if (m.joins?.[inv.vaultId]) { delete m.joins[inv.vaultId]; memSave(m); }
      const rep = await v.pullChanges();
      emit({ state: "joined", folder: resolve(folder), report: rep }, () => {
        echo(`Joined. Files go in ${short(folder!)}`);
        printReport(rep);
        echo(`\nFrom now on, in ${short(folder!)}:  tgsync (what changed)   tgsync pull   tgsync push`);
      });
    },
  },

  invite: {
    help: "Print an invite line to send to a friend.",
    usage: "[--link LINK] [--include-api] [-C VAULT]",
    options: { link: { type: "string" }, "include-api": { type: "boolean" }, ...VAULT_OPT },
    async run(_a, o) {
      const [v, cfg] = await openVault(o.vault as string, "invite");
      await v.pull();
      const tr = v.transport;
      const use = (o.link as string | undefined) ?? cfg.invite ??
        (tr instanceof TelegramTransport ? await exportInvite(tr.tg, tr.chat) : String(cfg.chat));
      if (cfg.invite !== use) { cfg.invite = use; saveCfg(o.vault as string, cfg); }
      let api: [number, string] | null = null;
      if (o["include-api"]) {
        const creds = loadCreds(cfg.profile ?? "default");
        if (!creds) throw new CliError("this account has no Telegram api_id/api_hash saved");
        api = [creds.api_id, creds.api_hash];
        info(yellow("This code contains your api_id/api_hash: only share it with people you trust."));
      }
      const code = encodeInvite({ link: use, vaultId: v.vaultId!, fingerprint: await fingerprint(v.keys.key(1)), api });
      emit({ invite: code }, () => {
        echo(`\n  tgsync join ${code}\n`);
        echo("They read you a short code; then:  tgsync accept <code>");
      });
    },
  },

  members: {
    help: "Who is in the vault, and who is waiting to join.",
    usage: "[-C VAULT]", options: VAULT_OPT,
    async run(_a, o) {
      const [v] = await openVault(o.vault as string, "members");
      const reqs = await v.pendingRequests();
      const codes = await Promise.all(reqs.map((r) => shortCode(r.recipient)));
      const mine = v.me.recipient;
      const ids = await Promise.all(v.members.map((m) => memberId(m.recipient)));
      emit({
        members: v.members.map((m, i) => ({ name: m.name, id: ids[i], you: m.recipient === mine })),
        waiting: reqs.map((r, i) => ({ code: codes[i], name: r.name })),
      }, () => {
        echo("members:");
        v.members.forEach((m, i) => echo(`  ${m.name || ids[i]}${m.recipient === mine ? "  (you)" : ""}`));
        if (reqs.length) {
          echo("\nwaiting to join (only accept a code the person read to you yourself):");
          reqs.forEach((r, i) => echo(`  ${codes[i]}  ${r.name || "(no name)"}     ->  tgsync accept ${codes[i]}`));
        }
      });
    },
  },

  accept: {
    help: "Let in the person whose join code is CODE (typing it is the confirmation).",
    usage: "CODE [--name NAME] [-C VAULT]",
    options: { name: { type: "string" }, ...VAULT_OPT },
    async run([code], o) {
      if (!code) throw new CliError("Missing argument 'CODE'.");
      const [v] = await openVault(o.vault as string, "accept");
      const want = code.trim().toLowerCase();
      let hit;
      for (const r of await v.pendingRequests()) if (await shortCode(r.recipient) === want) hit = r;
      if (!hit) throw new CliError(`nobody is waiting with code '${code}' (see \`tgsync members\`)`);
      await v.acceptRequest(hit, o.name as string | undefined);
      const who = (o.name as string | undefined) || hit.name || want;
      emit({ accepted: who }, () => echo(`Accepted ${who}. Tell them to run:  tgsync join`));
    },
  },

  remove: {
    help: "Remove a member (by name) and rotate the vault key.",
    usage: "WHO [--yes] [-C VAULT]",
    options: { yes: { type: "boolean" }, ...VAULT_OPT },
    async run([who], o) {
      if (!who) throw new CliError("Missing argument 'WHO'.");
      if (!o.yes) {
        if (JSON_MODE) throw new CliError("Removing rotates the vault key. (--json never asks; pass --yes)");
        const a = await ask("Rotate the vault key so they can't read anything new? [y/N]", "--yes", "n");
        if (!/^y(es)?$/i.test(a)) throw new CliError("Aborted!");
      }
      const [v] = await openVault(o.vault as string, "remove");
      await v.removeMember(who);
      const epoch = v.keys.current;
      emit({ removed: who, epoch }, () => echo(`Removed. New key epoch ${epoch}; they can't read anything new.`));
    },
  },

  login: {
    help: "Log a profile in to Telegram (or show which account it uses). new/join do this for you.",
    usage: "[--profile P] [--api-id ID --api-hash HASH] [--proxy URL]",
    options: { "api-id": { type: "string" }, "api-hash": { type: "string" }, ...PROFILE_OPT },
    async run(_a, o) {
      if (sandboxRoot() !== null) throw new CliError("The sandbox (TGSYNC_SANDBOX) needs no login.");
      const profile = await chooseProfile(o.profile as string | undefined);
      const api: [number, string] | null = o["api-id"] && o["api-hash"] ? [Number(o["api-id"]), o["api-hash"] as string] : null;
      const [, tg] = await ensureReady(profile, api, o.proxy as string | undefined);
      try {
        const me = await tg!.getMe();
        const account = `${me.firstName ?? ""} (@${me.username ?? me.id})`;
        emit({ profile, account }, () => echo(`Account '${profile}' is logged in as ${account}.`));
      } finally {
        await tg!.destroy();
      }
    },
  },

  pull: reportCmd("Download teammates' changes only (uploads nothing).", "pullChanges"),
  push: reportCmd("Upload your changes only (never touches your local files).", "pushChanges"),

  status: {
    help: "What you changed, and what others changed that you don't have yet.",
    usage: "[--check] [--offline] [-C VAULT]",
    options: { check: { type: "boolean" }, offline: { type: "boolean" }, ...VAULT_OPT },
    async run(_a, o) {
      const dir = o.vault as string;
      const cfg = loadCfg(dir, "status");
      const profile = cfg.profile ?? "default";
      const ident = await loadIdentity(profile);
      let tr: Transport | null = null;
      let onlineError: string | null = null;
      const chat = String(cfg.chat);
      if (!o.offline || o.check) {
        try {
          const tg = isSandboxLink(chat) ? null : await withTimeout(connectOrRelogin(profile), 60_000);
          tr = await withTimeout(transportFor(chat, tg, cfg.chat_peer), 60_000);
          savePeer(dir, cfg, tr);
        } catch (e) { onlineError = (e as Error).message || String(e); }
      }
      const v = await Vault.open(new NodeFiles(resolve(dir)), ident, tr ?? (null as unknown as Transport));
      if (!o.offline && tr) {
        try { // reads only the small change messages; your files are not touched
          await withTimeout(v.fetchChanges(), 60_000);
        } catch (e) { onlineError = (e as Error).message || String(e); }
      }
      const s = await v.status();
      const incoming: Incoming[] = o.offline ? [] : await v.incoming();
      const checks = o.check ? await check(v, tr, chat, profile, onlineError) : null;
      const ok = checks === null || checks.every((x) => x.ok);
      emit({
        vault_id: s.vault_id, epoch: s.epoch, fingerprint: s.fingerprint, profile,
        members: s.members.map(([n, r]) => n || r.slice(0, 12)),
        pending: s.pending.map(([op, path]) => ({ op, path })),
        incoming: o.offline || onlineError ? null : incoming, online_error: o.offline ? null : onlineError,
        problems: s.problems.map(([, what]) => what), checks,
      }, () => {
        echo(`vault ${s.vault_id}  key epoch ${s.epoch}  fingerprint ${s.fingerprint}`);
        echo(`you: account '${profile}', key ${ident.recipient.slice(0, 14)}...   members: ` +
             s.members.map(([n, r]) => n || r.slice(0, 12)).join(", "));
        if (s.pending.length) echo("your changes, not uploaded yet:");
        for (const [op, path] of s.pending) {
          echo(`  ${op === "put" || op === "mkdir" ? "M" : "D"} ${path}${op === "mkdir" || op === "rmdir" ? "/" : ""}`);
        }
        if (!s.pending.length) echo("  nothing to upload");
        if (o.offline) { /* nothing about others */ }
        else if (onlineError) echo(yellow(`  could not check the group (${onlineError}); others' changes not shown`));
        else if (incoming.length) {
          echo("changed by others, not in your folder yet:");
          for (const x of incoming) {
            const mark = x.op === "delete" || x.op === "rmdir" ? "D" : "M";
            echo(`  ${mark} ${x.path}${x.op === "mkdir" || x.op === "rmdir" ? "/" : ""}   (${x.who})`);
            if (x.also_local) echo(yellow("      you changed this too: `tgsync push` then `tgsync pull` keeps both versions (a conflict copy)"));
          }
          echo("get them:  tgsync pull");
        } else echo("  nothing new from others");
        for (const [, what] of s.problems) echo(red(`  problem: ${what}`));
        if (checks) {
          echo("\nchecking Telegram and the vault...");
          for (const x of checks) echo(`  ${x.ok ? "OK " : "BAD"}  ${x.what}${x.detail ? `  (${x.detail})` : ""}`);
          echo(ok ? "all good" : "something needs attention");
        }
      });
      if (!ok) process.exitCode = 1;
    },
  },

  log: {
    help: "Who changed what and when, newest first (works offline). Give PATH for one file or folder.",
    usage: "[PATH] [-n N] [-C VAULT]",
    options: { n: { type: "string", short: "n", default: "50" }, ...VAULT_OPT },
    async run([path], o) {
      const dir = o.vault as string;
      const cfg = loadCfg(dir, "log");
      const v = await Vault.open(new NodeFiles(resolve(dir)), await loadIdentity(cfg.profile ?? "default"), null as unknown as Transport);
      const rows = await v.log(path, Number(o.n));
      emit({ log: rows }, () => {
        if (!rows.length) {
          echo("No changes recorded yet. They show up here after the next `tgsync pull` or `tgsync push`.");
          return;
        }
        for (const r of rows) {
          const what = r.copy ? `${r.path} -> ${r.copy}` : r.path;
          echo(`${when(r.ts)}  ${r.who.padEnd(12)} ${(WORDS[r.op] ?? r.op).padEnd(14)} ${what}`);
        }
        echo("Older version of a file:  tgsync restore <path>");
      });
    },
  },

  restore: {
    help: "Bring back an older version of a file from the group. Leave things out and it asks.\n\n" +
      "  tgsync restore                    pick a recently changed file, then a version\n" +
      "  tgsync restore notes/x.md         pick one of that file's versions\n" +
      "  tgsync restore notes/x.md 812.0   restore exactly that version",
    usage: "[PATH] [REV] [-C VAULT]", options: VAULT_OPT,
    async run([path, rev], o) {
      const dir = o.vault as string;
      const [v] = await openVault(dir, "restore");
      await v.fetchChanges(); // know about every version, including the newest
      if (path === undefined) {
        const seen: string[] = [];
        for (const r of await v.log(undefined, 500)) if (r.op === "put" && !seen.includes(r.path)) seen.push(r.path);
        if (!seen.length) throw new CliError("no history yet");
        path = seen[await pick("Recently changed files:", seen.slice(0, 15))];
      }
      try { path = normalize(path); } catch (e) { throw new CliError((e as Error).message); }
      if (rev === undefined) {
        const rows = await v.versions(path);
        if (!rows.length) throw new CliError(`no history for '${path}'`);
        rev = rows[await pick(`Versions of ${path} (newest first):`, rows.map((r) => `${r.rev.padEnd(10)}  ${when(r.ts)}  ${r.who}`))].rev;
      }
      try { await v.restoreVersion(path, rev); } catch (e) { throw new CliError((e as Error).message); }
      emit({ restored: path, rev }, () =>
        echo(`Restored ${path} as of ${rev}. The version it replaced stays in the group's history. To share it:  tgsync push`));
    },
  },
};

const WORDS: { [op: string]: string } = { put: "wrote", delete: "deleted", conflict: "conflict", mkdir: "made folder", rmdir: "removed folder" };

function when(ts: number): string {
  const d = new Date(ts * 1000), p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

async function pick(title: string, rows: string[]): Promise<number> {
  if (JSON_MODE) throw new CliError(`${title} (--json never asks; pass PATH and REV)`);
  echo(title);
  rows.forEach((r, i) => echo(`  ${String(i + 1).padStart(2)}) ${r}`));
  return (await askNumber("Which one (number)", rows.length, 1, "PATH and REV")) - 1;
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout;
  return Promise.race([p, new Promise<T>((_, no) => { t = setTimeout(() => no(new Error("timed out")), ms); })])
    .finally(() => clearTimeout(t));
}

/** Online health check; stops at the first check that blocks the rest. */
async function check(v: Vault, tr: Transport | null, chat: string, profile: string, connectError: string | null) {
  const out: { ok: boolean; what: string; detail: string }[] = [];
  const line = (ok: boolean, what: string, detail = "") => out.push({ ok, what, detail });
  if (!isSandboxLink(chat)) {
    const creds = loadCreds(profile);
    line(!!creds, "Telegram credentials", creds ? `proxy: ${creds.proxy ?? "none"}` : "none saved; run `tgsync join` or `tgsync new`");
    if (!creds) return out;
  }
  if (!tr) { line(false, "connect + group access", connectError ?? "not connected"); return out; }
  if (tr instanceof TelegramTransport) {
    const me = await tr.tg.getMe();
    line(true, "Telegram account", `${me.firstName ?? ""} ${me.lastName ?? ""} id ${me.id}`.replace(/\s+/g, " ").trim());
  }
  let rep: Report;
  try { rep = await v.pull(); } catch (e) { line(false, "connect + group access", (e as Error).message); return out; }
  line(!v.removed && v.keys.size > 0, "vault membership", v.removed ? "removed" : v.keys.size ? `key epoch ${v.keys.current}` : "no keys");
  line(!rep.problems.length, "log health", rep.problems.length ? `${rep.problems.length} problem(s)` : "");
  const old = v.state.d.problems;
  line(!old.length, "problems on record", old.length ? String(old.length) : "");
  return out;
}

// ------------------------------------------------------------------ entry
function help(): string {
  const width = Math.max(...Object.keys(COMMANDS).map((c) => c.length));
  return [
    "Usage: tgsync [--json] COMMAND [ARGS]...",
    "",
    "  Share this folder through your Telegram group, end-to-end encrypted.",
    "",
    "  Inside a vault folder, plain `tgsync` shows what changed (same as `tgsync status`).",
    "  Nothing moves until you run `tgsync pull` (download) or `tgsync push` (upload).",
    "",
    "Options:",
    "  --json     Print one JSON object (for scripts and plugins); never ask questions.",
    "  --version  Show the version and exit.",
    "  --help     Show this message and exit.",
    "",
    "Commands:",
    ...Object.entries(COMMANDS).map(([n, c]) => `  ${n.padEnd(width)}  ${c.help.split("\n")[0]}`),
  ].join("\n");
}

export async function main(argv: string[]): Promise<number> {
  JSON_MODE = argv.includes("--json");
  argv = argv.filter((a) => a !== "--json");
  try {
    if (argv[0] === "--version") { echo(`tgsync, version ${VERSION}`); return 0; }
    if (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") { echo(help()); return 0; }
    const [name, ...rest] = argv;
    if (name === undefined) {
      if (existsSync(cfgPath(process.cwd()))) return await runCmd("status", []);
      if (JSON_MODE) throw notAVault(process.cwd());
      echo(help() + "\n");
      echo(notAVault(process.cwd()).message);
      return 0;
    }
    if (!COMMANDS[name]) throw new CliError(`No such command '${name}'. See \`tgsync --help\`.`);
    return await runCmd(name, rest);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (JSON_MODE) echo(JSON.stringify({ ok: false, error: msg }));
    else err(`Error: ${msg}`);
    if (!(e instanceof CliError) && process.env.TGSYNC_DEBUG && e instanceof Error) err(e.stack ?? "");
    return 1;
  } finally {
    if (lines) process.stdin.destroy(); // a question left stdin open
    for (const tr of OPEN.splice(0)) await tr.close().catch(() => {});
  }
}

async function runCmd(name: string, rest: string[]): Promise<number> {
  const cmd = COMMANDS[name];
  if (rest.includes("--help") || rest.includes("-h")) {
    echo(`Usage: tgsync ${name} ${cmd.usage}\n\n  ${cmd.help.replace(/\n/g, "\n  ")}`);
    return 0;
  }
  let parsed;
  try { parsed = parseArgs({ args: rest, options: cmd.options, allowPositionals: true, strict: true }); }
  catch (e) { throw new CliError(`${(e as Error).message}\nUsage: tgsync ${name} ${cmd.usage}`); }
  const o = parsed.values as Opts;
  if (typeof o.vault === "string") o.vault = expand(o.vault);
  await cmd.run(parsed.positionals, o);
  return process.exitCode === 1 ? 1 : 0;
}

// Run when executed directly (the bundle in dist/), not when imported by tests.
if (process.argv[1] && /tgsync(\.m?js)?$/.test(basename(process.argv[1]))) {
  process.exitCode = await main(process.argv.slice(2));
}
