// SPDX-License-Identifier: AGPL-3.0-or-later
// Telegram through mtcute (MTProto, your own user account). Same behaviour as src/tgsync/telegram.py:
// files are documents with a `tgs1:<kind>` caption, sends are paced, flood waits slow us down.
// The login is a session string in the profile folder (`mtcute.session`); nothing native.
import { BaseTelegramClient, TelegramClient } from "@mtcute/core/client.js";
import { InputMedia, Long, MemoryStorage, MtArgumentError, tl, type Chat, type Message as TgMessage } from "@mtcute/core";
import { HttpProxyTcpTransport, NodePlatform, SocksProxyTcpTransport, TcpTransport } from "@mtcute/node";
import { NodeCryptoProvider } from "@mtcute/node/utils.js";
import { SIMD_AVAILABLE, initSync } from "@mtcute/wasm";
import wasmSimd from "@mtcute/wasm/mtcute-simd.wasm";
import wasmPlain from "@mtcute/wasm/mtcute.wasm";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { caption, parseCaption } from "../protocol.ts";
import { TransportError, type Message, type Transport } from "../transport.ts";
import { appDir } from "./home.ts";

// Telegram does not publish exact limits. Folklore: ~20 messages/minute and ~1/second per chat.
// Defaults sit just under that; every flood wait slows this session down further.
const SEND_PER_MINUTE = 18;
const SEND_MIN_GAP = 1.2; // seconds between sends
const FETCH_MIN_GAP = 0.3; // seconds between downloads
const MAX_FLOOD_RETRIES = 6;

export class NotLoggedIn extends TransportError {}

// ------------------------------------------------------------------ credentials (telegram.json, shared with Python)
export interface Creds { api_id: number; api_hash: string; proxy: string | null }

const credsPath = (profile: string) => join(appDir(profile), "telegram.json");

export function loadCreds(profile: string): Creds | null {
  const p = credsPath(profile);
  if (!existsSync(p)) return null;
  const d = JSON.parse(readFileSync(p, "utf8"));
  return { api_id: Number(d.api_id), api_hash: String(d.api_hash), proxy: d.proxy ?? null };
}

export function saveCreds(profile: string, c: Creds): void {
  writePrivate(credsPath(profile), JSON.stringify(c));
}

function writePrivate(path: string, text: string): void {
  writeFileSync(path, text, { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* Windows: per-user ACLs */ }
}

/** 'socks5://host:port' / 'http://host:port' (optionally user:pass@). A "mixed" port works with either. */
export function parseProxy(url: string | null | undefined) {
  url = url || process.env.TGSYNC_PROXY;
  if (!url) return null;
  let u: URL;
  try { u = new URL(url.includes("://") ? url : "socks5://" + url); } catch { u = new URL("bad://"); }
  const scheme = ({ "socks5:": "socks5", "socks5h:": "socks5", "socks4:": "socks4", "http:": "http", "https:": "http" } as const)[u.protocol as "http:"];
  if (!scheme || !u.hostname || !u.port) throw new TransportError(`bad proxy '${url}'; use e.g. socks5://127.0.0.1:10808`);
  const auth = { user: decodeURIComponent(u.username) || undefined, password: decodeURIComponent(u.password) || undefined };
  const host = u.hostname.replace(/^\[|\]$/g, ""), port = Number(u.port);
  return scheme === "http"
    ? new HttpProxyTcpTransport({ host, port, ...auth })
    : new SocksProxyTcpTransport({ host, port, version: scheme === "socks4" ? 4 : 5, ...auth });
}

// ------------------------------------------------------------------ client and login
const sessionPath = (profile: string) => join(appDir(profile), "mtcute.session");

/** mtcute's crypto, with its wasm inside our bundle instead of looked up in node_modules (one-file CLI). */
class Crypto extends NodeCryptoProvider {
  override async initialize(): Promise<void> {
    initSync(SIMD_AVAILABLE ? wasmSimd : wasmPlain);
  }
}

function makeClient(creds: Creds): TelegramClient {
  const base = new BaseTelegramClient({
    apiId: creds.api_id, apiHash: creds.api_hash,
    storage: new MemoryStorage(),
    crypto: new Crypto(),
    platform: new NodePlatform(),
    transport: parseProxy(creds.proxy) ?? new TcpTransport(),
    // tgsync reports one clear error instead of mtcute's connection chatter; TGSYNC_DEBUG=1 shows every call
    logLevel: process.env.TGSYNC_DEBUG ? 4 : 0,
    updates: false,
  });
  return new TelegramClient({ client: base });
}

function unreachable(profile: string, creds: Creds, e: unknown): TransportError {
  const why = (e as Error)?.message ?? String(e);
  if (creds.proxy) {
    return new TransportError(`Can't reach Telegram through the proxy ${creds.proxy} (${why}).\n` +
      `Is the proxy running? Start it and run the same command again.\n(The proxy is saved in ${credsPath(profile)}.)`);
  }
  return new TransportError(`Can't reach Telegram (${why}). Check your internet, or use a proxy: ` +
    "add --proxy socks5://127.0.0.1:PORT to `tgsync new` / `tgsync join`.");
}

export interface LoginPrompts { phone(): Promise<string>; code(): Promise<string>; password(): Promise<string> }

/** Log in on the terminal (phone, code, 2FA password) and save the session. Returns "Name (@user)". */
export async function interactiveLogin(profile: string, creds: Creds, ask: LoginPrompts): Promise<string> {
  const tg = makeClient(creds);
  try {
    const me = await tg.start({ phone: ask.phone, code: ask.code, password: ask.password,
                                invalidCodeCallback: () => {} }).catch((e) => { throw wrapConnect(profile, creds, e); });
    writePrivate(sessionPath(profile), await tg.exportSession());
    return `${me.firstName ?? ""} (@${me.username ?? me.id})`;
  } finally {
    await tg.destroy();
  }
}

/** Network trouble becomes "can't reach Telegram"; anything else keeps its own message. */
function wrapConnect(profile: string, creds: Creds, e: unknown): Error {
  if (e instanceof TransportError) return e;
  const net = /^E(CONNREFUSED|CONNRESET|TIMEDOUT|NOTFOUND|HOSTUNREACH|NETUNREACH|AI_AGAIN|PIPE)$/.test((e as any)?.code ?? "") ||
    /ProxyConnectionError|timed? ?out|socket|connection/i.test(`${(e as any)?.name} ${(e as Error)?.message}`);
  return net && !tl.RpcError.is(e) ? unreachable(profile, creds, e) : new TransportError(`Telegram: ${(e as Error)?.message ?? e}`);
}

/** Connect with the saved session; NotLoggedIn when there is none or Telegram revoked it. */
export async function connect(profile: string): Promise<TelegramClient> {
  const creds = loadCreds(profile);
  if (!creds) throw new TransportError("no Telegram API credentials; run `tgsync new` or `tgsync join` to set up");
  if (!existsSync(sessionPath(profile))) throw new NotLoggedIn("not logged in to Telegram yet; run the command in a terminal to log in");
  const tg = makeClient(creds);
  try {
    await tg.importSession(readFileSync(sessionPath(profile), "utf8").trim());
    await tg.connect();
    await tg.getMe();
  } catch (e) {
    await tg.destroy();
    if (tl.RpcError.is(e) && (e.code === 401 || /AUTH_KEY|SESSION_REVOKED|USER_DEACTIVATED/.test(e.text))) {
      throw new NotLoggedIn("Telegram session missing or revoked; run `tgsync` in a terminal to log in again");
    }
    throw wrapConnect(profile, creds, e);
  }
  return tg;
}

// ------------------------------------------------------------------ groups
/** Invite link (t.me/+..., t.me/joinchat/...), @username or numeric id -> chat (joins via the link if needed).
 *  `peer` is what `savedPeer` returned on an earlier run. This login keeps no chat list between runs, and
 *  a private group needs its access hash, so the hash is saved; then the link (rate-limited lookups) is rarely used. */
export async function resolveChat(tg: TelegramClient, ref: string, peer?: string): Promise<Chat> {
  const [id, hash] = (peer ?? "").split(":");
  if (id && hash) {
    try {
      return await tg.getChat({ _: "inputPeerChannel", channelId: Number(id), accessHash: Long.fromString(hash) });
    } catch { /* left the group, or another login: use the link */ }
  }
  if (/(?:t\.me|telegram\.me)\/(?:joinchat\/|\+)[\w-]+/.test(ref)) {
    try { return await tg.getChat(ref); } catch (e) {
      if (!(e instanceof MtArgumentError)) throw e; // only "You haven't joined" means: join now
    }
    const res = await tg.joinChat(ref);
    if (res.status === "ok") return res.chat;
    throw new TransportError("Joined, but Telegram did not return the chat (the group may require admin approval " +
      "to join). Ask an admin to approve you, then run the command again.");
  }
  return tg.getChat(/^-?\d+$/.test(ref) ? Number(ref) : ref);
}

/** "channelId:accessHash" for a supergroup, to pass to `resolveChat` later. */
export function savedPeer(chat: Chat): string | undefined {
  const p = chat.inputPeer;
  return p._ === "inputPeerChannel" ? `${p.channelId}:${p.accessHash.toString()}` : undefined;
}

/** A private supergroup (everyone can post) and an invite link for it. */
export async function createGroup(tg: TelegramClient, title: string): Promise<[Chat, string]> {
  const chat = await tg.createSupergroup({ title, description: "tgsync vault" });
  return [chat, (await tg.exportInviteLink(chat.id)).link];
}

/** A fresh invite link (needs admin rights in the group). */
export async function exportInvite(tg: TelegramClient, chat: Chat): Promise<string> {
  try { return (await tg.exportInviteLink(chat.id)).link; } catch (e) {
    throw new TransportError(`cannot create an invite link (${(e as Error).message}); pass --link with the group's link`);
  }
}

// ------------------------------------------------------------------ the transport
class RateLimiter {
  private stamps: number[] = [];
  constructor(private perMinute: number, private minGap = 0) {}

  slowDown(): void {
    this.perMinute = Math.max(2, Math.floor(this.perMinute / 2));
    this.minGap = Math.max(this.minGap * 2, 2);
  }

  async wait(): Promise<void> {
    for (;;) {
      const now = performance.now() / 1000;
      while (this.stamps.length && now - this.stamps[0] > 60) this.stamps.shift();
      const gap = this.stamps.length ? this.minGap - (now - this.stamps.at(-1)!) : 0;
      const window = this.stamps.length >= this.perMinute ? 60 - (now - this.stamps[0]) : 0;
      const delay = Math.max(gap, window);
      if (delay <= 0) { this.stamps.push(performance.now() / 1000); return; }
      await sleep((delay + 0.05) * 1000);
    }
  }
}

const sleep = (ms: number) => new Promise((ok) => setTimeout(ok, ms));

export class TelegramTransport implements Transport {
  private sendRl = new RateLimiter(SEND_PER_MINUTE, SEND_MIN_GAP);
  private fetchRl = new RateLimiter(120, FETCH_MIN_GAP);
  private seen = new Map<number, TgMessage>();
  log: (s: string) => void = () => {};

  constructor(public tg: TelegramClient, public chat: Chat) {}

  private async retry<T>(fn: () => Promise<T>): Promise<T> {
    for (let i = 0; i < MAX_FLOOD_RETRIES; i++) {
      try {
        return await fn();
      } catch (e) {
        if (tl.RpcError.is(e, "FLOOD_WAIT_%d")) {
          this.sendRl.slowDown();
          this.fetchRl.slowDown();
          this.log(`Telegram flood-wait: sleeping ${e.seconds}s, then slowing down`);
          await sleep((e.seconds + 1) * 1000);
          continue;
        }
        if (tl.RpcError.is(e) && (e.code === 401 || /AUTH_KEY|SESSION_REVOKED|USER_DEACTIVATED/.test(e.text))) {
          throw new TransportError("Telegram session revoked; run `tgsync` in a terminal to log in again");
        }
        if (e instanceof TransportError) throw e;
        throw new TransportError(`Telegram error: ${(e as Error)?.message ?? e}`);
      }
    }
    throw new TransportError("giving up after repeated flood-waits");
  }

  async send(kind: string, data: Uint8Array): Promise<number> {
    await this.sendRl.wait();
    const msg = await this.retry(() => this.tg.sendMedia(this.chat.id,
      InputMedia.document(data, { fileName: "x.bin", caption: caption(kind) })));
    return msg.id;
  }

  async *iterAfter(afterId: number): AsyncIterable<Message> {
    for await (const m of this.tg.iterHistory(this.chat.id, { reverse: true, offset: { id: afterId + 1, date: 0 } })) {
      if (m.id <= afterId) continue;
      const kind = parseCaption(m.text);
      if (kind && m.media?.type === "document") {
        this.seen.set(m.id, m);
        yield { id: m.id, kind };
      }
    }
  }

  async fetch(id: number): Promise<Uint8Array> {
    await this.fetchRl.wait();
    return this.retry(async () => {
      let m = this.seen.get(id) ?? null;
      this.seen.delete(id);
      if (!m) [m] = await this.tg.getMessages(this.chat.id, id);
      if (!m || m.media?.type !== "document") throw new TransportError(`message ${id} is missing (deleted from the chat?)`);
      return this.tg.downloadAsBuffer(m.media);
    });
  }

  async close(): Promise<void> {
    await this.tg.destroy();
  }
}
