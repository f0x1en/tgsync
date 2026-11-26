// SPDX-License-Identifier: AGPL-3.0-or-later
// One vault folder. The protocol, replay, merging, membership and every sync decision live in the
// Rust core (core/, WebAssembly, `w.Engine`). This file only lists the folder, talks to the group
// and moves bytes. No printing, no prompts.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import type { Files, Stat } from "./files.ts";
import { INTERNAL_DIR, PathError, TMP_SUFFIX, makeIgnore, normalize } from "./paths.ts";
import { KeyRing } from "./crypto.ts";
import { DEFAULT_CHUNK, INLINE_MAX, KIND, openChunk, sealChunk, type Identity, type JoinRequest, type Member } from "./protocol.ts";
import { OfflineError, type Transport } from "./transport.ts";
import { w } from "./core.ts";

export const BIG_FILE = 8 * 1024 * 1024; // files at least this big get a heads-up while moving
const HASH_PIECE = 4 * 1024 * 1024;
const RACY_MS = 2000; // a file modified this close to when we hashed it is hashed again
export const ENGINE_FILE = ".tgsync/engine.json";
export const LOCAL_FILE = ".tgsync/local.json";

export class VaultError extends Error {}

export interface Report {
  pushed: number;
  pushed_paths: string[];
  applied_remote: number;
  written: string[];
  deleted: string[];
  conflicts: [string, string][];
  skipped: string[];
  problems: string[];
}

export const newReport = (): Report => ({
  pushed: 0, pushed_paths: [], applied_remote: 0, written: [], deleted: [], conflicts: [], skipped: [], problems: [],
});

/** A local change not uploaded yet. */
export interface Change { op: "put" | "delete" | "mkdir" | "rmdir"; path: string }

export interface Incoming { op: string; path: string; who: string; also_local: boolean }

/** [msg_id, entry index, ts, author id, op, path, conflict copy or null] */
type LogRow = [number, number, number, string, string, string, string | null];

interface Scanned { sha: string; st: Stat | null; raw: string }

interface Local {
  /** path -> [sha, size, mtime ms, when we hashed it (ms)]: skip re-hashing unchanged files. */
  stat: { [path: string]: [string, number, number, number] };
  log: LogRow[];
  /** "msg.index" -> [doc, text sha] for note versions (restore). */
  versions: { [rev: string]: [string, string] };
  problems: [number | null, string][];
  /** Big-file uploads not yet in a posted record, to resume after an interruption. */
  uploads?: { [path: string]: Upload };
}

/** What a big-file upload has posted so far. `parts`: sha256 (hex) of each posted chunk's plain bytes. */
interface Upload { size: number; mtime: number; chunkSize: number; epoch: number | null; fileId: string; ids: number[]; parts: string[] }

const REMOVED_MSG = "you were removed from this vault; local files are left untouched; to ask to come back, join again with an invite";
const enc = new TextEncoder();
const dec = new TextDecoder();
const seed = () => globalThis.crypto.getRandomValues(new Uint8Array(32));
const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const now = () => Math.floor(Date.now() / 1000);
const parentOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const isTextPath = (p: string) => p.toLowerCase().endsWith(".md");

function b64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

class LocalState {
  private constructor(private files: Files, public d: Local) {}

  static async load(files: Files): Promise<LocalState> {
    const empty: Local = { stat: {}, log: [], versions: {}, problems: [] };
    if (!(await files.stat(LOCAL_FILE))) return new LocalState(files, empty);
    return new LocalState(files, { ...empty, ...JSON.parse(dec.decode(await files.read(LOCAL_FILE))) });
  }

  async save(): Promise<void> {
    await this.files.write(LOCAL_FILE, enc.encode(JSON.stringify(this.d)), Date.now());
  }

  addProblem(msgId: number | null, what: string): void {
    this.d.problems.push([msgId, what]);
    if (this.d.problems.length > 200) this.d.problems.splice(0, this.d.problems.length - 200);
  }
}

export class Vault {
  members: Member[] = [];
  /** Join requests seen by pull() so far (new ones: someone may be waiting to be let in). */
  asks = 0;
  notify: (msg: string) => void = () => {};
  private busy: Promise<unknown> = Promise.resolve();
  private cache = new Map<number, Uint8Array>();

  private constructor(public files: Files, public me: Identity, public transport: Transport, public engine: w.Engine,
                      public state: LocalState, private ignored: (rel: string) => boolean) {
    this.refreshMembers();
  }

  get vaultId(): string | null { return this.engine.vaultId() ?? null; }
  get removed(): boolean { return this.engine.removed(); }
  get hasKeys(): boolean { return this.engine.hasKeys(); }
  /** Key epoch new data is sealed with (null without keys). */
  get epoch(): number | null { return this.engine.epoch() ?? null; }
  /** The vault key fingerprint, to compare out of band. */
  fingerprint(): string | null { return this.engine.fingerprint() ?? null; }
  get isAdmin(): boolean { return this.members.some((m) => m.recipient === this.me.recipient && m.admin); }

  /** Give a (possibly fresh) engine the last seq this profile posted in this vault. */
  private adoptSeq(): void {
    const vid = this.vaultId;
    if (vid && this.me.seqs) this.engine.setSentSeq(this.me.seqs.get(vid));
  }

  private refreshMembers(): void {
    this.members = JSON.parse(this.engine.members()).members;
  }

  private static signing(me: Identity): string {
    if (!me.signing) throw new VaultError("this profile has no signing key; log in from tgsync's settings once to create it");
    return me.signing;
  }

  /** Open the vault in a folder (works for a brand-new folder too). */
  static async open(files: Files, me: Identity, transport: Transport): Promise<Vault> {
    const signing = Vault.signing(me);
    const state = await LocalState.load(files);
    const ig = await files.stat(".tgsyncignore") ? dec.decode(await files.read(".tgsyncignore")) : "";
    let engine: w.Engine;
    if (await files.stat(ENGINE_FILE)) {
      engine = w.Engine.load(me.secret, me.recipient, signing, await files.read(ENGINE_FILE));
    } else {
      engine = new w.Engine(me.secret, me.recipient, signing, undefined);
    }
    const v = new Vault(files, me, transport, engine, state, makeIgnore(ig));
    v.adoptSeq();
    return v;
  }

  /** The vault keys for big-file chunks, sealed and opened with the platform's AES-GCM (much faster
   * than AES in WebAssembly; same format, PROTOCOL.md section 6). Read fresh: keys rotate. */
  private chunkKeys(): KeyRing {
    const keys: { [e: string]: string } = JSON.parse(this.engine.vaultKeys());
    const hexBytes = (h: string) => Uint8Array.from(h.match(/../g)!, (b) => parseInt(b, 16));
    return new KeyRing(new Map(Object.entries(keys).map(([e, k]) => [Number(e), hexBytes(k)])));
  }

  private async saveEngine(): Promise<void> {
    await this.files.write(ENGINE_FILE, this.engine.save(), Date.now());
  }

  /** One operation at a time per vault (the plugin may trigger several). */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.busy.then(fn, fn);
    this.busy = run.catch(() => {});
    return run;
  }

  // ------------------------------------------------------------------ setup
  static async create(files: Files, me: Identity, transport: Transport, name = ""): Promise<Vault> {
    const v = await Vault.open(files, me, transport);
    if (v.vaultId) throw new VaultError("this folder is already a tgsync vault");
    const c = JSON.parse(w.createVault(me.secret, me.recipient, Vault.signing(me), name, now(), seed()));
    await transport.send(KIND.descriptor, unb64(c.descriptor));
    v.engine.free();
    v.engine = new w.Engine(me.secret, me.recipient, Vault.signing(me), c.vault_id);
    v.adoptSeq();
    await v.pull();
    if (!v.hasKeys) throw new VaultError("failed to read back our own descriptor");
    await v.initFiles();
    return v;
  }

  /** Vaults in the group that currently include us: vault id -> fingerprint. */
  static async discover(transport: Transport, me: Identity): Promise<Map<string, string>> {
    const engines = new Map<string, w.Engine>();
    for await (const m of transport.iterAfter(0)) {
      if (m.kind !== KIND.descriptor) continue;
      let data: Uint8Array;
      let vid: unknown;
      try { data = await transport.fetch(m.id); vid = JSON.parse(dec.decode(data)).vault_id; } catch (e) {
        if (e instanceof OfflineError) throw e; // not "no vault here"
        continue;
      }
      if (typeof vid !== "string") continue;
      if (!engines.has(vid)) engines.set(vid, new w.Engine(me.secret, me.recipient, Vault.signing(me), vid));
      const e = engines.get(vid)!;
      e.beginPass();
      e.feed(m.id, m.kind, data);
    }
    const out = new Map<string, string>();
    for (const [vid, e] of engines) {
      if (e.hasKeys() && !e.removed()) out.set(vid, e.fingerprint()!);
      e.free();
    }
    return out;
  }

  static async join(files: Files, me: Identity, transport: Transport, vaultId: string): Promise<Vault> {
    const v = await Vault.open(files, me, transport);
    if (v.vaultId && v.hasKeys) throw new VaultError("this folder is already a tgsync vault");
    v.engine.free();
    v.engine = new w.Engine(me.secret, me.recipient, Vault.signing(me), vaultId);
    v.adoptSeq();
    await v.pull();
    if (!v.hasKeys || v.removed) {
      throw new VaultError(v.removed ? "you were removed from that vault"
        : "you are not a member of that vault (ask a member to approve you)");
    }
    await v.initFiles(false); // the vault's own .tgsyncignore comes down with the files
    return v;
  }

  private async initFiles(template = true): Promise<void> {
    if (template && !await this.files.stat(".tgsyncignore")) {
      await this.files.write(".tgsyncignore", enc.encode("# extra ignore patterns for this vault (gitignore syntax)\n"), Date.now());
    }
    await this.saveEngine();
    await this.state.save();
  }

  // ------------------------------------------------------------------- pull
  /** Replay new log messages in order (reads the group; writes no files). */
  async pull(): Promise<Report> {
    const rep = newReport();
    let fed = 0;
    for (let pass = 0; pass < 2; pass++) {
      this.engine.beginPass();
      for await (const m of this.transport.iterAfter(this.engine.cursor())) {
        const body = this.engine.wantsBody(m.kind, m.id) ? await this.transport.fetch(m.id) : new Uint8Array(0);
        this.engine.feed(m.id, m.kind, body);
        if (m.kind === KIND.join) this.asks++;
        fed++;
      }
      if (!(this.engine.blocked() && this.engine.hasKeys())) break;
    }
    const r = JSON.parse(this.engine.finishPull());
    for (const [id, i, ts, who, [op, path, copy]] of r.applied) {
      rep.applied_remote++;
      this.state.d.log.push([id, i, ts, who, op === "text" ? "put" : op, path, copy]);
      if (op === "conflict") rep.conflicts.push([path, copy]);
    }
    for (const [id, i, doc, sha] of r.text_versions) this.state.d.versions[`${id}.${i}`] = [doc, sha];
    for (const [id, what] of r.problems) {
      rep.problems.push(`msg ${id}: ${what}`);
      this.state.addProblem(id, what);
    }
    this.refreshMembers();
    if (fed) { // nothing new: nothing to save (saving a big vault's state takes a while)
      await this.saveEngine();
      await this.state.save();
    }
    return rep;
  }

  // ------------------------------------------------------------- local scan
  /** Non-ignored files and empty folders under the vault. */
  private async *walk(dir = ""): AsyncGenerator<[string, "file" | "emptydir"]> {
    const { files, dirs } = await this.files.list(dir);
    const join = (n: string) => (dir ? `${dir}/${n}` : n);
    const keptDirs = dirs.filter((d) => !this.ignored(join(d) + "/"));
    const keptFiles = files.filter((f) => !this.ignored(join(f)));
    if (dir && !keptDirs.length && !keptFiles.length) yield [dir, "emptydir"];
    for (const f of keptFiles) yield [join(f), "file"];
    for (const d of keptDirs) yield* this.walk(join(d));
  }

  /** SHA-256 of a file on disk, read in pieces. */
  async hashFile(path: string): Promise<string> {
    const h = nobleSha256.create();
    for await (const part of this.files.readChunks(path, HASH_PIECE)) h.update(part);
    return hexOf(h.digest());
  }

  /** sha of a file (`raw`: its name on disk), from the stat cache when size and mtime did not change. */
  private async shaOf(rel: string, raw: string, st: Stat): Promise<string> {
    const c = this.state.d.stat[rel];
    if (c && c[1] === st.size && c[2] === st.mtime && c[3] - c[2] > RACY_MS) return c[0];
    const sha = await this.hashFile(raw);
    this.state.d.stat[rel] = [sha, st.size, st.mtime, Date.now()];
    return sha;
  }

  /**
   * Everything in the folder: vault path -> sha ("dir" for empty folders), its stat and its name on
   * disk (which may differ from the vault path in Unicode form, e.g. NFD names written by macOS).
   * `unreadable`: files that are there but could not be hashed; they must never look deleted.
   */
  private async scan(rep: Report): Promise<{ files: Map<string, Scanned>; unreadable: Set<string> }> {
    const files = new Map<string, Scanned>();
    const unreadable = new Set<string>();
    for await (const [raw, kind] of this.walk()) {
      let rel: string;
      try { rel = normalize(raw); } catch (e) { rep.skipped.push(`${raw}: ${(e as PathError).message}`); continue; }
      if (kind === "emptydir") { files.set(rel, { sha: "dir", st: null, raw }); continue; }
      const st = await this.files.stat(raw);
      if (!st || st.type !== "file") { rep.skipped.push(`${rel}: not a regular file`); unreadable.add(rel); continue; }
      try { files.set(rel, { sha: await this.shaOf(rel, raw, st), st, raw }); } catch (e) { rep.skipped.push(`${rel}: ${e}`); unreadable.add(rel); }
    }
    return { files, unreadable };
  }

  /** Local changes not uploaded yet (no content read beyond hashing). */
  async pendingChanges(rep = newReport()): Promise<Change[]> {
    const synced: { [p: string]: string } = JSON.parse(this.engine.synced());
    const { files, unreadable } = await this.scan(rep);
    const out: Change[] = [];
    for (const [p, { sha }] of files) {
      if (synced[p] !== sha) out.push({ op: sha === "dir" ? "mkdir" : "put", path: p });
    }
    for (const [p, sha] of Object.entries(synced)) {
      if (!files.has(p) && !unreadable.has(p)) out.push({ op: sha === "dir" ? "rmdir" : "delete", path: p });
    }
    return out.sort((a, b) => (a.path < b.path ? -1 : 1));
  }

  // ------------------------------------------------------------------- push
  /** Upload a big file as sealed chunks; returns its blob for the record. */
  /** Upload a big file as sealed chunks; returns its blob for the record. An upload cut off earlier
   *  (same size, mtime, chunk size and key) continues: posted chunks whose bytes are unchanged are kept. */
  private async uploadChunks(rel: string, raw: string, size: number, mtime: number, chunkSize: number): Promise<{ sha: string; blob: object }> {
    const count = Math.max(1, Math.ceil(size / chunkSize));
    const uploads = (this.state.d.uploads ??= {});
    const prev = uploads[rel];
    const same = prev && prev.size === size && prev.mtime === mtime && prev.chunkSize === chunkSize && prev.epoch === this.epoch;
    const up: Upload = same ? prev : { size, mtime, chunkSize, epoch: this.epoch, fileId: hexOf(globalThis.crypto.getRandomValues(new Uint8Array(8))), ids: [], parts: [] };
    uploads[rel] = up;
    if (size >= BIG_FILE) {
      this.notify(up.ids.length ? `resuming the upload of ${rel} (${up.ids.length} of ${count} parts were sent before)`
        : `uploading ${rel} (${humanSize(size)}); big files take a while`);
    }
    const h = nobleSha256.create();
    let total = 0, i = 0;
    const ring = this.chunkKeys();
    for await (const part of this.files.readChunks(raw, chunkSize)) {
      if (i >= count) break;
      h.update(part);
      total += part.length;
      const digest = hexOf(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", part as Uint8Array<ArrayBuffer>)));
      if (up.parts[i] !== digest) { // not sent yet, or the bytes changed since: send (again) from here
        up.ids.length = up.parts.length = i;
        up.ids.push(await this.transport.send(KIND.chunk, await sealChunk(ring, up.fileId, i, count, part)));
        up.parts.push(digest);
        await this.state.save(); // a cut-off upload continues from here
      }
      i++;
    }
    if (i !== count || total !== size) {
      delete uploads[rel];
      throw new Error("changed while uploading; it is uploaded at the next sync");
    }
    return { sha: hexOf(h.digest()), blob: { file_id: up.fileId, chunks: up.ids.slice(0, count), chunk_size: chunkSize, inline: null } };
  }

  /** Upload every local change: as many records as needed (500 entries / 4 MiB each). */
  async push(rep: Report, chunkSize = DEFAULT_CHUNK): Promise<void> {
    const synced: { [p: string]: string } = JSON.parse(this.engine.synced());
    // Content the group already has as a plain file: a copy or rename re-uses its blob (notes do not).
    const tree = JSON.parse(this.engine.tree()) as { [p: string]: { sha: string; doc: string | null } };
    const known = new Set(Object.values(tree).filter((n) => !n.doc && n.sha !== "dir").map((n) => n.sha));
    const { files, unreadable } = await this.scan(rep);
    const disk: { [p: string]: object } = {};
    // Present but unreadable right now: send nothing for it, and certainly not a delete.
    for (const rel of unreadable) if (synced[rel]) disk[rel] = { sha: synced[rel], size: 0, mtime: 0, keep: true };
    const keepAsIs = (rel: string, why: string) => {
      rep.skipped.push(`${rel}: ${why}`);
      if (synced[rel]) disk[rel] = { sha: synced[rel], size: 0, mtime: 0, keep: true };
    };
    for (const [rel, { sha, st, raw }] of files) {
      if (sha === "dir") { disk[rel] = { sha, size: 0, mtime: 0, dir: true }; continue; }
      const base = { sha, size: st!.size, mtime: st!.mtime / 1000 };
      if (synced[rel] === sha) { disk[rel] = { ...base, keep: true }; continue; }
      try {
        if (st!.size <= INLINE_MAX) {
          const data = await this.files.read(raw);
          if (hexOf(nobleSha256(data)) !== sha) { keepAsIs(rel, "changed while reading; it is uploaded at the next sync"); continue; }
          let text: string | null = null;
          if (isTextPath(rel)) {
            // ignoreBOM: keep a byte-order mark, so the text hashes to the file's sha everywhere.
            try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data); } catch { /* not UTF-8: plain file */ }
          }
          disk[rel] = text !== null ? { ...base, text } : { ...base, bytes: b64(data) };
        } else if (known.has(sha)) {
          disk[rel] = { ...base, bytes: "" }; // the group has this content: the core re-uses its blob
        } else {
          const up = await this.uploadChunks(rel, raw, st!.size, st!.mtime, chunkSize);
          if (up.sha !== sha) { keepAsIs(rel, "changed while uploading; it is uploaded at the next sync"); continue; }
          disk[rel] = { ...base, blob: up.blob };
        }
      } catch (e) {
        if (e instanceof OfflineError) throw e;
        keepAsIs(rel, (e as Error).message);
      }
    }
    // One scan, as many records as needed: the core marks each record's files synced once posted.
    let listing: string | undefined = JSON.stringify(disk);
    for (;;) {
      const plan = this.engine.planPush(listing, seed());
      listing = undefined; // the engine keeps it for the next records
      if (plan === null) break;
      const p = JSON.parse(plan as string);
      const body = this.engine.sealRecord(Date.now() / 1000, seed());
      await this.saveEngine(); // the seq is used now (write-ahead), in the folder and with the profile
      if (this.vaultId) this.me.seqs?.set(this.vaultId, this.engine.sentSeq());
      await this.transport.send(KIND.record, body);
      this.engine.pushed();
      await this.saveEngine();
      rep.pushed += p.done.length;
      rep.pushed_paths.push(...p.done.map((d: [string, string | null]) => d[0]));
    }
    delete this.state.d.uploads; // all posted: nothing to resume
    await this.state.save();
  }

  // ------------------------------------------------------------ materialize
  private async payloadOf(msgId: number): Promise<Uint8Array> {
    if (!this.cache.has(msgId)) {
      if (this.cache.size > 64) this.cache.clear();
      this.cache.set(msgId, this.engine.recordPayload(await this.transport.fetch(msgId)));
    }
    return this.cache.get(msgId)!;
  }

  /** Write one file the core asked for: verified before it replaces anything; big files stream. */
  private async writeFile(path: string, sha: string, mtimeS: number, text: string | null, blob: any): Promise<void> {
    let mtime = Math.round(mtimeS * 1000);
    const st = await this.files.stat(path);
    if (st && st.mtime === mtime) mtime += 1; // never keep the same (size, mtime) as the old version
    if (text !== null && text !== undefined) {
      const data = enc.encode(text);
      if (hexOf(nobleSha256(data)) !== sha) throw new Error("merged note does not match its hash");
      await this.files.write(path, data, mtime); // the writer's time, so the stat cache can trust it
      return;
    }
    if (blob.inline) {
      const [off, len] = blob.inline;
      const data = (await this.payloadOf(blob.payload_msg)).slice(off, off + len);
      if (hexOf(nobleSha256(data)) !== sha) throw new Error("content hash mismatch after decryption");
      await this.files.write(path, data, mtime);
      return;
    }
    const ids: number[] = blob.chunks ?? [];
    const size = ids.length * (blob.chunk_size ?? 0);
    if (size >= BIG_FILE) this.notify(`downloading ${path} (${humanSize(size)}); big files take a while and only appear when finished`);
    const h = nobleSha256.create();
    const wr = await this.files.writer(path);
    const ring = this.chunkKeys();
    try {
      for (const [i, mid] of ids.entries()) {
        const part = await openChunk(ring, blob.file_id, i, ids.length, await this.transport.fetch(mid));
        h.update(part);
        await wr.write(part);
      }
      if (hexOf(h.digest()) !== sha) throw new Error("content hash mismatch after decryption");
      await wr.finish(mtime);
    } catch (e) {
      await wr.abort();
      throw e;
    }
  }

  /** Remove now-empty parent folders, but never a synced empty folder. */
  private async pruneEmpty(dir: string, tree: { [p: string]: { sha: string } }): Promise<void> {
    while (dir && !tree[dir] && await this.files.rmdirIfEmpty(dir)) dir = parentOf(dir);
  }

  /** Write the tree into the folder, never overwriting local edits that are not uploaded yet. */
  async materialize(rep: Report): Promise<void> {
    const { files, unreadable } = await this.scan(rep);
    const shas: { [p: string]: string } = {};
    for (const [p, { sha }] of files) shas[p] = sha;
    const before: { [p: string]: string } = JSON.parse(this.engine.synced());
    // Unreadable files count as unchanged for planning; any op on them is dropped below.
    for (const p of unreadable) if (before[p]) shas[p] = before[p];
    const tree: { [p: string]: { sha: string } } = JSON.parse(this.engine.tree());
    const plan = JSON.parse(this.engine.planMaterialize(JSON.stringify(shas)));
    const synced: { [p: string]: string } = plan.synced;
    const onDisk = (p: string) => files.get(p)?.raw ?? p; // the file's own name (Unicode form) if it exists
    const undo = (p: string) => { if (before[p] === undefined) delete synced[p]; else synced[p] = before[p]; };
    let offline: OfflineError | null = null;
    for (const op of plan.ops) {
      if (offline) { undo(op.path); continue; } // not done: stays as it was, for the next pull
      if (unreadable.has(op.path)) { // never write over (or delete) a file we could not read
        rep.skipped.push(`${op.path}: could not read your copy; left alone`);
        undo(op.path);
        continue;
      }
      try {
        if (op.op === "write") {
          await this.writeFile(onDisk(op.path), op.sha, op.mtime, op.text, op.blob);
          const st = await this.files.stat(onDisk(op.path));
          if (st) this.state.d.stat[op.path] = [op.sha, st.size, st.mtime, Date.now()];
          rep.written.push(op.path);
        } else if (op.op === "delete") {
          if (await this.files.stat(onDisk(op.path))) await this.files.remove(onDisk(op.path)); // already gone: fine
          delete this.state.d.stat[op.path];
          rep.deleted.push(op.path);
          await this.pruneEmpty(parentOf(onDisk(op.path)), tree);
        } else if (op.op === "mkdir") {
          await this.files.mkdir(op.path);
          rep.written.push(op.path + "/");
        } else if (op.op === "rmdir") {
          if (await this.files.rmdirIfEmpty(onDisk(op.path))) {
            rep.deleted.push(op.path + "/");
            await this.pruneEmpty(parentOf(onDisk(op.path)), tree);
          }
        }
      } catch (e) {
        undo(op.path);
        if (e instanceof OfflineError) { offline = e; continue; }
        rep.problems.push(`${op.path}: could not ${op.op}: ${(e as Error).message}`);
      }
    }
    for (const [p, n] of Object.entries(tree)) {
      const mine = shas[p];
      if (n.sha !== "dir" && mine !== undefined && mine !== n.sha && mine !== before[p] && before[p] !== n.sha) {
        rep.skipped.push(`${p}: you changed it and so did someone else; the next sync keeps both versions`);
      }
    }
    for (const [p, last] of Object.entries(before)) {
      if (!tree[p] && last !== "dir" && shas[p] !== undefined && shas[p] !== last) {
        rep.skipped.push(`${p}: deleted by someone else, but you changed it; kept (the next sync shares it again)`);
      }
    }
    this.engine.materialized(JSON.stringify(synced));
    await this.saveEngine();
    await this.state.save();
    if (offline) throw offline; // what was written is saved; the next pull does the rest
  }

  // ---------------------------------------------------- the user's commands
  private checkMember(): void {
    if (this.removed) throw new VaultError(REMOVED_MSG);
    if (!this.hasKeys) throw new VaultError("no vault keys; are you a member?");
  }

  /** Download and apply others' changes; uploads nothing. */
  pullChanges(): Promise<Report> {
    return this.exclusive(async () => {
      const rep = await this.pull();
      this.checkMember();
      await this.materialize(rep);
      return rep;
    });
  }

  /** Upload your changes; never touches your files. */
  pushChanges(chunkSize = DEFAULT_CHUNK): Promise<Report> {
    return this.exclusive(async () => {
      const rep = await this.pull(); // log only: needed to know the vault state
      this.checkMember();
      await this.push(rep, chunkSize);
      if (rep.pushed) {
        const r2 = await this.pull();
        rep.applied_remote += r2.applied_remote;
        rep.conflicts.push(...r2.conflicts);
        rep.problems.push(...r2.problems);
      }
      return rep;
    });
  }

  /** Read what others posted (like `git fetch`); touches no files. */
  fetchChanges(): Promise<Report> {
    return this.exclusive(async () => {
      const rep = await this.pull();
      this.checkMember();
      return rep;
    });
  }

  /** Others' changes that are not in your folder yet; `also_local`: you changed that file too. */
  async incoming(): Promise<Incoming[]> {
    const synced: { [p: string]: string } = JSON.parse(this.engine.synced());
    const tree: { [p: string]: { sha: string } } = JSON.parse(this.engine.tree());
    const local = new Set((await this.pendingChanges()).map((c) => c.path));
    const names = this.memberNames();
    const who = (path: string) => {
      const row = [...this.state.d.log].reverse().find((r) => r[5] === path || r[6] === path);
      return row ? names.get(row[3]) ?? row[3].slice(0, 8) : "?";
    };
    const out: Incoming[] = [];
    for (const path of Object.keys(tree).sort()) {
      const sha = tree[path].sha;
      if ((synced[path] ?? null) !== sha) out.push({ op: sha === "dir" ? "mkdir" : "put", path, who: who(path), also_local: local.has(path) });
    }
    for (const path of Object.keys(synced).sort()) {
      if (!tree[path]) out.push({ op: synced[path] === "dir" ? "rmdir" : "delete", path, who: who(path), also_local: local.has(path) });
    }
    return out;
  }

  async status() {
    const rep = newReport();
    const changes = await this.pendingChanges(rep);
    await this.state.save();
    return {
      vault_id: this.vaultId,
      epoch: this.epoch,
      fingerprint: this.fingerprint(),
      members: this.members.map((m) => [m.name, m.recipient] as [string, string]),
      tracked: Object.keys(JSON.parse(this.engine.tree())).length,
      pending: changes.map((c) => [c.op, c.path] as [string, string]),
      skipped: rep.skipped,
      problems: this.state.d.problems.slice(-10),
      cursor: this.engine.cursor(),
    };
  }

  /** Who changed what, newest first (local copy of the log; works offline). */
  async log(path?: string, limit = 50) {
    const names = this.memberNames();
    let rows = this.state.d.log;
    if (path) {
      const dir = path.replace(/\/+$/, "") + "/";
      rows = rows.filter((r) => r[5] === path || r[6] === path || r[5].startsWith(dir));
    }
    return [...rows].sort((a, b) => b[0] - a[0] || b[1] - a[1]).slice(0, limit)
      .map(([, , ts, a, op, p, other]) => ({ ts, who: names.get(a) ?? a.slice(0, 8), op, path: p, copy: other }));
  }

  /** Uploaded versions of a file, newest first. Each one can come back with restoreVersion(). */
  async versions(path: string, limit = 20) {
    const names = this.memberNames();
    return this.state.d.log.filter((r) => r[5] === path && r[4] === "put")
      .sort((a, b) => b[0] - a[0] || b[1] - a[1]).slice(0, limit)
      .map(([msg, i, ts, a]) => ({ rev: `${msg}.${i}`, ts, who: names.get(a) ?? a.slice(0, 8) }));
  }

  /** Put an older version of `path` into the folder (the next push shares it). */
  restoreVersion(path: string, rev: string): Promise<void> {
    return this.exclusive(async () => {
      this.checkMember();
      const m = /^(\d+)\.(\d+)$/.exec(rev);
      const row = m && this.state.d.log.find((r) => r[0] === +m[1] && r[1] === +m[2] && r[5] === path && r[4] === "put");
      if (!row) throw new VaultError(`${rev} is not a version of ${path}`);
      const st = await this.files.stat(path);
      const synced: { [p: string]: string } = JSON.parse(this.engine.synced());
      if (st?.type === "file" && await this.hashFile(path) !== synced[path]) {
        throw new VaultError(`${path} has changes not uploaded yet; sync first so they stay in the history`);
      }
      const ver = this.state.d.versions[rev];
      if (ver) {
        const text = this.engine.textAt(ver[0], ver[1]);
        if (text === undefined || text === null) throw new VaultError(`${rev}: that version of the note is not available`);
        await this.files.write(path, enc.encode(text), Date.now());
        return;
      }
      const entry = JSON.parse(this.engine.openRecord(await this.transport.fetch(row[0]))).entries[row[1]];
      if (entry.op === "text") { // a note edit carries Loro operations, not the file: needs its saved version
        throw new VaultError(`${rev}: that version of the note is not available here (it was merged before this folder kept versions)`);
      }
      await this.writeFile(path, entry.sha, Date.now() / 1000, null, { payload_msg: row[0], ...entry.blob });
    });
  }

  private memberNames(): Map<string, string> {
    return new Map(this.members.map((m) => [m.id!, m.name || m.recipient.slice(0, 12)]));
  }

  // ------------------------------------------------------------------ members (admins only)
  private postDescriptor(make: () => Uint8Array): Promise<void> {
    return this.exclusive(() => this.postDescriptorNow(make));
  }

  private async postDescriptorNow(make: () => Uint8Array): Promise<void> {
    await this.pull();
    this.checkMember();
    const id = await this.transport.send(KIND.descriptor, make());
    const rep = await this.pull();
    // Only our own message matters here; others' problems in the same pull are not about this change.
    const ours = rep.problems.filter((p) => p.startsWith(`msg ${id}:`));
    if (ours.length) throw new VaultError(`the change was not accepted: ${ours.join("; ")}`);
  }

  addMember(recipient: string, name = "", signer: string | null = null): Promise<void> {
    return this.postDescriptor(() => this.engine.addMember(recipient, name, signer ?? undefined, now(), seed()));
  }

  static async postJoinRequest(transport: Transport, me: Identity, vaultId: string, name: string): Promise<void> {
    await transport.send(KIND.join, w.encodeJoinRequest(vaultId, me.recipient, name, w.signerOf(Vault.signing(me))));
  }

  /** Join requests for this vault from people who are not members yet (latest per key). */
  pendingRequests(): Promise<JoinRequest[]> {
    return this.exclusive(() => this.pendingRequestsNow());
  }

  private async pendingRequestsNow(): Promise<JoinRequest[]> {
    await this.pull();
    const have = new Set(this.members.map((m) => m.recipient));
    const found = new Map<string, JoinRequest>();
    for await (const m of this.transport.iterAfter(0)) {
      if (m.kind !== KIND.join) continue;
      let r: any = null;
      try { r = JSON.parse(w.decodeJoinRequest(await this.transport.fetch(m.id))); } catch (e) {
        if (e instanceof OfflineError) throw e; // not "no requests"
        continue;
      }
      if (r && r.vault_id === this.vaultId && !have.has(r.recipient)) {
        // Requests are not authenticated: anyone could post one with someone else's key and their own
        // signing key. Two requests for one key with different signing keys: accept neither.
        const prev = found.get(r.recipient);
        const conflict = !!prev && (prev.conflict || (prev.signer ?? null) !== (r.signer ?? null));
        found.set(r.recipient, { vaultId: r.vault_id, recipient: r.recipient, name: r.name, msgId: m.id, signer: r.signer, conflict });
      }
    }
    return [...found.values()].sort((a, b) => a.msgId - b.msgId);
  }

  /** Let in someone who asked to join (typing their code is the confirmation). */
  acceptRequest(req: JoinRequest, name?: string): Promise<void> {
    if (req.conflict) {
      return Promise.reject(new VaultError("this person's join request was posted twice with different signing keys, so one of them is not theirs; " +
        "nothing was accepted. Ask them to make a new tgsync profile (`--profile NEW`) and ask to join again"));
    }
    return this.addMember(req.recipient, name || req.name, req.signer ?? null);
  }

  /** Remove by name, member id or key; rotates the vault key. */
  removeMember(target: string): Promise<void> {
    return this.postDescriptor(() => this.engine.removeMember(target, now(), seed()));
  }

  giveAdmin(target: string): Promise<void> {
    return this.postDescriptor(() => this.engine.giveAdmin(target, now(), seed()));
  }

  dropAdmin(): Promise<void> {
    return this.postDescriptor(() => this.engine.dropAdmin(now(), seed()));
  }
}

export function humanSize(n: number): string {
  let x = n;
  for (const unit of ["B", "KB", "MB", "GB"]) {
    if (x < 1024 || unit === "GB") return unit === "B" ? `${x.toFixed(0)} ${unit}` : `${x.toFixed(1)} ${unit}`;
    x /= 1024;
  }
  return `${n} B`;
}

export { INTERNAL_DIR, TMP_SUFFIX };
