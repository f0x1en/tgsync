// SPDX-License-Identifier: AGPL-3.0-or-later
// Sync engine (PROTOCOL.md section 9): replay the group's log, compare with the folder, upload,
// write files. Same behaviour as src/tgsync/engine.py. No printing, no prompts.
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { CryptoError, KeyRing, blobEpoch, fingerprint, fromUtf8, hex, memberId, sha256, utf8 } from "./crypto.ts";
import type { Files } from "./files.ts";
import { INTERNAL_DIR, PathError, TMP_SUFFIX, makeIgnore, normalize } from "./paths.ts";
import {
  DEFAULT_CHUNK, INLINE_MAX, KIND, MAX_ENTRIES_PER_RECORD, RECORD_PAYLOAD_MAX, acceptDescriptor, addMember,
  buildDescriptor, decodeJoinRequest, decodeRecord, encodeJoinRequest, encodeRecord, openChunk, parseDescriptor,
  removeMember, sealChunk, type Identity, type JoinRequest, type Member, type Record as Rec,
} from "./protocol.ts";
import { State, type LogRow } from "./state.ts";
import type { Transport } from "./transport.ts";
import { DIR, type Node, type Tree } from "./tree.ts";

export const BIG_FILE = 8 * 1024 * 1024; // files at least this big get a heads-up while moving
const HASH_PIECE = 4 * 1024 * 1024;

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

/** A local change to upload. */
export interface Change { op: "put" | "delete" | "mkdir" | "rmdir"; path: string; base?: string | null; size?: number; mtime?: number; sha?: string }

export interface Incoming { op: string; path: string; who: string; also_local: boolean }

const REMOVED_MSG = "you were removed from this vault; local files are left untouched; to ask to come back, run `tgsync join` in this folder";

export class Vault {
  keys = new KeyRing();
  members: Member[] = [];
  tree: Tree;
  notify: (msg: string) => void = () => {};
  private sentSeq = 0;
  private descSeen = 0;
  private cache = new Map<number, Uint8Array>();
  private busy: Promise<unknown> = Promise.resolve();

  private constructor(public files: Files, public me: Identity, public transport: Transport, public state: State,
                      private ignored: (rel: string) => boolean) {
    this.tree = state.loadTree();
  }

  get vaultId(): string | null { return this.state.d.vault_id; }
  get removed(): boolean { return this.state.d.removed; }

  /** Open the vault in a folder (works for a brand-new folder too). */
  static async open(files: Files, me: Identity, transport: Transport): Promise<Vault> {
    const state = await State.load(files);
    const ig = await files.stat(".tgsyncignore") ? fromUtf8(await files.read(".tgsyncignore")) : "";
    const v = new Vault(files, me, transport, state, makeIgnore(ig));
    for (const [, text] of state.d.descriptors) {
      try {
        const d = await acceptDescriptor(utf8(text), me, v.keys, v.vaultId, true);
        if (d) v.members = d.members;
      } catch { /* a stored descriptor that no longer validates is skipped */ }
    }
    v.sentSeq = state.d.authors[me.id] ?? 0;
    return v;
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
    const vaultId = hex(globalThis.crypto.getRandomValues(new Uint8Array(8)));
    const ring = new KeyRing(new Map([[1, globalThis.crypto.getRandomValues(new Uint8Array(32))]]));
    await transport.send(KIND.descriptor, await buildDescriptor(ring, vaultId, [{ recipient: me.recipient, name }]));
    v.state.d.vault_id = vaultId;
    await v.pull();
    if (!v.keys.size) throw new VaultError("failed to read back our own descriptor");
    await v.initFiles();
    return v;
  }

  /** Vaults in the group that currently include us: vault id -> fingerprint. */
  static async discover(transport: Transport, me: Identity): Promise<Map<string, string>> {
    const rings = new Map<string, KeyRing>();
    const member = new Map<string, boolean>();
    for await (const m of transport.iterAfter(0)) {
      if (m.kind !== KIND.descriptor) continue;
      try {
        const data = await transport.fetch(m.id);
        const vid: string = parseDescriptor(data).vault_id;
        if (!rings.has(vid)) rings.set(vid, new KeyRing());
        const d = await acceptDescriptor(data, me, rings.get(vid)!, vid);
        member.set(vid, d !== null);
        if (d === null) rings.set(vid, new KeyRing()); // dropped: a later re-add is a fresh join
      } catch { continue; }
    }
    const out = new Map<string, string>();
    for (const [vid, r] of rings) {
      if (r.size && member.get(vid)) out.set(vid, await fingerprint(r.has(1) ? r.key(1) : r.key(r.epochs[0])));
    }
    return out;
  }

  static async join(files: Files, me: Identity, transport: Transport, vaultId: string): Promise<Vault> {
    const v = await Vault.open(files, me, transport);
    if (v.vaultId) throw new VaultError("this folder is already a tgsync vault");
    v.state.d.vault_id = vaultId;
    await v.pull();
    if (!v.keys.size || v.removed) {
      throw new VaultError(v.removed ? "you were removed from that vault"
        : "you are not a member of that vault (ask a member to approve you)");
    }
    await v.initFiles();
    return v;
  }

  private async initFiles(): Promise<void> {
    if (!await this.files.stat(".tgsyncignore")) {
      await this.files.write(".tgsyncignore", utf8("# extra ignore patterns for this vault (gitignore syntax)\n"), Date.now());
    }
    await this.state.save();
  }

  private vid(): string {
    if (!this.vaultId) throw new VaultError("vault id unknown");
    return this.vaultId;
  }

  // ------------------------------------------------------------------- pull
  /** Replay new log messages in order (reads the group; writes no files). */
  async pull(): Promise<Report> {
    const rep = newReport();
    for (let i = 0; i < 2; i++) {
      const blocked = await this.pullPass(rep);
      if (!(blocked && this.keys.size)) break;
    }
    return rep;
  }

  private async pullPass(rep: Report): Promise<boolean> {
    const st = this.state.d;
    const authors = { ...st.authors };
    const newDesc: [number, string][] = [];
    const log: LogRow[] = [];
    let last = st.cursor;
    let blocked = false; // saw records we cannot read yet: the cursor stays before them
    const fresh = !st.active; // never synced to disk yet
    try {
      for await (const msg of this.transport.iterAfter(st.cursor)) {
        if (msg.kind === KIND.descriptor) {
          if (msg.id <= this.descSeen) continue;
          this.descSeen = msg.id;
          const data = await this.transport.fetch(msg.id);
          try {
            const d = await acceptDescriptor(data, this.me, this.keys, this.vaultId);
            if (d === null) {
              if (this.keys.size && fresh) { this.keys = new KeyRing(); this.members = []; }
              else if (this.keys.size) st.removed = true;
            } else {
              this.members = d.members;
              newDesc.push([msg.id, fromUtf8(data)]);
            }
          } catch (e) {
            this.problem(rep, msg.id, `rejected descriptor: ${(e as Error).message}`);
          }
        } else if (msg.kind === KIND.record) {
          if (st.removed) { /* skip */ }
          else if (!this.keys.size || blocked) { blocked = true; continue; }
          else {
            const data = await this.transport.fetch(msg.id);
            let rec: Rec | undefined;
            try {
              rec = await decodeRecord(this.keys, data);
            } catch (e) {
              let missing = false;
              try { missing = !this.keys.has(blobEpoch(data)); } catch { /* not ours */ }
              if (missing) { blocked = true; continue; }
              this.problem(rep, msg.id, `unreadable record: ${(e as Error).message}`);
            }
            if (rec) {
              const prev = authors[rec.author] ?? 0;
              if (rec.seq <= prev) {
                this.problem(rep, msg.id, `replayed/duplicate record from ${rec.author.slice(0, 6)} seq ${rec.seq}`);
              } else {
                if (prev && rec.seq !== prev + 1) {
                  this.problem(rep, msg.id, `gap in ${rec.author.slice(0, 6)}'s history: ${prev} -> ${rec.seq} (message dropped?)`);
                }
                authors[rec.author] = rec.seq;
                rec.entries.forEach((ent, i) => {
                  const r = this.tree.applyEntry(ent, rec.author, rec.ts, msg.id);
                  if (r && r[0] !== "noop") {
                    rep.applied_remote++;
                    log.push([msg.id, i, rec.ts, rec.author, r[0], r[1], r[2]]);
                  }
                  if (r && r[0] === "conflict") rep.conflicts.push([r[1], r[2]!]);
                });
              }
            }
          }
        }
        if (!blocked) last = msg.id;
      }
    } finally {
      await this.state.saveReplay(this.tree, last, authors, newDesc, log);
    }
    this.sentSeq = Math.max(this.sentSeq, authors[this.me.id] ?? 0);
    return blocked;
  }

  private problem(rep: Report, msgId: number, what: string): void {
    rep.problems.push(`msg ${msgId}: ${what}`);
    this.state.addProblem(msgId, what);
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

  /** Compare the folder with what was last synced; returns the changes to upload. */
  async scanLocal(rep: Report): Promise<Change[]> {
    const synced = this.state.synced();
    const seen = new Set<string>();
    const changes: Change[] = [];
    for await (const [raw, kind] of this.walk()) {
      let rel: string;
      try { rel = normalize(raw); } catch (e) { rep.skipped.push(`${raw}: ${(e as PathError).message}`); continue; }
      seen.add(rel);
      if (kind === "emptydir") {
        const node = this.tree.get(rel);
        if (node?.sha === DIR) { if (!synced.has(rel)) this.state.setSynced(rel, DIR, 0, 0); }
        else if (!synced.has(rel)) changes.push({ op: "mkdir", path: rel });
        continue;
      }
      const st = await this.files.stat(raw);
      if (!st || st.type !== "file") { rep.skipped.push(`${rel}: not a regular file`); continue; }
      const prev = synced.get(rel);
      if (prev && prev[1] === st.size && prev[2] === st.mtime) continue;
      let sha: string;
      try { sha = await this.hashFile(raw); } catch (e) { rep.skipped.push(`${rel}: ${e}`); continue; }
      const node = this.tree.get(rel);
      if ((prev && prev[0] === sha) || (node && node.sha === sha)) { this.state.setSynced(rel, sha, st.size, st.mtime); continue; }
      changes.push({ op: "put", path: rel, base: prev ? prev[0] : null, size: st.size, mtime: st.mtime / 1000, sha });
    }
    for (const [rel, [sha]] of synced) {
      if (!seen.has(rel) && !(await this.files.stat(rel))) {
        changes.push(sha === DIR ? { op: "rmdir", path: rel } : { op: "delete", path: rel, base: sha });
      }
    }
    await this.state.save();
    return changes;
  }

  // ------------------------------------------------------------------- push
  async push(changes: Change[], rep: Report, chunkSize = DEFAULT_CHUNK): Promise<void> {
    if (!changes.length) return;
    const known = new Map<string, Node>();
    for (const n of this.tree.nodes.values()) if (n.sha !== DIR) known.set(n.sha, n); // content the group has
    let batch: any[] = [];
    let payload: Uint8Array[] = [];
    let payloadLen = 0;
    const flush = async () => {
      if (!batch.length) return;
      this.sentSeq++;
      const rec = { author: this.me.id, seq: this.sentSeq, ts: Date.now() / 1000, entries: batch, payload: concatAll(payload, payloadLen) };
      await this.transport.send(KIND.record, await encodeRecord(this.keys, rec));
      rep.pushed += batch.length;
      rep.pushed_paths.push(...batch.map((e) => e.path));
      batch = []; payload = []; payloadLen = 0;
    };
    for (const ch of changes) {
      const old = ch.sha ? known.get(ch.sha) : undefined;
      if (ch.op !== "put") {
        batch.push(ch);
      } else if (old) { // renamed or copied: point at the existing upload, send no data
        batch.push({ op: "put", path: ch.path, base: ch.base, mtime: ch.mtime, sha: old.sha, size: old.size, blob: { ...old.blob } });
      } else {
        let entry: any;
        try { entry = await this.preparePut(ch, chunkSize, payload, payloadLen); } catch (e) { rep.skipped.push(`${ch.path}: ${(e as Error).message}`); continue; }
        if (entry.blob.inline) payloadLen += entry.size;
        batch.push(entry);
      }
      if (batch.length >= MAX_ENTRIES_PER_RECORD || payloadLen >= RECORD_PAYLOAD_MAX) await flush();
    }
    await flush();
  }

  /** Build a put entry. Small files join the record payload; big ones stream out as chunks. */
  private async preparePut(ch: Change, chunkSize: number, payload: Uint8Array[], payloadLen: number): Promise<any> {
    const st = await this.files.stat(ch.path);
    if (!st || st.type !== "file") throw new Error("disappeared before upload");
    const entry: any = { op: "put", path: ch.path, base: ch.base, mtime: ch.mtime };
    if (st.size <= INLINE_MAX) {
      const data = await this.files.read(ch.path);
      payload.push(data);
      return Object.assign(entry, { sha: hex(await sha256(data)), size: data.length,
        blob: { file_id: randomId(), chunks: null, inline: [payloadLen, data.length] } });
    }
    if (st.size >= BIG_FILE) this.notify(`uploading ${ch.path} (${humanSize(st.size)}); big files take a while`);
    const fileId = randomId();
    const count = Math.max(1, Math.ceil(st.size / chunkSize));
    const h = nobleSha256.create();
    const ids: number[] = [];
    let total = 0;
    for await (const part of this.files.readChunks(ch.path, chunkSize)) {
      if (ids.length >= count) break;
      h.update(part);
      total += part.length;
      ids.push(await this.transport.send(KIND.chunk, await sealChunk(this.keys, fileId, ids.length, count, part)));
    }
    if (ids.length !== count || total !== st.size) throw new Error("changed while uploading; run `tgsync push` again");
    return Object.assign(entry, { sha: hex(h.digest()), size: total,
      blob: { file_id: fileId, chunks: ids, chunk_size: chunkSize, inline: null } });
  }

  /** SHA-256 of a file on disk, read in pieces. */
  async hashFile(path: string): Promise<string> {
    const h = nobleSha256.create();
    for await (const part of this.files.readChunks(path, HASH_PIECE)) h.update(part);
    return hex(h.digest());
  }

  // ------------------------------------------------------------ materialize
  private async payloadOf(node: Node): Promise<Uint8Array> {
    const mid = node.blob.payload_msg!;
    if (!this.cache.has(mid)) {
      if (this.cache.size > 64) this.cache.clear();
      this.cache.set(mid, (await decodeRecord(this.keys, await this.transport.fetch(mid))).payload);
    }
    return this.cache.get(mid)!;
  }

  /** Download a node into `path`: verified before it replaces anything; big files stream chunk by chunk. */
  private async writeNode(node: Node, path: string, mtime: number): Promise<void> {
    const inline = node.blob.inline;
    if (inline) {
      const data = (await this.payloadOf(node)).slice(inline[0], inline[0] + inline[1]);
      if (hex(await sha256(data)) !== node.sha) throw new CryptoError("content hash mismatch after decryption");
      await this.files.write(path, data, mtime);
      return;
    }
    if (node.size >= BIG_FILE) this.notify(`downloading ${node.path} (${humanSize(node.size)}); big files take a while and only appear when finished`);
    const ids = node.blob.chunks ?? [];
    const h = nobleSha256.create();
    const w = await this.files.writer(path);
    try {
      for (const [i, mid] of ids.entries()) {
        const part = await openChunk(this.keys, node.blob.file_id!, i, ids.length, await this.transport.fetch(mid));
        h.update(part);
        await w.write(part);
      }
      if (hex(h.digest()) !== node.sha) throw new CryptoError("content hash mismatch after decryption");
      await w.finish(mtime);
    } catch (e) {
      await w.abort();
      throw e;
    }
  }

  /** Write the tree into the folder, never overwriting local edits that are not uploaded yet. */
  async materialize(rep: Report): Promise<void> {
    const synced = this.state.synced();
    const preserved = new Set([...this.tree.nodes.values()].filter((n) => n.sha !== DIR).map((n) => n.sha));
    const diskSha = async (path: string): Promise<string | null> => {
      const st = await this.files.stat(path);
      if (!st || st.type !== "file") return null;
      const prev = synced.get(path);
      if (prev && prev[1] === st.size && prev[2] === st.mtime) return prev[0];
      return this.hashFile(path);
    };
    for (const [path, node] of [...this.tree.nodes].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
      if (node.sha === DIR) {
        const st = await this.files.stat(path);
        if (!st) { await this.files.mkdir(path); rep.written.push(path + "/"); }
        if (!st || st.type === "dir") this.state.setSynced(path, DIR, 0, 0);
        continue;
      }
      const have = await diskSha(path);
      const prev = synced.get(path);
      if (have === node.sha) {
        const st = (await this.files.stat(path))!;
        this.state.setSynced(path, node.sha, st.size, st.mtime);
        continue;
      }
      if (have !== null && have !== (prev ? prev[0] : null) && !preserved.has(have)) {
        rep.skipped.push(`${path}: you changed it and so did someone else; run \`tgsync push\`, then \`tgsync pull\` to get both versions`);
        continue;
      }
      try {
        let mtime = Math.round(node.mtime * 1000);
        const st = await this.files.stat(path);
        if (st && st.mtime === mtime) mtime += 1; // never keep the same (size, mtime) as the old version
        await this.writeNode(node, path, mtime);
      } catch (e) {
        rep.problems.push(`${path}: could not restore: ${(e as Error).message}`);
        continue;
      }
      const st = (await this.files.stat(path))!;
      this.state.setSynced(path, node.sha, st.size, st.mtime);
      rep.written.push(path);
    }
    for (const [path, [sha]] of synced) {
      if (this.tree.nodes.has(path)) continue;
      const st = await this.files.stat(path);
      if (sha === DIR) {
        if (st?.type === "dir" && await this.files.rmdirIfEmpty(path)) {
          rep.deleted.push(path + "/");
          await this.pruneEmpty(parentOf(path));
        }
      } else if (st?.type === "file") {
        const have = await this.hashFile(path);
        if (have !== sha && !preserved.has(have)) {
          rep.skipped.push(`${path}: deleted by someone else, but you changed it; kept`);
          this.state.delSynced(path);
          continue;
        }
        await this.files.remove(path);
        rep.deleted.push(path);
        await this.pruneEmpty(parentOf(path));
      }
      this.state.delSynced(path);
    }
    this.state.d.active = true;
    await this.state.save();
  }

  /** Remove now-empty parent folders, but never a synced empty folder. */
  private async pruneEmpty(dir: string): Promise<void> {
    while (dir && !this.tree.get(dir) && await this.files.rmdirIfEmpty(dir)) dir = parentOf(dir);
  }

  // ---------------------------------------------------- the user's commands
  private checkMember(): void {
    if (this.removed) throw new VaultError(REMOVED_MSG);
    if (!this.keys.size) throw new VaultError("no vault keys; are you a member?");
  }

  /** `tgsync pull`: download and apply others' changes; uploads nothing. */
  pullChanges(): Promise<Report> {
    return this.exclusive(async () => {
      const rep = await this.pull();
      this.checkMember();
      await this.materialize(rep);
      return rep;
    });
  }

  /** `tgsync push`: upload your changes; never touches your files. */
  pushChanges(chunkSize = DEFAULT_CHUNK): Promise<Report> {
    return this.exclusive(async () => {
      const rep = await this.pull(); // log only: needed to know the vault state
      this.checkMember();
      const changes = await this.scanLocal(rep);
      if (changes.length) {
        await this.push(changes, rep, chunkSize);
        const r2 = await this.pull();
        rep.applied_remote += r2.applied_remote;
        rep.conflicts.push(...r2.conflicts);
        rep.problems.push(...r2.problems);
        await this.markPushedSynced(changes);
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

  private async markPushedSynced(changes: Change[]): Promise<void> {
    for (const ch of changes) {
      const node = this.tree.get(ch.path);
      if (ch.op === "put" && node) {
        const st = await this.files.stat(ch.path);
        if (st?.type === "file" && await this.hashFile(ch.path) === node.sha) {
          this.state.setSynced(ch.path, node.sha, st.size, st.mtime);
        }
      } else if (ch.op === "mkdir" && node?.sha === DIR) this.state.setSynced(ch.path, DIR, 0, 0);
      else if ((ch.op === "delete" || ch.op === "rmdir") && !node) this.state.delSynced(ch.path);
    }
    await this.state.save();
  }

  /** Others' changes that are not in your folder yet; `also_local`: you changed that file too. */
  async incoming(): Promise<Incoming[]> {
    const synced = this.state.synced();
    const local = new Set((await this.scanLocal(newReport())).map((c) => c.path));
    const names = await this.memberNames();
    const who = (path: string) => {
      const rows = this.state.log(path, 1);
      return rows.length ? names.get(rows[0][1]) ?? rows[0][1].slice(0, 8) : "?";
    };
    const out: Incoming[] = [];
    for (const [path, node] of [...this.tree.nodes].sort(([a], [b]) => (a < b ? -1 : 1))) {
      if ((synced.get(path)?.[0] ?? null) !== node.sha) {
        out.push({ op: node.sha === DIR ? "mkdir" : "put", path, who: who(path), also_local: local.has(path) });
      }
    }
    for (const [path, [sha]] of [...synced].sort(([a], [b]) => (a < b ? -1 : 1))) {
      if (!this.tree.nodes.has(path)) out.push({ op: sha === DIR ? "rmdir" : "delete", path, who: who(path), also_local: local.has(path) });
    }
    return out;
  }

  async status() {
    const rep = newReport();
    const changes = await this.scanLocal(rep);
    return {
      vault_id: this.vaultId,
      epoch: this.keys.size ? this.keys.current : null,
      fingerprint: this.keys.size ? await fingerprint(this.keys.key(this.keys.current)) : null,
      members: this.members.map((m) => [m.name, m.recipient] as [string, string]),
      tracked: this.tree.nodes.size,
      pending: changes.map((c) => [c.op, c.path] as [string, string]),
      skipped: rep.skipped,
      problems: this.state.d.problems.slice(-10),
      cursor: this.state.d.cursor,
    };
  }

  /** Who changed what, newest first (local copy of the log; works offline). */
  async log(path?: string, limit = 50) {
    const names = await this.memberNames();
    return this.state.log(path, limit).map(([ts, a, op, p, other]) => ({ ts, who: names.get(a) ?? a.slice(0, 8), op, path: p, copy: other }));
  }

  /** Uploaded versions of a file, newest first. Each one can come back with restoreVersion(). */
  async versions(path: string, limit = 20) {
    const names = await this.memberNames();
    return this.state.d.log.filter((r) => r[5] === path && r[4] === "put")
      .sort((a, b) => b[0] - a[0] || b[1] - a[1]).slice(0, limit)
      .map(([msg, i, ts, a]) => ({ rev: `${msg}.${i}`, ts, who: names.get(a) ?? a.slice(0, 8) }));
  }

  /** Download an older version of `path` from the group into the folder (`tgsync push` shares it). */
  restoreVersion(path: string, rev: string): Promise<void> {
    return this.exclusive(async () => {
      this.checkMember();
      const m = /^(\d+)\.(\d+)$/.exec(rev);
      const row = m && this.state.d.log.find((r) => r[0] === +m[1] && r[1] === +m[2] && r[5] === path && r[4] === "put");
      if (!row) throw new VaultError(`${rev} is not a version of ${path} (see \`tgsync restore ${path}\`)`);
      const st = await this.files.stat(path);
      if (st?.type === "file" && await this.hashFile(path) !== this.state.synced().get(path)?.[0]) {
        throw new VaultError(`${path} has changes you did not upload; run \`tgsync push\` first so they stay in the history`);
      }
      const entry = (await decodeRecord(this.keys, await this.transport.fetch(row[0]))).entries[row[1]];
      const node: Node = { ...entry, blob: { payload_msg: row[0], ...entry.blob }, author: row[3], msg_id: row[0] };
      await this.writeNode(node, path, Date.now());
    });
  }

  private async memberNames(): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    for (const m of this.members) out.set(await memberId(m.recipient), m.name || m.recipient.slice(0, 12));
    return out;
  }

  // ------------------------------------------------------------------ members
  async addMember(recipient: string, name = ""): Promise<void> {
    await this.pull();
    await this.transport.send(KIND.descriptor, await addMember(this.keys, this.vid(), this.members, { recipient, name }));
    await this.pull();
  }

  static async postJoinRequest(transport: Transport, me: Identity, vaultId: string, name: string): Promise<void> {
    await transport.send(KIND.join, encodeJoinRequest(vaultId, me.recipient, name));
  }

  /** Join requests for this vault from people who are not members yet (latest per key). */
  async pendingRequests(): Promise<JoinRequest[]> {
    await this.pull();
    const have = new Set(this.members.map((m) => m.recipient));
    const found = new Map<string, JoinRequest>();
    for await (const m of this.transport.iterAfter(0)) {
      if (m.kind !== KIND.join) continue;
      let req: JoinRequest | null = null;
      try { req = decodeJoinRequest(await this.transport.fetch(m.id), m.id); } catch { continue; }
      if (req && req.vaultId === this.vaultId && !have.has(req.recipient)) found.set(req.recipient, req);
    }
    return [...found.values()].sort((a, b) => a.msgId - b.msgId);
  }

  /** Let in someone who asked to join (typing their code is the confirmation). */
  acceptRequest(req: JoinRequest, name?: string): Promise<void> {
    return this.addMember(req.recipient, name || req.name);
  }

  async removeMember(target: string): Promise<void> {
    await this.pull();
    const ring = new KeyRing(this.keys.keys); // rotate on a copy; adopt it once the descriptor is accepted
    await this.transport.send(KIND.descriptor, await removeMember(ring, this.vid(), this.members, target));
    await this.pull();
  }
}

// ---------------------------------------------------------------------- helpers
function concatAll(parts: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const randomId = () => hex(globalThis.crypto.getRandomValues(new Uint8Array(8)));
const parentOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");

export function humanSize(n: number): string {
  let x = n;
  for (const unit of ["B", "KB", "MB", "GB"]) {
    if (x < 1024 || unit === "GB") return unit === "B" ? `${x.toFixed(0)} ${unit}` : `${x.toFixed(1)} ${unit}`;
    x /= 1024;
  }
  return `${n} B`;
}

export { INTERNAL_DIR, TMP_SUFFIX };
