// SPDX-License-Identifier: AGPL-3.0-or-later
// Local, private state of one vault folder: `.tgsync/state.json` (JSON, so it also works on phones).
// Not shared and not part of the protocol.
import type { Files } from "./files.ts";
import { Tree, type Node } from "./tree.ts";

export const STATE_FILE = ".tgsync/state.json";
export const RACY_MS = 2000; // a file modified this close to when we hashed it is hashed again

/** [sha, size, mtime ms, when we recorded it (ms)] */
export type Synced = [string, number, number, number];
/** [msg_id, entry index, ts, author id, op, path, conflict copy or null] */
export type LogRow = [number, number, number, string, string, string, string | null];

interface Data {
  v: 1;
  vault_id: string | null;
  cursor: number;
  removed: boolean;
  active: boolean;
  tree: Node[];
  synced: { [path: string]: Synced };
  authors: { [author: string]: number };
  descriptors: [number, string][]; // [msg id, descriptor text]
  log: LogRow[];
  problems: [number | null, string][];
}

const EMPTY = (): Data => ({
  v: 1, vault_id: null, cursor: 0, removed: false, active: false, tree: [], synced: {}, authors: {},
  descriptors: [], log: [], problems: [],
});

export class State {
  private constructor(private files: Files, public d: Data) {}

  static async load(files: Files): Promise<State> {
    const st = await files.stat(STATE_FILE);
    if (!st) return new State(files, EMPTY());
    const d = JSON.parse(new TextDecoder().decode(await files.read(STATE_FILE)));
    return new State(files, { ...EMPTY(), ...d });
  }

  async save(): Promise<void> {
    await this.files.write(STATE_FILE, new TextEncoder().encode(JSON.stringify(this.d)), Date.now());
  }

  loadTree(): Tree {
    const t = new Tree();
    for (const n of this.d.tree) t.set(n);
    return t;
  }

  /** Everything derived from replaying the log, persisted together. */
  async saveReplay(tree: Tree, cursor: number, authors: { [a: string]: number }, desc: [number, string][], log: LogRow[]) {
    this.d.tree = [...tree.nodes.values()];
    this.d.cursor = cursor;
    this.d.authors = { ...authors };
    const have = new Set(this.d.descriptors.map(([id]) => id));
    for (const x of desc) if (!have.has(x[0])) this.d.descriptors.push(x);
    const seen = new Set(this.d.log.map((r) => `${r[0]}:${r[1]}`));
    for (const r of log) if (!seen.has(`${r[0]}:${r[1]}`)) this.d.log.push(r);
    await this.save();
  }

  /** Last synced [sha, size, mtime] per path; mtime -1 when it was recorded too close to the edit to trust. */
  synced(): Map<string, [string, number, number]> {
    const out = new Map<string, [string, number, number]>();
    for (const [p, [sha, size, mtime, observed]] of Object.entries(this.d.synced)) {
      out.set(p, [sha, size, observed - mtime > RACY_MS ? mtime : -1]);
    }
    return out;
  }

  setSynced(path: string, sha: string, size: number, mtime: number): void {
    this.d.synced[path] = [sha, size, mtime, Date.now()];
  }

  delSynced(path: string): void {
    delete this.d.synced[path];
  }

  addProblem(msgId: number | null, what: string): void {
    this.d.problems.push([msgId, what]);
  }

  /** Newest first: [ts, author, op, path, other]. With `path`: that file, its conflict copies, or a folder's contents. */
  log(path?: string, limit = 50): [number, string, string, string, string | null][] {
    let rows = this.d.log;
    if (path) {
      const dir = path.replace(/\/+$/, "") + "/";
      rows = rows.filter((r) => r[5] === path || r[6] === path || r[5].startsWith(dir));
    }
    return [...rows].sort((a, b) => b[0] - a[0] || b[1] - a[1]).slice(0, limit).map((r) => [r[2], r[3], r[4], r[5], r[6]]);
  }
}
