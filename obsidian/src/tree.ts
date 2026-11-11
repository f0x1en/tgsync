// SPDX-License-Identifier: AGPL-3.0-or-later
// Deterministic replay of log entries into the file tree (PROTOCOL.md section 9).
// Same rules as src/tgsync/tree.py: every client reaches the same tree and conflict names.
import { conflictName, normalize } from "./paths.ts";

export const DIR = "dir"; // sha of a folder node

export interface Blob {
  file_id?: string;
  chunks?: number[] | null;
  chunk_size?: number;
  inline?: [number, number] | null;
  payload_msg?: number;
  [k: string]: unknown;
}

export interface Node {
  path: string;
  sha: string;
  size: number;
  mtime: number;
  blob: Blob;
  author: string;
  msg_id: number;
}

export type Result = [string, string, string | null] | null;

export class Tree {
  nodes = new Map<string, Node>();
  private fold = new Map<string, string>();

  get(path: string): Node | undefined { return this.nodes.get(path); }

  set(node: Node): void {
    this.nodes.set(node.path, node);
    this.fold.set(node.path.toLowerCase(), node.path);
  }

  private remove(path: string): void {
    this.nodes.delete(path);
    if (this.fold.get(path.toLowerCase()) === path) this.fold.delete(path.toLowerCase());
  }

  private freeConflictPath(path: string, author: string, ts: number): string {
    let cand = conflictName(path, author, ts);
    for (let n = 2; this.fold.has(cand.toLowerCase()); n++) cand = conflictName(path, `${author.slice(0, 5)}${n}`, ts);
    return cand;
  }

  /** Apply one entry. Returns [kind, path, conflictPath|null] or null if ignored. */
  applyEntry(entry: any, author: string, ts: number, msgId: number): Result {
    let op: string, path: string;
    try {
      op = entry.op;
      if (op === undefined) return null;
      path = normalize(entry.path);
    } catch {
      return null; // malformed/unsafe entries from a buggy peer are skipped, never applied
    }
    const cur = this.nodes.get(path);
    const clash = this.fold.get(path.toLowerCase());
    if (op === "put") {
      const size = Math.trunc(Number(entry.size));
      const mtime = Number(entry.mtime ?? ts);
      const blob = entry.blob;
      if (entry.sha === undefined || !Number.isFinite(size) || !Number.isFinite(mtime)
          || typeof blob !== "object" || blob === null || Array.isArray(blob)) return null;
      const node: Node = { path, sha: entry.sha, size, mtime, blob: { ...blob }, author, msg_id: msgId };
      if (node.blob.payload_msg === undefined) node.blob.payload_msg = msgId;
      if (clash !== undefined && clash !== path) return this.conflict(node, author, ts);
      if (!cur || cur.sha === node.sha || cur.sha === entry.base) {
        if (cur && cur.sha === node.sha) return ["noop", path, null];
        this.set(node);
        return ["put", path, null];
      }
      return this.conflict(node, author, ts);
    }
    if (op === "delete") {
      if (cur && cur.sha === entry.base) { this.remove(path); return ["delete", path, null]; }
      return null;
    }
    if (op === "mkdir") {
      if (cur || clash !== undefined) return null;
      this.set({ path, sha: DIR, size: 0, mtime: ts, blob: {}, author, msg_id: msgId });
      return ["mkdir", path, null];
    }
    if (op === "rmdir") {
      if (cur && cur.sha === DIR) { this.remove(path); return ["rmdir", path, null]; }
      return null;
    }
    return null;
  }

  private conflict(node: Node, author: string, ts: number): Result {
    const original = node.path;
    node.path = this.freeConflictPath(original, author, ts);
    this.set(node);
    return ["conflict", original, node.path];
  }
}
