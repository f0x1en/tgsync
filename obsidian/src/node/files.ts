// SPDX-License-Identifier: AGPL-3.0-or-later
// Files on disk through Node `fs` (CLI and tests). The plugin uses Obsidian's adapter instead.
import { lstat, mkdir, readFile, readdir, rename, rmdir, unlink, utimes, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Files, Stat } from "../files.ts";
import { TMP_SUFFIX } from "../paths.ts";

export class NodeFiles implements Files {
  constructor(public root: string) {}

  private abs(p: string): string { return p ? join(this.root, ...p.split("/")) : this.root; }

  async list(dir: string) {
    const files: string[] = [], dirs: string[] = [];
    for (const e of await readdir(this.abs(dir), { withFileTypes: true })) (e.isDirectory() ? dirs : files).push(e.name);
    return { files, dirs };
  }

  async stat(p: string): Promise<Stat | null> {
    try {
      const s = await lstat(this.abs(p));
      return { type: s.isFile() ? "file" : s.isDirectory() ? "dir" : "other", size: s.size, mtime: s.mtimeMs };
    } catch {
      return null;
    }
  }

  async read(p: string): Promise<Uint8Array> { return new Uint8Array(await readFile(this.abs(p))); }

  async write(p: string, data: Uint8Array, mtime: number): Promise<void> {
    const dest = this.abs(p), tmp = dest + TMP_SUFFIX;
    await mkdir(dirname(dest), { recursive: true });
    try {
      await writeFile(tmp, data);
      await utimes(tmp, mtime / 1000, mtime / 1000);
      await rename(tmp, dest);
    } catch (e) {
      await unlink(tmp).catch(() => {});
      throw e;
    }
  }

  async remove(p: string): Promise<void> { await unlink(this.abs(p)); }
  async mkdir(p: string): Promise<void> { await mkdir(this.abs(p), { recursive: true }); }

  async rmdirIfEmpty(p: string): Promise<boolean> {
    try { await rmdir(this.abs(p)); return true; } catch { return false; }
  }
}

