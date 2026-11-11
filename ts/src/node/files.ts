// SPDX-License-Identifier: AGPL-3.0-or-later
// Files on disk through Node `fs` (CLI and tests). The plugin uses Obsidian's adapter instead.
import { lstat, mkdir, open, readFile, readdir, rename, rmdir, unlink, utimes, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { Files, Stat, Writer } from "../files.ts";
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

  async *readChunks(p: string, size: number): AsyncIterable<Uint8Array> {
    const fh = await open(this.abs(p), "r");
    try {
      for (;;) {
        const buf = new Uint8Array(size);
        let got = 0;
        while (got < size) {
          const { bytesRead } = await fh.read(buf, got, size - got, null);
          if (!bytesRead) break;
          got += bytesRead;
        }
        if (!got) return;
        yield got === size ? buf : buf.subarray(0, got);
        if (got < size) return;
      }
    } finally {
      await fh.close();
    }
  }

  async writer(p: string): Promise<Writer> {
    const dest = this.abs(p), tmp = dest + TMP_SUFFIX;
    await mkdir(dirname(dest), { recursive: true });
    const fh = await open(tmp, "w");
    let closed = false;
    const close = async () => { if (!closed) { closed = true; await fh.close(); } };
    return {
      write: async (data) => { await fh.write(data); },
      finish: async (mtime) => {
        await close();
        await utimes(tmp, mtime / 1000, mtime / 1000);
        await rename(tmp, dest);
      },
      abort: async () => { await close(); await unlink(tmp).catch(() => {}); },
    };
  }

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

