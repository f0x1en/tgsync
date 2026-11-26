// SPDX-License-Identifier: AGPL-3.0-or-later
// Files on disk through Node `fs` (the plugin on desktop, and tests).
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
      // Buffers sized to what is left of the file (a small note must not cost a 4 MiB buffer);
      // at least 64 KiB, in case the file grows while it is read.
      const total = (await fh.stat()).size;
      let pos = 0;
      for (;;) {
        const want = Math.min(size, Math.max(total - pos, 64 * 1024));
        const buf = new Uint8Array(want);
        let got = 0;
        while (got < want) {
          const { bytesRead } = await fh.read(buf, got, want - got, null);
          if (!bytesRead) break;
          got += bytesRead;
        }
        if (!got) return;
        pos += got;
        yield got === want ? buf : buf.subarray(0, got);
        if (got < want) return;
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

