// SPDX-License-Identifier: AGPL-3.0-or-later
// Sandbox group: a folder plays the Telegram group (same format as src/tgsync/sandbox.py, so the
// Python and TypeScript CLIs can share one). Each message is a file `<id, 8 digits>.<kind>`.
import { randomBytes } from "node:crypto";
import { link, readFile, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { TransportError, type Message, type Transport } from "../transport.ts";

export const PREFIX = "sandbox:";

export class DirTransport implements Transport {
  dir: string;
  constructor(public link: string) { this.dir = link.slice(PREFIX.length); }

  private async ids(): Promise<[number, string][]> {
    let names: string[];
    try { names = await readdir(this.dir); } catch { throw new TransportError(`sandbox group ${this.dir} does not exist`); }
    const out: [number, string][] = [];
    for (const n of names) {
      const m = /^(\d+)\.(.+)$/.exec(n);
      if (m) out.push([Number(m[1]), m[2]]);
    }
    return out.sort((a, b) => a[0] - b[0]);
  }

  async send(kind: string, data: Uint8Array): Promise<number> {
    const tmp = join(this.dir, `.tmp-${process.pid}-${randomBytes(4).toString("hex")}`);
    await writeFile(tmp, data);
    try {
      for (;;) {
        const ids = await this.ids();
        const id = (ids.length ? ids[ids.length - 1][0] : 0) + 1;
        try {
          await link(tmp, join(this.dir, `${String(id).padStart(8, "0")}.${kind}`)); // fails if another process took it
          return id;
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        }
      }
    } finally {
      await unlink(tmp);
    }
  }

  async *iterAfter(afterId: number): AsyncIterable<Message> {
    for (const [id, kind] of await this.ids()) if (id > afterId) yield { id, kind };
  }

  async fetch(id: number): Promise<Uint8Array> {
    for (const [i, kind] of await this.ids()) {
      if (i === id) return new Uint8Array(await readFile(join(this.dir, `${String(id).padStart(8, "0")}.${kind}`)));
    }
    throw new TransportError(`message ${id} missing`);
  }

  async close(): Promise<void> {}
}
