// SPDX-License-Identifier: AGPL-3.0-or-later
// One tgsync run per vault folder: `.tgsync/lock` holds the process id. Two runs in one folder at
// once (say the Obsidian plugin and a terminal) would both post with the same record number, and
// readers would drop one of them. A lock left by a process that is gone is taken over.
import { mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { INTERNAL_DIR } from "../paths.ts";

export class LockBusy extends Error {
  constructor(public pid: number) { super(`another tgsync is running in this folder (process ${pid})`); }
}

/** Take the folder's lock, waiting up to `waitMs` for a live holder (`onWait` is told once).
 *  Returns the function that releases it. */
export async function takeLock(dir: string, waitMs: number, onWait: (pid: number) => void = () => {}): Promise<() => void> {
  const p = join(dir, INTERNAL_DIR, "lock");
  mkdirSync(join(dir, INTERNAL_DIR), { recursive: true });
  const until = Date.now() + waitMs;
  let said = false;
  for (;;) {
    try { writeFileSync(p, String(process.pid), { flag: "wx" }); break; } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    let holder = "";
    try { holder = readFileSync(p, "utf8"); } catch { continue; } // just released
    const pid = Number(holder);
    const alive = (() => {
      // no number: being written right now, unless it is old (the Python CLI left an empty lock in every vault)
      if (!Number.isInteger(pid) || pid <= 0) { try { return Date.now() - statSync(p).mtimeMs < 5000; } catch { return true; } }
      if (pid === process.pid) return true; // this process (the plugin) is using it right now
      try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
    })();
    if (!alive) {
      try { if (readFileSync(p, "utf8") === holder) unlinkSync(p); } catch { /* someone else did */ }
      continue;
    }
    if (!said) { onWait(pid); said = true; }
    if (Date.now() > until) throw new LockBusy(pid);
    await new Promise((ok) => setTimeout(ok, 200));
  }
  return () => {
    try { if (readFileSync(p, "utf8") === String(process.pid)) unlinkSync(p); } catch { /* gone */ }
  };
}
