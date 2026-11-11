// SPDX-License-Identifier: AGPL-3.0-or-later
// The vault folder, as the engine sees it. Paths are vault-relative with "/". Node `fs` (CLI)
// and Obsidian's vault adapter (plugin) implement this.

export interface Stat { type: "file" | "dir" | "other"; size: number; mtime: number /* ms since epoch */ }

export interface Files {
  /** Direct children of a folder ("" = vault root): file and folder names. */
  list(dir: string): Promise<{ files: string[]; dirs: string[] }>;
  /** null if missing. Symlinks and special files are "other" (never synced, never deleted). */
  stat(path: string): Promise<Stat | null>;
  read(path: string): Promise<Uint8Array>;
  /** Write atomically (temp file + rename), creating parent folders; set the modification time. */
  write(path: string, data: Uint8Array, mtime: number): Promise<void>;
  remove(path: string): Promise<void>;
  mkdir(path: string): Promise<void>;
  /** Remove a folder only if empty; returns whether it was removed. */
  rmdirIfEmpty(path: string): Promise<boolean>;
}
