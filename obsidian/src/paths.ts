// SPDX-License-Identifier: AGPL-3.0-or-later
// Vault path rules and conflict-copy names (PROTOCOL.md section 8).

export const INTERNAL_DIR = ".tgsync";
export const TMP_SUFFIX = ".tgsync-tmp";
const MAX_PATH_LEN = 240;
const BAD_CHARS = /[<>:"|?*\x00-\x1f\\]/;
const RESERVED = new Set(["CON", "PRN", "AUX", "NUL",
  ...[1, 2, 3, 4, 5, 6, 7, 8, 9].flatMap((i) => [`COM${i}`, `LPT${i}`])]);

export class PathError extends Error {}

/** Validate and normalise a vault-relative path; throws PathError for unsafe ones. */
export function normalize(rel: string): string {
  if (typeof rel !== "string" || !rel || [...rel].length > MAX_PATH_LEN) throw new PathError("bad path length");
  rel = rel.normalize("NFC");
  if (rel.startsWith("/") || /^[A-Za-z]:/.test(rel)) throw new PathError(`absolute path not allowed: ${rel}`);
  if (BAD_CHARS.test(rel)) throw new PathError(`illegal characters: ${rel}`);
  const parts = rel.split("/");
  for (const p of parts) {
    if (p === "" || p === "." || p === "..") throw new PathError(`bad path component in ${rel}`);
    if (p.endsWith(".") || p.endsWith(" ")) throw new PathError(`component ends with dot/space: ${rel}`);
    if (RESERVED.has(p.split(".")[0].toUpperCase())) throw new PathError(`reserved Windows name in ${rel}`);
  }
  if (parts[0] === INTERNAL_DIR || parts[0] === ".git") throw new PathError(`reserved directory: ${rel}`);
  if (rel.endsWith(TMP_SUFFIX)) throw new PathError("reserved suffix");
  return parts.join("/");
}

/** Python posixpath.splitext: the last dot, unless everything before it is dots. */
function splitext(base: string): [string, string] {
  const i = base.lastIndexOf(".");
  if (i <= 0 || /^\.+$/.test(base.slice(0, i))) return [base, ""];
  return [base.slice(0, i), base.slice(i)];
}

export function conflictName(path: string, author: string, ts: number): string {
  const d = new Date(ts * 1000);
  const p2 = (n: number) => String(n).padStart(2, "0");
  const stamp = `${d.getUTCFullYear()}-${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())} ${p2(d.getUTCHours())}${p2(d.getUTCMinutes())}`;
  const slash = path.lastIndexOf("/");
  const dir = slash >= 0 ? path.slice(0, slash) : "";
  const [stem, ext] = splitext(path.slice(slash + 1));
  const name = `${stem} (conflict ${author.slice(0, 6)} ${stamp})${ext}`;
  return dir ? `${dir}/${name}` : name;
}
