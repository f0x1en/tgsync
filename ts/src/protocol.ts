// SPDX-License-Identifier: AGPL-3.0-or-later
// What the host needs of the message formats (PROTOCOL.md sections 1, 6); the rest is the Rust core's.
import { w } from "./core.ts";
import type { KeyRing } from "./crypto.ts";
import { utf8 } from "./crypto.ts";

export const KIND = { descriptor: "d", record: "r", chunk: "c", join: "j" } as const;
const CAPTION_PREFIX = "tgs1:";
export const INLINE_MAX = 256 * 1024;
export const DEFAULT_CHUNK = 32 * 1024 * 1024;

export const caption = (kind: string): string => CAPTION_PREFIX + kind;
export function parseCaption(text: string | null | undefined): string | null {
  return text && text.startsWith(CAPTION_PREFIX) && text.length === CAPTION_PREFIX.length + 1 ? text.slice(-1) : null;
}

// ------------------------------------------------------------------ chunks (platform AES-GCM: faster than in WebAssembly)
const chunkCtx = (fileId: string, i: number, n: number) => utf8(`${fileId}:${i}:${n}`);
export const sealChunk = (keys: KeyRing, fileId: string, i: number, n: number, data: Uint8Array) =>
  keys.seal("chunk", chunkCtx(fileId, i, n), data);
export const openChunk = (keys: KeyRing, fileId: string, i: number, n: number, blob: Uint8Array) =>
  keys.open("chunk", chunkCtx(fileId, i, n), blob);

// ------------------------------------------------------------------ people
export interface Member { recipient: string; name: string; id?: string; signer?: string | null; admin?: boolean }
/** `signing`: Ed25519 signing key (64 hex) for vaults with admins and signed records. */
export interface Identity {
  secret: string; recipient: string; id: string; signing?: string;
  /** Last record seq posted per vault, kept with the profile (outside the folder): a re-joined folder
   * starts a fresh engine, which must not reuse a seq whose record the group does not show yet. */
  seqs?: { get(vaultId: string): number; set(vaultId: string, seq: number): void };
}

// ------------------------------------------------------------------ invites and join requests (Rust core)
export interface Invite { link: string; vaultId: string; fingerprint: string; api: [number, string] | null }

export const encodeInvite = (i: Invite): string => w.encodeInvite(i.link, i.vaultId, i.fingerprint, i.api?.[0], i.api?.[1]);

export function decodeInvite(code: string): Invite {
  const d = JSON.parse(w.decodeInvite(code));
  return { link: d.link, vaultId: d.vault_id, fingerprint: d.fingerprint, api: d.api ?? null };
}

export interface JoinRequest { vaultId: string; recipient: string; name: string; msgId: number; signer?: string | null; conflict?: boolean }
