// SPDX-License-Identifier: AGPL-3.0-or-later
// Message formats of tgsync protocol v1 (PROTOCOL.md sections 1, 4-7).
import {
  CryptoError, KeyRing, b64, concat, fromUtf8, hex, mac, memberId, sha256, u32be, unb64, unwrap, utf8, wrapFor,
} from "./crypto.ts";

export const KIND = { descriptor: "d", record: "r", chunk: "c", join: "j" } as const;
export const CAPTION_PREFIX = "tgs1:";
export const INLINE_MAX = 256 * 1024;
export const RECORD_PAYLOAD_MAX = 4 * 1024 * 1024;
export const DEFAULT_CHUNK = 32 * 1024 * 1024;
export const MAX_ENTRIES_PER_RECORD = 500;

export const caption = (kind: string): string => CAPTION_PREFIX + kind;
export function parseCaption(text: string | null | undefined): string | null {
  return text && text.startsWith(CAPTION_PREFIX) && text.length === CAPTION_PREFIX.length + 1 ? text.slice(-1) : null;
}

// ------------------------------------------------------------------ records and chunks
export interface Record { author: string; seq: number; ts: number; entries: any[]; payload: Uint8Array }

export async function encodeRecord(keys: KeyRing, rec: Record): Promise<Uint8Array> {
  const header = utf8(JSON.stringify({ v: 1, author: rec.author, seq: rec.seq, ts: rec.ts, entries: rec.entries }));
  return keys.seal("record", new Uint8Array(0), concat(u32be(header.length), header, rec.payload));
}

export async function decodeRecord(keys: KeyRing, blob: Uint8Array): Promise<Record> {
  const plain = await keys.open("record", new Uint8Array(0), blob);
  if (plain.length < 4) throw new CryptoError("record too short");
  const hl = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
  if (hl > plain.length - 4) throw new CryptoError("record header length invalid");
  let h: any;
  try { h = JSON.parse(fromUtf8(plain.subarray(4, 4 + hl))); } catch (e) { throw new CryptoError(`malformed record: ${e}`); }
  if (h?.v !== 1) throw new CryptoError(`unsupported record version ${h?.v}`);
  if (!Array.isArray(h.entries) || !Number.isFinite(Number(h.seq)) || !Number.isFinite(Number(h.ts)) || h.author === undefined) {
    throw new CryptoError("malformed record");
  }
  return { author: String(h.author), seq: Math.trunc(Number(h.seq)), ts: Number(h.ts), entries: h.entries, payload: plain.slice(4 + hl) };
}

const chunkCtx = (fileId: string, i: number, n: number) => utf8(`${fileId}:${i}:${n}`);
export const sealChunk = (keys: KeyRing, fileId: string, i: number, n: number, data: Uint8Array) =>
  keys.seal("chunk", chunkCtx(fileId, i, n), data);
export const openChunk = (keys: KeyRing, fileId: string, i: number, n: number, blob: Uint8Array) =>
  keys.open("chunk", chunkCtx(fileId, i, n), blob);

// ------------------------------------------------------------------ descriptors
export interface Member { recipient: string; name: string }
export interface Identity { secret: string; recipient: string; id: string }
export interface Descriptor { vaultId: string; epoch: number; members: Member[]; raw: any }

/** Canonical JSON: sorted keys, no spaces, ASCII escapes (= Python json.dumps(sort_keys=True, separators=(",", ":"))). */
export function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v).sort().map((k) => `${canon(k)}:${canon((v as any)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v).replace(/[^\x00-\x7f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

export async function buildDescriptor(ring: KeyRing, vaultId: string, members: Member[], proofEpoch?: number): Promise<Uint8Array> {
  const epoch = ring.current;
  proofEpoch ??= epoch;
  const keys: { [e: string]: string } = {};
  for (const [e, k] of ring.keys) keys[String(e)] = b64(k);
  const keysPayload = utf8(JSON.stringify({ keys }));
  const roster = await Promise.all(members.map(async (m) => ({ id: await memberId(m.recipient), recipient: m.recipient, name: m.name })));
  const body: any = {
    v: 1,
    vault_id: vaultId,
    epoch,
    created: Math.floor(Date.now() / 1000),
    proof_epoch: proofEpoch,
    members: await Promise.all(members.map(async (m) => ({ id: await memberId(m.recipient), wrapped: b64(await wrapFor(m.recipient, keysPayload)) }))),
    roster: b64(await ring.seal("roster", utf8(vaultId), utf8(JSON.stringify(roster)), epoch)),
    keycheck: hex(await mac(ring.key(epoch), utf8("descriptor"), utf8(vaultId), utf8(String(epoch)))),
  };
  const digest = await sha256(utf8(canon(body)));
  body.proof = b64(await ring.seal("descproof", utf8(`${vaultId}:${epoch}`), digest, proofEpoch));
  return utf8(canon(body));
}

export function parseDescriptor(data: Uint8Array): any {
  let d: any;
  try { d = JSON.parse(fromUtf8(data)); } catch (e) { throw new CryptoError(`malformed descriptor: ${e}`); }
  for (const k of ["v", "vault_id", "epoch", "members", "roster", "proof", "proof_epoch", "keycheck"]) {
    if (d?.[k] === undefined) throw new CryptoError(`malformed descriptor: missing ${k}`);
  }
  if (d.v !== 1) throw new CryptoError(`unsupported descriptor version ${d.v}`);
  return d;
}

/** Validate a descriptor and merge its keys into `ring`. null = valid but excludes us. Throws on forgery. */
export async function acceptDescriptor(data: Uint8Array, me: Identity, ring: KeyRing, expectedVaultId: string | null,
                                       trusted = false): Promise<Descriptor | null> {
  const d = parseDescriptor(data);
  const vaultId: string = d.vault_id;
  if (expectedVaultId && vaultId !== expectedVaultId) throw new CryptoError("descriptor belongs to a different vault");
  const epoch: number = d.epoch;
  if (ring.size && epoch < ring.current) throw new CryptoError("descriptor epoch is older than ours (replay?)");
  const mine = (d.members as any[]).find((m) => m?.id === me.id);
  if (!mine) return null;
  const keys = new Map<number, Uint8Array>();
  try {
    const payload = JSON.parse(fromUtf8(await unwrap(me.secret, unb64(mine.wrapped))));
    for (const [e, k] of Object.entries(payload.keys)) keys.set(Number(e), unb64(k as string));
  } catch (e) {
    throw new CryptoError(`malformed wrapped keys: ${e}`);
  }
  if (!keys.has(epoch)) throw new CryptoError("descriptor does not contain its own epoch key");
  const candidate = new KeyRing(ring.keys);
  for (const [e, k] of keys) candidate.add(e, k);
  if (hex(await mac(keys.get(epoch)!, utf8("descriptor"), utf8(vaultId), utf8(String(epoch)))) !== d.keycheck) {
    throw new CryptoError("descriptor keycheck mismatch");
  }
  const proofEpoch: number = d.proof_epoch;
  if (proofEpoch !== epoch && proofEpoch !== epoch - 1) throw new CryptoError("bad proof epoch");
  let verifier = candidate;
  if (!trusted && ring.size) {
    if (!ring.has(proofEpoch)) throw new CryptoError("descriptor proof uses a key we do not hold");
    verifier = ring;
  }
  const { proof, ...body } = d;
  const digest = await verifier.open("descproof", utf8(`${vaultId}:${epoch}`), unb64(proof));
  if (hex(digest) !== hex(await sha256(utf8(canon(body))))) throw new CryptoError("descriptor proof does not match body");
  for (const [e, k] of keys) ring.add(e, k);
  try {
    const roster = JSON.parse(fromUtf8(await ring.open("roster", utf8(vaultId), unb64(d.roster))));
    return { vaultId, epoch, members: roster.map((r: any) => ({ recipient: r.recipient, name: r.name ?? "" })), raw: d };
  } catch (e) {
    throw new CryptoError(`cannot read roster: ${e}`);
  }
}

export async function addMember(ring: KeyRing, vaultId: string, members: Member[], m: Member): Promise<Uint8Array> {
  if (members.some((x) => x.recipient === m.recipient)) throw new CryptoError("already a member");
  return buildDescriptor(ring, vaultId, [...members, m]);
}

/** Remove by recipient/id/name and rotate to a new epoch key (adds it to `ring`). */
export async function removeMember(ring: KeyRing, vaultId: string, members: Member[], target: string): Promise<Uint8Array> {
  const keep: Member[] = [];
  for (const m of members) if (![m.recipient, await memberId(m.recipient), m.name].includes(target)) keep.push(m);
  if (keep.length === members.length) throw new CryptoError(`no such member: ${target}`);
  if (!keep.length) throw new CryptoError("refusing to remove the last member");
  const old = ring.current;
  ring.add(old + 1, globalThis.crypto.getRandomValues(new Uint8Array(32)));
  return buildDescriptor(ring, vaultId, keep, old);
}

// ------------------------------------------------------------------ invites and join requests
export const INVITE_PREFIX = "tgsync1-";
export interface Invite { link: string; vaultId: string; fingerprint: string; api: [number, string] | null }

export function encodeInvite(inv: Invite): string {
  const d: any = { l: inv.link, v: inv.vaultId, f: inv.fingerprint };
  if (inv.api) d.a = inv.api;
  return INVITE_PREFIX + b64(utf8(JSON.stringify(d))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeInvite(code: string): Invite {
  code = code.replace(/\s+/g, "");
  if (!code.startsWith(INVITE_PREFIX)) throw new Error("that does not look like a tgsync invite code (should start with 'tgsync1-')");
  try {
    const body = code.slice(INVITE_PREFIX.length).replace(/-/g, "+").replace(/_/g, "/");
    const d = JSON.parse(fromUtf8(unb64(body + "=".repeat((4 - (body.length % 4)) % 4))));
    if (d.l === undefined || d.v === undefined || d.f === undefined) throw new Error();
    return { link: String(d.l), vaultId: String(d.v), fingerprint: String(d.f), api: d.a ? [Number(d.a[0]), String(d.a[1])] : null };
  } catch {
    throw new Error("invite code is damaged (copy the whole thing)");
  }
}

export interface JoinRequest { vaultId: string; recipient: string; name: string; msgId: number }

export const encodeJoinRequest = (vaultId: string, recipient: string, name: string): Uint8Array =>
  utf8(JSON.stringify({ v: 1, vault: vaultId, recipient, name: [...name].slice(0, 40).join("") }));

/** null for anything malformed: join requests come from untrusted senders. */
export function decodeJoinRequest(data: Uint8Array, msgId = 0): JoinRequest | null {
  try {
    const d = JSON.parse(fromUtf8(data));
    if (d.v !== 1 || !String(d.recipient).startsWith("age1") || d.vault === undefined) return null;
    return { vaultId: String(d.vault), recipient: String(d.recipient), name: [...String(d.name ?? "")].slice(0, 40).join(""), msgId };
  } catch {
    return null;
  }
}
