// SPDX-License-Identifier: AGPL-3.0-or-later
// Crypto of tgsync protocol v1 (PROTOCOL.md section 2-3). WebCrypto only, so it runs in
// Obsidian desktop (Electron) and mobile (WebView) alike.
import { Decrypter, Encrypter } from "age-encryption";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
export const utf8 = (s: string): Uint8Array => enc.encode(s);
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b);
export const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const unhex = (s: string): Uint8Array => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
export const b64 = (b: Uint8Array): string => btoa(Array.from(b, (x) => String.fromCharCode(x)).join(""));
export const unb64 = (s: string): Uint8Array => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

export class CryptoError extends Error {}

const MAGIC = utf8("TGS1");
const HEADER = 8, NONCE = 12, TAG = 16;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest("SHA-256", data as BufferSource));
}

export async function subkey(key: Uint8Array, purpose: Uint8Array, ctx: Uint8Array): Promise<Uint8Array> {
  const ikm = await subtle.importKey("raw", key as BufferSource, "HKDF", false, ["deriveBits"]);
  const info = concat(utf8("tgsync/v1/"), purpose, new Uint8Array([0]), ctx);
  const bits = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: info as BufferSource }, ikm, 256);
  return new Uint8Array(bits);
}

export async function mac(key: Uint8Array, ...parts: Uint8Array[]): Promise<Uint8Array> {
  const k = await subtle.importKey("raw", key as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const msg = concat(...parts.flatMap((p) => [u32be(p.length), p]));
  return new Uint8Array(await subtle.sign("HMAC", k, msg as BufferSource));
}

export async function fingerprint(key: Uint8Array): Promise<string> {
  const d = hex(await sha256(concat(utf8("tgsync/fingerprint/v1"), key))).slice(0, 20);
  return d.match(/..../g)!.join(" ");
}

export function blobEpoch(blob: Uint8Array): number {
  if (blob.length < HEADER) throw new CryptoError("blob too short");
  if (fromUtf8(blob.subarray(0, 4)) !== "TGS1") throw new CryptoError("bad magic");
  return new DataView(blob.buffer, blob.byteOffset).getUint32(4);
}

async function aesKey(key: Uint8Array, purpose: Uint8Array, ctx: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey("raw", (await subkey(key, purpose, ctx)) as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Vault keys by epoch; the newest epoch seals. */
export class KeyRing {
  keys = new Map<number, Uint8Array>();

  constructor(keys?: Map<number, Uint8Array>) { if (keys) this.keys = new Map(keys); }
  get size(): number { return this.keys.size; }
  get epochs(): number[] { return [...this.keys.keys()].sort((a, b) => a - b); }
  get current(): number {
    if (!this.keys.size) throw new CryptoError("keyring is empty");
    return Math.max(...this.keys.keys());
  }
  has(epoch: number): boolean { return this.keys.has(epoch); }
  key(epoch: number): Uint8Array {
    const k = this.keys.get(epoch);
    if (!k) throw new CryptoError(`no key for epoch ${epoch}`);
    return k;
  }
  add(epoch: number, key: Uint8Array): void {
    if (key.length !== 32) throw new CryptoError("vault key must be 32 bytes");
    const old = this.keys.get(epoch);
    if (old && hex(old) !== hex(key)) throw new CryptoError(`conflicting key for epoch ${epoch}`);
    this.keys.set(epoch, key);
  }

  async seal(purpose: string, ctx: Uint8Array, plain: Uint8Array, epoch = this.current, nonce?: Uint8Array): Promise<Uint8Array> {
    const header = concat(MAGIC, u32be(epoch));
    const n = nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(NONCE));
    const p = utf8(purpose);
    const aad = concat(header, p, new Uint8Array([0]), ctx);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv: n as BufferSource, additionalData: aad as BufferSource },
      await aesKey(this.key(epoch), p, ctx), plain as BufferSource);
    return concat(header, n, new Uint8Array(ct));
  }

  async open(purpose: string, ctx: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
    if (blob.length < HEADER + NONCE + TAG) throw new CryptoError("blob too short");
    const epoch = blobEpoch(blob);
    if (!this.has(epoch)) throw new CryptoError(`no key for epoch ${epoch}`);
    const p = utf8(purpose);
    const aad = concat(blob.subarray(0, HEADER), p, new Uint8Array([0]), ctx);
    try {
      return new Uint8Array(await subtle.decrypt(
        { name: "AES-GCM", iv: blob.subarray(HEADER, HEADER + NONCE) as BufferSource, additionalData: aad as BufferSource },
        await aesKey(this.key(epoch), p, ctx), blob.subarray(HEADER + NONCE) as BufferSource));
    } catch {
      throw new CryptoError("authentication failed (tampered, wrong key or wrong context)");
    }
  }
}

// ---------------------------------------------------------------- people (age X25519)
export async function memberId(recipient: string): Promise<string> {
  return hex(await sha256(utf8(recipient))).slice(0, 16);
}

export async function shortCode(recipient: string): Promise<string> {
  const m = (await memberId(recipient)).slice(0, 8);
  return `${m.slice(0, 4)}-${m.slice(4)}`;
}

export async function wrapFor(recipient: string, plain: Uint8Array): Promise<Uint8Array> {
  const e = new Encrypter();
  e.addRecipient(recipient);
  return e.encrypt(plain);
}

export async function unwrap(secret: string, ciphertext: Uint8Array): Promise<Uint8Array> {
  const d = new Decrypter();
  d.addIdentity(secret);
  try {
    return await d.decrypt(ciphertext);
  } catch (e) {
    throw new CryptoError(`cannot decrypt with this identity: ${e}`);
  }
}
