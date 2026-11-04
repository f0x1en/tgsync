# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authenticated encryption primitives.

Design:
  * One random 256-bit *vault key* per epoch (rotated when a member is removed).
  * Every sealed blob uses a unique subkey = HKDF(vault_key, purpose || ctx), so
    a chunk key is never reused across (file, chunk index) and random 96-bit
    nonces are safe.
  * Header (magic, epoch), purpose and ctx are bound as AES-GCM AAD, so blobs
    can't be swapped between files, chunk positions, or purposes.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import CryptoError

MAGIC = b"TGS1"
_HEADER = struct.Struct(">4sI")  # magic, epoch
NONCE_LEN = 12
TAG_LEN = 16
OVERHEAD = _HEADER.size + NONCE_LEN + TAG_LEN


def new_vault_key() -> bytes:
    return os.urandom(32)


def _subkey(root: bytes, purpose: bytes, ctx: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"tgsync/v1/" + purpose + b"\x00" + ctx,
    ).derive(root)


def fingerprint(key: bytes) -> str:
    """Human-comparable fingerprint of a vault key (safe to read aloud)."""
    digest = hashlib.sha256(b"tgsync/fingerprint/v1" + key).hexdigest()[:20]
    return " ".join(digest[i : i + 4] for i in range(0, 20, 4))


def mac(key: bytes, *parts: bytes) -> bytes:
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(struct.pack(">I", len(p)))
        m.update(p)
    return m.digest()


class KeyRing:
    """Vault keys by epoch. The newest epoch is used for sealing."""

    def __init__(self, keys: dict[int, bytes] | None = None):
        self._keys: dict[int, bytes] = dict(keys or {})

    def __bool__(self) -> bool:
        return bool(self._keys)

    @property
    def epochs(self) -> list[int]:
        return sorted(self._keys)

    @property
    def current_epoch(self) -> int:
        if not self._keys:
            raise CryptoError("keyring is empty")
        return max(self._keys)

    def key(self, epoch: int) -> bytes:
        try:
            return self._keys[epoch]
        except KeyError:
            raise CryptoError(f"no key for epoch {epoch}") from None

    def has(self, epoch: int) -> bool:
        return epoch in self._keys

    def add(self, epoch: int, key: bytes) -> None:
        if len(key) != 32:
            raise CryptoError("vault key must be 32 bytes")
        if epoch in self._keys and self._keys[epoch] != key:
            raise CryptoError(f"conflicting key for epoch {epoch}")
        self._keys[epoch] = key

    def export(self) -> dict[int, bytes]:
        return dict(self._keys)

    def seal(self, purpose: bytes, ctx: bytes, plaintext: bytes, epoch: int | None = None) -> bytes:
        ep = self.current_epoch if epoch is None else epoch
        header = _HEADER.pack(MAGIC, ep)
        nonce = os.urandom(NONCE_LEN)
        aad = header + purpose + b"\x00" + ctx
        ct = AESGCM(_subkey(self.key(ep), purpose, ctx)).encrypt(nonce, plaintext, aad)
        return header + nonce + ct

    def open(self, purpose: bytes, ctx: bytes, blob: bytes) -> bytes:
        if len(blob) < OVERHEAD:
            raise CryptoError("blob too short")
        magic, epoch = _HEADER.unpack_from(blob)
        if magic != MAGIC:
            raise CryptoError("bad magic")
        if not self.has(epoch):
            raise CryptoError(f"no key for epoch {epoch}")
        header = blob[: _HEADER.size]
        nonce = blob[_HEADER.size : _HEADER.size + NONCE_LEN]
        ct = blob[_HEADER.size + NONCE_LEN :]
        aad = header + purpose + b"\x00" + ctx
        try:
            return AESGCM(_subkey(self.key(epoch), purpose, ctx)).decrypt(nonce, ct, aad)
        except InvalidTag:
            raise CryptoError("authentication failed (tampered, wrong key or wrong context)") from None


def blob_epoch(blob: bytes) -> int:
    if len(blob) < _HEADER.size:
        raise CryptoError("blob too short")
    magic, epoch = _HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise CryptoError("bad magic")
    return epoch
