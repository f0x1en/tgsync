# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operation-log records and the chunked blob format.

A *record* is one Telegram message holding a batch of file operations from one
author. Small files ride inline in the record (one message per batch, so
Telegram's ~20 msgs/min limit isn't hit by vaults of many small notes). Large
files are split into independently sealed chunk messages referenced by id.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field

from .crypto import KeyRing
from .errors import CryptoError

KIND_DESCRIPTOR = "d"
KIND_RECORD = "r"
KIND_CHUNK = "c"
CAPTION_PREFIX = "tgs1:"

INLINE_MAX = 256 * 1024  # files up to this size are embedded in the record
RECORD_PAYLOAD_MAX = 4 * 1024 * 1024
DEFAULT_CHUNK = 32 * 1024 * 1024
MAX_ENTRIES_PER_RECORD = 500


def caption(kind: str) -> str:
    return CAPTION_PREFIX + kind


def parse_caption(text: str | None) -> str | None:
    if text and text.startswith(CAPTION_PREFIX) and len(text) == len(CAPTION_PREFIX) + 1:
        return text[len(CAPTION_PREFIX)]
    return None


@dataclass
class Record:
    author: str
    seq: int
    ts: float
    entries: list[dict]
    payload: bytes = b""
    extra: dict = field(default_factory=dict)


def encode_record(keys: KeyRing, rec: Record) -> bytes:
    header = json.dumps(
        {"v": 1, "author": rec.author, "seq": rec.seq, "ts": rec.ts, "entries": rec.entries},
        separators=(",", ":"),
    ).encode()
    plain = struct.pack(">I", len(header)) + header + rec.payload
    return keys.seal(b"record", b"", plain)


def decode_record(keys: KeyRing, blob: bytes) -> Record:
    plain = keys.open(b"record", b"", blob)
    if len(plain) < 4:
        raise CryptoError("record too short")
    (hl,) = struct.unpack_from(">I", plain)
    if hl > len(plain) - 4:
        raise CryptoError("record header length invalid")
    try:
        h = json.loads(plain[4 : 4 + hl])
        if h["v"] != 1:
            raise CryptoError(f"unsupported record version {h['v']}")
        entries = h["entries"]
        if not isinstance(entries, list):
            raise ValueError("entries")
        return Record(str(h["author"]), int(h["seq"]), float(h["ts"]), entries, plain[4 + hl :])
    except (ValueError, KeyError, TypeError) as e:
        raise CryptoError(f"malformed record: {e}") from None


def chunk_ctx(file_id: str, index: int, count: int) -> bytes:
    return f"{file_id}:{index}:{count}".encode()


def seal_chunk(keys: KeyRing, file_id: str, index: int, count: int, data: bytes) -> bytes:
    return keys.seal(b"chunk", chunk_ctx(file_id, index, count), data)


def open_chunk(keys: KeyRing, file_id: str, index: int, count: int, blob: bytes) -> bytes:
    return keys.open(b"chunk", chunk_ctx(file_id, index, count), blob)
