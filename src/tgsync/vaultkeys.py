# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vault descriptors: how the shared vault key reaches each member.

A *descriptor* is posted to the channel in the clear but contains nothing
sensitive: for every member it carries the vault keys (all epochs) wrapped to
that member's age recipient, plus the member roster sealed under the vault key.

Authenticity: every descriptor carries a `proof` sealed with a vault key the
poster already holds (the same epoch for "member added", the previous epoch for
"key rotated"). Existing members therefore reject descriptors injected by anyone
who is merely able to post in the chat. A brand-new joiner has no key yet, so
they must compare the key fingerprint with an existing member (trust on first
use, exactly like verifying a Signal safety number).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass

from .crypto import KeyRing, fingerprint, mac, new_vault_key
from .errors import CryptoError, KeyError_
from .identity import Identity, member_id, wrap_for

b64e = lambda b: base64.b64encode(b).decode()  # noqa: E731
b64d = lambda s: base64.b64decode(s.encode())  # noqa: E731


@dataclass
class Member:
    recipient: str
    name: str = ""

    @property
    def id(self) -> str:
        return member_id(self.recipient)


@dataclass
class Descriptor:
    vault_id: str
    epoch: int
    members: list[Member]
    raw: dict


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def build(
    keyring: KeyRing,
    vault_id: str,
    members: list[Member],
    proof_epoch: int | None = None,
) -> bytes:
    """Create a descriptor for `members` carrying every epoch key in `keyring`."""
    epoch = keyring.current_epoch
    proof_epoch = epoch if proof_epoch is None else proof_epoch
    keys_payload = json.dumps({"keys": {str(ep): b64e(k) for ep, k in keyring.export().items()}}).encode()
    roster = [{"id": m.id, "recipient": m.recipient, "name": m.name} for m in members]
    body = {
        "v": 1,
        "vault_id": vault_id,
        "epoch": epoch,
        "created": int(time.time()),
        "proof_epoch": proof_epoch,
        "members": [{"id": m.id, "wrapped": b64e(wrap_for(m.recipient, keys_payload))} for m in members],
        "roster": b64e(keyring.seal(b"roster", vault_id.encode(), json.dumps(roster).encode(), epoch)),
        "keycheck": mac(keyring.key(epoch), b"descriptor", vault_id.encode(), str(epoch).encode()).hex(),
    }
    digest = hashlib.sha256(_canon(body)).digest()
    ctx = f"{vault_id}:{epoch}".encode()
    body["proof"] = b64e(keyring.seal(b"descproof", ctx, digest, proof_epoch))
    return _canon(body)


def create_vault(creator: Identity, name: str = "") -> tuple[bytes, KeyRing, str]:
    vault_id = os.urandom(8).hex()
    ring = KeyRing({1: new_vault_key()})
    desc = build(ring, vault_id, [Member(creator.recipient, name)])
    return desc, ring, vault_id


def parse(data: bytes) -> dict:
    try:
        d = json.loads(data)
        for k in ("v", "vault_id", "epoch", "members", "roster", "proof", "proof_epoch", "keycheck"):
            d[k]
        if d["v"] != 1:
            raise CryptoError(f"unsupported descriptor version {d['v']}")
        return d
    except (ValueError, KeyError, TypeError) as e:
        raise CryptoError(f"malformed descriptor: {e}") from None


def accept(
    data: bytes,
    identity: Identity,
    ring: KeyRing,
    expected_vault_id: str | None,
) -> Descriptor | None:
    """Validate a descriptor and merge its keys into `ring`.

    Returns None when the descriptor is valid but does not include us (e.g. we were
    removed). Raises CryptoError/KeyError_ for forged or inconsistent descriptors.
    """
    d = parse(data)
    vault_id = d["vault_id"]
    if expected_vault_id and vault_id != expected_vault_id:
        raise CryptoError("descriptor belongs to a different vault")
    epoch = d["epoch"]
    if ring and epoch < ring.current_epoch:
        raise CryptoError("descriptor epoch is older than ours (replay?)")

    mine = next((m for m in d["members"] if m["id"] == identity.id), None)
    if mine is None:
        return None
    try:
        payload = json.loads(identity.unwrap(b64d(mine["wrapped"])))
        keys = {int(ep): b64d(k) for ep, k in payload["keys"].items()}
    except (ValueError, KeyError, TypeError) as e:
        raise CryptoError(f"malformed wrapped keys: {e}") from None
    if epoch not in keys:
        raise CryptoError("descriptor does not contain its own epoch key")

    # Build a candidate ring: existing keys must agree with descriptor keys.
    candidate = KeyRing(ring.export())
    for ep, k in keys.items():
        candidate.add(ep, k)  # raises on conflicting key for a known epoch

    # keycheck + proof
    if mac(keys[epoch], b"descriptor", vault_id.encode(), str(epoch).encode()).hex() != d["keycheck"]:
        raise CryptoError("descriptor keycheck mismatch")
    proof_epoch = d["proof_epoch"]
    if proof_epoch not in (epoch, epoch - 1):
        raise CryptoError("bad proof epoch")
    if ring:  # established member: proof must be made with a key we ALREADY trust
        if not ring.has(proof_epoch):
            raise CryptoError("descriptor proof uses a key we do not hold")
        verifier = ring
    else:  # joining: only self-consistency can be checked (verify the fingerprint out of band)
        verifier = candidate
    body = {k: v for k, v in d.items() if k != "proof"}
    ctx = f"{vault_id}:{epoch}".encode()
    digest = verifier.open(b"descproof", ctx, b64d(d["proof"]))
    if digest != hashlib.sha256(_canon(body)).digest():
        raise CryptoError("descriptor proof does not match body")

    for ep, k in keys.items():
        ring.add(ep, k)
    try:
        roster = json.loads(ring.open(b"roster", vault_id.encode(), b64d(d["roster"])))
        members = [Member(r["recipient"], r.get("name", "")) for r in roster]
    except (CryptoError, ValueError, KeyError) as e:
        raise CryptoError(f"cannot read roster: {e}") from None
    return Descriptor(vault_id, epoch, members, d)


def add_member(ring: KeyRing, vault_id: str, members: list[Member], new: Member) -> tuple[bytes, list[Member]]:
    if any(m.recipient == new.recipient for m in members):
        raise KeyError_("already a member")
    updated = members + [new]
    return build(ring, vault_id, updated), updated


def remove_member(ring: KeyRing, vault_id: str, members: list[Member], target: str) -> tuple[bytes, list[Member]]:
    """Remove by recipient/id/name and rotate to a fresh epoch key.

    The removed member keeps old data they already could read; they cannot read
    anything written after rotation.
    """
    keep = [m for m in members if target not in (m.recipient, m.id, m.name)]
    if len(keep) == len(members):
        raise KeyError_(f"no such member: {target!r}")
    if not keep:
        raise KeyError_("refusing to remove the last member")
    old_epoch = ring.current_epoch
    ring.add(old_epoch + 1, new_vault_key())
    return build(ring, vault_id, keep, proof_epoch=old_epoch), keep


__all__ = [
    "Descriptor", "Member", "accept", "add_member", "build", "create_vault",
    "fingerprint", "parse", "remove_member",
]
