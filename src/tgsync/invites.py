# SPDX-License-Identifier: AGPL-3.0-or-later
"""Invite codes (owner -> friend) and join requests (friend -> owner).

An invite code is one copy-pasteable string: the Telegram group link, the vault id and the key
fingerprint. Because it comes from a member over a channel you trust, it replaces the manual
"compare the fingerprint" step. It does NOT grant access: the friend still has to be approved by
a member, who adds their public key to the vault.

A join request is a small *unencrypted* message posted in the group (the friend has no key yet)
holding the friend's public key and a display name. Anyone in the group can post one, so the
approver must check the short code the friend sees against the one in `tgsync members`.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from .errors import TgSyncError
from .identity import Identity, member_id

PREFIX = "tgsync1-"
KIND_JOIN = "j"


class InviteError(TgSyncError):
    pass


@dataclass
class Invite:
    link: str
    vault_id: str
    fingerprint: str
    api: tuple[int, str] | None = None


def encode_invite(inv: Invite) -> str:
    d: dict = {"l": inv.link, "v": inv.vault_id, "f": inv.fingerprint}
    if inv.api:
        d["a"] = [inv.api[0], inv.api[1]]
    raw = json.dumps(d, separators=(",", ":")).encode()
    return PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_invite(code: str) -> Invite:
    code = "".join(code.split())
    if not code.startswith(PREFIX):
        raise InviteError("that does not look like a tgsync invite code (should start with 'tgsync1-')")
    body = code[len(PREFIX):]
    try:
        d = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        api = tuple(d["a"]) if "a" in d else None
        return Invite(str(d["l"]), str(d["v"]), str(d["f"]), (int(api[0]), str(api[1])) if api else None)
    except (ValueError, KeyError, TypeError, IndexError):
        raise InviteError("invite code is damaged (copy the whole thing)") from None


def short_code(recipient: str) -> str:
    """8 hex chars both sides can read aloud to confirm a join request is genuine."""
    mid = member_id(recipient)[:8]
    return f"{mid[:4]}-{mid[4:]}"


@dataclass
class JoinRequest:
    vault_id: str
    recipient: str
    name: str
    msg_id: int = 0

    @property
    def code(self) -> str:
        return short_code(self.recipient)


def encode_request(vault_id: str, ident: Identity, name: str) -> bytes:
    return json.dumps({"v": 1, "vault": vault_id, "recipient": ident.recipient, "name": name[:40]},
                      separators=(",", ":")).encode()


def decode_request(data: bytes, msg_id: int = 0) -> JoinRequest | None:
    """Returns None for anything malformed; join requests come from untrusted senders."""
    try:
        d = json.loads(data)
        if d["v"] != 1 or not str(d["recipient"]).startswith("age1"):
            return None
        return JoinRequest(str(d["vault"]), str(d["recipient"]), str(d.get("name", ""))[:40], msg_id)
    except (ValueError, KeyError, TypeError):
        return None
