# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline sandbox: a folder on disk plays the Telegram group (for trying tgsync and developing).

    export TGSYNC_SANDBOX=~/tgs-sandbox TGSYNC_PROFILE=alice    # terminal 1
    export TGSYNC_SANDBOX=~/tgs-sandbox TGSYNC_PROFILE=bob      # terminal 2

With TGSYNC_SANDBOX set, keys/profiles live in $TGSYNC_SANDBOX/config (never your real ones),
`new` makes a group folder in $TGSYNC_SANDBOX/groups/, and no Telegram login is needed.
Each message is one file `<id>.<kind>`; ids are claimed with an atomic hard link, so
several tgsync processes can post to the same group at once.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from .errors import TransportError
from .transport import Message

PREFIX = "sandbox:"


def root() -> Path | None:
    v = os.environ.get("TGSYNC_SANDBOX")
    return Path(v).expanduser().resolve() if v else None


def new_group() -> str:
    """Create an empty group folder and return its link ("sandbox:/abs/path")."""
    base = root()
    assert base is not None
    d = base / "groups" / secrets.token_hex(4)
    d.mkdir(parents=True)
    return PREFIX + str(d)


def is_link(ref: str) -> bool:
    return ref.startswith(PREFIX)


class DirTransport:
    def __init__(self, link: str):
        self.dir = Path(link[len(PREFIX):])
        if not self.dir.is_dir():
            raise TransportError(f"sandbox group {self.dir} does not exist (was the sandbox deleted?)")
        self.link = link
        self.log = lambda s: None

    def _ids(self) -> list[tuple[int, str]]:
        out = []
        for p in self.dir.iterdir():
            mid, _, kind = p.name.partition(".")
            if mid.isdigit() and kind:
                out.append((int(mid), kind))
        return sorted(out)

    async def send(self, kind: str, data: bytes) -> int:
        tmp = self.dir / f".tmp-{os.getpid()}-{secrets.token_hex(4)}"
        tmp.write_bytes(data)
        try:
            while True:
                ids = self._ids()
                mid = (ids[-1][0] if ids else 0) + 1
                try:
                    os.link(tmp, self.dir / f"{mid:08d}.{kind}")  # fails if another process took this id
                    return mid
                except FileExistsError:
                    continue
        finally:
            tmp.unlink()

    async def iter_after(self, after_id: int):
        for mid, kind in self._ids():
            if mid > after_id:
                yield Message(mid, kind)

    async def fetch(self, msg_id: int) -> bytes:
        for p in self.dir.glob(f"{msg_id:08d}.*"):
            return p.read_bytes()
        raise TransportError(f"message {msg_id} missing")

    async def close(self) -> None:
        pass
