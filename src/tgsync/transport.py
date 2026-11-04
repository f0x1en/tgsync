# SPDX-License-Identifier: AGPL-3.0-or-later
"""Transport interface plus an in-memory fake used by tests and `--dry` runs."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol

from .errors import TransportError


@dataclass
class Message:
    id: int
    kind: str
    sender: int | None = None


class Transport(Protocol):
    async def send(self, kind: str, data: bytes) -> int: ...
    def iter_after(self, after_id: int) -> AsyncIterator[Message]: ...
    async def fetch(self, msg_id: int) -> bytes: ...
    async def close(self) -> None: ...


class FakeChannel:
    """Shared in-memory 'chat'. Each client gets a FakeTransport onto it."""

    def __init__(self) -> None:
        self.messages: dict[int, tuple[str, bytes]] = {}
        self.next_id = 1
        self.sent = 0

    def transport(self, sender: int = 0) -> FakeTransport:
        return FakeTransport(self, sender)


class FakeTransport:
    def __init__(self, channel: FakeChannel, sender: int):
        self.ch = channel
        self.sender = sender
        self.senders: dict[int, int] = {}

    async def send(self, kind: str, data: bytes) -> int:
        mid = self.ch.next_id
        self.ch.next_id += 1
        self.ch.messages[mid] = (kind, bytes(data))
        self.ch.sent += 1
        self.senders[mid] = self.sender
        return mid

    async def iter_after(self, after_id: int):
        for mid in sorted(self.ch.messages):
            if mid > after_id:
                yield Message(mid, self.ch.messages[mid][0])

    async def fetch(self, msg_id: int) -> bytes:
        try:
            return self.ch.messages[msg_id][1]
        except KeyError:
            raise TransportError(f"message {msg_id} missing") from None

    async def close(self) -> None:
        pass
