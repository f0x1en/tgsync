# SPDX-License-Identifier: AGPL-3.0-or-later
"""Telethon-backed transport (MTProto, your own user account).

NOTE: written against Telethon 1.x docs; exercised in CI only through the fake
transport. Run `tgsync doctor` against a throwaway group before trusting it.
"""

from __future__ import annotations

import asyncio
import io
import os
import re
import sqlite3
import time
from collections import deque
from collections.abc import AsyncIterator
from urllib.parse import urlparse

from telethon import TelegramClient, errors, utils
from telethon.tl import functions, types

from . import oplog
from .errors import TransportError
from .identity import TelegramCreds, app_dir
from .transport import Message

# Telegram does not publish exact limits. Folklore: ~20 messages/minute and ~1/second per chat.
# Defaults sit just under that; FloodWait handling below is the real safety net, and every
# FloodWait permanently (for this session) slows us further.
SEND_PER_MINUTE = 18
SEND_MIN_GAP = 1.2  # seconds between sends
FETCH_MIN_GAP = 0.3  # seconds between downloads / history calls
MAX_FLOOD_RETRIES = 6
_INVITE = re.compile(r"(?:t\.me|telegram\.me)/(?:joinchat/|\+)([\w-]+)")


class RateLimiter:
    """Sliding one-minute window plus a minimum gap between calls."""

    def __init__(self, per_minute: int, min_gap: float = 0.0):
        self.per_minute = per_minute
        self.min_gap = min_gap
        self.stamps: deque[float] = deque()

    def slow_down(self) -> None:
        self.per_minute = max(2, self.per_minute // 2)
        self.min_gap = max(self.min_gap * 2, 2.0)

    async def wait(self) -> None:
        while True:
            now = time.monotonic()
            while self.stamps and now - self.stamps[0] > 60:
                self.stamps.popleft()
            gap = (self.min_gap - (now - self.stamps[-1])) if self.stamps else 0.0
            window = (60 - (now - self.stamps[0])) if len(self.stamps) >= self.per_minute else 0.0
            delay = max(gap, window)
            if delay <= 0:
                self.stamps.append(time.monotonic())
                return
            await asyncio.sleep(delay + 0.05)


def parse_proxy(url: str | None):
    """'socks5://host:port' / 'http://host:port' (optionally user:pass@) -> Telethon proxy tuple.

    A "mixed" proxy port (HTTP+SOCKS on one port) works with either scheme; socks5 is preferred.
    """
    url = url or os.environ.get("TGSYNC_PROXY")
    if not url:
        return None
    u = urlparse(url if "://" in url else "socks5://" + url)
    scheme = {"socks5": "socks5", "socks5h": "socks5", "socks4": "socks4", "http": "http", "https": "http"}.get(u.scheme)
    if not scheme or not u.hostname or not u.port:
        raise TransportError(f"bad proxy {url!r}; use e.g. socks5://127.0.0.1:10808")
    return (scheme, u.hostname, u.port, True, u.username, u.password)


def make_client(profile: str, creds: TelegramCreds) -> TelegramClient:
    session = str(app_dir(profile) / "telegram")
    # flood_sleep_threshold=0: surface FloodWait to us so we can report and honour it
    return TelegramClient(session, creds.api_id, creds.api_hash, flood_sleep_threshold=0,
                          proxy=parse_proxy(creds.proxy), connection_retries=3, timeout=15)


async def interactive_login(profile: str, creds: TelegramCreds) -> str:
    client = make_client(profile, creds)
    await client.start()  # prompts for phone, code and 2FA password on the terminal
    me = await client.get_me()
    await client.disconnect()
    return f"{me.first_name or ''} (@{me.username or me.id})"


async def connect(profile: str) -> TelegramClient:
    client = make_client(profile, TelegramCreds.load(profile))
    try:
        await client.connect()
    except sqlite3.OperationalError as e:
        if "locked" in str(e):
            raise TransportError(
                "Your Telegram session is in use by another tgsync process (a running `tgsync watch` "
                "or `tui`?). Only one process per Telegram account at a time: stop it, or just let "
                "`watch` do the syncing."
            ) from None
        raise
    if not await client.is_user_authorized():
        await client.disconnect()
        raise TransportError("Telegram session missing or revoked; run `tgsync login`")
    return client


async def resolve_chat(client: TelegramClient, ref: str):
    """Accepts an invite link, @username, or numeric peer id."""
    m = _INVITE.search(ref)
    if m:
        h = m.group(1)
        info = await client(functions.messages.CheckChatInviteRequest(h))
        if isinstance(info, types.ChatInviteAlready):
            return info.chat
        res = await client(functions.messages.ImportChatInviteRequest(h))
        return res.chats[0]
    try:
        return await client.get_entity(int(ref))
    except ValueError:
        return await client.get_entity(ref)
    except Exception:
        await client.get_dialogs()  # populate the entity cache, then retry
        return await client.get_entity(int(ref))


async def create_group(client: TelegramClient, title: str) -> tuple[object, str]:
    """Create a private supergroup (everyone can post) and an invite link."""
    res = await client(functions.channels.CreateChannelRequest(title=title, about="tgsync vault", megagroup=True))
    chat = res.chats[0]
    inv = await client(functions.messages.ExportChatInviteRequest(peer=chat))
    return chat, inv.link


class TelethonTransport:
    def __init__(self, client: TelegramClient, entity, send_per_minute: int = SEND_PER_MINUTE,
                 send_min_gap: float = SEND_MIN_GAP):
        self.client = client
        self.entity = entity
        self._rl = RateLimiter(send_per_minute, send_min_gap)
        self._fetch_rl = RateLimiter(120, FETCH_MIN_GAP)
        self._seen: dict[int, object] = {}
        self.log = lambda s: None

    async def _retry(self, fn):
        for _ in range(MAX_FLOOD_RETRIES):
            try:
                return await fn()
            except errors.FloodWaitError as e:
                self._rl.slow_down()
                self._fetch_rl.slow_down()
                self.log(f"Telegram flood-wait: sleeping {e.seconds}s, then slowing down")
                await asyncio.sleep(e.seconds + 1)
            except (ConnectionError, TimeoutError, errors.RPCError) as e:
                if isinstance(e, (errors.AuthKeyError, errors.SessionRevokedError, errors.UserDeactivatedError)):
                    raise TransportError("Telegram session revoked; run `tgsync login`") from e
                raise TransportError(f"Telegram error: {e}") from e
        raise TransportError("giving up after repeated flood-waits")

    async def send(self, kind: str, data: bytes) -> int:
        await self._rl.wait()

        async def go():
            f = io.BytesIO(data)
            f.name = "x.bin"
            return await self.client.send_file(self.entity, f, caption=oplog.caption(kind), force_document=True)

        msg = await self._retry(go)
        return msg.id

    async def iter_after(self, after_id: int) -> AsyncIterator[Message]:
        async for m in self.client.iter_messages(self.entity, min_id=after_id, reverse=True, limit=None):
            kind = oplog.parse_caption(m.message)
            if kind and m.document:
                self._seen[m.id] = m
                yield Message(m.id, kind, m.sender_id)

    async def fetch(self, msg_id: int) -> bytes:
        await self._fetch_rl.wait()

        async def go():
            m = self._seen.pop(msg_id, None) or await self.client.get_messages(self.entity, ids=msg_id)
            if m is None or not m.document:
                raise TransportError(f"message {msg_id} is missing (deleted from the chat?)")
            return await self.client.download_media(m, file=bytes)

        data = await self._retry(go)
        if data is None:
            raise TransportError(f"download of message {msg_id} failed")
        return data

    async def close(self) -> None:
        await self.client.disconnect()


def peer_id(entity) -> int:
    return utils.get_peer_id(entity)
