# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from tgsync import oplog
from tgsync.crypto import KeyRing, new_vault_key
from tgsync.errors import CryptoError, PathError, TransportError
from tgsync.paths import conflict_name, normalize


def ring():
    return KeyRing({1: new_vault_key()})


def test_roundtrip_and_overhead():
    r = ring()
    blob = r.seal(b"p", b"c", b"hello")
    assert r.open(b"p", b"c", blob) == b"hello"
    assert blob != r.seal(b"p", b"c", b"hello")  # fresh nonce


@pytest.mark.parametrize("purpose,ctx", [(b"q", b"c"), (b"p", b"d")])
def test_context_binding(purpose, ctx):
    r = ring()
    blob = r.seal(b"p", b"c", b"x")
    with pytest.raises(CryptoError):
        r.open(purpose, ctx, blob)


def test_tamper_header_and_body():
    r = ring()
    blob = bytearray(r.seal(b"p", b"c", b"x" * 100))
    for i in (0, 5, 20, len(blob) - 1):
        bad = bytearray(blob); bad[i] ^= 1
        with pytest.raises(CryptoError):
            r.open(b"p", b"c", bytes(bad))


def test_wrong_key():
    with pytest.raises(CryptoError):
        ring().open(b"p", b"c", ring().seal(b"p", b"c", b"x"))


def test_chunks_cannot_be_reordered():
    r = ring()
    c0 = oplog.seal_chunk(r, "f", 0, 2, b"a")
    with pytest.raises(CryptoError):
        oplog.open_chunk(r, "f", 1, 2, c0)
    with pytest.raises(CryptoError):
        oplog.open_chunk(r, "g", 0, 2, c0)
    with pytest.raises(CryptoError):
        oplog.open_chunk(r, "f", 0, 3, c0)  # truncation/extension attack


@pytest.mark.parametrize("bad", ["../x", "/etc/passwd", "C:/x", "a/../b", "a\\b", "CON", "aux.txt",
                                 "a/NUL.md", "x.", "x ", ".tgsync/state.db", ".git/config", "a//b", "a:b"])
def test_bad_paths(bad):
    with pytest.raises(PathError):
        normalize(bad)


def test_good_paths():
    assert normalize("notes/日本語.md") == "notes/日本語.md"
    assert normalize("a/b c/d.txt") == "a/b c/d.txt"


def test_conflict_name_is_deterministic():
    assert conflict_name("a/b.md", "abcdef123", 0) == conflict_name("a/b.md", "abcdef123", 0)
    assert conflict_name("a/b.md", "abcdef123", 0).startswith("a/b (conflict abcdef")


def test_proxy_parsing():
    from tgsync.telegram import parse_proxy
    assert parse_proxy("socks5://127.0.0.1:10808") == ("socks5", "127.0.0.1", 10808, True, None, None)
    assert parse_proxy("127.0.0.1:10808")[0] == "socks5"
    assert parse_proxy("http://u:p@h:8080") == ("http", "h", 8080, True, "u", "p")
    assert parse_proxy(None) is None
    with pytest.raises(TransportError):
        parse_proxy("socks5://nohost")


async def test_rate_limiter_spacing_and_slowdown():
    import time

    from tgsync.telegram import RateLimiter
    rl = RateLimiter(100, 0.2)
    t = time.monotonic()
    for _ in range(3):
        await rl.wait()
    assert time.monotonic() - t >= 0.39
    rl.slow_down()
    assert rl.per_minute == 50 and rl.min_gap >= 2.0


async def test_rate_limiter_window():
    from tgsync.telegram import RateLimiter
    rl = RateLimiter(2, 0)
    await rl.wait(); await rl.wait()
    import asyncio
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(rl.wait(), 0.3)  # third call must block ~60s
