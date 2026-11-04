# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

import pytest

from tgsync import identity
from tgsync.engine import Vault
from tgsync.transport import FakeChannel


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("TGSYNC_HOME", str(tmp_path / "home"))


class Peer:
    def __init__(self, tmp: Path, name: str, channel: FakeChannel, use_git=False):
        self.name = name
        self.root = tmp / name
        self.ident = identity.generate()
        self.transport = channel.transport(hash(name) & 0xFFFF)
        self.use_git = use_git
        self.vault: Vault | None = None

    def write(self, rel: str, data: bytes | str):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)

    def read(self, rel: str) -> bytes:
        return (self.root / rel).read_bytes()

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def files(self) -> set[str]:
        return {p.relative_to(self.root).as_posix() for p in self.root.rglob("*")
                if p.is_file() and ".tgsync" not in p.parts and p.name != ".tgsyncignore"}


@pytest.fixture
def channel():
    return FakeChannel()


@pytest.fixture
def mk(tmp_path, channel):
    def make(name: str, git=False) -> Peer:
        return Peer(tmp_path, name, channel, git)
    return make


@pytest.fixture
async def pair(mk):
    a, b = mk("alice"), mk("bob")
    a.vault = await Vault.create(a.root, a.ident, a.transport, "alice", use_git=False)
    await a.vault.add_member(b.ident.recipient, "bob")
    b.vault = await Vault.join(b.root, b.ident, b.transport, a.vault.vault_id, use_git=False)
    return a, b
