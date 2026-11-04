# SPDX-License-Identifier: AGPL-3.0-or-later
import shutil

import pytest
from click.testing import CliRunner

from tgsync import cli, identity
from tgsync.engine import Vault
from tgsync.history import History

needs_git = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")


@needs_git
async def test_git_history_records_local_and_remote_changes(mk):
    a, b = mk("alice"), mk("bob")
    a.vault = await Vault.create(a.root, a.ident, a.transport, "alice", use_git=True)
    await a.vault.add_member(b.ident.recipient, "bob")
    b.vault = await Vault.join(b.root, b.ident, b.transport, a.vault.vault_id, use_git=True)
    a.write("n.md", "v1"); await a.vault.sync(); await b.vault.sync()
    a.write("n.md", "v2"); await a.vault.sync(); await b.vault.sync()
    log = History(b.root).log("n.md")
    assert len(log) >= 2
    old = log[-1].split()[0]
    assert History(b.root).show(old, "n.md") == b"v1"
    # git dir is isolated from the vault and never synced
    assert not (b.root / ".git").exists()
    assert b.files() == {"n.md"}


async def test_cli_status_offline(mk, monkeypatch, tmp_path):
    a = mk("alice")
    identity.init_identity("default")
    ident = identity.load_identity("default")
    a.ident = ident
    a.vault = await Vault.create(a.root, ident, a.transport, "alice", use_git=False)
    cli._save_cfg(a.root, {"chat": 1, "profile": "default", "git": False})
    a.write("x.md", "hi")
    a.vault.close()
    r = CliRunner().invoke(cli.main, ["status", "-C", str(a.root)])
    assert r.exit_code == 0, r.output
    assert "M x.md" in r.output


@needs_git
async def test_git_history_sees_same_size_same_mtime_versions(mk):
    import os
    import time
    now = time.time()
    a, b = mk("alice"), mk("bob")
    a.vault = await Vault.create(a.root, a.ident, a.transport, "alice", use_git=False)
    await a.vault.add_member(b.ident.recipient, "bob")
    b.vault = await Vault.join(b.root, b.ident, b.transport, a.vault.vault_id, use_git=True)
    for text in ("v1", "v2", "v3"):
        a.write("n.md", text)
        os.utime(a.root / "n.md", (now, now))  # identical (recent) mtime + size each time
        await a.vault.sync()
        await b.vault.sync()
    assert len(History(b.root).log("n.md")) == 3
