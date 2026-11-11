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
    cli.common._save_cfg(a.root, {"chat": 1, "profile": "default", "git": False})
    a.write("x.md", "hi")
    a.vault.close()
    r = CliRunner().invoke(cli.main, ["status", "--offline", "-C", str(a.root)])
    assert r.exit_code == 0, r.output
    assert "M x.md" in r.output


@needs_git
async def test_git_history_sees_same_size_same_mtime_versions(mk, monkeypatch):
    import os
    import time

    from tgsync import state
    # Make every scan re-hash (so the sender always notices the edit, however slow the machine);
    # this test is about the RECEIVER's git history when versions share size and mtime.
    monkeypatch.setattr(state, "RACY_NS", 10**18)
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


@needs_git
async def test_restore_flows(mk):
    a = mk("alice")
    ident = identity.generate()
    a.vault = await Vault.create(a.root, ident, a.transport, "alice", use_git=True)
    for text in ("one", "two", "three"):
        a.write("n.md", text)
        await a.vault.sync()
    a.vault.close()
    r = CliRunner()
    h = History(a.root)
    revs = [row[0] for row in h.versions("n.md")]           # newest first: three, two, one
    assert len(revs) == 3
    # 1) explicit path + rev
    out = r.invoke(cli.main, ["restore", "n.md", revs[2], "-C", str(a.root)])
    assert out.exit_code == 0, out.output
    assert a.read("n.md") == b"one"
    # the version we overwrote is still in history (nothing lost)
    assert any(h.show(rv, "n.md") == b"three" for rv in revs)
    # 2) path only -> pick a version (input "2" = second newest of the file)
    versions = [row[0] for row in h.versions("n.md")]
    out = r.invoke(cli.main, ["restore", "n.md", "-C", str(a.root)], input="2\n")
    assert out.exit_code == 0, out.output
    assert a.read("n.md") == h.show(versions[1], "n.md")
    # 3) lone argument that is a snapshot id -> pick a file in it
    out = r.invoke(cli.main, ["restore", revs[0], "-C", str(a.root)], input="1\n")
    assert out.exit_code == 0, out.output
    assert "Files in snapshot" in out.output
    # 4) nothing given -> pick snapshot, then file
    out = r.invoke(cli.main, ["restore", "-C", str(a.root)], input="1\n1\n")
    assert out.exit_code == 0, out.output
    assert "Recent snapshots" in out.output
    # bad input is a clean error, not a traceback
    out = r.invoke(cli.main, ["restore", "n.md", "zzzzzzz", "-C", str(a.root)])
    assert out.exit_code != 0 and "not a snapshot id" in out.output


def test_bare_command_outside_a_vault_shows_help(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = CliRunner().invoke(cli.main, [])
    assert out.exit_code == 0 and "Commands:" in out.output and "tgsync new ." in out.output


async def test_bare_command_inside_a_vault_shows_status(mk, monkeypatch):
    a = mk("alice")
    identity.init_identity("default")
    ident = identity.load_identity("default")
    a.vault = await Vault.create(a.root, ident, a.transport, "alice", use_git=False)
    cli.common._save_cfg(a.root, {"chat": 1, "profile": "default", "git": False})
    a.write("x.md", "hi")
    a.vault.close()

    async def fake_open(vault_dir):  # runs inside the CLI's own event loop/thread, like the real one
        return Vault(a.root, ident, a.transport, use_git=False), a.transport

    monkeypatch.setattr(cli.common, "_open", fake_open)
    monkeypatch.chdir(a.root)
    # the CLI runs its own event loop, so call it from a worker thread
    import asyncio
    out = await asyncio.to_thread(CliRunner().invoke, cli.main, [])
    assert out.exit_code == 0, out.output
    assert "M x.md" in out.output                                                   # shows the change...
    assert all(k != "r" for k, _ in a.transport.ch.messages.values())                # ...but uploads nothing


async def test_status_shows_account_and_changes(mk):
    a = mk("alice")
    identity.init_identity("default")
    ident = identity.load_identity("default")
    a.vault = await Vault.create(a.root, ident, a.transport, "alice", use_git=False)
    cli.common._save_cfg(a.root, {"chat": 1, "profile": "default", "git": False})
    a.write("x.md", "hi")
    a.vault.close()
    out = CliRunner().invoke(cli.main, ["status", "--offline", "-C", str(a.root)])
    assert out.exit_code == 0 and "account 'default'" in out.output and "M x.md" in out.output


async def test_report_lists_files(pair):
    a, b = pair
    a.write("n/one.md", "1")
    ra = await a.vault.sync()
    assert "n/one.md" in ra.pushed_paths
    rb = await b.vault.sync()
    assert rb.written == ["n/one.md"]
