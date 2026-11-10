# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio

import pytest
from click.testing import CliRunner

from tgsync import cli, identity, invites
from tgsync.engine import Vault
from tgsync.errors import KeyError_


def test_invite_roundtrip_and_errors():
    inv = invites.Invite("https://t.me/+abc_DEF-123", "087af3cab094cff5", "08b2 171c fd8a d9b8 94fc")
    assert invites.decode_invite(invites.encode_invite(inv)) == inv
    with_api = invites.Invite("https://t.me/+x", "v", "f", (123, "hash"))
    assert invites.decode_invite(invites.encode_invite(with_api)).api == (123, "hash")
    code = invites.encode_invite(inv)
    assert invites.decode_invite("  " + code[:20] + "\n" + code[20:] + " ") == inv  # pasted with wraps
    for bad in ("", "hello", "tgsync1-", "tgsync1-!!!!", "tgsync1-" + "A" * 7):
        with pytest.raises(invites.InviteError):
            invites.decode_invite(bad)


def test_request_parsing_rejects_garbage():
    assert invites.decode_request(b"not json") is None
    assert invites.decode_request(b'{"v":2}') is None
    assert invites.decode_request(b'{"v":1,"vault":"x","recipient":"notage"}') is None
    ok = invites.decode_request(b'{"v":1,"vault":"x","recipient":"age1abc","name":"bob"}', 7)
    assert ok and ok.msg_id == 7 and ok.code == invites.short_code("age1abc")


async def test_request_approve_join_flow(mk):
    a, b, eve = mk("alice"), mk("bob"), mk("eve")
    a.vault = await Vault.create(a.root, a.ident, a.transport, "alice", use_git=False)
    a.write("welcome.md", "hi bob")
    await a.vault.sync()
    # bob asks to join; a request for some OTHER vault and junk must be ignored
    await Vault.post_join_request(b.transport, b.ident, a.vault.vault_id, "bob")
    await Vault.post_join_request(eve.transport, eve.ident, "ffffffffffffffff", "eve")
    await a.transport.send(invites.KIND_JOIN, b"garbage")
    pending = await a.vault.pending_requests()
    assert [(r.name, r.recipient) for r in pending] == [("bob", b.ident.recipient)]
    assert pending[0].code == invites.short_code(b.ident.recipient)
    # until approved, bob cannot read anything
    found = await Vault.discover(b.transport, b.ident)
    assert a.vault.vault_id not in found
    await a.vault.accept_request(pending[0])
    assert await a.vault.pending_requests() == []          # no longer pending
    found = await Vault.discover(b.transport, b.ident)
    assert a.vault.vault_id in found
    b.vault = await Vault.join(b.root, b.ident, b.transport, a.vault.vault_id, use_git=False)
    await b.vault.sync()
    assert b.read("welcome.md") == b"hi bob"


async def test_duplicate_requests_collapse(mk):
    a, b = mk("alice"), mk("bob")
    a.vault = await Vault.create(a.root, a.ident, a.transport, "alice", use_git=False)
    for n in ("bob", "bobby"):
        await Vault.post_join_request(b.transport, b.ident, a.vault.vault_id, n)
    assert [r.name for r in await a.vault.pending_requests()] == ["bobby"]


def test_creds_use_env_and_keep_proxy(monkeypatch):
    from tgsync.identity import TelegramCreds
    monkeypatch.setenv("TGSYNC_API_ID", "123")
    monkeypatch.setenv("TGSYNC_API_HASH", "abc")
    c = cli.common._creds_for("default", "socks5://h:1", None)       # no prompts: env supplies the pair
    assert (c.api_id, c.api_hash, c.proxy) == (123, "abc", "socks5://h:1")
    monkeypatch.setenv("TGSYNC_API_ID", "456")
    cli.common._creds_for("default", None, None)
    saved = TelegramCreds.load("default")
    assert (saved.api_id, saved.proxy) == (456, "socks5://h:1")  # new pair, saved proxy kept
    assert cli.common._creds_for("default", "none", None).proxy is None


def test_removed_commands_are_gone():
    names = set(cli.main.commands)
    assert names == {"new", "join", "invite", "members", "accept", "remove", "sync", "pull", "push", "status", "restore"}


def test_profile_names_are_safe():
    for bad in ("../x", "a/b", "", "x" * 40, "a b"):
        with pytest.raises(KeyError_):
            identity.check_profile_name(bad)


def test_env_profile_override(monkeypatch):
    monkeypatch.setenv("TGSYNC_PROFILE", "b")
    assert identity.current_profile() == "b"


async def test_removed_member_can_ask_again_and_is_not_treated_as_member(mk, pair):
    a, b = pair
    await a.vault.remove_member("bob")
    # the old "bob was added" descriptor still exists, but the latest one drops bob
    assert a.vault.vault_id not in await Vault.discover(b.transport, b.ident)
    import pytest as _pytest

    from tgsync.errors import VaultError
    fresh = mk("bob2")
    with _pytest.raises(VaultError, match="not a member"):
        await Vault.join(fresh.root, b.ident, b.transport, a.vault.vault_id, use_git=False)
    assert not (fresh.root / ".tgsync").exists()                  # no half-made vault left behind
    await Vault.post_join_request(b.transport, b.ident, a.vault.vault_id, "bob")
    (req,) = await a.vault.pending_requests()
    await a.vault.accept_request(req)
    assert a.vault.vault_id in await Vault.discover(b.transport, b.ident)
    again = mk("bob3")
    v = await Vault.join(again.root, b.ident, b.transport, a.vault.vault_id, use_git=False)
    assert v.keys.current_epoch == 2 and not v.removed


async def test_readded_member_gets_all_history_including_while_removed(mk, pair):
    a, b = pair
    a.write("before.md", "epoch one")
    await a.vault.sync(); await b.vault.sync()
    await a.vault.remove_member("bob")
    a.write("during.md", "written while bob was out")
    await a.vault.sync()
    await Vault.post_join_request(b.transport, b.ident, a.vault.vault_id, "bob")
    (req,) = await a.vault.pending_requests()
    await a.vault.accept_request(req)
    a.write("after.md", "after re-add")
    await a.vault.sync()
    fresh = mk("bob_again")
    v = await Vault.join(fresh.root, b.ident, b.transport, a.vault.vault_id, use_git=False)
    rep = await v.sync()
    assert fresh.files() == {"before.md", "during.md", "after.md"}, rep.problems
    assert fresh.read("during.md") == b"written while bob was out"
    assert rep.problems == []
    # survives a restart: keyring is rebuilt from stored descriptors
    v.close()
    again = Vault(fresh.root, b.ident, b.transport, use_git=False)
    assert again.keys.epochs == [1, 2]
    a.write("later.md", "x")
    await a.vault.sync()
    await again.sync()
    assert fresh.read("later.md") == b"x"


async def _vault_at(mk, name="alice"):
    a = mk(name)
    identity.init_identity("default")
    a.vault = await Vault.create(a.root, identity.load_identity("default"), a.transport, name, use_git=False)
    cli.common._save_cfg(a.root, {"chat": 1, "profile": "default", "git": False})
    vid = a.vault.vault_id
    a.vault.close()
    return a, vid


async def test_not_a_vault_error_lists_known_vaults(mk, tmp_path):
    a, _ = await _vault_at(mk)
    CliRunner().invoke(cli.main, ["status", "-C", str(a.root)])  # using a vault remembers it
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    out = await asyncio.to_thread(CliRunner().invoke, cli.main, ["push", "-C", str(elsewhere)])
    assert out.exit_code != 0
    assert f"cd {cli.common._short(a.root)} && tgsync push" in out.output
    assert "tgsync join <invite line> ." in out.output and "tgsync new ." in out.output


def test_join_without_code_and_nothing_pending_explains():
    out = CliRunner().invoke(cli.main, ["join"])
    assert out.exit_code != 0 and "Paste the invite line" in out.output


async def test_new_in_existing_vault_fails_before_telegram(mk, monkeypatch):
    a, _ = await _vault_at(mk)

    async def boom(*a, **k):
        raise AssertionError("must not touch Telegram")

    monkeypatch.setattr(cli.common, "_ensure_ready", boom)
    out = CliRunner().invoke(cli.main, ["new", str(a.root)])
    assert out.exit_code != 0 and "already a tgsync vault" in out.output


async def test_plain_join_reuses_remembered_code_and_folder(mk, monkeypatch):
    from tgsync.invites import Invite, encode_invite
    a, vid = await _vault_at(mk)
    code = encode_invite(Invite("https://t.me/+x", vid, "ab"))
    cli.common._mem_save({"joins": {vid: {"code": code, "profile": "default", "folder": str(a.root)}}})

    async def ready(profile, *a, **k):
        return identity.load_identity(profile), None

    async def transport(client, ref):
        return a.transport, 1

    monkeypatch.setattr(cli.common, "_ensure_ready", ready)
    monkeypatch.setattr(cli.common, "_transport", transport)
    # no code, no folder, no account question; still a member, so it says so and changes nothing
    out = await asyncio.to_thread(CliRunner().invoke, cli.main, ["join"])
    assert out.exit_code != 0 and "already joined this vault" in out.output, out.output
