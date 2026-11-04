# SPDX-License-Identifier: AGPL-3.0-or-later
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


def test_profile_commands():
    r = CliRunner()
    assert identity.current_profile() == "default"
    identity.init_identity("default")
    identity.init_identity("work")
    out = r.invoke(cli.main, ["profile", "list"]).output
    assert "default" in out and "work" in out and "no Telegram login" in out
    assert r.invoke(cli.main, ["profile", "use", "work"]).exit_code == 0
    assert identity.current_profile() == "work"
    assert r.invoke(cli.main, ["profile", "use", "nope"]).exit_code != 0
    assert r.invoke(cli.main, ["keys", "show"]).output.strip() == identity.load_identity("work").recipient
    assert r.invoke(cli.main, ["profile", "remove", "work"], input="n\n").exit_code != 0
    assert "work" in identity.list_profiles()
    assert r.invoke(cli.main, ["profile", "remove", "work"], input="y\n").exit_code == 0
    assert identity.list_profiles() == ["default"]
    assert identity.current_profile() == "default"   # fell back after deleting the current one


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
