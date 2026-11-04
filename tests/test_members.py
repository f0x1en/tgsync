# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from tgsync.engine import Vault
from tgsync.errors import VaultError


async def test_non_member_cannot_join(mk, pair):
    a, b = pair
    eve = mk("eve")
    with pytest.raises(VaultError):
        await Vault.join(eve.root, eve.ident, eve.transport, a.vault.vault_id, use_git=False)


async def test_discover_and_fingerprint_match(mk, pair):
    a, b = pair
    found = await Vault.discover(b.transport, b.ident)
    assert list(found) == [a.vault.vault_id]
    from tgsync.crypto import fingerprint
    assert found[a.vault.vault_id][1] == fingerprint(a.vault.keys.key(1))


async def test_removed_member_cannot_read_new_data_but_others_can(mk, pair):
    a, b = pair
    c = mk("carol")
    await a.vault.add_member(c.ident.recipient, "carol")
    c.vault = await Vault.join(c.root, c.ident, c.transport, a.vault.vault_id, use_git=False)
    a.write("old.md", "before removal")
    await a.vault.sync(); await c.vault.sync(); await b.vault.sync()
    await a.vault.remove_member("bob")
    assert a.vault.keys.current_epoch == 2
    a.write("new.md", "after removal")
    await a.vault.sync()
    await c.vault.sync()
    assert c.read("new.md") == b"after removal"
    with pytest.raises(VaultError, match="removed"):
        await b.vault.sync()
    assert b.vault.removed
    assert not b.exists("new.md")


async def test_forged_descriptor_from_outsider_rejected(mk, pair, channel):
    a, b = pair
    from tgsync import vaultkeys
    eve = mk("eve")
    # eve builds her own vault with the same vault_id and wraps keys to bob
    data, ring, _ = vaultkeys.create_vault(eve.ident, "eve")
    forged = vaultkeys.build(ring, a.vault.vault_id, [vaultkeys.Member(b.ident.recipient, "bob")])
    await eve.transport.send("d", forged)
    rep = await b.vault.sync()
    assert any("rejected descriptor" in p for p in rep.problems)
    assert b.vault.keys.key(1) == a.vault.keys.key(1)
