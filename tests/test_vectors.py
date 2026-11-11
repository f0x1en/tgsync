# SPDX-License-Identifier: AGPL-3.0-or-later
"""The Python code must agree with spec/vectors.json (the TypeScript plugin tests use the same file)."""

import json
from pathlib import Path

import pytest

from tgsync import invites, oplog, paths, vaultkeys
from tgsync.crypto import KeyRing, _subkey, fingerprint, mac
from tgsync.errors import CryptoError, PathError
from tgsync.identity import Identity, member_id
from tgsync.tree import Tree

V = json.loads((Path(__file__).parent.parent / "spec" / "vectors.json").read_text())
X = bytes.fromhex


def test_subkeys_and_mac_and_fingerprint():
    for s in V["subkey"]:
        assert _subkey(X(s["key"]), s["purpose"].encode(), s["ctx"].encode()).hex() == s["subkey"]
    for m in V["mac"]:
        assert mac(X(m["key"]), *(p.encode() for p in m["parts"])).hex() == m["mac"]
    for f in V["fingerprint"]:
        assert fingerprint(X(f["key"])) == f["fingerprint"]


def test_seal_open():
    for s in V["seal"]:
        ring = KeyRing({s["epoch"]: X(s["key"])})
        assert ring.open(s["purpose"].encode(), s["ctx"].encode(), X(s["blob"])) == X(s["plaintext"])
    ring = KeyRing({int(e): X(k) for e, k in V["open_ring"].items()})
    for bad in V["open_must_fail"]:
        with pytest.raises(CryptoError):
            ring.open(bad["purpose"].encode(), bad["ctx"].encode(), X(bad["blob"]))


def test_identities():
    for i in V["identities"].values():
        assert member_id(i["recipient"]) == i["id"]
        assert invites.short_code(i["recipient"]) == i["short_code"]


@pytest.mark.parametrize("who", ["alice", "bob"])
def test_descriptor_sequence(who):
    d = V["descriptors"]
    i = V["identities"][who]
    ident = Identity(i["secret"], i["recipient"])
    ring = KeyRing()
    for data, want in zip(d["sequence"], d[f"expect_{who}"], strict=True):
        got = vaultkeys.accept(data.encode(), ident, ring, d["vault_id"])
        if want == "excluded":
            assert got is None
        else:
            assert got is not None and got.epoch == want["epoch"]
            assert [m.name for m in got.members] == want["members"]
    if who == "alice":
        assert ring.key(2).hex() == d["epoch2_key"]


def test_forged_descriptor_rejected():
    d = V["descriptors"]
    a = V["identities"]["alice"]
    ident = Identity(a["secret"], a["recipient"])
    ring = KeyRing()
    vaultkeys.accept(d["sequence"][0].encode(), ident, ring, d["vault_id"])
    with pytest.raises(CryptoError):
        vaultkeys.accept(d["forged_after_d1"].encode(), ident, ring, d["vault_id"])


def test_record_and_chunk():
    r = V["record"]
    rec = oplog.decode_record(KeyRing({r["epoch"]: X(r["key"])}), X(r["blob"]))
    assert (rec.author, rec.seq, rec.ts, rec.entries, rec.payload.hex()) == (r["author"], r["seq"], r["ts"], r["entries"], r["payload"])
    c = V["chunk"]
    assert oplog.open_chunk(KeyRing({1: X(c["key"])}), c["file_id"], c["index"], c["count"], X(c["blob"])).hex() == c["data"]


def test_invite_and_join_request():
    i = V["invite"]
    inv = invites.decode_invite(i["code"])
    assert (inv.link, inv.vault_id, inv.fingerprint, list(inv.api or ())) == (i["link"], i["vault_id"], i["fingerprint"], i["api"])
    j = V["join_request"]
    req = invites.decode_request(j["body"].encode())
    assert req is not None and (req.vault_id, req.recipient, req.name) == (j["vault"], j["recipient"], j["name"])


def test_paths_and_conflict_names():
    for p in V["paths"]:
        if p["ok"]:
            assert paths.normalize(p["in"]) == p["out"]
        else:
            with pytest.raises(PathError):
                paths.normalize(p["in"])
    for c in V["conflict_name"]:
        assert paths.conflict_name(c["path"], c["author"], c["ts"]) == c["out"]


def test_replay():
    rv = V["replay"]
    t = Tree()
    results = []
    for m in rv["log"]:
        for e in m["entries"]:
            r = t.apply_entry(json.loads(json.dumps(e)), m["author"], m["ts"], m["msg_id"])
            results.append(list(r) if r else None)
    assert results == rv["results"]
    assert {p: {"sha": n.sha, "author": n.author, "msg_id": n.msg_id, "payload_msg": n.blob.get("payload_msg")}
            for p, n in t.nodes.items()} == rv["tree"]
