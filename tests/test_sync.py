# SPDX-License-Identifier: AGPL-3.0-or-later
import os

from tgsync import oplog


async def test_basic_roundtrip(pair):
    a, b = pair
    a.write("notes/hello.md", "# hi")
    a.write("big.bin", os.urandom(300_000))
    await a.vault.sync()
    rep = await b.vault.sync()
    assert b.read("notes/hello.md") == b"# hi"
    assert b.read("big.bin") == a.read("big.bin")
    assert sorted(rep.written) == ["big.bin", "notes/hello.md"]


async def test_small_files_are_batched(pair, channel):
    a, b = pair
    for i in range(50):
        a.write(f"n/{i}.md", f"note {i}")
    before = channel.sent
    await a.vault.sync()
    assert channel.sent - before == 1  # 50 notes -> one Telegram message


async def test_chunked_large_file(pair, channel):
    a, b = pair
    data = os.urandom(1_000_000)
    a.write("movie.bin", data)
    await a.vault.sync(chunk_size=300_000)
    kinds = [k for k, _ in channel.messages.values()]
    assert kinds.count(oplog.KIND_CHUNK) == 4
    await b.vault.sync()
    assert b.read("movie.bin") == data


async def test_server_sees_only_ciphertext(pair, channel):
    a, b = pair
    a.write("secret-plans.md", "TOP SECRET LAUNCH CODES")
    await a.vault.sync()
    blob = b"".join(d for k, d in channel.messages.values() if k != oplog.KIND_DESCRIPTOR)
    assert b"TOP SECRET" not in blob and b"secret-plans" not in blob


async def test_edit_and_delete_propagate(pair):
    a, b = pair
    a.write("x.md", "v1")
    await a.vault.sync(); await b.vault.sync()
    b.write("x.md", "v2")
    await b.vault.sync(); await a.vault.sync()
    assert a.read("x.md") == b"v2"
    (a.root / "x.md").unlink()
    await a.vault.sync(); await b.vault.sync()
    assert not b.exists("x.md")


async def test_concurrent_edit_makes_conflict_copy(pair):
    a, b = pair
    a.write("x.md", "base")
    await a.vault.sync(); await b.vault.sync()
    a.write("x.md", "alice edit")
    b.write("x.md", "bob edit")
    await a.vault.sync()          # alice lands first
    await b.vault.sync()          # bob's edit becomes a conflict copy
    await a.vault.sync()
    assert a.files() == b.files()
    assert a.read("x.md") == b.read("x.md") == b"alice edit"
    conflict = [f for f in a.files() if "conflict" in f]
    assert len(conflict) == 1
    assert a.read(conflict[0]) == b.read(conflict[0]) == b"bob edit"


async def test_edit_beats_delete(pair):
    a, b = pair
    a.write("x.md", "base")
    await a.vault.sync(); await b.vault.sync()
    (a.root / "x.md").unlink()
    b.write("x.md", "bob kept working")
    await a.vault.sync()
    await b.vault.sync()
    await a.vault.sync()
    assert a.read("x.md") == b"bob kept working" == b.read("x.md")


async def test_tampered_record_is_rejected_not_applied(pair, channel):
    a, b = pair
    a.write("x.md", "hello")
    await a.vault.sync()
    mid = max(i for i, (k, _) in channel.messages.items() if k == oplog.KIND_RECORD)
    k, d = channel.messages[mid]
    channel.messages[mid] = (k, d[:-1] + bytes([d[-1] ^ 1]))
    rep = await b.vault.sync()
    assert not b.exists("x.md")
    assert any("unreadable" in p for p in rep.problems)


async def test_replayed_record_ignored(pair, channel):
    a, b = pair
    a.write("x.md", "hello")
    await a.vault.sync()
    mid = max(i for i, (k, _) in channel.messages.items() if k == oplog.KIND_RECORD)
    channel.messages[channel.next_id] = channel.messages[mid]
    channel.next_id += 1
    rep = await b.vault.sync()
    assert b.read("x.md") == b"hello"
    assert any("replayed" in p for p in rep.problems)


async def test_unsafe_paths_from_peer_are_ignored(pair):
    a, b = pair
    v = a.vault
    rec = oplog.Record(a.ident.id, 1, 0, [
        {"op": "put", "path": "../../evil", "sha": "0" * 64, "size": 0, "base": None, "blob": {"inline": [0, 0], "file_id": "x"}},
        {"op": "put", "path": "C:/Windows/x", "sha": "0" * 64, "size": 0, "base": None, "blob": {"inline": [0, 0], "file_id": "x"}},
    ])
    await v.transport.send(oplog.KIND_RECORD, oplog.encode_record(v.keys, rec))
    await b.vault.sync()
    assert b.files() == set()


async def test_local_edit_not_clobbered_when_offline_changes(pair):
    a, b = pair
    a.write("x.md", "1")
    await a.vault.sync(); await b.vault.sync()
    a.write("x.md", "2")
    await a.vault.sync()
    b.write("x.md", "mine")
    await b.vault.sync()
    assert "mine" in "".join(b.read(f).decode() for f in b.files())  # never lost


async def test_pull_only_and_push_only(pair):
    a, b = pair
    a.write("n.md", "from alice")
    rep = await a.vault.push_changes()
    assert rep.pushed >= 1  # n.md (+ the auto-created .tgsyncignore)
    assert not b.exists("n.md")            # b has not pulled yet
    b.write("mine.md", "bob local")
    rep = await b.vault.pull_changes()     # pull must not upload bob's file
    assert b.read("n.md") == b"from alice" and rep.pushed == 0
    await a.vault.pull_changes()
    assert not a.exists("mine.md")         # bob's file was never pushed
    await b.vault.push_changes()
    await a.vault.pull_changes()
    assert a.read("mine.md") == b"bob local"


async def test_push_does_not_modify_local_files(pair):
    a, b = pair
    a.write("x.md", "base")
    await a.vault.sync(); await b.vault.sync()
    b.write("x.md", "bob v2"); await b.vault.push_changes()
    a.write("x.md", "alice v2")
    await a.vault.push_changes()
    assert a.read("x.md") == b"alice v2"   # push alone never overwrites local files


async def test_editor_scratch_files_ignored(pair):
    a, b = pair
    for junk in (".note.md.swp", "note.md~", "4913", ".#lock", "#auto#", ".netrwhist"):
        a.write(junk, "junk")
    a.write("note.md", "real")
    await a.vault.sync(); await b.vault.sync()
    assert b.files() == {"note.md"}


async def test_same_size_same_mtime_edit_is_detected(pair):
    """Racy-timestamp case: edit lands in the same mtime tick with the same size."""
    a, b = pair
    a.write("n.md", "v1")
    await a.vault.sync()
    st = (a.root / "n.md").stat()
    a.write("n.md", "v2")
    os.utime(a.root / "n.md", ns=(st.st_atime_ns, st.st_mtime_ns))  # identical size + mtime
    await a.vault.sync()
    await b.vault.sync()
    assert b.read("n.md") == b"v2"


async def test_push_marks_files_synced(pair):
    a, b = pair
    a.write("n.md", "x")
    await a.vault.push_changes()
    assert [c for c in a.vault.status()["pending"] if c[1] == "n.md"] == []
    again = await a.vault.push_changes()
    assert again.pushed == 0  # nothing re-uploaded


async def test_deleted_file_push_marks_synced(pair):
    a, b = pair
    a.write("n.md", "x")
    await a.vault.sync()
    (a.root / "n.md").unlink()
    await a.vault.push_changes()
    assert (await a.vault.push_changes()).pushed == 0


async def test_big_files_announce_themselves(pair, monkeypatch):
    from tgsync import engine
    monkeypatch.setattr(engine, "BIG_FILE", 1000)
    a, b = pair
    msgs_a, msgs_b = [], []
    a.vault.notify, b.vault.notify = msgs_a.append, msgs_b.append
    a.write("small.md", "tiny")
    a.write("movie.bin", os.urandom(300_000))
    await a.vault.sync()
    await b.vault.sync()
    assert len(msgs_a) == 1 and "uploading movie.bin" in msgs_a[0] and "KB" in msgs_a[0]
    assert len(msgs_b) == 1 and "downloading movie.bin" in msgs_b[0] and "only appear" in msgs_b[0]


def test_human_size():
    from tgsync.engine import human_size
    assert human_size(5) == "5 B" and human_size(2048) == "2.0 KB" and human_size(100_000_000) == "95.4 MB"


async def test_joining_with_the_same_files_on_disk_uploads_nothing_again(pair, mk):
    from tgsync.engine import Vault
    a, _ = pair
    a.write("same.md", "shared text")
    a.write("other.md", "alice's version")
    await a.vault.sync()
    c = mk("carol")              # e.g. re-joined in her old folder: files are there, state is fresh
    c.write("same.md", "shared text")
    c.write("other.md", "carol's own edit")
    await a.vault.add_member(c.ident.recipient, "carol")
    c.vault = await Vault.join(c.root, c.ident, c.transport, a.vault.vault_id, use_git=False)
    rep = await c.vault.sync()
    assert "same.md" not in rep.pushed_paths          # identical to the vault: not uploaded again
    assert "other.md" in rep.pushed_paths             # a real difference is still shared, not lost
    assert c.read("same.md") == b"shared text"
