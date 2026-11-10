# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sync engine: pull the ordered log, push local changes, materialise the tree."""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import invites, oplog, vaultkeys
from .crypto import KeyRing, blob_epoch, fingerprint
from .errors import CryptoError, KeyError_, PathError, TransportError, VaultError
from .history import History
from .identity import Identity
from .lock import VaultLock
from .paths import INTERNAL_DIR, TMP_SUFFIX, load_ignore, normalize, safe_join
from .state import State
from .transport import Transport
from .tree import Node, Tree

HASH_BLOCK = 1024 * 1024
BIG_FILE = 8 * 1024 * 1024  # files at least this big get a heads-up message while transferring


def human_size(n: int) -> str:
    x = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if x < 1024 or unit == "GB":
            return f"{x:.0f} {unit}" if unit == "B" else f"{x:.1f} {unit}"
        x /= 1024
    return f"{n} B"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while block := f.read(HASH_BLOCK):
            h.update(block)
    return h.hexdigest()


@dataclass
class SyncReport:
    pushed: int = 0
    pushed_paths: list[str] = field(default_factory=list)
    applied_remote: int = 0
    written: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    conflicts: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    committed: str | None = None

    def summary(self) -> str:
        return (
            f"pushed {self.pushed} change(s), applied {self.applied_remote} remote op(s), "
            f"wrote {len(self.written)}, deleted {len(self.deleted)}, "
            f"{len(self.conflicts)} conflict(s), {len(self.skipped)} skipped, {len(self.problems)} problem(s)"
        )


class Vault:
    def __init__(self, root: Path, identity: Identity, transport: Transport, use_git: bool = True):
        self.root = root.resolve()
        self.identity = identity
        self.transport = transport
        self.meta = self.root / INTERNAL_DIR
        self.state = State(self.meta / "state.db")
        self.keys = KeyRing()
        self.members: list[vaultkeys.Member] = []
        self.vault_id: str | None = self.state.get("vault_id")
        self.removed = self.state.get("removed") == "1"
        self.tree: Tree = self.state.load_tree()
        self.history = History(self.root) if use_git and History.available() else None
        self._sent_seq = 0
        self._cache: dict[int, bytes] = {}
        self._desc_seen = 0
        self.notify = lambda msg: None  # set by the CLI to print heads-up lines
        self._ignore = load_ignore(self.root)
        for data in self.state.descriptors():
            with contextlib.suppress(CryptoError, KeyError_):
                d = vaultkeys.accept(data, self.identity, self.keys, self.vault_id, trusted=True)
                if d:
                    self.members = d.members

    # ---------------------------------------------------------------- setup
    @classmethod
    async def create(cls, root: Path, identity: Identity, transport: Transport, name: str = "",
                     use_git: bool = True) -> Vault:
        root.mkdir(parents=True, exist_ok=True)
        v = cls(root, identity, transport, use_git)
        if v.vault_id:
            raise VaultError("this folder is already a tgsync vault")
        data, ring, vault_id = vaultkeys.create_vault(identity, name)
        await transport.send(oplog.KIND_DESCRIPTOR, data)
        v.state.set("vault_id", vault_id)
        v.vault_id = vault_id
        await v.pull()
        if not v.keys:
            raise VaultError("failed to read back our own descriptor")
        v._init_files()
        return v

    @classmethod
    async def discover(cls, transport: Transport, identity: Identity) -> dict[str, tuple[KeyRing, str]]:
        """Find vaults in the chat that currently include us. Returns {vault_id: (ring, fingerprint)}.

        Descriptors are replayed in order, so a later one that drops us (we were removed) wins.
        """
        rings: dict[str, KeyRing] = {}
        member: dict[str, bool] = {}
        async for m in transport.iter_after(0):
            if m.kind != oplog.KIND_DESCRIPTOR:
                continue
            try:
                data = await transport.fetch(m.id)
                vid = vaultkeys.parse(data)["vault_id"]
                ring = rings.setdefault(vid, KeyRing())
                d = vaultkeys.accept(data, identity, ring, vid)
                member[vid] = d is not None
                if d is None:  # dropped from the vault: forget old keys; a later re-add is a fresh join
                    rings[vid] = KeyRing()
            except (CryptoError, KeyError_, TransportError):
                continue
        return {vid: (r, fingerprint(r.key(1) if r.has(1) else r.key(r.epochs[0])))
                for vid, r in rings.items() if r and member.get(vid)}

    @classmethod
    async def join(cls, root: Path, identity: Identity, transport: Transport, vault_id: str,
                   use_git: bool = True) -> Vault:
        root.mkdir(parents=True, exist_ok=True)
        v = cls(root, identity, transport, use_git)
        if v.vault_id:
            raise VaultError("this folder is already a tgsync vault")
        v.state.set("vault_id", vault_id)
        v.vault_id = vault_id
        await v.pull()
        if not v.keys or v.removed:
            reason = ("you were removed from that vault" if v.removed
                      else "you are not a member of that vault (ask a member to approve you)")
            v.close()
            shutil.rmtree(root / INTERNAL_DIR, ignore_errors=True)
            with contextlib.suppress(OSError):
                root.rmdir()  # only succeeds if we created it and it is empty
            raise VaultError(reason)
        v._init_files()
        return v

    def _init_files(self) -> None:
        ig = self.root / ".tgsyncignore"
        if not ig.exists():
            ig.write_text("# extra ignore patterns for this vault (gitignore syntax)\n")
        if self.history:
            self.history.init()

    def _vid(self) -> str:
        if not self.vault_id:
            raise VaultError("vault id unknown")
        return self.vault_id

    def close(self) -> None:
        self.state.close()

    # ------------------------------------------------------------------ pull
    async def pull(self) -> SyncReport:
        """Replay new log messages in order.

        If records appear before we hold any key (we were added to the vault later), they are not
        applied and the cursor is NOT advanced past them; once a descriptor gives us keys we
        rescan from that point so late joiners receive the full history.
        """
        rep = SyncReport()
        for _ in range(2):
            blocked = await self._pull_pass(rep)
            if not (blocked and self.keys):
                break
        return rep

    async def _pull_pass(self, rep: SyncReport) -> bool:
        cursor = self.state.cursor
        authors = self.state.author_seqs()
        new_desc: list[tuple[int, bytes]] = []
        last = cursor
        blocked = False  # saw records we could not read yet; freeze the cursor before them
        fresh = self.state.get("active") != "1"  # this vault has never been synced to disk
        try:
            async for msg in self.transport.iter_after(cursor):
                if msg.kind == oplog.KIND_DESCRIPTOR:
                    if msg.id <= self._desc_seen:
                        continue  # already handled in an earlier pass of this run
                    self._desc_seen = msg.id
                    data = await self.transport.fetch(msg.id)
                    try:
                        d = vaultkeys.accept(data, self.identity, self.keys, self.vault_id)
                    except (CryptoError, KeyError_) as err:
                        self._problem(rep, msg.id, f"rejected descriptor: {err}")
                    else:
                        if d is None:
                            if self.keys and fresh:  # never used this vault yet: a later re-add is a fresh join
                                self.keys, self.members = KeyRing(), []
                            elif self.keys:
                                self.removed = True
                                self.state.set("removed", "1")
                        else:
                            self.members = d.members
                            new_desc.append((msg.id, data))
                elif msg.kind == oplog.KIND_RECORD:
                    if self.removed:
                        pass
                    elif not self.keys or blocked:
                        blocked = True
                        continue
                    else:
                        data = await self.transport.fetch(msg.id)
                        try:
                            rec = oplog.decode_record(self.keys, data)
                        except CryptoError as err:
                            try:
                                missing = not self.keys.has(blob_epoch(data))
                            except CryptoError:
                                missing = False
                            if missing:  # written under a key epoch we do not hold yet
                                blocked = True
                                continue
                            self._problem(rep, msg.id, f"unreadable record: {err}")
                        else:
                            prev = authors.get(rec.author, 0)
                            if rec.seq <= prev:
                                self._problem(rep, msg.id, f"replayed/duplicate record from {rec.author[:6]} seq {rec.seq}")
                            else:
                                if rec.seq != prev + 1 and prev:
                                    self._problem(rep, msg.id, f"gap in {rec.author[:6]}'s history: {prev} -> {rec.seq} (message dropped?)")
                                authors[rec.author] = rec.seq
                                for ent in rec.entries:
                                    r = self.tree.apply_entry(ent, rec.author, rec.ts, msg.id)
                                    if r is not None and r[0] != "noop":
                                        rep.applied_remote += 1
                                    if r is not None and r[0] == "conflict":
                                        rep.conflicts.append((r[1], r[2]))
                if not blocked:
                    last = msg.id
        finally:
            self.state.save_tree(self.tree, last, authors, new_desc)
        self._sent_seq = max(self._sent_seq, authors.get(self.identity.id, 0))
        return blocked

    def _problem(self, rep: SyncReport, msg_id: int, what: str) -> None:
        rep.problems.append(f"msg {msg_id}: {what}")
        self.state.add_problem(msg_id, what)

    # ------------------------------------------------------------ local scan
    def _walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = Path(dirpath).relative_to(self.root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir
            dirnames[:] = [d for d in dirnames if not self._ignored(f"{rel_dir}/{d}".lstrip("/") + "/")]
            for fn in filenames:
                rel = f"{rel_dir}/{fn}".lstrip("/")
                if self._ignored(rel):
                    continue
                yield rel, Path(dirpath) / fn

    def _ignored(self, rel: str) -> bool:
        return self._ignore.match_file(rel)

    def scan_local(self, rep: SyncReport) -> list[dict]:
        """Compare disk with last-synced state; returns put/delete requests."""
        synced = self.state.synced()
        seen: set[str] = set()
        changes: list[dict] = []
        for rel, p in self._walk():
            try:
                rel = normalize(rel)
                st = p.lstat()
            except (PathError, OSError) as e:
                rep.skipped.append(f"{rel}: {e}")
                continue
            if not os.path.isfile(p) or p.is_symlink():
                rep.skipped.append(f"{rel}: not a regular file")
                continue
            seen.add(rel)
            prev = synced.get(rel)
            if prev and prev[1] == st.st_size and prev[2] == st.st_mtime_ns:
                continue
            try:
                sha = sha256_file(p)
            except OSError as e:
                rep.skipped.append(f"{rel}: {e}")
                continue
            if prev and prev[0] == sha:
                self.state.set_synced(rel, sha, st.st_size, st.st_mtime_ns)
                continue
            changes.append({"op": "put", "path": rel, "base": prev[0] if prev else None,
                            "size": st.st_size, "mtime": st.st_mtime})
        for rel, (sha, _, _) in synced.items():
            if rel not in seen and not (self.root / rel).exists():
                changes.append({"op": "delete", "path": rel, "base": sha})
        self.state.commit()
        return changes

    # ------------------------------------------------------------------ push
    async def push(self, changes: list[dict], rep: SyncReport, chunk_size: int = oplog.DEFAULT_CHUNK) -> list[str]:
        if not changes:
            return []
        batch: list[dict] = []
        payload = bytearray()
        pushed_paths: list[str] = []

        async def flush() -> None:
            nonlocal batch, payload
            if not batch:
                return
            self._sent_seq += 1
            rec = oplog.Record(self.identity.id, self._sent_seq, time.time(), batch, bytes(payload))
            await self.transport.send(oplog.KIND_RECORD, oplog.encode_record(self.keys, rec))
            rep.pushed += len(batch)
            rep.pushed_paths += [e["path"] for e in batch]
            batch, payload = [], bytearray()

        for ch in changes:
            if ch["op"] == "delete":
                batch.append(ch)
                pushed_paths.append(ch["path"])
            else:
                p = safe_join(self.root, ch["path"])
                try:
                    entry = await self._prepare_put(ch, p, chunk_size, payload)
                except OSError as e:
                    rep.skipped.append(f"{ch['path']}: {e}")
                    continue
                batch.append(entry)
                pushed_paths.append(ch["path"])
            if len(batch) >= oplog.MAX_ENTRIES_PER_RECORD or len(payload) >= oplog.RECORD_PAYLOAD_MAX:
                await flush()
        await flush()
        return pushed_paths

    async def _prepare_put(self, ch: dict, p: Path, chunk_size: int, payload: bytearray) -> dict:
        size = p.stat().st_size
        entry = {"op": "put", "path": ch["path"], "base": ch["base"], "mtime": ch["mtime"]}
        if size <= oplog.INLINE_MAX:
            data = p.read_bytes()
            entry.update(sha=hashlib.sha256(data).hexdigest(), size=len(data),
                         blob={"file_id": os.urandom(8).hex(), "chunks": None, "inline": [len(payload), len(data)]})
            payload += data
            return entry
        # large file: stream in sealed chunks
        if size >= BIG_FILE:
            self.notify(f"uploading {ch['path']} ({human_size(size)}); big files take a while")
        file_id = os.urandom(8).hex()
        count = max(1, -(-size // chunk_size))
        h = hashlib.sha256()
        ids: list[int] = []
        total = 0
        with open(p, "rb") as f:
            for i in range(count):
                data = f.read(chunk_size)
                h.update(data)
                total += len(data)
                sealed = oplog.seal_chunk(self.keys, file_id, i, count, data)
                ids.append(await self.transport.send(oplog.KIND_CHUNK, sealed))
        entry.update(sha=h.hexdigest(), size=total, blob={"file_id": file_id, "chunks": ids, "chunk_size": chunk_size,
                                                "inline": None})
        return entry

    # ----------------------------------------------------------- materialise
    async def _payload(self, node: Node) -> bytes:
        mid = node.blob["payload_msg"]
        if mid not in self._cache:
            if len(self._cache) > 64:
                self._cache.clear()
            rec = oplog.decode_record(self.keys, await self.transport.fetch(mid))
            self._cache[mid] = rec.payload
        return self._cache[mid]

    async def _write_node(self, node: Node, dest: Path) -> None:
        if node.size >= BIG_FILE:
            self.notify(f"downloading {node.path} ({human_size(node.size)}); big files take a while and "
                        f"only appear in your folder when finished")
        tmp = dest.with_name(dest.name + TMP_SUFFIX)
        dest.parent.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256()
        try:
            with open(tmp, "wb") as f:
                inline = node.blob.get("inline")
                if inline:
                    off, ln = inline
                    data = (await self._payload(node))[off : off + ln]
                    h.update(data)
                    f.write(data)
                else:
                    ids = node.blob["chunks"]
                    for i, mid in enumerate(ids):
                        data = oplog.open_chunk(self.keys, node.blob["file_id"], i, len(ids),
                                                await self.transport.fetch(mid))
                        h.update(data)
                        f.write(data)
            if h.hexdigest() != node.sha:
                raise CryptoError("content hash mismatch after decryption")
            target_ns = int(node.mtime * 1e9)
            try:  # never leave the exact same (size, mtime) as the previous version: stat-cache
                if dest.stat().st_mtime_ns == target_ns:  # based tools (git) would miss the change
                    target_ns += 1_000_000
            except OSError:
                pass
            os.utime(tmp, ns=(target_ns, target_ns))
            os.replace(tmp, dest)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise

    async def materialize(self, rep: SyncReport) -> None:
        synced = self.state.synced()
        preserved = {n.sha for n in self.tree.nodes.values()}
        for path, node in sorted(self.tree.nodes.items()):
            dest = safe_join(self.root, path)
            disk_sha = None
            if dest.is_file() and not dest.is_symlink():
                st = dest.stat()
                prev = synced.get(path)
                if prev and prev[1] == st.st_size and prev[2] == st.st_mtime_ns:
                    disk_sha = prev[0]
                else:
                    disk_sha = sha256_file(dest)
            if disk_sha == node.sha:
                st = dest.stat()
                self.state.set_synced(path, node.sha, st.st_size, st.st_mtime_ns)
                continue
            prev = synced.get(path)
            if disk_sha is not None and disk_sha != (prev[0] if prev else None) and disk_sha not in preserved:
                rep.skipped.append(f"{path}: local edits not yet pushed; will reconcile on next sync")
                continue
            try:
                await self._write_node(node, dest)
            except (CryptoError, TransportError, OSError) as e:
                rep.problems.append(f"{path}: could not restore: {e}")
                continue
            st = dest.stat()
            self.state.set_synced(path, node.sha, st.st_size, st.st_mtime_ns)
            rep.written.append(path)
        for path, (sha, _, _) in list(synced.items()):
            if path in self.tree.nodes:
                continue
            dest = safe_join(self.root, path)
            if dest.is_file():
                if sha256_file(dest) != sha and sha256_file(dest) not in preserved:
                    rep.skipped.append(f"{path}: deleted remotely but has local edits; kept")
                    self.state.del_synced(path)
                    continue
                dest.unlink()
                rep.deleted.append(path)
                self._prune_empty(dest.parent)
            self.state.del_synced(path)
        self.state.set("active", "1")
        self.state.commit()

    def _prune_empty(self, d: Path) -> None:
        while d != self.root and d.is_dir() and not any(d.iterdir()):
            d.rmdir()
            d = d.parent

    # ------------------------------------------------------------------ sync
    async def sync(self, chunk_size: int = oplog.DEFAULT_CHUNK) -> SyncReport:
        if self.removed:
            raise VaultError("you were removed from this vault; it can no longer be synced; to ask to come back, run `tgsync join` in this folder")
        with VaultLock(self.meta / "lock"):
            if self.history:
                self.history.commit("local changes before sync")
            rep = await self.pull()
            if self.removed:
                raise VaultError("you were removed from this vault; local files are left untouched; to ask to come back, run `tgsync join` in this folder")
            if not self.keys:
                raise VaultError("no vault keys; are you a member?")
            changes = self.scan_local(rep)
            if changes:
                await self.push(changes, rep, chunk_size)
                r2 = await self.pull()
                rep.applied_remote += r2.applied_remote
                rep.conflicts += r2.conflicts
                rep.problems += r2.problems
            await self.materialize(rep)
            if self.history:
                msg = f"sync: {len(rep.written)} written, {len(rep.deleted)} deleted, {rep.pushed} pushed"
                rep.committed = self.history.commit(msg, rep.written)
            return rep

    async def pull_changes(self) -> SyncReport:
        """Download and apply others' changes only (like `git pull`); uploads nothing."""
        with VaultLock(self.meta / "lock"):
            rep = await self.pull()
            self._check_member(rep)
            if self.history:
                self.history.commit("local changes before pull")
            await self.materialize(rep)
            if self.history:
                rep.committed = self.history.commit(
                    f"pull: {len(rep.written)} written, {len(rep.deleted)} deleted", rep.written)
            return rep

    async def push_changes(self, chunk_size: int = oplog.DEFAULT_CHUNK) -> SyncReport:
        """Upload your local changes only (like `git push`); does not touch your files."""
        with VaultLock(self.meta / "lock"):
            if self.history:
                self.history.commit("local changes before push")
            rep = await self.pull()  # log only: needed to know the vault state, writes no files
            self._check_member(rep)
            changes = self.scan_local(rep)
            if changes:
                await self.push(changes, rep, chunk_size)
                r2 = await self.pull()
                rep.applied_remote += r2.applied_remote
                rep.conflicts += r2.conflicts
                rep.problems += r2.problems
                self._mark_pushed_synced(changes)
            return rep

    def _mark_pushed_synced(self, changes: list[dict]) -> None:
        """After a push, files whose content is now the accepted tree version count as synced."""
        for ch in changes:
            node = self.tree.get(ch["path"])
            p = self.root / ch["path"]
            if ch["op"] == "put" and node and p.is_file() and sha256_file(p) == node.sha:
                st = p.stat()
                self.state.set_synced(ch["path"], node.sha, st.st_size, st.st_mtime_ns)
            elif ch["op"] == "delete" and node is None:
                self.state.del_synced(ch["path"])
        self.state.commit()

    def _check_member(self, rep: SyncReport) -> None:
        if self.removed:
            raise VaultError("you were removed from this vault; local files are left untouched; to ask to come back, run `tgsync join` in this folder")
        if not self.keys:
            raise VaultError("no vault keys; are you a member?")

    # --------------------------------------------------------------- members
    async def add_member(self, recipient: str, name: str = "") -> None:
        await self.pull()
        data, _ = vaultkeys.add_member(self.keys, self._vid(), self.members, vaultkeys.Member(recipient, name))
        await self.transport.send(oplog.KIND_DESCRIPTOR, data)
        await self.pull()

    @staticmethod
    async def post_join_request(transport: Transport, ident: Identity, vault_id: str, name: str) -> None:
        await transport.send(invites.KIND_JOIN, invites.encode_request(vault_id, ident, name))

    async def pending_requests(self) -> list[invites.JoinRequest]:
        """Join requests for this vault from people who are not members yet (latest per key)."""
        await self.pull()
        have = {m.recipient for m in self.members}
        found: dict[str, invites.JoinRequest] = {}
        async for m in self.transport.iter_after(0):
            if m.kind != invites.KIND_JOIN:
                continue
            try:
                req = invites.decode_request(await self.transport.fetch(m.id), m.id)
            except TransportError:
                continue
            if req and req.vault_id == self.vault_id and req.recipient not in have:
                found[req.recipient] = req
        return sorted(found.values(), key=lambda r: r.msg_id)

    async def accept_request(self, req: invites.JoinRequest, name: str | None = None) -> None:
        await self.add_member(req.recipient, name or req.name)

    async def remove_member(self, target: str) -> None:
        await self.pull()
        ring = KeyRing(self.keys.export())  # rotate on a copy; adopt only once the descriptor is accepted
        data, _ = vaultkeys.remove_member(ring, self._vid(), self.members, target)
        await self.transport.send(oplog.KIND_DESCRIPTOR, data)
        await self.pull()

    def status(self) -> dict:
        rep = SyncReport()
        changes = self.scan_local(rep)
        return {
            "vault_id": self.vault_id,
            "epoch": self.keys.current_epoch if self.keys else None,
            "fingerprint": fingerprint(self.keys.key(self.keys.current_epoch)) if self.keys else None,
            "members": [(m.name, m.recipient) for m in self.members],
            "tracked": len(self.tree.nodes),
            "pending": [(c["op"], c["path"]) for c in changes],
            "skipped": rep.skipped,
            "problems": self.state.problems()[-10:],
            "cursor": self.state.cursor,
        }


__all__ = ["SyncReport", "Vault"]
