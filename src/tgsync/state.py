# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local SQLite state: log cursor, replicated tree, per-path synced hashes."""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .tree import Node, Tree

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tree (path TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS synced (path TEXT PRIMARY KEY, sha TEXT NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS descriptors (msg_id INTEGER PRIMARY KEY, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS authors (author TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS problems (id INTEGER PRIMARY KEY AUTOINCREMENT, msg_id INTEGER, what TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS log (msg_id INTEGER NOT NULL, i INTEGER NOT NULL, ts REAL NOT NULL, author TEXT NOT NULL,
                                op TEXT NOT NULL, path TEXT NOT NULL, other TEXT, PRIMARY KEY (msg_id, i));
"""


RACY_NS = 2_000_000_000  # 2 s: covers coarse filesystem timestamps (FAT/NTFS/HFS+)


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript(SCHEMA)
        try:  # migration: when each file was last hashed (for racy-timestamp detection)
            self.db.execute("ALTER TABLE synced ADD COLUMN observed_ns INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    # kv
    def get(self, k: str, default: str | None = None) -> str | None:
        r = self.db.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return r[0] if r else default

    def set(self, k: str, v: str) -> None:
        self.db.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))
        self.db.commit()

    @property
    def cursor(self) -> int:
        return int(self.get("cursor", "0") or 0)

    # tree
    def load_tree(self) -> Tree:
        t = Tree()
        for (js,) in self.db.execute("SELECT json FROM tree"):
            t._set(Node.from_json(json.loads(js)))
        return t

    def save_tree(self, tree: Tree, cursor: int, authors: dict[str, int], descriptors: list[tuple[int, bytes]],
                  log: list[tuple] | None = None) -> None:
        """Atomically persist everything derived from log replay."""
        with self.db:
            self.db.execute("DELETE FROM tree")
            self.db.executemany(
                "INSERT INTO tree(path,json) VALUES(?,?)",
                [(p, json.dumps(n.to_json())) for p, n in tree.nodes.items()],
            )
            self.db.execute("INSERT INTO kv(k,v) VALUES('cursor',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (str(cursor),))
            self.db.executemany(
                "INSERT INTO authors(author,seq) VALUES(?,?) ON CONFLICT(author) DO UPDATE SET seq=excluded.seq",
                list(authors.items()),
            )
            self.db.executemany("INSERT OR IGNORE INTO descriptors(msg_id,data) VALUES(?,?)", descriptors)
            self.db.executemany("INSERT OR IGNORE INTO log VALUES(?,?,?,?,?,?,?)", log or [])

    def descriptors(self) -> list[bytes]:
        return [r[0] for r in self.db.execute("SELECT data FROM descriptors ORDER BY msg_id")]

    def author_seqs(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT author, seq FROM authors"))

    def log(self, path: str | None = None, limit: int = 50) -> list[tuple[float, str, str, str, str | None]]:
        """Newest first: (ts, author id, op, path, conflict copy or None)."""
        q = "SELECT ts, author, op, path, other FROM log"
        args: tuple = ()
        if path:
            q += " WHERE path=? OR other=? OR path LIKE ?"
            args = (path, path, path.rstrip("/") + "/%")
        return list(self.db.execute(q + " ORDER BY msg_id DESC, i DESC LIMIT ?", (*args, limit)))

    # synced
    def synced(self) -> dict[str, tuple[str, int, int]]:
        # A file whose mtime is within RACY_NS of the moment we hashed it could have been edited again
        # in the same timestamp tick with the same size; report mtime -1 so callers re-hash it.
        q = ("SELECT path, sha, size, CASE WHEN observed_ns - mtime_ns > ? THEN mtime_ns ELSE -1 END "
             "FROM synced")
        return {p: (s, z, m) for p, s, z, m in self.db.execute(q, (RACY_NS,))}

    def set_synced(self, path: str, sha: str, size: int, mtime_ns: int) -> None:
        self.db.execute(
            "INSERT INTO synced(path,sha,size,mtime_ns,observed_ns) VALUES(?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET sha=excluded.sha,size=excluded.size,"
            "mtime_ns=excluded.mtime_ns,observed_ns=excluded.observed_ns",
            (path, sha, size, mtime_ns, time.time_ns()),
        )

    def del_synced(self, path: str) -> None:
        self.db.execute("DELETE FROM synced WHERE path=?", (path,))

    def commit(self) -> None:
        self.db.commit()

    # problems
    def add_problem(self, msg_id: int | None, what: str) -> None:
        self.db.execute("INSERT INTO problems(msg_id,what) VALUES(?,?)", (msg_id, what))
        self.db.commit()

    def problems(self) -> list[tuple[int | None, str]]:
        return list(self.db.execute("SELECT msg_id, what FROM problems ORDER BY id"))
