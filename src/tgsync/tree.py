# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic replicated state: every client replays the same ordered log
(Telegram message-id order) and arrives at the identical tree, including
identical conflict-copy names. No client ever has to guess who "won".

Rules (applied in log order):
  put   : accepted if path is new, content already equal, or `base` equals the
          current content (fast-forward). Otherwise someone else changed the
          file first -> this write lands at a deterministic conflict-copy path.
  delete: only honoured if `base` equals current content. A concurrent edit
          beats a delete (never silently lose data).
  mkdir : an empty folder (node with sha DIR). Ignored if the path is taken.
  rmdir : removes that folder node.
A put may point at content already in the log (its blob carries `payload_msg`), so a
rename or copy uploads nothing new; the content hash is still checked on download.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import PathError
from .paths import conflict_name, normalize

DIR = "dir"  # sha of a folder node


@dataclass
class Node:
    path: str
    sha: str
    size: int
    mtime: float
    blob: dict  # {"file_id", "chunks": [...], "chunk_size", "inline": [off,len]|None, "payload_msg": id}
    author: str
    msg_id: int

    def to_json(self) -> dict:
        return {
            "path": self.path, "sha": self.sha, "size": self.size, "mtime": self.mtime,
            "blob": self.blob, "author": self.author, "msg_id": self.msg_id,
        }

    @classmethod
    def from_json(cls, d: dict) -> Node:
        return cls(d["path"], d["sha"], d["size"], d["mtime"], d["blob"], d["author"], d["msg_id"])


class Tree:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self._fold: dict[str, str] = {}

    def get(self, path: str) -> Node | None:
        return self.nodes.get(path)

    def _set(self, node: Node) -> None:
        self.nodes[node.path] = node
        self._fold[node.path.casefold()] = node.path

    def _remove(self, path: str) -> None:
        self.nodes.pop(path, None)
        if self._fold.get(path.casefold()) == path:
            del self._fold[path.casefold()]

    def _free_conflict_path(self, path: str, author: str, ts: float) -> str:
        cand = conflict_name(path, author, ts)
        n = 2
        while cand.casefold() in self._fold:
            cand = conflict_name(path, f"{author[:5]}{n}", ts)
            n += 1
        return cand

    def apply_entry(self, entry: dict, author: str, ts: float, msg_id: int):
        """Apply one entry. Returns (kind, path, conflict_path|None) or None if ignored."""
        try:
            op = entry["op"]
            path = normalize(entry["path"])
        except (KeyError, PathError, TypeError):
            return None  # malformed/unsafe entries from a buggy peer are skipped, never applied
        cur = self.nodes.get(path)
        clash = self._fold.get(path.casefold())
        if op == "put":
            try:
                node = Node(path, entry["sha"], int(entry["size"]), float(entry.get("mtime", ts)),
                            dict(entry["blob"]), author, msg_id)
                node.blob.setdefault("payload_msg", msg_id)
            except (KeyError, TypeError, ValueError):
                return None
            if clash is not None and clash != path:
                return self._conflict(node, author, ts)
            base = entry.get("base")
            if cur is None or cur.sha == node.sha or cur.sha == base:
                if cur is not None and cur.sha == node.sha:
                    return ("noop", path, None)
                self._set(node)
                return ("put", path, None)
            return self._conflict(node, author, ts)
        if op == "delete":
            if cur is not None and cur.sha == entry.get("base"):
                self._remove(path)
                return ("delete", path, None)
            return None
        if op == "mkdir":
            if cur is not None or clash is not None:
                return None
            self._set(Node(path, DIR, 0, ts, {}, author, msg_id))
            return ("mkdir", path, None)
        if op == "rmdir":
            if cur is not None and cur.sha == DIR:
                self._remove(path)
                return ("rmdir", path, None)
            return None
        return None

    def _conflict(self, node: Node, author: str, ts: float):
        original = node.path
        cpath = self._free_conflict_path(original, author, ts)
        node.path = cpath
        self._set(node)
        return ("conflict", original, cpath)
