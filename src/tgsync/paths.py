# SPDX-License-Identifier: AGPL-3.0-or-later
"""Portable path handling (Windows + Linux + macOS) and ignore rules."""

from __future__ import annotations

import posixpath
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import pathspec

from .errors import PathError

INTERNAL_DIR = ".tgsync"
TMP_SUFFIX = ".tgsync-tmp"

_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f\\]')
MAX_PATH_LEN = 240

DEFAULT_IGNORE = """\
# tgsync ignore rules (gitignore syntax)
.tgsync/
.git/
*.tgsync-tmp
.DS_Store
Thumbs.db
desktop.ini
# Obsidian: per-device UI state churns constantly and conflicts for no reason
.obsidian/workspace.json
.obsidian/workspaces.json
.obsidian/cache
.trash/
"""


def normalize(rel: str) -> str:
    """Validate and normalise a vault-relative POSIX path. Raises PathError."""
    if not rel or len(rel) > MAX_PATH_LEN:
        raise PathError(f"bad path length: {rel[:40]!r}")
    rel = unicodedata.normalize("NFC", rel)
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
        raise PathError(f"absolute path not allowed: {rel!r}")
    if _BAD_CHARS.search(rel):
        raise PathError(f"path has characters that are illegal on some platforms: {rel!r}")
    parts = rel.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise PathError(f"bad path component in {rel!r}")
        if part.endswith((".", " ")):
            raise PathError(f"component ends with dot/space (illegal on Windows): {rel!r}")
        if part.split(".")[0].upper() in _RESERVED:
            raise PathError(f"reserved Windows name in {rel!r}")
    if parts[0] == INTERNAL_DIR or parts[0] == ".git":
        raise PathError(f"reserved directory: {rel!r}")
    if rel.endswith(TMP_SUFFIX):
        raise PathError("reserved suffix")
    return posixpath.join(*parts)


def to_rel(vault: Path, p: Path) -> str:
    return p.relative_to(vault).as_posix()


def safe_join(vault: Path, rel: str) -> Path:
    """Join after normalising; guarantees result stays inside the vault."""
    rel = normalize(rel)
    target = (vault / rel)
    root = vault.resolve()
    resolved = target.resolve()
    if root != resolved and root not in resolved.parents:
        raise PathError(f"path escapes vault: {rel!r}")
    return target


def load_ignore(vault: Path) -> pathspec.PathSpec:
    lines = DEFAULT_IGNORE.splitlines()
    f = vault / ".tgsyncignore"
    if f.exists():
        lines += f.read_text("utf-8", errors="replace").splitlines()
    return pathspec.PathSpec.from_lines("gitignore", lines)


def conflict_name(path: str, author: str, ts: float) -> str:
    stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H%M")
    d, base = posixpath.split(path)
    stem, ext = posixpath.splitext(base)
    name = f"{stem} (conflict {author[:6]} {stamp}){ext}"
    return posixpath.join(d, name) if d else name
