# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local git history of the vault (separate git-dir; never touches the vault's own .git)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .errors import VaultError
from .paths import INTERNAL_DIR


class History:
    def __init__(self, vault: Path):
        self.vault = vault
        self.gitdir = vault / INTERNAL_DIR / "history.git"

    @staticmethod
    def available() -> bool:
        return shutil.which("git") is not None

    def _git(self, *args: str, check: bool = True, input: bytes | None = None) -> subprocess.CompletedProcess:
        cmd = ["git", f"--git-dir={self.gitdir}", f"--work-tree={self.vault}",
               "-c", "user.name=tgsync", "-c", "user.email=tgsync@localhost",
               "-c", "core.autocrlf=false", "-c", "core.quotepath=off", *args]
        r = subprocess.run(cmd, capture_output=True, input=input)
        if check and r.returncode != 0:
            raise VaultError(f"git {' '.join(args[:2])} failed: {r.stderr.decode(errors='replace').strip()}")
        return r

    def init(self) -> None:
        if not self.available():
            raise VaultError("git is required for local history but was not found on PATH")
        if not (self.gitdir / "HEAD").exists():
            self.gitdir.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q", "--bare", str(self.gitdir)], check=True, capture_output=True)
            exclude = self.gitdir / "info" / "exclude"
            exclude.parent.mkdir(exist_ok=True)
            exclude.write_text(f"{INTERNAL_DIR}/\n.git/\n*.tgsync-tmp\n")

    def commit(self, message: str, force_paths: list[str] | None = None) -> str | None:
        """Snapshot the vault. Returns short sha, or None if nothing changed.

        `force_paths` are files tgsync itself just rewrote. Those are hashed and staged directly,
        bypassing git's stat cache, which can miss a same-size rewrite with a similar timestamp
        (notably on Windows).
        """
        self._git("add", "-A", "--", ".")
        for rel in force_paths or []:
            f = self.vault / rel
            if not f.is_file():
                continue
            sha = self._git("hash-object", "-w", "--", str(f)).stdout.decode().strip()
            self._git("update-index", "--add", "--cacheinfo", f"100644,{sha},{rel}")
        if self._git("diff", "--cached", "--quiet", check=False).returncode == 0:
            return None
        self._git("commit", "-q", "-m", message)
        return self._git("rev-parse", "--short", "HEAD").stdout.decode().strip()

    def log(self, path: str | None = None, limit: int = 30) -> list[str]:
        if self._git("rev-parse", "--verify", "-q", "HEAD", check=False).returncode != 0:
            return []
        args = ["log", f"-{limit}", "--date=iso", "--pretty=format:%h  %ad  %s"]
        if path:
            args += ["--", path]
        return self._git(*args).stdout.decode(errors="replace").splitlines()

    def is_commit(self, rev: str) -> bool:
        return self._git("rev-parse", "--verify", "-q", f"{rev}^{{commit}}", check=False).returncode == 0

    def _rows(self, *args: str) -> list[tuple[str, str, str]]:
        if self._git("rev-parse", "--verify", "-q", "HEAD", check=False).returncode != 0:
            return []
        out = self._git("log", "--date=format:%Y-%m-%d %H:%M", "--pretty=format:%h\t%ad\t%s", *args).stdout
        rows = []
        for line in out.decode(errors="replace").splitlines():
            h, d, subj = (line.split("\t", 2) + ["", ""])[:3]
            rows.append((h, d, subj))
        return rows

    def recent(self, limit: int = 15) -> list[tuple[str, str, str]]:
        return self._rows(f"-{limit}")

    def versions(self, path: str, limit: int = 20) -> list[tuple[str, str, str]]:
        """Snapshots in which `path` changed (newest first)."""
        return self._rows(f"-{limit}", "--", path)

    def files_in(self, rev: str) -> list[str]:
        """Files that changed in snapshot `rev` (deletions included)."""
        out = self._git("diff-tree", "--root", "--no-commit-id", "--name-only", "-r", rev).stdout
        return [x for x in out.decode(errors="replace").splitlines() if x]

    def show(self, rev: str, path: str) -> bytes:
        return self._git("show", f"{rev}:{path}").stdout
