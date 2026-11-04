# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cross-platform single-instance lock for a vault."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .errors import VaultError

if sys.platform == "win32":
    import msvcrt

    def _lock(fd: int) -> None:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


class VaultLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> VaultLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _lock(self.fd)
        except OSError:
            os.close(self.fd)
            self.fd = None
            raise VaultError("another tgsync process is already syncing this vault") from None
        return self

    def __exit__(self, *exc) -> None:
        if self.fd is not None:
            try:
                _unlock(self.fd)
            finally:
                os.close(self.fd)
                self.fd = None
