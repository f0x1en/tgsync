# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-user age identity and local (per-machine) application directories."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import platformdirs
import pyrage

from .errors import KeyError_


def root_dir() -> Path:
    base = os.environ.get("TGSYNC_HOME")
    d = Path(base) if base else Path(platformdirs.user_config_dir("tgsync", appauthor=False))
    d.mkdir(parents=True, exist_ok=True)
    return d


_PROFILE_OK = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def check_profile_name(name: str) -> str:
    if not _PROFILE_OK.match(name):
        raise KeyError_("profile names may only use letters, digits, '_' and '-' (max 32)")
    return name


def list_profiles() -> list[str]:
    root = root_dir()
    return sorted(p.name for p in root.iterdir()
                  if p.is_dir() and ((p / "identity.age-key").exists() or (p / "telegram.json").exists()))


def current_profile() -> str:
    """Env TGSYNC_PROFILE, else 'default'."""
    env = os.environ.get("TGSYNC_PROFILE")
    return check_profile_name(env) if env else "default"


def app_dir(profile: str = "default") -> Path:
    d = root_dir() / check_profile_name(profile)
    d.mkdir(parents=True, exist_ok=True)
    _private(d, directory=True)
    return d


def _private(p: Path, directory: bool = False) -> None:
    try:
        os.chmod(p, 0o700 if directory else 0o600)
    except OSError:
        pass  # Windows: relies on the per-user profile ACLs


def write_private(path: Path, data: bytes) -> None:
    """Create a file readable only by the current user (no window of wider perms)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    _private(path)


def member_id(recipient: str) -> str:
    return hashlib.sha256(recipient.encode()).hexdigest()[:16]


@dataclass
class Identity:
    secret: str  # AGE-SECRET-KEY-1...
    recipient: str  # age1...

    @property
    def id(self) -> str:
        return member_id(self.recipient)

    def _obj(self):
        return pyrage.x25519.Identity.from_str(self.secret)

    def unwrap(self, ciphertext: bytes) -> bytes:
        try:
            return pyrage.decrypt(ciphertext, [self._obj()])
        except Exception as e:  # pyrage raises DecryptError
            raise KeyError_(f"cannot decrypt with this identity: {e}") from None


def wrap_for(recipient: str, plaintext: bytes) -> bytes:
    try:
        r = pyrage.x25519.Recipient.from_str(recipient)
    except Exception as e:
        raise KeyError_(f"invalid age recipient {recipient!r}: {e}") from None
    return pyrage.encrypt(plaintext, [r])


def generate() -> Identity:
    i = pyrage.x25519.Identity.generate()
    return Identity(str(i), str(i.to_public()))


def identity_path(profile: str = "default") -> Path:
    return app_dir(profile) / "identity.age-key"


def load_identity(profile: str = "default") -> Identity:
    p = identity_path(profile)
    if not p.exists():
        raise KeyError_(f"no identity for profile {profile!r}; run `tgsync new` or `tgsync join`")
    secret = p.read_text().strip().splitlines()[-1].strip()
    i = pyrage.x25519.Identity.from_str(secret)
    return Identity(secret, str(i.to_public()))


def init_identity(profile: str = "default", force: bool = False) -> Identity:
    p = identity_path(profile)
    if p.exists() and not force:
        raise KeyError_(f"identity already exists at {p} (use --force to overwrite; this loses access!)")
    ident = generate()
    write_private(p, f"# public key: {ident.recipient}\n{ident.secret}\n".encode())
    return ident


@dataclass
class TelegramCreds:
    api_id: int
    api_hash: str
    proxy: str | None = None  # e.g. socks5://127.0.0.1:10808 or http://host:port

    @staticmethod
    def path(profile: str) -> Path:
        return app_dir(profile) / "telegram.json"

    def save(self, profile: str) -> None:
        write_private(self.path(profile), json.dumps({"api_id": self.api_id, "api_hash": self.api_hash, "proxy": self.proxy}).encode())

    @classmethod
    def load(cls, profile: str) -> TelegramCreds:
        p = cls.path(profile)
        if not p.exists():
            raise KeyError_("no Telegram API credentials; run `tgsync new` or `tgsync join` to set up")
        d = json.loads(p.read_text())
        return cls(int(d["api_id"]), d["api_hash"], d.get("proxy"))
