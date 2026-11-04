# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exception types."""


class TgSyncError(Exception):
    """Base error."""


class CryptoError(TgSyncError):
    """Decryption/authentication failure or malformed ciphertext."""


class KeyError_(TgSyncError):
    """Missing or invalid key material."""


class TransportError(TgSyncError):
    """Telegram transport problem."""


class VaultError(TgSyncError):
    """Vault configuration/state problem."""


class PathError(TgSyncError):
    """A path is unsafe or not portable across platforms."""
