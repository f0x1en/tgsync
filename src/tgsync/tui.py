# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal cross-platform Textual UI: status, members, pending changes, history, sync."""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, RichLog

from .errors import TgSyncError
from .history import History


class VaultApp(App):
    TITLE = "tgsync"
    BINDINGS = [("s", "sync", "Sync now"), ("r", "refresh", "Refresh local"), ("q", "quit", "Quit")]

    def __init__(self, vault_dir: Path, opener):
        super().__init__()
        self.vault_dir = vault_dir
        self.opener = opener

    def compose(self) -> ComposeResult:
        yield Header()
        yield RichLog(id="log", wrap=True, markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.action_refresh()

    def _out(self) -> RichLog:
        return self.query_one("#log", RichLog)

    def action_refresh(self) -> None:
        log = self._out()
        log.clear()
        try:
            from .cli import _load_cfg
            from .engine import Vault
            from .identity import load_identity

            cfg = _load_cfg(self.vault_dir)
            v = Vault(self.vault_dir, load_identity(cfg.get("profile", "default")), None, use_git=False)  # type: ignore[arg-type]
            s = v.status()
            v.close()
        except Exception as e:
            log.write(f"error: {e}")
            return
        log.write(f"vault {s['vault_id']}  epoch {s['epoch']}\nfingerprint {s['fingerprint']}\n")
        log.write("members: " + ", ".join(n or r[:12] for n, r in s["members"]))
        log.write(f"\n{s['tracked']} tracked file(s). Pending local changes:")
        for op, path in s["pending"] or [("", "(none)")]:
            log.write(f"  {'M' if op == 'put' else 'D' if op else ' '} {path}")
        for _, what in s["problems"]:
            log.write(f"  PROBLEM: {what}")
        log.write("\nRecent history:")
        for line in History(self.vault_dir).log(limit=15) or ["(no history yet)"]:
            log.write("  " + line)

    def action_sync(self) -> None:
        self.run_worker(self._sync(), exclusive=True)

    async def _sync(self) -> None:
        log = self._out()
        log.write("\nsyncing...")
        try:
            v, tr = await self.opener(self.vault_dir)
            rep = await v.sync()
            await tr.close()
            log.write(rep.summary())
        except TgSyncError as e:
            log.write(f"sync failed: {e}")
        except Exception as e:  # keep the UI alive on network errors
            log.write(f"sync failed: {e!r}")
        self.action_refresh()


def run_tui(vault_dir: Path, opener) -> None:
    VaultApp(vault_dir, opener).run()
