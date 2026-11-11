# SPDX-License-Identifier: AGPL-3.0-or-later
"""Moving files: `sync`, `pull`, `push`, and `status`."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .. import sandbox
from ..engine import Vault
from ..errors import TgSyncError
from ..history import History
from ..identity import TelegramCreds, load_identity
from . import common as c
from .common import main, vault_opt


def _run_report(vault_dir: Path, what: str) -> None:
    async def go():
        v, tr = await c._open(vault_dir)
        try:
            c.emit_report(await getattr(v, what)())
        finally:
            await tr.close()

    c._guard(lambda: c.run(go()))


@main.command()
@vault_opt
def sync(vault_dir: Path) -> None:
    """Download others' changes AND upload yours (this is also what plain `tgsync` does)."""
    _run_report(vault_dir, "sync")


@main.command()
@vault_opt
def pull(vault_dir: Path) -> None:
    """Download teammates' changes only (uploads nothing)."""
    _run_report(vault_dir, "pull_changes")


@main.command()
@vault_opt
def push(vault_dir: Path) -> None:
    """Upload your changes only (never touches your local files)."""
    _run_report(vault_dir, "push_changes")


async def _check(vault_dir: Path) -> list[dict]:
    """Online health check -> [{"ok", "what", "detail"}]; stops at the first check that blocks the rest."""
    out: list[dict] = []

    def line(ok: bool, what: str, detail: str = "") -> None:
        out.append({"ok": ok, "what": what, "detail": detail})

    cfg = c._load_cfg(vault_dir)
    profile = cfg.get("profile", "default")
    online = not sandbox.is_link(str(cfg["chat"]))
    line(History.available(), "git installed (local history)")
    if online:
        try:
            creds = TelegramCreds.load(profile)
            line(True, "Telegram credentials", f"proxy: {creds.proxy or 'none'}")
        except TgSyncError as e:
            line(False, "Telegram credentials", str(e))
            return out
    try:
        v, tr = await c._open(vault_dir)
    except Exception as e:  # noqa: BLE001
        line(False, "connect + group access", f"{type(e).__name__}: {e}")
        return out
    try:
        if online:
            me = await tr.client.get_me()
            line(True, "Telegram account", f"{me.first_name or ''} {me.last_name or ''} id {me.id}".strip())
        rep = await v.pull()
        line(not v.removed and bool(v.keys), "vault membership",
             "removed" if v.removed else f"key epoch {v.keys.current_epoch}" if v.keys else "no keys")
        line(not rep.problems, "log health", f"{len(rep.problems)} problem(s)" if rep.problems else "")
        old = v.state.problems()
        line(not old, "problems on record", f"{len(old)}" if old else "")
    finally:
        await tr.close()
    return out


@main.command()
@click.option("--check", is_flag=True, help="Also test Telegram access and vault health (needs network).")
@vault_opt
def status(check: bool, vault_dir: Path) -> None:
    """What changed locally (works offline)."""
    cfg = c._load_cfg(vault_dir)
    profile = cfg.get("profile", "default")
    ident = load_identity(profile)
    v = Vault(vault_dir, ident, None, use_git=False)  # type: ignore[arg-type]
    s = v.status()
    v.close()
    checks = c._guard(lambda: c.run(_check(vault_dir))) if check else None
    ok = checks is None or all(x["ok"] for x in checks)

    def text() -> None:
        click.echo(f"vault {s['vault_id']}  key epoch {s['epoch']}  fingerprint {s['fingerprint']}")
        click.echo(f"you: account '{profile}', key {ident.recipient[:14]}...   "
                   f"members: " + ", ".join(n or r[:12] for n, r in s["members"]))
        for op, path in s["pending"]:
            click.echo(f"  {'M' if op in ('put', 'mkdir') else 'D'} {path}{'/' if op in ('mkdir', 'rmdir') else ''}")
        if not s["pending"]:
            click.echo("  nothing to upload")
        for _, what in s["problems"]:
            click.secho(f"  problem: {what}", fg="red")
        if checks is not None:
            click.echo("\nchecking Telegram and the vault...")
            for x in checks:
                click.echo(f"  {'OK ' if x['ok'] else 'BAD'}  {x['what']}" + (f"  ({x['detail']})" if x["detail"] else ""))
            click.echo("all good" if ok else "something needs attention")

    c.emit({"vault_id": s["vault_id"], "epoch": s["epoch"], "fingerprint": s["fingerprint"], "profile": profile,
            "members": [n or r[:12] for n, r in s["members"]],
            "pending": [{"op": op, "path": p} for op, p in s["pending"]],
            "problems": [what for _, what in s["problems"]], "checks": checks}, text)
    if not ok:
        sys.exit(1)
