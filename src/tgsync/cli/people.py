# SPDX-License-Identifier: AGPL-3.0-or-later
"""Who is in the vault: `invite`, `members`, `accept`, `remove`."""

from __future__ import annotations

from pathlib import Path

import click

from ..crypto import fingerprint
from ..identity import TelegramCreds
from ..invites import Invite, encode_invite
from . import common as c
from .common import main, vault_opt


@main.command()
@click.option("--link", help="Group invite link to use (default: the saved one, else a new one).")
@click.option("--include-api", is_flag=True,
              help="Put your Telegram api_id/api_hash in the code so friends need not create their own.")
@vault_opt
def invite(link: str | None, include_api: bool, vault_dir: Path) -> None:
    """Print an invite line to send to a friend."""

    async def go():
        from ..telegram import export_invite

        cfg = c._load_cfg(vault_dir)
        v, tr = await c._open(vault_dir)
        try:
            await v.pull()
            use = link or cfg.get("invite") or await export_invite(tr.client, tr.entity)
            if cfg.get("invite") != use:
                cfg["invite"] = use
                c._save_cfg(vault_dir, cfg)
            api = None
            if include_api:
                creds = TelegramCreds.load(cfg.get("profile", "default"))
                api = (creds.api_id, creds.api_hash)
                c.info(click.style("This code contains your api_id/api_hash: only share it with people you trust.",
                                   fg="yellow"))
            code = encode_invite(Invite(use, v.vault_id, fingerprint(v.keys.key(1)), api))

            def text() -> None:
                click.echo(f"\n  tgsync join {code}\n")
                click.echo("They read you a short code; then:  tgsync accept <code>")

            c.emit({"invite": code}, text)
        finally:
            await tr.close()

    c._guard(lambda: c.run(go()))


@main.command()
@vault_opt
def members(vault_dir: Path) -> None:
    """Who is in the vault, and who is waiting to join."""

    async def go():
        v, tr = await c._open(vault_dir)
        try:
            reqs = await v.pending_requests()
            mine = v.identity.recipient

            def text() -> None:
                click.echo("members:")
                for m in v.members:
                    you = "  (you)" if m.recipient == mine else ""
                    click.echo(f"  {m.name or m.id}{you}")
                if reqs:
                    click.echo("\nwaiting to join (only accept a code the person read to you yourself):")
                    for r in reqs:
                        click.echo(f"  {r.code}  {r.name or '(no name)'}     ->  tgsync accept {r.code}")

            c.emit({"members": [{"name": m.name, "id": m.id, "you": m.recipient == mine} for m in v.members],
                    "waiting": [{"code": r.code, "name": r.name} for r in reqs]}, text)
        finally:
            await tr.close()

    c._guard(lambda: c.run(go()))


@main.command()
@click.argument("code")
@click.option("--name", help="Name to show in the member list (default: the name they gave).")
@vault_opt
def accept(code: str, name: str | None, vault_dir: Path) -> None:
    """Let in the person whose join code is CODE (typing it is the confirmation)."""

    async def go():
        v, tr = await c._open(vault_dir)
        try:
            want = code.strip().lower()
            hits = [r for r in await v.pending_requests() if r.code == want]
            if not hits:
                raise click.ClickException(f"nobody is waiting with code {code!r} (see `tgsync members`)")
            r = hits[0]
            await v.accept_request(r, name)
            who = name or r.name or r.code
            c.emit({"accepted": who}, lambda: click.echo(f"Accepted {who}. Tell them to run:  tgsync join"))
        finally:
            await tr.close()

    c._guard(lambda: c.run(go()))


@main.command()
@click.argument("who")
@click.option("--yes", is_flag=True, help="Don't ask for confirmation.")
@vault_opt
def remove(who: str, yes: bool, vault_dir: Path) -> None:
    """Remove a member (by name) and rotate the vault key."""
    if not yes:
        if c.json_mode():
            raise click.ClickException("Removing rotates the vault key. (--json never asks; pass --yes)")
        click.confirm("Rotate the vault key so they can't read anything new?", abort=True)

    async def go():
        v, tr = await c._open(vault_dir)
        try:
            await v.remove_member(who)
            epoch = v.keys.current_epoch
            c.emit({"removed": who, "epoch": epoch},
                   lambda: click.echo(f"Removed. New key epoch {epoch}; they can't read anything new."))
        finally:
            await tr.close()

    c._guard(lambda: c.run(go()))
