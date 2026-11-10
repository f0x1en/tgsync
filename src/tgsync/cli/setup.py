# SPDX-License-Identifier: AGPL-3.0-or-later
"""Setting up a vault: `new` and `join`."""

from __future__ import annotations

from pathlib import Path

import click

from ..crypto import fingerprint
from ..engine import Vault
from ..errors import TgSyncError
from ..invites import Invite, decode_invite, encode_invite, short_code
from . import common as c
from .common import main, profile_opt, proxy_opt


@main.command()
@click.argument("folder", type=click.Path(file_okay=False, path_type=Path))
@click.option("--chat", help="Use an existing Telegram group (invite link, @name or id) instead of making one.")
@click.option("--name", default="", help="Your name in the member list.")
@click.option("--no-git", is_flag=True, help="No local version history.")
@click.option("--api-id", type=int, help="Telegram app id (a teammate can give you theirs).")
@click.option("--api-hash", help="Telegram app hash.")
@profile_opt
@proxy_opt
def new(folder: Path, chat: str | None, name: str, no_git: bool, api_id: int | None, api_hash: str | None,
        profile: str | None, proxy: str | None) -> None:
    """Start a new vault in FOLDER (makes a private Telegram group, key and login as needed)."""
    if c._cfg_path(folder).exists():  # check before making a Telegram group
        raise click.ClickException(f"{c._short(folder)} is already a tgsync vault. To use it:  "
                                   f"cd {c._short(folder)} && tgsync\n"
                                   f"To start another vault, pick a new folder:  tgsync new ~/vaults/NAME")
    profile = c._choose_profile(profile)
    api = (api_id, api_hash) if api_id and api_hash else None

    async def go():
        ident, client = await c._ensure_ready(profile, api, proxy)
        link = None
        if chat:
            tr, chat_id = await c._transport(client, chat)
        else:
            tr, chat_id, link = await c._new_group(client, folder.resolve().name or "tgsync vault")
        try:
            v = await Vault.create(folder, ident, tr, name or profile, use_git=not no_git)
            cfg = {"chat": chat_id, "profile": profile, "git": not no_git}
            if link:
                cfg["invite"] = link
            c._save_cfg(folder, cfg)
            c._remember_vault(folder)
            code = encode_invite(Invite(link, v.vault_id, fingerprint(v.keys.key(1)))) if link else None

            def text() -> None:
                click.echo(f"Vault ready in {c._short(folder)} (account '{profile}').\n")
                click.echo(f"  cd {c._short(folder)}")
                click.echo("  tgsync          sync your changes (run it inside the folder)")
                if code:
                    click.echo("\nTo add a friend, send them this line:\n")
                    click.echo(f"  tgsync join {code}\n")
                    click.echo("They get a short code like ab12-cd34 and tell it to you. Then, in the vault folder:\n"
                               "  tgsync accept ab12-cd34\n"
                               "(`tgsync invite` prints the line again later.)")
                else:
                    click.echo("Make an invite for friends with:  tgsync invite --link <group link>")

            c.emit({"folder": str(folder.resolve()), "profile": profile, "vault_id": v.vault_id,
                    "invite": code}, text)
        finally:
            await tr.close()

    c._guard(lambda: c.run(go()))


@main.command("join")
@click.argument("code", required=False)
@click.argument("folder", required=False, type=click.Path(file_okay=False, path_type=Path))
@click.option("--name", help="Name members will see (default: your account name).")
@click.option("--no-git", is_flag=True)
@profile_opt
@proxy_opt
def join_cmd(code: str, folder: Path | None, name: str | None, no_git: bool, profile: str | None,
             proxy: str | None) -> None:
    """Join a vault from an invite code. After they accept you, run plain `tgsync join` again."""
    joins = c._mem().get("joins", {})
    if code is None:
        if not joins:
            raise click.ClickException("Paste the invite line your friend sent you, e.g.\n"
                                       "  tgsync join tgsync1-...  [FOLDER]")
        if len(joins) > 1:
            raise click.ClickException("You are waiting on several vaults; run one of these:\n" + "\n".join(
                f"  tgsync join {j['code']}" for j in joins.values()))
        code = next(iter(joins.values()))["code"]
    try:
        inv = decode_invite(code)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e
    saved = joins.get(inv.vault_id, {})
    if folder is None and saved.get("folder"):
        folder = Path(saved["folder"])
    if folder is None:
        here = Path.cwd()
        default = "." if not any(here.iterdir()) else f"~/vaults/{inv.vault_id[:6]}"
        folder = Path(c.ask("Folder for the vault", "FOLDER", default=default)).expanduser()
    if c._cfg_path(folder).exists():  # check before touching Telegram
        if c._vault_id_at(folder) == inv.vault_id:
            raise click.ClickException(f"You already joined this vault in {c._short(folder)}. To sync:  "
                                       f"cd {c._short(folder)} && tgsync")
        raise click.ClickException(f"{c._short(folder)} already holds a different tgsync vault. "
                                   f"Pick an empty or new folder, e.g.:\n"
                                   f"  tgsync join <invite line> ~/vaults/{inv.vault_id[:6]}")
    profile = c._choose_profile(profile or saved.get("profile"))

    async def go():
        ident, client = await c._ensure_ready(profile, inv.api, proxy)
        tr, chat_id = await c._transport(client, inv.link)
        try:
            found = await Vault.discover(tr, ident)
            if inv.vault_id not in found:
                who = name or profile
                await Vault.post_join_request(tr, ident, inv.vault_id, who)
                m = c._mem()
                m.setdefault("joins", {})[inv.vault_id] = {
                    "code": code, "profile": profile, "folder": str(folder.expanduser().resolve())}
                c._mem_save(m)
                sc = short_code(ident.recipient)

                def waiting() -> None:
                    click.echo(f"Join request sent as '{who}'. Files will go in {c._short(folder)}.")
                    click.secho(f"Tell the person who invited you this code: {sc}", bold=True)
                    click.echo(f"They run:  tgsync accept {sc}")
                    click.echo("Then you run:  tgsync join     (no need to paste the line again; any time, no hurry)")

                c.emit({"state": "waiting", "code": sc, "folder": str(folder.resolve())}, waiting)
                return
            if found[inv.vault_id][1].replace(" ", "") != inv.fingerprint.replace(" ", ""):
                raise click.ClickException("KEY FINGERPRINT MISMATCH between the invite and the vault - refusing to join")
            v = await Vault.join(folder, ident, tr, inv.vault_id, use_git=not no_git)
            v.notify = c._say
            c._save_cfg(folder, {"chat": chat_id, "profile": profile, "git": not no_git, "invite": inv.link})
            c._remember_vault(folder)
            m = c._mem()
            if m.get("joins", {}).pop(inv.vault_id, None) is not None:
                c._mem_save(m)
            rep = await v.sync()

            def joined() -> None:
                click.echo(f"Joined. Files go in {c._short(folder)}")
                c._print_report(rep)
                click.echo(f"\nFrom now on:  cd {c._short(folder)} && tgsync")

            c.emit({"state": "joined", "folder": str(folder.resolve()), "report": c.report_dict(rep)}, joined)
        finally:
            await tr.close()

    c._guard(lambda: c.run(go()))
