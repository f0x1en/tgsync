# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared CLI plumbing: the `tgsync` group, --json mode, vault config, remembered input,
and the ONE place that decides between real Telegram and the offline sandbox."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path

import click

from .. import __version__, sandbox
from ..engine import SyncReport, Vault
from ..errors import TgSyncError
from ..identity import (
    TelegramCreds,
    check_profile_name,
    current_profile,
    init_identity,
    list_profiles,
    load_identity,
    root_dir,
)
from ..paths import INTERNAL_DIR
from ..state import State


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------------ --json mode
# `tgsync --json <command>` prints exactly one JSON object on stdout ({"ok": true, ...} or
# {"ok": false, "error": "..."}) and never asks questions. This is the interface for other
# tools (e.g. an editor plugin); human messages and progress go to stderr. See HACKING.md.
def json_mode() -> bool:
    ctx = click.get_current_context(silent=True)
    return bool(ctx and ctx.meta.get("json"))


def info(msg: str) -> None:
    """A human message; goes to stderr in --json mode so stdout stays one JSON object."""
    click.echo(msg, err=json_mode())


def emit(data: dict, text: Callable[[], None]) -> None:
    """Print a command's result: as JSON in --json mode, else by calling `text()`."""
    if json_mode():
        click.echo(json.dumps({"ok": True, **data}, default=str))
    else:
        text()


def ask(question: str, flag: str, **kw):
    """click.prompt, except in --json mode where it fails and names the flag to pass instead."""
    if json_mode():
        raise click.ClickException(f"{question}? (--json never asks; pass {flag})")
    return click.prompt(question, **kw)


def report_dict(rep: SyncReport) -> dict:
    return dataclasses.asdict(rep)


# ------------------------------------------------------------------ vault config
def _cfg_path(vault: Path) -> Path:
    return vault / INTERNAL_DIR / "config.json"


def _load_cfg(vault: Path) -> dict:
    p = _cfg_path(vault)
    if not p.exists():
        raise _not_a_vault(vault)
    _remember_vault(vault)
    return json.loads(p.read_text())


def _save_cfg(vault: Path, cfg: dict) -> None:
    _cfg_path(vault).parent.mkdir(parents=True, exist_ok=True)
    _cfg_path(vault).write_text(json.dumps(cfg, indent=2))


# Things this computer remembers so you don't retype them: your vault folders, and join
# requests you sent (invite line, account, folder) so a later `tgsync join` needs no arguments.
def _mem_path() -> Path:
    return root_dir() / "remembered.json"


def _mem() -> dict:
    try:
        return json.loads(_mem_path().read_text())
    except (OSError, ValueError):
        return {}


def _mem_save(m: dict) -> None:
    _mem_path().write_text(json.dumps(m, indent=2))


def _remember_vault(vault: Path) -> None:
    m = _mem()
    path = str(vault.resolve())
    old = m.get("vaults", [])
    m["vaults"] = [v for v in old if v != path and _cfg_path(Path(v)).exists()] + [path]
    if m["vaults"] != old:
        _mem_save(m)


def _known_vaults() -> list[Path]:
    return [Path(v) for v in _mem().get("vaults", []) if _cfg_path(Path(v)).exists()]


def _short(p: Path) -> str:
    """Path as you would type it: ~/x instead of /home/you/x."""
    p = p.expanduser().resolve()
    try:
        return "~/" + p.relative_to(Path.home()).as_posix()
    except ValueError:
        return str(p)


def _vault_id_at(folder: Path) -> str | None:
    db = folder / INTERNAL_DIR / "state.db"
    if not db.exists():
        return None
    st = State(db)
    try:
        return st.get("vault_id")
    finally:
        st.close()


def _not_a_vault(vault: Path) -> click.ClickException:
    ctx = click.get_current_context(silent=True)
    cmd = ctx.info_name if ctx and ctx.info_name not in (None, "main", "tgsync") else "sync"
    lines = [f"{_short(vault)} is not a tgsync vault."]
    known = _known_vaults()
    if known:
        lines.append("Your vaults on this computer:")
        lines += [f"  cd {_short(v)} && tgsync {cmd}" for v in known]
    if _mem().get("joins"):
        lines.append("You asked to join a vault. When they have accepted you:  tgsync join")
    lines.append("Join a friend's vault into this folder:  tgsync join <invite line> .")
    lines.append("Start a new vault in this folder:        tgsync new .")
    return click.ClickException("\n".join(lines))


# ------------------------------------------------------------------ output
def _say(msg: str) -> None:
    click.echo("  ... " + msg, err=True)


def _lines(sym: str, paths: list[str], limit: int = 15) -> None:
    for p in paths[:limit]:
        click.echo(f"  {sym} {p}")
    if len(paths) > limit:
        click.echo(f"  {sym} ... and {len(paths) - limit} more")


def _print_report(rep: SyncReport) -> None:
    click.echo(rep.summary())
    _lines("^", rep.pushed_paths)  # uploaded
    _lines("v", rep.written)  # downloaded / updated here
    _lines("x", rep.deleted)  # deleted here
    for a, b in rep.conflicts:
        click.secho(f"  conflict: {a} -> kept both, other copy at {b}", fg="yellow")
    for s in rep.skipped:
        click.secho(f"  skipped: {s}", fg="yellow")
    for p in rep.problems:
        click.secho(f"  problem: {p}", fg="red", err=True)


def emit_report(rep: SyncReport, after: str = "") -> None:
    def text() -> None:
        _print_report(rep)
        if after:
            click.echo(after)
    emit({"report": report_dict(rep)}, text)


# ------------------------------------------------------------------ Telegram or sandbox
# Everything that connects goes through here, so commands never care which one they talk to.
async def _connect_or_relogin(profile: str):
    """Connect; if the Telegram session is gone/revoked, log in again right here (terminal only)."""
    from ..telegram import NotLoggedIn, connect, interactive_login

    try:
        return await connect(profile)
    except NotLoggedIn:
        if not sys.stdin.isatty() or json_mode():
            raise
        info("Your Telegram session is missing or expired; logging in again.")
        await interactive_login(profile, TelegramCreds.load(profile))
        return await connect(profile)


async def _transport(client, ref: str):
    """-> (transport, value to store as cfg["chat"]) for a group link/id, real or sandbox."""
    if sandbox.is_link(ref):
        if sandbox.root() is None:  # its keys live in the sandbox config dir
            base = Path(ref[len(sandbox.PREFIX):]).parent.parent
            raise click.ClickException(f"This is a sandbox vault. First run:  export TGSYNC_SANDBOX={base}")
        return sandbox.DirTransport(ref), ref
    from ..telegram import TelethonTransport, peer_id, resolve_chat

    entity = await resolve_chat(client, ref)
    tr = TelethonTransport(client, entity)
    tr.log = lambda s: click.echo(s, err=True)
    return tr, peer_id(entity)


async def _new_group(client, title: str):
    """-> (transport, cfg chat value, invite link) for a brand-new group."""
    if sandbox.root() is not None:
        link = sandbox.new_group()
        return sandbox.DirTransport(link), link, link
    from ..telegram import TelethonTransport, create_group, peer_id

    entity, link = await create_group(client, title)
    return TelethonTransport(client, entity), peer_id(entity), link


async def _open(vault_dir: Path):
    cfg = _load_cfg(vault_dir)
    profile = cfg.get("profile", "default")
    chat = str(cfg["chat"])
    client = None if sandbox.is_link(chat) else await _connect_or_relogin(profile)
    tr, _ = await _transport(client, chat)
    v = Vault(vault_dir, load_identity(profile), tr, use_git=cfg.get("git", True))
    v.notify = _say
    return v, tr


def _creds_for(profile: str, proxy: str | None, api: tuple[int, str] | None) -> TelegramCreds:
    """Load or collect Telegram API credentials for a profile and persist them (with the proxy)."""
    from ..telegram import parse_proxy

    try:
        saved: TelegramCreds | None = TelegramCreds.load(profile)
    except TgSyncError:
        saved = None
    if api is None and os.environ.get("TGSYNC_API_ID") and os.environ.get("TGSYNC_API_HASH"):
        api = (int(os.environ["TGSYNC_API_ID"]), os.environ["TGSYNC_API_HASH"])
    if api:
        creds = TelegramCreds(api[0], api[1].strip(), saved.proxy if saved else None)
    elif saved:
        creds = saved
    else:
        if not json_mode():
            click.echo("Ask a teammate for their api_id/api_hash (the same pair works for everyone),\n"
                       "or create one at https://my.telegram.org -> API development tools")
        creds = TelegramCreds(ask("api_id", "--api-id/--api-hash or TGSYNC_API_ID/TGSYNC_API_HASH", type=int),
                              ask("api_hash", "--api-hash").strip())
    if proxy is not None:
        creds.proxy = None if proxy.lower() == "none" else proxy
    try:
        parse_proxy(creds.proxy)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e
    creds.save(profile)
    return creds


def _choose_profile(explicit: str | None) -> str:
    """Pick the account for new/join: explicit > TGSYNC_PROFILE > only one saved > ask > 'default'."""
    explicit = explicit or os.environ.get("TGSYNC_PROFILE")
    if explicit:
        return check_profile_name(explicit)
    profiles = list_profiles()
    if not profiles:
        return "default"
    if len(profiles) == 1:
        return profiles[0]
    if json_mode():
        raise click.ClickException(f"Which account? (--json never asks; pass --profile, one of: {', '.join(profiles)})")
    cur = current_profile()
    click.echo("Which account should this vault use?")
    for i, name in enumerate(profiles, 1):
        click.echo(f"  {i}) {name}")
    click.echo(f"  {len(profiles) + 1}) a new account")
    n = click.prompt("Choose", type=click.IntRange(1, len(profiles) + 1),
                     default=profiles.index(cur) + 1 if cur in profiles else 1)
    if n == len(profiles) + 1:
        return check_profile_name(click.prompt("Name for the new account"))
    return profiles[n - 1]


async def _ensure_ready(profile: str, api: tuple[int, str] | None = None, proxy: str | None = None):
    """Make sure the profile has a key (and, for Telegram, credentials and a login) -> (identity, client).

    In the sandbox the client is None: nothing to log in to.
    """
    try:
        ident = load_identity(profile)
    except TgSyncError:
        ident = init_identity(profile)
        info(f"Created a new key for account '{profile}'.")
    if sandbox.root() is not None:
        return ident, None
    from ..telegram import NotLoggedIn, connect, interactive_login

    creds = _creds_for(profile, proxy, api)
    try:
        client = await connect(profile)
    except NotLoggedIn:
        if json_mode():
            raise click.ClickException(f"Telegram login needed for account '{profile}'; "
                                       f"run the same command once in a terminal without --json") from None
        info(f"Logging in to Telegram for account '{profile}'...")
        info("Logged in as " + await interactive_login(profile, creds))
        client = await connect(profile)
    return ident, client


def _guard(fn):
    try:
        return fn()
    except click.ClickException:
        raise
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e


vault_opt = click.option("--vault", "-C", "vault_dir", type=click.Path(file_okay=False, path_type=Path),
                         default=".", show_default=False, help="Vault folder (default: here).")
profile_opt = click.option("--profile", default=None, help="Which of your Telegram accounts to use.")
proxy_opt = click.option("--proxy", help="Telegram proxy, e.g. socks5://127.0.0.1:10808 (saved).")


# --------------------------------------------------------------------- the group
class _Group(click.Group):
    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except click.ClickException as e:
            if not ctx.meta.get("json"):
                raise
            click.echo(json.dumps({"ok": False, "error": e.format_message()}))
            ctx.exit(1)


@click.group(cls=_Group, invoke_without_command=True)
@click.option("--json", "as_json", is_flag=True,
              help="Print one JSON object (for scripts and plugins); never ask questions.")
@click.version_option(__version__)
@click.pass_context
def main(ctx: click.Context, as_json: bool) -> None:
    """Sync this folder with your Telegram group, end-to-end encrypted.

    Run with no command inside a vault folder to sync it.
    """
    ctx.meta["json"] = as_json
    if ctx.invoked_subcommand is not None:
        return
    if _cfg_path(Path.cwd()).exists():
        ctx.invoke(main.commands["sync"], vault_dir=Path.cwd())
    elif as_json:
        raise _not_a_vault(Path.cwd())
    else:
        click.echo(ctx.get_help() + "\n")
        click.echo(_not_a_vault(Path.cwd()).format_message())
