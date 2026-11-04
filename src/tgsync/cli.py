# SPDX-License-Identifier: AGPL-3.0-or-later
"""Command-line interface: a button that syncs a folder with a Telegram group.

    tgsync              sync this folder (pull + push), same as `tgsync sync`
    tgsync status       what changed locally (add --check to test Telegram access)
    tgsync restore      bring back an older version of a file
    tgsync new DIR      start a vault        tgsync join CODE   join one
    tgsync invite / members / accept CODE / remove NAME
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import click

from . import __version__
from .crypto import fingerprint
from .engine import SyncReport, Vault
from .errors import TgSyncError
from .history import History
from .identity import (
    TelegramCreds,
    check_profile_name,
    current_profile,
    init_identity,
    list_profiles,
    load_identity,
)
from .invites import Invite, decode_invite, encode_invite, short_code
from .paths import INTERNAL_DIR


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------------ helpers
def _cfg_path(vault: Path) -> Path:
    return vault / INTERNAL_DIR / "config.json"


def _load_cfg(vault: Path) -> dict:
    p = _cfg_path(vault)
    if not p.exists():
        raise click.ClickException(
            f"{vault.resolve()} is not a tgsync vault. Go into your vault folder, or start one with "
            "`tgsync new <folder>` / `tgsync join <invite code>`.")
    return json.loads(p.read_text())


def _save_cfg(vault: Path, cfg: dict) -> None:
    _cfg_path(vault).parent.mkdir(parents=True, exist_ok=True)
    _cfg_path(vault).write_text(json.dumps(cfg, indent=2))


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


async def _connect_or_relogin(profile: str):
    """Connect; if the Telegram session is gone/revoked, log in again right here (terminal only)."""
    from .telegram import NotLoggedIn, connect, interactive_login

    try:
        return await connect(profile)
    except NotLoggedIn:
        if not sys.stdin.isatty():
            raise
        click.echo("Your Telegram session is missing or expired; logging in again.", err=True)
        await interactive_login(profile, TelegramCreds.load(profile))
        return await connect(profile)


async def _open(vault_dir: Path):
    from .telegram import TelethonTransport, resolve_chat

    cfg = _load_cfg(vault_dir)
    profile = cfg.get("profile", "default")
    client = await _connect_or_relogin(profile)
    entity = await resolve_chat(client, str(cfg["chat"]))
    tr = TelethonTransport(client, entity)
    tr.log = lambda s: click.echo(s, err=True)
    v = Vault(vault_dir, load_identity(profile), tr, use_git=cfg.get("git", True))
    v.notify = _say
    return v, tr


def _creds_for(profile: str, proxy: str | None, api: tuple[int, str] | None) -> TelegramCreds:
    """Load or collect Telegram API credentials for a profile and persist them (with the proxy)."""
    from .telegram import parse_proxy

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
        click.echo("Ask a teammate for their api_id/api_hash (the same pair works for everyone),\n"
                   "or create one at https://my.telegram.org -> API development tools")
        creds = TelegramCreds(click.prompt("api_id", type=int), click.prompt("api_hash").strip())
    if proxy is not None:
        creds.proxy = None if proxy.lower() == "none" else proxy
    try:
        parse_proxy(creds.proxy)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e
    creds.save(profile)
    return creds


def _choose_profile(explicit: str | None) -> str:
    """Pick the account for new/join: explicit > only one saved > ask > 'default' (new)."""
    if explicit:
        return check_profile_name(explicit)
    profiles = list_profiles()
    if not profiles:
        return "default"
    if len(profiles) == 1:
        return profiles[0]
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
    """Make sure the profile has a key, API credentials and a logged-in session -> (identity, client)."""
    from .telegram import NotLoggedIn, connect, interactive_login

    try:
        ident = load_identity(profile)
    except TgSyncError:
        ident = init_identity(profile)
        click.echo(f"Created a new key for account '{profile}'.")
    creds = _creds_for(profile, proxy, api)
    try:
        client = await connect(profile)
    except NotLoggedIn:
        click.echo(f"Logging in to Telegram for account '{profile}'...")
        click.echo("Logged in as " + await interactive_login(profile, creds))
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


# --------------------------------------------------------------------- main
@click.group(invoke_without_command=True)
@click.version_option(__version__)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Sync this folder with your Telegram group, end-to-end encrypted.

    Run with no command inside a vault folder to sync it.
    """
    if ctx.invoked_subcommand is not None:
        return
    if _cfg_path(Path.cwd()).exists():
        ctx.invoke(sync, vault_dir=Path.cwd())
    else:
        click.echo(ctx.get_help())
        click.echo("\nNew here?  `tgsync join <invite code>`  or  `tgsync new ~/vaults/name`")


# -------------------------------------------------------------- set up a vault
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
    profile = _choose_profile(profile)
    api = (api_id, api_hash) if api_id and api_hash else None

    async def go():
        from .telegram import TelethonTransport, create_group, peer_id, resolve_chat

        ident, client = await _ensure_ready(profile, api, proxy)
        link = None
        if chat:
            entity = await resolve_chat(client, chat)
        else:
            entity, link = await create_group(client, folder.resolve().name or "tgsync vault")
        tr = TelethonTransport(client, entity)
        try:
            v = await Vault.create(folder, ident, tr, name or profile, use_git=not no_git)
            cfg = {"chat": peer_id(entity), "profile": profile, "git": not no_git}
            if link:
                cfg["invite"] = link
            _save_cfg(folder, cfg)
            click.echo(f"Vault ready in {folder}")
            if link:
                code = encode_invite(Invite(link, v.vault_id, fingerprint(v.keys.key(1))))
                click.echo("\nTo add a friend, send them this line:\n")
                click.echo(f"  tgsync join {code}\n")
                click.echo("They will read a short code back to you; then:  tgsync accept <code>")
            else:
                click.echo("Make an invite for friends with:  tgsync invite --link <group link>")
        finally:
            await tr.close()

    _guard(lambda: run(go()))


@main.command("join")
@click.argument("code")
@click.argument("folder", required=False, type=click.Path(file_okay=False, path_type=Path))
@click.option("--name", help="Name members will see (default: your account name).")
@click.option("--no-git", is_flag=True)
@profile_opt
@proxy_opt
def join_cmd(code: str, folder: Path | None, name: str | None, no_git: bool, profile: str | None,
             proxy: str | None) -> None:
    """Join a vault from an invite code. Run it again after the owner accepts you."""
    try:
        inv = decode_invite(code)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e
    profile = _choose_profile(profile)

    async def go():
        from .telegram import TelethonTransport, peer_id, resolve_chat

        ident, client = await _ensure_ready(profile, inv.api, proxy)
        entity = await resolve_chat(client, inv.link)
        tr = TelethonTransport(client, entity)
        try:
            found = await Vault.discover(tr, ident)
            if inv.vault_id not in found:
                who = name or profile
                await Vault.post_join_request(tr, ident, inv.vault_id, who)
                click.echo(f"Join request sent as '{who}'.")
                click.secho(f"Tell the person who invited you this code: {short_code(ident.recipient)}", bold=True)
                click.echo("Once they accept it, run this same command again (any time, no hurry).")
                return
            if found[inv.vault_id][1].replace(" ", "") != inv.fingerprint.replace(" ", ""):
                raise click.ClickException("KEY FINGERPRINT MISMATCH between the invite and the vault - refusing to join")
            dest = folder or Path(click.prompt("Folder for the vault",
                                               default=f"~/vaults/{inv.vault_id[:6]}")).expanduser()
            v = await Vault.join(dest, ident, tr, inv.vault_id, use_git=not no_git)
            v.notify = _say
            _save_cfg(dest, {"chat": peer_id(entity), "profile": profile, "git": not no_git, "invite": inv.link})
            click.echo(f"Joined. Files go in {dest}")
            _print_report(await v.sync())
        finally:
            await tr.close()

    _guard(lambda: run(go()))


# --------------------------------------------------------------------- people
@main.command()
@click.option("--link", help="Group invite link to use (default: the saved one, else a new one).")
@click.option("--include-api", is_flag=True,
              help="Put your Telegram api_id/api_hash in the code so friends need not create their own.")
@vault_opt
def invite(link: str | None, include_api: bool, vault_dir: Path) -> None:
    """Print an invite line to send to a friend."""

    async def go():
        from .telegram import export_invite

        cfg = _load_cfg(vault_dir)
        v, tr = await _open(vault_dir)
        try:
            await v.pull()
            use = link or cfg.get("invite") or await export_invite(tr.client, tr.entity)
            if cfg.get("invite") != use:
                cfg["invite"] = use
                _save_cfg(vault_dir, cfg)
            api = None
            if include_api:
                c = TelegramCreds.load(cfg.get("profile", "default"))
                api = (c.api_id, c.api_hash)
                click.secho("This code contains your api_id/api_hash: only share it with people you trust.",
                            fg="yellow")
            code = encode_invite(Invite(use, v.vault_id, fingerprint(v.keys.key(1)), api))
            click.echo(f"\n  tgsync join {code}\n")
            click.echo("They read you a short code; then:  tgsync accept <code>")
        finally:
            await tr.close()

    _guard(lambda: run(go()))


@main.command()
@vault_opt
def members(vault_dir: Path) -> None:
    """Who is in the vault, and who is waiting to join."""

    async def go():
        v, tr = await _open(vault_dir)
        try:
            reqs = await v.pending_requests()
            click.echo("members:")
            for m in v.members:
                you = "  (you)" if m.recipient == v.identity.recipient else ""
                click.echo(f"  {m.name or m.id}{you}")
            if reqs:
                click.echo("\nwaiting to join (only accept a code the person read to you yourself):")
                for r in reqs:
                    click.echo(f"  {r.code}  {r.name or '(no name)'}     ->  tgsync accept {r.code}")
        finally:
            await tr.close()

    _guard(lambda: run(go()))


@main.command()
@click.argument("code")
@click.option("--name", help="Name to show in the member list (default: the name they gave).")
@vault_opt
def accept(code: str, name: str | None, vault_dir: Path) -> None:
    """Let in the person whose join code is CODE (typing it is the confirmation)."""

    async def go():
        v, tr = await _open(vault_dir)
        try:
            want = code.strip().lower()
            hits = [r for r in await v.pending_requests() if r.code == want]
            if not hits:
                raise click.ClickException(f"nobody is waiting with code {code!r} (see `tgsync members`)")
            r = hits[0]
            await v.accept_request(r, name)
            click.echo(f"Accepted {name or r.name or r.code}. They can run `tgsync join` again now.")
        finally:
            await tr.close()

    _guard(lambda: run(go()))


@main.command()
@click.argument("who")
@click.confirmation_option(prompt="Rotate the vault key so they can't read anything new?")
@vault_opt
def remove(who: str, vault_dir: Path) -> None:
    """Remove a member (by name) and rotate the vault key."""

    async def go():
        v, tr = await _open(vault_dir)
        try:
            await v.remove_member(who)
            click.echo(f"Removed. New key epoch {v.keys.current_epoch}; they can't read anything new.")
        finally:
            await tr.close()

    _guard(lambda: run(go()))


# ----------------------------------------------------------------------- sync
@main.command()
@vault_opt
def sync(vault_dir: Path) -> None:
    """Download others' changes and upload yours (this is also what plain `tgsync` does)."""

    async def go():
        v, tr = await _open(vault_dir)
        try:
            _print_report(await v.sync())
        finally:
            await tr.close()

    _guard(lambda: run(go()))


async def _check(vault_dir: Path) -> bool:
    """Online health check (what `doctor` + `whoami` used to do)."""
    ok_all = True

    def line(ok: bool, what: str, detail: str = "") -> None:
        nonlocal ok_all
        ok_all &= ok
        click.echo(f"  {'OK ' if ok else 'BAD'}  {what}" + (f"  ({detail})" if detail else ""))

    cfg = _load_cfg(vault_dir)
    profile = cfg.get("profile", "default")
    line(History.available(), "git installed (local history)")
    try:
        creds = TelegramCreds.load(profile)
        line(True, "Telegram credentials", f"proxy: {creds.proxy or 'none'}")
    except TgSyncError as e:
        line(False, "Telegram credentials", str(e))
        return False
    try:
        v, tr = await _open(vault_dir)
    except Exception as e:  # noqa: BLE001
        line(False, "Telegram connect + group access", f"{type(e).__name__}: {e}")
        return False
    try:
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
    return ok_all


@main.command()
@click.option("--check", is_flag=True, help="Also test Telegram access and vault health (needs network).")
@vault_opt
def status(check: bool, vault_dir: Path) -> None:
    """What changed locally (works offline)."""
    cfg = _load_cfg(vault_dir)
    profile = cfg.get("profile", "default")
    ident = load_identity(profile)
    v = Vault(vault_dir, ident, None, use_git=False)  # type: ignore[arg-type]
    s = v.status()
    v.close()
    click.echo(f"vault {s['vault_id']}  key epoch {s['epoch']}  fingerprint {s['fingerprint']}")
    click.echo(f"you: account '{profile}', key {ident.recipient[:14]}...   "
               f"members: " + ", ".join(n or r[:12] for n, r in s["members"]))
    for op, path in s["pending"]:
        click.echo(f"  {'M' if op == 'put' else 'D'} {path}")
    if not s["pending"]:
        click.echo("  nothing to upload")
    for _, what in s["problems"]:
        click.secho(f"  problem: {what}", fg="red")
    if check:
        click.echo("\nchecking Telegram and the vault...")
        ok = run(_check(vault_dir))
        click.echo("all good" if ok else "something needs attention")
        sys.exit(0 if ok else 1)


# -------------------------------------------------------------------- restore
def _pick(title: str, rows: list[str]) -> int:
    click.echo(title)
    for i, r in enumerate(rows, 1):
        click.echo(f"  {i:>2}) {r}")
    return click.prompt("Which one (number)", type=click.IntRange(1, len(rows)), default=1) - 1


@main.command()
@click.argument("path", required=False)
@click.argument("rev", required=False)
@vault_opt
def restore(path: str | None, rev: str | None, vault_dir: Path) -> None:
    """Bring back an older version of a file. Leave things out and it asks.

    \b
    tgsync restore                    pick a snapshot, then a file in it
    tgsync restore a1b2c3d            pick a file from that snapshot
    tgsync restore notes/x.md         pick one of that file's older versions
    tgsync restore notes/x.md a1b2c3d restore exactly that version
    """
    from .paths import safe_join

    vault = vault_dir.resolve()
    h = History(vault)
    if not (vault / INTERNAL_DIR / "history.git").exists():
        raise click.ClickException("this vault has no local history yet (run `tgsync` first)")
    if path and rev is None and not (vault / path).exists() and h.is_commit(path):
        path, rev = None, path  # a lone argument that is a snapshot id means "this snapshot"
    if rev is not None and not h.is_commit(rev):
        raise click.ClickException(f"{rev!r} is not a snapshot id")
    if rev is None and path is None:
        rows = h.recent()
        if not rows:
            raise click.ClickException("no history yet")
        rev = rows[_pick("Recent snapshots:", [f"{r[0]}  {r[1]}  {r[2]}" for r in rows])][0]
    if path is None:
        assert rev is not None
        files = h.files_in(rev)
        if not files:
            raise click.ClickException(f"snapshot {rev} changed no files")
        path = files[_pick(f"Files in snapshot {rev}:", files)]
    if rev is None:
        rows = h.versions(path)
        if not rows:
            raise click.ClickException(f"no history for {path!r}")
        rev = rows[_pick(f"Versions of {path}:", [f"{r[0]}  {r[1]}  {r[2]}" for r in rows])][0]
    try:
        data = h.show(rev, path)
    except TgSyncError:
        raise click.ClickException(f"{path!r} does not exist in snapshot {rev} (it may have been deleted then; "
                                   f"try an earlier snapshot)") from None
    dest = safe_join(vault, path)
    h.commit(f"before restoring {path}")  # whatever is there now stays recoverable
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    click.echo(f"Restored {path} as of {rev}. Your previous version is saved in history. "
               f"Run `tgsync` to share it.")


if __name__ == "__main__":
    main()
