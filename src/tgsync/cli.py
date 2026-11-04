# SPDX-License-Identifier: AGPL-3.0-or-later
"""Command-line interface."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from . import __version__
from .crypto import fingerprint
from .engine import SyncReport, Vault
from .errors import TgSyncError
from .history import History
from .identity import TelegramCreds, init_identity, load_identity
from .paths import INTERNAL_DIR


def run(coro):
    return asyncio.run(coro)


def _cfg_path(vault: Path) -> Path:
    return vault / INTERNAL_DIR / "config.json"


def _load_cfg(vault: Path) -> dict:
    p = _cfg_path(vault)
    if not p.exists():
        raise click.ClickException(f"{vault} is not a tgsync vault (run `tgsync vault create|join`)")
    return json.loads(p.read_text())


def _save_cfg(vault: Path, cfg: dict) -> None:
    _cfg_path(vault).parent.mkdir(parents=True, exist_ok=True)
    _cfg_path(vault).write_text(json.dumps(cfg, indent=2))


async def _open(vault_dir: Path):
    from .telegram import TelethonTransport, connect, resolve_chat

    cfg = _load_cfg(vault_dir)
    profile = cfg.get("profile", "default")
    client = await connect(profile)
    entity = await resolve_chat(client, str(cfg["chat"]))
    tr = TelethonTransport(client, entity)
    tr.log = lambda s: click.echo(s, err=True)
    v = Vault(vault_dir, load_identity(profile), tr, use_git=cfg.get("git", True))
    return v, tr


def _print_report(rep: SyncReport) -> None:
    click.echo(rep.summary())
    for a, b in rep.conflicts:
        click.secho(f"  conflict: {a} -> kept both, other copy at {b}", fg="yellow")
    for s in rep.skipped:
        click.secho(f"  skipped: {s}", fg="yellow")
    for p in rep.problems:
        click.secho(f"  problem: {p}", fg="red", err=True)


vault_opt = click.option("--vault", "-C", "vault_dir", type=click.Path(file_okay=False, path_type=Path),
                         default=".", show_default=True, help="Vault folder.")


@click.group()
@click.version_option(__version__)
def main() -> None:
    """End-to-end encrypted shared folder sync over Telegram."""


# ---------------------------------------------------------------- account
@main.command()
@click.option("--profile", default="default", show_default=True)
@click.option("--proxy", help="e.g. socks5://127.0.0.1:10808 (saved for all later commands). Use 'none' to clear.")
@click.option("--api-id", type=int, envvar="TGSYNC_API_ID", help="Telegram app id (a teammate can share theirs).")
@click.option("--api-hash", envvar="TGSYNC_API_HASH", help="Telegram app hash (shared the same way).")
def login(profile: str, proxy: str | None, api_id: int | None, api_hash: str | None) -> None:
    """Log in to Telegram with your own account (api_id/api_hash from my.telegram.org)."""
    from .telegram import interactive_login, parse_proxy

    if api_id and api_hash:
        creds = TelegramCreds(api_id, api_hash.strip())
        try:  # keep a previously saved proxy unless a new one is given
            creds.proxy = TelegramCreds.load(profile).proxy
        except TgSyncError:
            pass
    else:
        try:
            creds = TelegramCreds.load(profile)
        except TgSyncError:
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
    if creds.proxy:
        click.echo(f"Using proxy {creds.proxy}")
    try:
        click.echo("Logged in as " + run(interactive_login(profile, creds)))
    except KeyboardInterrupt:
        raise click.Abort()
    except Exception as e:
        raise click.ClickException(f"{type(e).__name__}: {e} (is your proxy running? try --proxy socks5://127.0.0.1:10808)") from e


@main.command()
@click.option("--profile", default=None, help="Profile name (default: the one saved in the vault, else 'default').")
@click.option("--vault", "-C", "vault_dir", type=click.Path(file_okay=False, path_type=Path), default=None,
              help="Look up the profile that this vault folder uses.")
def whoami(profile: str | None, vault_dir: Path | None) -> None:
    """Show which profile / Telegram account you are acting as."""
    from .telegram import connect

    if vault_dir is not None and profile is None:
        profile = _load_cfg(vault_dir).get("profile", "default")
    profile = profile or "default"

    async def go():
        ident = load_identity(profile)
        creds = TelegramCreds.load(profile)
        click.echo(f"profile:   {profile}")
        click.echo(f"public key: {ident.recipient}")
        click.echo(f"proxy:     {creds.proxy or '(none)'}")
        client = await connect(profile)
        me = await client.get_me()
        await client.disconnect()
        click.echo(f"telegram:  {me.first_name or ''} {me.last_name or ''}  id {me.id}  phone +{me.phone}")

    _guard(lambda: run(go()))


@main.group()
def keys() -> None:
    """Your personal age identity."""


@keys.command("init")
@click.option("--profile", default="default")
@click.option("--force", is_flag=True)
def keys_init(profile: str, force: bool) -> None:
    """Generate your keypair. Share the printed public key with a vault member."""
    try:
        ident = init_identity(profile, force)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"Your public key (safe to share):\n  {ident.recipient}")


@keys.command("show")
@click.option("--profile", default="default")
def keys_show(profile: str) -> None:
    """Print your public key."""
    try:
        click.echo(load_identity(profile).recipient)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e


# ------------------------------------------------------------------ vault
@main.group()
def vault() -> None:
    """Create or join a vault."""


@vault.command("create")
@click.argument("folder", type=click.Path(file_okay=False, path_type=Path))
@click.option("--new-group", "title", help="Create a new private Telegram group with this title.")
@click.option("--chat", help="Use an existing group: invite link, @username or id.")
@click.option("--name", default="", help="Your display name in the member list.")
@click.option("--profile", default="default")
@click.option("--no-git", is_flag=True, help="Disable local git history.")
def vault_create(folder: Path, title: str | None, chat: str | None, name: str, profile: str, no_git: bool) -> None:
    """Start a new vault in FOLDER."""
    if bool(title) == bool(chat):
        raise click.UsageError("give exactly one of --new-group or --chat")

    async def go():
        from .telegram import TelethonTransport, connect, create_group, peer_id, resolve_chat

        ident = load_identity(profile)
        client = await connect(profile)
        link = None
        if title:
            entity, link = await create_group(client, title)
        else:
            entity = await resolve_chat(client, chat)
        tr = TelethonTransport(client, entity)
        v = await Vault.create(folder, ident, tr, name, use_git=not no_git)
        _save_cfg(folder, {"chat": peer_id(entity), "profile": profile, "git": not no_git})
        fp = fingerprint(v.keys.key(1))
        click.echo(f"Vault {v.vault_id} created in {folder}\n")
        invite = link or "<group invite link>"
        click.echo("Send your teammates this (the link is private; send the fingerprint over a different "
                   "channel if you can):")
        click.echo("  1. pip install it:  git clone https://github.com/f0x1en/tgsync && cd tgsync && pip install -e .")
        click.echo("  2. tgsync keys init && tgsync login        <- then send YOU the public key it prints")
        click.echo("You then run:  tgsync members add <their public key> --name <name>")
        click.echo("They then run:")
        click.echo(f'  tgsync vault join ~/vaults/{folder.name} --chat {invite} --fingerprint "{fp}"')
        await tr.close()

    _guard(lambda: run(go()))


@vault.command("join")
@click.argument("folder", type=click.Path(file_okay=False, path_type=Path))
@click.option("--chat", required=True, help="Group invite link, @username or id.")
@click.option("--profile", default="default")
@click.option("--fingerprint", "fp", help="Expected key fingerprint (from a current member).")
@click.option("--no-git", is_flag=True)
def vault_join(folder: Path, chat: str, profile: str, fp: str | None, no_git: bool) -> None:
    """Join an existing vault after a member added your public key."""

    async def go():
        from .telegram import TelethonTransport, connect, peer_id, resolve_chat

        ident = load_identity(profile)
        client = await connect(profile)
        entity = await resolve_chat(client, chat)
        tr = TelethonTransport(client, entity)
        found = await Vault.discover(tr, ident)
        if not found:
            raise click.ClickException(
                "No vault in that chat includes you yet. Send this to a member:\n  " + ident.recipient)
        if len(found) > 1:
            raise click.ClickException("multiple vaults found in this chat: " + ", ".join(found))
        vid, (_, got) = next(iter(found.items()))
        click.echo(f"Vault {vid}\nKey fingerprint: {got}")
        if fp:
            if fp.replace(" ", "").lower() != got.replace(" ", ""):
                raise click.ClickException("FINGERPRINT MISMATCH - refusing to join")
        elif not click.confirm("Does this fingerprint match what a current member sees?"):
            raise click.Abort()
        v = await Vault.join(folder, ident, tr, vid, use_git=not no_git)
        _save_cfg(folder, {"chat": peer_id(entity), "profile": profile, "git": not no_git})
        rep = await v.sync()
        _print_report(rep)
        await tr.close()

    _guard(lambda: run(go()))


# ---------------------------------------------------------------- members
@main.group()
def members() -> None:
    """Manage who can read the vault."""


@members.command("list")
@vault_opt
def members_list(vault_dir: Path) -> None:
    async def go():
        v, tr = await _open(vault_dir)
        await v.pull()
        for m in v.members:
            click.echo(f"{m.name or '(unnamed)':16} {m.id}  {m.recipient}")
        click.echo(f"epoch {v.keys.current_epoch}, key fingerprint {fingerprint(v.keys.key(v.keys.current_epoch))}")
        await tr.close()

    _guard(lambda: run(go()))


@members.command("add")
@click.argument("recipient")
@click.option("--name", default="")
@vault_opt
def members_add(recipient: str, name: str, vault_dir: Path) -> None:
    """Grant a teammate access using their age public key (`tgsync keys show`)."""

    async def go():
        v, tr = await _open(vault_dir)
        await v.add_member(recipient, name)
        click.echo(f"Added {name or recipient}. Make sure they are also in the Telegram group.")
        await tr.close()

    _guard(lambda: run(go()))


@members.command("remove")
@click.argument("who")
@click.confirmation_option(prompt="Rotate the vault key and cut this member off from new data?")
@vault_opt
def members_remove(who: str, vault_dir: Path) -> None:
    """Remove a member (by name, id or key) and rotate the vault key."""

    async def go():
        v, tr = await _open(vault_dir)
        await v.remove_member(who)
        click.echo(f"Removed. Now on key epoch {v.keys.current_epoch}; they cannot read anything new. (Kicking them from the group is optional.)")
        await tr.close()

    _guard(lambda: run(go()))


# ------------------------------------------------------------------- sync
@main.command()
@vault_opt
def sync(vault_dir: Path) -> None:
    """Pull, push and apply once."""

    async def go():
        v, tr = await _open(vault_dir)
        _print_report(await v.sync())
        await tr.close()

    _guard(lambda: run(go()))


@main.command()
@vault_opt
def pull(vault_dir: Path) -> None:
    """Download and apply teammates' changes (uploads nothing)."""

    async def go():
        v, tr = await _open(vault_dir)
        _print_report(await v.pull_changes())
        await tr.close()

    _guard(lambda: run(go()))


@main.command()
@vault_opt
def push(vault_dir: Path) -> None:
    """Upload your local changes (does not modify your files)."""

    async def go():
        v, tr = await _open(vault_dir)
        _print_report(await v.push_changes())
        await tr.close()

    _guard(lambda: run(go()))


@main.command()
@click.option("--interval", default=30, show_default=True, help="Seconds between remote polls.")
@vault_opt
def watch(interval: int, vault_dir: Path) -> None:
    """Keep syncing: on local file changes and on a timer."""
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    async def go():
        v, tr = await _open(vault_dir)
        loop = asyncio.get_running_loop()
        wake = asyncio.Event()

        class H(FileSystemEventHandler):
            def on_any_event(self, event):
                if INTERNAL_DIR not in Path(event.src_path).parts and not event.src_path.endswith("tgsync-tmp"):
                    loop.call_soon_threadsafe(wake.set)

        obs = Observer()
        obs.schedule(H(), str(v.root), recursive=True)
        obs.start()
        click.echo(f"Watching {v.root} (Ctrl-C to stop)")
        try:
            while True:
                try:
                    rep = await v.sync()
                    if rep.pushed or rep.written or rep.deleted or rep.conflicts or rep.problems:
                        _print_report(rep)
                except TgSyncError as e:
                    click.secho(f"sync failed: {e}", fg="red", err=True)
                try:
                    await asyncio.wait_for(wake.wait(), timeout=interval)
                    await asyncio.sleep(2)  # debounce bursts of edits
                except asyncio.TimeoutError:
                    pass
                wake.clear()
        finally:
            obs.stop()
            await tr.close()

    try:
        _guard(lambda: run(go()))
    except KeyboardInterrupt:
        pass


@main.command()
@vault_opt
def status(vault_dir: Path) -> None:
    """Show local pending changes and vault info (works offline)."""
    cfg = _load_cfg(vault_dir)
    v = Vault(vault_dir, load_identity(cfg.get("profile", "default")), None, use_git=False)  # type: ignore[arg-type]
    s = v.status()
    click.echo(f"vault {s['vault_id']}  epoch {s['epoch']}  fingerprint {s['fingerprint']}")
    click.echo(f"{s['tracked']} tracked file(s); members: " + ", ".join(n or r[:12] for n, r in s["members"]))
    for op, path in s["pending"]:
        click.echo(f"  {'M' if op == 'put' else 'D'} {path}")
    if not s["pending"]:
        click.echo("  nothing to push")
    for _, what in s["problems"]:
        click.secho(f"  problem: {what}", fg="red")


@main.command()
@click.argument("path", required=False)
@vault_opt
def history(path: str | None, vault_dir: Path) -> None:
    """Local git history of the vault."""
    for line in History(vault_dir.resolve()).log(path):
        click.echo(line)


@main.command()
@click.argument("path")
@click.argument("rev")
@vault_opt
def restore(path: str, rev: str, vault_dir: Path) -> None:
    """Restore PATH as of git revision REV (shown by `history`). It syncs like any edit."""
    from .paths import safe_join

    data = History(vault_dir.resolve()).show(rev, path)
    dest = safe_join(vault_dir.resolve(), path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    click.echo(f"Restored {path} from {rev}; run `tgsync sync` to share it.")


@main.command()
@vault_opt
def doctor(vault_dir: Path) -> None:
    """Check proxy, login, group access and vault health."""
    ok_all = True

    def line(ok: bool, what: str, detail: str = "") -> None:
        nonlocal ok_all
        ok_all &= ok
        click.echo(f"  {'OK ' if ok else 'BAD'}  {what}" + (f"  ({detail})" if detail else ""))

    async def go():
        cfg = _load_cfg(vault_dir)
        profile = cfg.get("profile", "default")
        try:
            ident = load_identity(profile)
            line(True, "identity", ident.recipient[:16] + "...")
        except TgSyncError as e:
            return line(False, "identity", str(e))
        line(History.available(), "git installed (local history)")
        try:
            creds = TelegramCreds.load(profile)
            line(True, "Telegram credentials", f"proxy: {creds.proxy or 'none'}")
        except TgSyncError as e:
            return line(False, "Telegram credentials", str(e))
        try:
            v, tr = await _open(vault_dir)
        except Exception as e:
            return line(False, "Telegram connect / group access", f"{type(e).__name__}: {e}")
        line(True, "Telegram connect + group access")
        try:
            rep = await v.pull()
            line(not v.removed and bool(v.keys), "vault membership",
                 "removed" if v.removed else f"key epoch {v.keys.current_epoch}" if v.keys else "no keys")
            line(not rep.problems, "log health", f"{len(rep.problems)} problem(s) just now" if rep.problems else "")
            old = v.state.problems()
            line(not old, "recorded problems", f"{len(old)} on record, see `tgsync status`" if old else "")
            line(True, "pending local changes", f"{len(v.scan_local(rep))}")
        finally:
            await tr.close()

    _guard(lambda: run(go()))
    click.echo("all good" if ok_all else "something needs attention")
    sys.exit(0 if ok_all else 1)


def _guard(fn):
    try:
        return fn()
    except click.ClickException:
        raise
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e


if __name__ == "__main__":
    main()
