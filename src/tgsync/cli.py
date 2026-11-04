# SPDX-License-Identifier: AGPL-3.0-or-later
"""Command-line interface."""

from __future__ import annotations

import asyncio
import json
import sys
import time
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
    delete_profile,
    init_identity,
    list_profiles,
    load_identity,
    root_dir,
    set_current_profile,
)
from .invites import Invite, decode_invite, encode_invite, short_code
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


def _lines(sym: str, paths: list[str], limit: int = 15) -> None:
    for p in paths[:limit]:
        click.echo(f"  {sym} {p}")
    if len(paths) > limit:
        click.echo(f"  {sym} ... and {len(paths) - limit} more")


def _print_report(rep: SyncReport) -> None:
    click.echo(rep.summary())
    _lines("^", rep.pushed_paths)   # uploaded
    _lines("v", rep.written)        # downloaded / updated here
    _lines("x", rep.deleted)        # deleted here
    for a, b in rep.conflicts:
        click.secho(f"  conflict: {a} -> kept both, other copy at {b}", fg="yellow")
    for s in rep.skipped:
        click.secho(f"  skipped: {s}", fg="yellow")
    for p in rep.problems:
        click.secho(f"  problem: {p}", fg="red", err=True)


vault_opt = click.option("--vault", "-C", "vault_dir", type=click.Path(file_okay=False, path_type=Path),
                         default=".", show_default=True, help="Vault folder.")


@click.group(invoke_without_command=True)
@click.version_option(__version__)
@click.pass_context
def main(ctx: click.Context) -> None:
    """End-to-end encrypted shared folder sync over Telegram.

    Run with no command inside a vault folder to see where things stand.
    """
    if ctx.invoked_subcommand is not None:
        return
    if _cfg_path(Path.cwd()).exists():
        ctx.invoke(status, vault_dir=Path.cwd())
        click.echo("\nNext:  tgsync pull (get others' changes)  |  tgsync push (share yours)  |  "
                   "tgsync sync (both)  |  tgsync --help")
    else:
        click.echo(ctx.get_help())
        click.echo("\nNew here?  `tgsync join <invite code>`  or  `tgsync vault create ~/vaults/name --new-group \"name\"`")


# ---------------------------------------------------------------- account
@main.command()
@click.option("--profile", default=None, help="Account profile (default: the current one, see `tgsync profile`).")
@click.option("--proxy", help="e.g. socks5://127.0.0.1:10808 (saved for all later commands). Use 'none' to clear.")
@click.option("--api-id", type=int, envvar="TGSYNC_API_ID", help="Telegram app id (a teammate can share theirs).")
@click.option("--api-hash", envvar="TGSYNC_API_HASH", help="Telegram app hash (shared the same way).")
def login(profile: str | None, proxy: str | None, api_id: int | None, api_hash: str | None) -> None:
    """Log in to Telegram with your own account (api_id/api_hash from my.telegram.org)."""
    _login(profile or current_profile(), proxy, api_id, api_hash)


def _creds_for(profile: str, proxy: str | None, api: tuple[int, str] | None) -> TelegramCreds:
    """Load or collect api credentials for a profile and persist them (with the proxy, if given)."""
    from .telegram import parse_proxy

    try:
        saved: TelegramCreds | None = TelegramCreds.load(profile)
    except TgSyncError:
        saved = None
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


def _login(profile: str, proxy: str | None, api_id: int | None, api_hash: str | None) -> None:
    from .telegram import interactive_login

    check_profile_name(profile)
    creds = _creds_for(profile, proxy, (api_id, api_hash) if api_id and api_hash else None)
    if creds.proxy:
        click.echo(f"Using proxy {creds.proxy}")
    try:
        click.echo("Logged in as " + run(interactive_login(profile, creds)))
    except KeyboardInterrupt:
        raise click.Abort()
    except Exception as e:
        raise click.ClickException(
            f"{type(e).__name__}: {e} (is your proxy running? try --proxy socks5://127.0.0.1:10808)") from e


@main.command()
@click.option("--profile", default=None, help="Profile name (default: the one saved in the vault, else 'default').")
@click.option("--vault", "-C", "vault_dir", type=click.Path(file_okay=False, path_type=Path), default=None,
              help="Look up the profile that this vault folder uses.")
def whoami(profile: str | None, vault_dir: Path | None) -> None:
    """Show which profile / Telegram account you are acting as."""
    from .telegram import connect

    if vault_dir is not None and profile is None:
        profile = _load_cfg(vault_dir).get("profile", "default")
    profile = profile or current_profile()

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
@click.option("--profile", default=None, help="Account profile (default: the current one).")
@click.option("--force", is_flag=True)
def keys_init(profile: str | None, force: bool) -> None:
    """Generate your keypair for a profile."""
    profile = profile or current_profile()
    try:
        ident = init_identity(profile, force)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"Your public key (safe to share):\n  {ident.recipient}")


@keys.command("show")
@click.option("--profile", default=None, help="Account profile (default: the current one).")
def keys_show(profile: str | None) -> None:
    """Print your public key."""
    profile = profile or current_profile()
    try:
        click.echo(load_identity(profile).recipient)
    except TgSyncError as e:
        raise click.ClickException(str(e)) from e



def _choose_profile(explicit: str | None) -> str:
    """Pick the account for create/join: explicit > only one saved > ask > 'default' (new)."""
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
        click.echo(f"  {i}) {name}{'   (current)' if name == cur else ''}")
    click.echo(f"  {len(profiles) + 1}) a new account")
    n = click.prompt("Choose", type=click.IntRange(1, len(profiles) + 1),
                     default=profiles.index(cur) + 1 if cur in profiles else 1)
    if n == len(profiles) + 1:
        return check_profile_name(click.prompt("Name for the new account profile"))
    return profiles[n - 1]


async def _ensure_ready(profile: str, api: tuple[int, str] | None = None, proxy: str | None = None):
    """Make sure the profile has a key, API credentials and a logged-in session. Returns (ident, client)."""
    from .telegram import NotLoggedIn, connect, interactive_login

    try:
        ident = load_identity(profile)
    except TgSyncError:
        ident = init_identity(profile)
        click.echo(f"Created a new key for profile '{profile}'.")
    creds = _creds_for(profile, proxy, api)
    try:
        client = await connect(profile)
    except NotLoggedIn:
        click.echo(f"Logging in to Telegram for profile '{profile}'...")
        click.echo("Logged in as " + await interactive_login(profile, creds))
        client = await connect(profile)
    return ident, client


# ------------------------------------------------------------------ vault
@main.group()
def vault() -> None:
    """Create or join a vault."""


@vault.command("create")
@click.argument("folder", type=click.Path(file_okay=False, path_type=Path))
@click.option("--new-group", "title", help="Create a new private Telegram group with this title.")
@click.option("--chat", help="Use an existing group: invite link, @username or id.")
@click.option("--name", default="", help="Your display name in the member list.")
@click.option("--profile", default=None, help="Account profile (default: the current one).")
@click.option("--no-git", is_flag=True, help="Disable local git history.")
def vault_create(folder: Path, title: str | None, chat: str | None, name: str, profile: str | None,
                 no_git: bool) -> None:
    """Start a new vault in FOLDER."""
    if bool(title) == bool(chat):
        raise click.UsageError("give exactly one of --new-group or --chat")
    profile = _choose_profile(profile)

    async def go():
        from .telegram import TelethonTransport, create_group, peer_id, resolve_chat

        ident, client = await _ensure_ready(profile)
        link = None
        if title:
            entity, link = await create_group(client, title)
        else:
            entity = await resolve_chat(client, chat)
        tr = TelethonTransport(client, entity)
        v = await Vault.create(folder, ident, tr, name or profile, use_git=not no_git)
        cfg = {"chat": peer_id(entity), "profile": profile, "git": not no_git}
        if link:
            cfg["invite"] = link
        _save_cfg(folder, cfg)
        click.echo(f"Vault {v.vault_id} created in {folder}")
        if link:
            code = encode_invite(Invite(link, v.vault_id, fingerprint(v.keys.key(1))))
            click.echo("\nInvite a friend: send them this code (and the install steps in the README):\n")
            click.echo(f"  tgsync join {code}\n")
            click.echo("They will get a short code; when they read it to you: `tgsync members accept <code>`.")
        else:
            click.echo("Run `tgsync invite --link <group link>` to make an invite code.")
        await tr.close()

    _guard(lambda: run(go()))


@vault.command("join")
@click.argument("folder", type=click.Path(file_okay=False, path_type=Path))
@click.option("--chat", required=True, help="Group invite link, @username or id.")
@click.option("--profile", default=None, help="Account profile (default: the current one).")
@click.option("--fingerprint", "fp", help="Expected key fingerprint (from a current member).")
@click.option("--no-git", is_flag=True)
def vault_join(folder: Path, chat: str, profile: str | None, fp: str | None, no_git: bool) -> None:
    """Join an existing vault you were already added to (see also: `tgsync join CODE`)."""
    profile = _choose_profile(profile)

    async def go():
        from .telegram import TelethonTransport, peer_id, resolve_chat

        ident, client = await _ensure_ready(profile)
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



@main.command()
@vault_opt
@click.option("--link", help="Group invite link to put in the code (default: the saved one, else a new one).")
@click.option("--include-api", is_flag=True,
              help="Also put your Telegram api_id/api_hash in the code so friends need not create their own.")
def invite(vault_dir: Path, link: str | None, include_api: bool) -> None:
    """Make an invite code for a friend."""

    async def go():
        from .telegram import export_invite

        cfg = _load_cfg(vault_dir)
        v, tr = await _open(vault_dir)
        await v.pull()
        use = link or cfg.get("invite") or await export_invite(tr.client, tr.entity)
        if cfg.get("invite") != use:
            cfg["invite"] = use
            _save_cfg(vault_dir, cfg)
        api = None
        if include_api:
            c = TelegramCreds.load(cfg.get("profile", "default"))
            api = (c.api_id, c.api_hash)
            click.secho("This code contains your api_id/api_hash: share it only with people you trust.", fg="yellow")
        code = encode_invite(Invite(use, v.vault_id, fingerprint(v.keys.key(1)), api))
        click.echo(f"\n  tgsync join {code}\n")
        click.echo("Send that to your friend. When they run it they get a short code to read back to you;")
        click.echo("you then run `tgsync members accept <code>` (`tgsync members pending` lists waiting people).")
        await tr.close()

    _guard(lambda: run(go()))


@main.command("join")
@click.argument("code")
@click.argument("folder", required=False, type=click.Path(file_okay=False, path_type=Path))
@click.option("--profile", default=None, help="Which of your accounts to use (asked if you have several).")
@click.option("--name", help="Name members will see (default: your profile name).")
@click.option("--proxy", help="Telegram proxy, e.g. socks5://127.0.0.1:10808 (saved).")
@click.option("--wait", default=0, show_default=True,
              help="Seconds to wait for approval (default: ask, then come back later).")
@click.option("--no-git", is_flag=True)
def join_cmd(code: str, folder: Path | None, profile: str | None, name: str | None, proxy: str | None,
             wait: int, no_git: bool) -> None:
    """Join a vault from an invite code (creates your key and logs in if needed)."""

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
                if wait > 0:
                    click.echo("Waiting for approval", nl=False)
                    deadline = time.monotonic() + wait
                    while time.monotonic() < deadline:
                        await asyncio.sleep(15)
                        click.echo(".", nl=False)
                        found = await Vault.discover(tr, ident)
                        if inv.vault_id in found:
                            break
                    click.echo()
            if inv.vault_id not in found:
                click.echo("Not approved yet. Come back any time after they accept you and run this same "
                           "command again; nothing else is needed.")
                return
            if found[inv.vault_id][1].replace(" ", "") != inv.fingerprint.replace(" ", ""):
                raise click.ClickException("KEY FINGERPRINT MISMATCH between the invite and the vault - refusing to join")
            dest = folder or Path(click.prompt("Folder for the vault", default=f"~/vaults/{inv.vault_id[:6]}")).expanduser()
            v = await Vault.join(dest, ident, tr, inv.vault_id, use_git=not no_git)
            _save_cfg(dest, {"chat": peer_id(entity), "profile": profile, "git": not no_git, "invite": inv.link})
            click.echo(f"Joined. Files go in {dest}")
            _print_report(await v.sync())
        finally:
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



@members.command("pending")
@vault_opt
def members_pending(vault_dir: Path) -> None:
    """List people who asked to join, with the code they should read to you."""

    async def go():
        v, tr = await _open(vault_dir)
        reqs = await v.pending_requests()
        if not reqs:
            click.echo("nobody is waiting")
        for r in reqs:
            click.echo(f"{r.code}  {r.name or '(no name)'}")
        if reqs:
            click.echo("\nOnly accept someone whose code they read to you yourself:  "
                       "tgsync members accept <code>")
        await tr.close()

    _guard(lambda: run(go()))


@members.command("accept")
@click.argument("code")
@click.option("--name", help="Name to show in the member list (default: the name they gave).")
@vault_opt
def members_accept(code: str, name: str | None, vault_dir: Path) -> None:
    """Let in the person whose join code is CODE (typing it is the confirmation)."""

    async def go():
        v, tr = await _open(vault_dir)
        want = code.strip().lower()
        hits = [r for r in await v.pending_requests() if r.code == want]
        if not hits:
            raise click.ClickException(f"no pending request with code {code!r} (see `tgsync members pending`)")
        r = hits[0]
        await v.accept_request(r, name)
        click.echo(f"Accepted {name or r.name or r.code}. They can now run `tgsync join` again.")
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



# ---------------------------------------------------------------- profiles
@main.group()
def profile() -> None:
    """Manage your accounts on this machine (most people never need this)."""


@profile.command("list")
def profile_list() -> None:
    cur = current_profile()
    names = list_profiles()
    if not names:
        click.echo("no profiles yet; `tgsync join CODE` or `tgsync profile add NAME` creates one")
    for n in names:
        try:
            pub = load_identity(n).recipient[:14] + "..."
        except TgSyncError:
            pub = "(no key)"
        try:
            c = TelegramCreds.load(n)
            sess = (root_dir() / n / "telegram.session").exists()
            tg = ("logged in" if sess else "not logged in") + (f", proxy {c.proxy}" if c.proxy else "")
        except TgSyncError:
            tg = "no Telegram login"
        click.echo(f"{'*' if n == cur else ' '} {n:12} {pub}  {tg}")


@profile.command("add")
@click.argument("name")
@click.option("--proxy")
@click.option("--api-id", type=int, envvar="TGSYNC_API_ID")
@click.option("--api-hash", envvar="TGSYNC_API_HASH")
def profile_add(name: str, proxy: str | None, api_id: int | None, api_hash: str | None) -> None:
    """Create a profile (key + Telegram login) for another account."""
    check_profile_name(name)
    if name in list_profiles():
        raise click.ClickException(f"profile {name!r} already exists")
    if list_profiles() and proxy is None:  # reuse the proxy of an existing profile as a sensible default
        try:
            proxy = TelegramCreds.load(current_profile()).proxy
        except TgSyncError:
            pass
    ident = init_identity(name)
    click.echo(f"Created key for '{name}': {ident.recipient}")
    _login(name, proxy, api_id, api_hash)


@profile.command("use")
@click.argument("name")
def profile_use(name: str) -> None:
    """Make NAME the profile used when you don't pass --profile and are outside a vault."""
    if name not in list_profiles():
        raise click.ClickException(f"no such profile {name!r}; see `tgsync profile list`")
    set_current_profile(name)
    click.echo(f"current profile: {name}")


@profile.command("current")
def profile_current() -> None:
    click.echo(current_profile())


@profile.command("remove")
@click.argument("name")
def profile_remove(name: str) -> None:
    """Delete a profile's key and Telegram session from this machine."""
    if name not in list_profiles():
        raise click.ClickException(f"no such profile {name!r}")
    click.secho("This deletes your private key. Vaults that only this key can open become unreadable "
                "unless you re-join them.", fg="yellow")
    if not click.confirm(f"Delete profile {name!r}?"):
        raise click.Abort()
    delete_profile(name)
    click.echo("deleted")

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
        raise click.ClickException("this vault has no local history yet (run `tgsync sync` first)")
    if path and rev is None and not (vault / path).exists() and h.is_commit(path):
        path, rev = None, path  # a lone argument that is a snapshot id means "this snapshot"
    if rev is not None and not h.is_commit(rev):
        raise click.ClickException(f"{rev!r} is not a snapshot id; see `tgsync history`")
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
               f"Run `tgsync push` to share it.")


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
