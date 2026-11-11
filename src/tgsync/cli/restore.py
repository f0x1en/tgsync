# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local history: `log` and `restore` (both work offline)."""

from __future__ import annotations

import time
from pathlib import Path

import click

from ..engine import Vault
from ..errors import TgSyncError
from ..history import History
from ..identity import load_identity
from ..paths import INTERNAL_DIR, safe_join
from . import common as c
from .common import main, vault_opt


def _pick(title: str, rows: list[str]) -> int:
    if c.json_mode():
        raise click.ClickException(f"{title} (--json never asks; pass PATH and REV)")
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
    c.emit({"restored": path, "rev": rev},
           lambda: click.echo(f"Restored {path} as of {rev}. Your previous version is saved in history. "
                              f"Run `tgsync` to share it."))


_WORDS = {"put": "wrote", "delete": "deleted", "conflict": "conflict", "mkdir": "made folder",
          "rmdir": "removed folder"}


@main.command()
@click.argument("path", required=False)
@click.option("-n", "limit", default=50, show_default=True, help="How many changes to show.")
@vault_opt
def log(path: str | None, limit: int, vault_dir: Path) -> None:
    """Who changed what and when, newest first (works offline). Give PATH for one file or folder."""
    cfg = c._load_cfg(vault_dir)
    v = Vault(vault_dir, load_identity(cfg.get("profile", "default")), None, use_git=False)  # type: ignore[arg-type]
    rows = v.log(path, limit)
    v.close()

    def text() -> None:
        if not rows:
            click.echo("No changes recorded yet. Changes show up here after the next `tgsync`.")
            return
        for r in rows:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["ts"]))
            what = f"{r['path']} -> {r['copy']}" if r["copy"] else r["path"]
            click.echo(f"{when}  {r['who']:<12} {_WORDS.get(r['op'], r['op']):<14} {what}")
        click.echo("Older version of a file:  tgsync restore <path>")

    c.emit({"log": rows}, text)
