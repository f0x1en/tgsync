# tgsync

A shared, end-to-end encrypted folder (works great as an Obsidian vault) that uses a private
Telegram group as the sync/backup server. Each teammate runs their own copy with their own
Telegram account. Linux, Windows, macOS; a small CLI, no GUI: your editor and file manager are the UI.

> Status: alpha. Crypto, sync and conflict logic are covered by automated tests against an
> in-memory fake of Telegram. The real transport has been exercised by hand against live
> Telegram on one account (create, push, join, 100 MB multi-chunk file, `watch`). Multi-person
> conflict handling over real Telegram is not yet field-tested. Use a throwaway group first.

## How it works

* Your vault is just a folder. Open it in Obsidian (or anything).
* Everything sent to Telegram is AES-256-GCM ciphertext: file contents, file names, and the
  member list. Telegram sees only opaque `x.bin` documents, plus their (ciphertext) sizes and timing.
* One random vault key; each member gets it wrapped to their own **age** (X25519) public key.
  No passphrase to share. Removing a member rotates to a new key epoch.
* The group chat is an append-only, ordered operation log. Every client replays it
  identically, so concurrent edits yield identical results everywhere: the later writer's
  version becomes `note (conflict ab12cd 2026-11-04 1030).md`. Edits beat deletes. Nothing is
  silently lost.
* Many small notes are batched into one Telegram message (Telegram limits ~20 msgs/min);
  big files are split into sealed 32 MiB chunks.
* A local git repo (`.tgsync/history.git`, separate from any `.git` of yours) snapshots the
  vault before and after each sync: `tgsync history`, `tgsync restore`.

## Daily use (works like git: nothing runs unless you type a command)

Open your vault folder in any editor (nvim, VS Code, Obsidian...) and just work. Swap/backup
files from editors are ignored automatically. When you want to share or fetch:

```bash
cd ~/vaults/team
tgsync status      # what changed locally (works offline)
tgsync pull        # download teammates' changes (uploads nothing)
tgsync push        # upload your changes (never touches your files)
tgsync sync        # both, in one go
tgsync history     # local git history of the vault; `tgsync restore <path> <rev>` to undo
tgsync doctor      # check proxy, login, group access, vault health
```

No background process exists unless you start `tgsync watch` yourself. Commands act on the
current folder (or `-C <folder>`). If two people change the same note, nothing is lost: the
later one is kept as `note (conflict ...).md` next to it.

## Setup

Install (each person; needs Python 3.10+ and git):
```bash
pipx install git+https://github.com/f0x1en/tgsync      # or: uv tool install git+https://github.com/f0x1en/tgsync
tgsync --version
```
Update later with `pipx upgrade tgsync`. (Developing it? `pip install -e ".[dev]"` in a clone.)

**api_id / api_hash:** one person creates the pair once at https://my.telegram.org -> *API
development tools* and shares it with the team privately (it identifies the *app*, not anyone's
account; don't publish it). The owner can put it into the invite with `tgsync invite --include-api`
so friends never have to touch that website. Behind a firewall? add `--proxy socks5://127.0.0.1:10808`
once (it is saved).

**First person (owner)**
```bash
tgsync vault create ~/vaults/team --new-group "team vault"
# creates your key, logs you in (phone + code), makes the group, prints an invite code
```

**Inviting a friend**
1. Owner: `tgsync invite` -> send the printed `tgsync join tgsync1-...` line to the friend.
2. Friend: run that line. It creates their key, logs them into Telegram, joins the group, sends a
   join request and prints a short code like `f17d-13fd`. They read the code to the owner.
3. Owner: `tgsync members accept f17d-13fd` (typing the code you were told is the confirmation;
   `tgsync members pending` lists who is waiting).
4. Friend: whenever they like, however long it takes, run the same `tgsync join ...` line again;
   the vault downloads.

The invite code carries the vault's key fingerprint, so the join is checked automatically.
A join request alone grants nothing: only an owner/member approving it adds their key.

**Removing someone:** `tgsync members remove bob`. The key rotates, so they can't read anything
new. Kicking them from the Telegram group is optional (they only see ciphertext); they keep what
they had already synced. If they later ask to join again and you accept, they get everything.

**Several Telegram accounts on one machine** (for testing, or a separate work account): vault
folders remember their account, so you rarely type anything. When you create or join and have
more than one, you're asked which to use.
```bash
tgsync profile add work      # new key + Telegram login
tgsync profile list          # who is who  (* = current)
tgsync profile use work      # default account outside a vault folder
tgsync whoami -C ~/vaults/team
tgsync profile remove work   # deletes that key from this machine
```

## Security model & limits

* Telegram (and anyone in the group without a key) cannot read or forge content. A malicious
  or compromised **member** has the vault key and can read everything and write anything.
* Telegram can delete or withhold messages. Dropped messages in an author's sequence are
  reported as problems; replays are ignored; tampering fails authentication.
* Joining trusts the fingerprint you verify out of band (like Signal safety numbers).
* A removed member keeps what they already synced; they can't read data written after rotation.
* Your age secret key lives in your user config dir (`0600` on Unix; per-user profile ACLs on
  Windows). Protect your disk, and back it up: losing it means losing access.
* Not synced: empty folders, symlinks, files matching `.tgsyncignore`. Renames re-upload
  content (no cross-file dedupe yet).
* Automating a user account is a grey area under Telegram's ToS; keep traffic modest. The limiter
  caps sends at 18/min with >=1.2 s gaps, spaces downloads, honours FloodWait and slows itself
  down after one. Telegram does not publish exact limits.
* One tgsync process per Telegram account at a time (the session file is single-process). Use
  `tgsync watch` and leave it running instead of also running `sync` by hand.
* Speed is bounded by Telegram and your network: ~100 MB took ~4 minutes each way through a proxy.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
pytest && ruff check src tests && mypy src
```

## License

Copyright (C) 2026 tgsync contributors. Licensed under the **GNU Affero General Public License
v3.0 or later** (see `LICENSE`). If you modify tgsync and run it for others as a service, you
must offer them your modified source.
