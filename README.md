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

## Setup (each person)

```bash
git clone https://github.com/f0x1en/tgsync && cd tgsync
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .                                         # or: uv pip install -e .
tgsync keys init              # prints your public key
tgsync login                  # needs an api_id/api_hash pair (see below)
# behind a firewall? add --proxy socks5://127.0.0.1:10808 (saved; used by every later command)
```

**First person**
```bash
tgsync vault create ~/vaults/team --new-group "team vault" --name alice
# prints a group invite link and the key fingerprint
tgsync members add age1... --name bob      # bob's public key
```
**Everyone else** (send your `tgsync keys show` output to a member first):
```bash
tgsync vault join ~/vaults/team --chat https://t.me/+xxxx
# compare the fingerprint with alice's over a channel you trust (call, Signal, in person)
tgsync watch -C ~/vaults/team       # or just `tgsync sync` when you want
```

**api_id / api_hash:** one person creates the pair once at https://my.telegram.org -> *API
development tools* and shares it with the team privately. It identifies the *app*, not anyone's
account, so everyone can log in with the same pair and skip that website (and its aggressive
"too many attempts" limits): `tgsync login --api-id 123 --api-hash abc...` (or set
`TGSYNC_API_ID` / `TGSYNC_API_HASH`). Don't publish it. Telegram can rate-limit an app id that
is abused, which would affect everyone using it.

Remove someone: `tgsync members remove bob`. The key rotates, so they can't read anything new.
Kicking them from the Telegram group is optional (they only see ciphertext); they keep whatever
they had already synced.

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
