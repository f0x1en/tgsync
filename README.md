# tgsync

A shared, end-to-end encrypted folder (works great as an Obsidian vault) that uses a private
Telegram group as the sync/backup server. Each teammate runs their own copy with their own
Telegram account. Linux, Windows, macOS; a small CLI, no GUI: your editor and file manager are the UI.

> Status: alpha. Crypto, sync and conflict logic are covered by automated tests against an
> in-memory fake of Telegram, and `scripts/live_e2e.py` replays the full two-person story (invite,
> approval, sync, conflict, removal, re-join) on real Telegram with two accounts. Use a throwaway
> group first.

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
  vault before and after each sync; `tgsync restore` brings old versions back.

## Daily use

Open your vault folder in any editor (nvim, VS Code, Obsidian...) and just work. Swap/backup
files from editors are ignored automatically. Nothing moves until you say so:

```bash
cd ~/vaults/team
tgsync            # what changed: yours, and others' that you don't have yet; warns if you both
                  # edited the same file. Touches no files (same as `tgsync status`; `--offline`)
tgsync pull       # download others' changes (publishes nothing)
tgsync push       # upload yours (never touches your local files)
tgsync log        # who changed what and when (works offline); `tgsync log notes/x.md` for one file
tgsync restore    # bring back an older version of a file (it asks which)
```

tgsync never runs in the background: it does something only when you run it. Run plain `tgsync`
before you start editing to see if someone changed the same notes. If two people change the same
note anyway, nothing is lost: after `tgsync push` and `tgsync pull` the later one is kept as
`note (conflict ...).md` next to it. Big files print a heads-up ("downloading ... big files take a while") and appear in your
folder only once they have fully arrived.

## Setup

Install (each person; needs Python 3.10+ and git):
```bash
pipx install git+https://github.com/f0x1en/tgsync      # or: uv tool install git+https://github.com/f0x1en/tgsync
tgsync --version
```
If `tgsync` isn't found afterwards, run `pipx ensurepath` and open a new terminal. Update later with
`pipx upgrade tgsync`. (Developing it? `pip install -e ".[dev]"` in a clone.)

**api_id / api_hash:** one person creates the pair once at https://my.telegram.org -> *API
development tools* and shares it with the team privately (it identifies the *app*, not anyone's
account; don't publish it). The owner can put it into the invite with `tgsync invite --include-api`
so friends never have to touch that website. Behind a firewall? add `--proxy socks5://127.0.0.1:10808`
once (it is saved).

**First person (owner)**
```bash
tgsync new ~/vaults/team
# makes your key, logs you in (phone + code), creates a private group, prints an invite line
```

**Inviting a friend**
1. Owner: `tgsync invite` (or use the line `new` printed) and send the `tgsync join tgsync1-...`
   line to the friend.
2. Friend: run that line. It creates their key, logs them into Telegram, joins the group, sends a
   join request and prints a short code like `f17d-13fd`. They read the code to the owner.
3. Owner: `tgsync accept f17d-13fd` (typing the code you were told is the confirmation;
   `tgsync members` shows who is waiting).
4. Friend: whenever they like, however long it takes, run plain `tgsync join`; the vault
   downloads. Files already in their folder are not uploaded until they run `tgsync push`. (The invite line, account and folder from step 2 are remembered in
   `~/.config/tgsync/remembered.json`, so nothing needs retyping.)

The invite code carries the vault's key fingerprint, so the join is checked automatically.
A join request alone grants nothing: only a member accepting it adds their key.

**Removing someone:** `tgsync remove bob`. The key rotates, so they can't read anything new.
Kicking them from the Telegram group is optional (they only see ciphertext); they keep what they
had already synced. If they later ask to join again and you accept, they get everything.

**Several Telegram accounts on one machine:** vault folders remember their account. If you have
more than one, `new` and `join` ask which to use (or pass `--profile NAME`). Account data lives in
`~/.config/tgsync/<name>/` (delete that folder to forget an account).

## Security model & limits

* Telegram (and anyone in the group without a key) cannot read or forge content. A malicious
  or compromised **member** has the vault key and can read everything and write anything.
* Telegram can delete or withhold messages. Dropped messages in an author's sequence are
  reported as problems; replays are ignored; tampering fails authentication.
* Joining trusts the fingerprint you verify out of band (like Signal safety numbers).
* A removed member keeps what they already synced; they can't read data written after rotation.
* Your age secret key lives in your user config dir (`0600` on Unix; per-user profile ACLs on
  Windows). Protect your disk, and back it up: losing it means losing access.
* Not synced: symlinks, files matching `.tgsyncignore`. Empty folders are synced. A renamed,
  moved or copied file uploads no content again (the group already has it). Everyone should
  update: older versions cannot read such renames and report "content hash mismatch".
* `tgsync log` lists changes from the moment you update; earlier changes are not in it.
* Automating a user account is a grey area under Telegram's ToS; keep traffic modest. The limiter
  caps sends at 18/min with >=1.2 s gaps, spaces downloads, honours FloodWait and slows itself
  down after one. Telegram does not publish exact limits.
* One tgsync command per Telegram account at a time (the session file is single-process); if you
  start two at once the second one says so and you just retry.
* Speed is bounded by Telegram and your network: ~100 MB took ~4 minutes each way through a proxy.

## Development

```bash
uv venv && uv pip install -e ".[dev]"      # test/lint environment
make check                                 # ruff + mypy + pytest
pipx install --editable .                  # optional: a global `tgsync` that follows your edits
```
Try it offline with two people, no Telegram: `export TGSYNC_SANDBOX=~/tgs TGSYNC_PROFILE=alice`
(and `bob` in a second terminal). Code map, sandbox walkthrough, `--json` output for scripts and
plugins: see [HACKING.md](HACKING.md).

## License

Copyright (C) 2026 tgsync contributors. Licensed under the **GNU Affero General Public License
v3.0 or later** (see `LICENSE`). If you modify tgsync and run it for others as a service, you
must offer them your modified source.
