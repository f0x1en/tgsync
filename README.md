# tgsync

A shared, end-to-end encrypted folder (works great as an Obsidian vault) that uses a private
Telegram group as a dumb, untrusted server. Each teammate runs their own copy with their own
Telegram account. Notes that two people edit at the same time merge (CRDT); everything else keeps
both versions. An Obsidian plugin that syncs by itself (desktop for now), and a small CLI.

> Status: alpha. The engine is being rewritten in Rust (branch `rust-core`); the Node CLI already
> runs on it, and the two-account test on real Telegram passes with it. Use a throwaway group first.

## Design in one picture

```
 your folder ──► host (Node CLI / Obsidian plugin) ──► Rust core (WebAssembly, sans-IO) ──► sealed messages
                 lists files, moves bytes,              all decisions: crypto, replay,         in one private
                 talks to Telegram                      merging, membership, push/pull plans   Telegram group
```

* **The group is an append-only log.** Every message is ciphertext (AES-256-GCM): file contents,
  file names, the member list. Telegram sees only `x.bin` documents, their sizes and their timing.
* **Every client replays the same log the same way**, so all reach the same files without a server
  deciding anything (PROTOCOL.md section 9). An edit beats a concurrent delete; nothing is lost
  silently.
* **Notes merge.** A `.md` edit travels as a [Loro](https://loro.dev) CRDT update (about 130 bytes for
  a one-line change in a 31 KB note); two people editing one note get one merged note. Other files
  that both changed keep both versions (`file (conflict ab12cd 2026-11-04 1030).ext`).
* **Members and admins.** The vault key is wrapped to each member's age (X25519) key. Only admins
  (Ed25519 signers) change who is in; removing someone rotates the key. Every record is signed by
  its author, and a record only counts if its author was a member, using the newest key, at that
  point in the log: a removed member can neither read nor write anything new.
* **The core is sans-IO**: no network, files, clock or randomness inside. That makes it testable
  as a pure function of the log, and lets one engine run in Node, in Obsidian, and in the simulator.

**See it** (offline, a folder plays the group): `scripts/demo.sh` runs alice and bob editing one
note at the same time:
```
# Plan                      alice: "buy milk" -> "buy oat milk"
- buy oat milk              bob:   adds "book flights"
- call mom                  after push/pull: one note, the same for both, no conflict copy
- book flights
```

## How it is tested

* **Deterministic simulation** (`make sim`): 2-6 clients share one fake group; a seed picks every
  action and fault: Telegram showing new messages late, refusing uploads (flood wait), delivering
  one twice; clients crashing between posting and saving, restarting from saved state; junk and
  bit-flipped messages; exact re-posts of old messages; members posting malformed or forged
  records; the admin removing and re-adding members (key rotation) while others keep writing; every
  fifth seed is an old (v1) vault run in compatibility mode. After the clients settle it checks that every replica holds the same
  tree and notes, every folder equals its tree, every upload a member marked as done survived (or was
  knowingly replaced), every note edit is merged into its document, and (secrecy) every applied record
  was sealed with the newest key and signed by its author, a member at that point. 10 000 seeds x 200 steps pass; a
  failing seed prints its trace and replays exactly. Each check was confirmed to catch the bug it
  guards against by breaking the code on purpose.
* Bugs the simulator found and that are fixed: a junk message naming an unknown key epoch froze
  every client for good; anyone in the group could make a member believe they were removed; a
  removed member could keep writing with the old key, and teammates who had not seen the key change
  kept writing data the removed member could read; such rejected writes are now re-sent with the new key;
  a member who re-joined could reuse a record number, and readers then dropped those edits; anyone
  could re-post an old membership message and so undo later adds (dropping members) or leave someone
  removed and added back stuck with old keys.
* Fixed test vectors (`spec/vectors.json`, from the original Python version) checked by the TypeScript and Rust code; unit
  tests for the core; the Node CLI's tests; two-process sandbox tests through `--json`; a live
  two-account test on real Telegram (`make live`); CI on Linux, Windows and macOS, plus
  a WebAssembly build smoke test.

Measured on one laptop core (`cargo run --release -p tgsync-sim --bin bench`): sealing/opening
32 MiB chunks 924/1247 MB/s; replaying 2000 signed records (50 000 files) 0.33 s; saving/loading
that state 224/192 ms; a note edit costs 2.2 ms to prepare and 0.2 ms to apply; joining after 200
add/remove cycles (402 membership messages) 0.09 s. End to end through
the Node CLI on a sandbox group (`cd ts && npm run bench`), a 1 GB file uploads at 83 MB/s and downloads
at 151 MB/s with flat memory (316 MB peak). A vault of 20 000 notes: first push 8 s, first pull
5 s, then one edited note 1.2 s to push and 1.0 s to pull (`npm run bench-notes`). Real transfer speed is
bounded by Telegram.

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
before you start editing to see if someone changed the same files. If two people change the same
note anyway, nothing is lost: after `tgsync push` and `tgsync pull` the edits are merged into one
note. Other files keep both versions: the later one as `file (conflict ...).ext` next to it. Big
files print a heads-up ("downloading ... big files take a while") and appear in your folder only
once they have fully arrived. If Telegram cannot be reached for 60 seconds (network or proxy down),
the command stops and says so; nothing is lost, and running it again later finishes the job (a big
upload continues with the parts it had already sent). One tgsync runs in a folder at a time: a second
one (say the Obsidian plugin while you push in a terminal) waits for the first to finish.

## Setup

Install (each person; needs Node 20+): tgsync is one file, `tgsync.mjs`, with the Rust core inside.
Get it from the latest CI run (`gh run download -n tgsync-cli`), or build it (see Development), then:
```bash
install -m 755 tgsync.mjs ~/.local/bin/tgsync    # any folder on your PATH
tgsync --version
```
Profiles from the old Python version (`~/.config/tgsync/<name>/`) keep working; log in once again with
`tgsync login`. Vaults made by the old version keep working too, in compatibility mode (no merging, no
admins); for the new features start a new vault.

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
3. Owner (or any admin): `tgsync accept f17d-13fd` (typing the code you were told is the
   confirmation; `tgsync members` shows who is waiting). The vault's creator is its first admin.
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

* Telegram (and anyone in the group without a key) cannot read or forge content. A malicious or
  compromised **member** has the vault key and can read everything and write anything until removed;
  records are signed, so `tgsync log` shows who wrote what.
* Only admins can add or remove members (descriptors are signed; PROTOCOL.md section 11). In vaults
  made by older versions (v1) any member can, as before. Anyone who can post in the group can still
  post junk; it is skipped and reported.
* Telegram can delete or withhold messages. Dropped messages in an author's sequence are reported;
  replays are ignored; tampering fails authentication.
* Joining trusts the fingerprint in the invite, which you got from a member out of band (like Signal
  safety numbers).
* A removed member keeps what they already synced; they cannot read data written after the key
  rotation, and their new records are rejected.
* Your age secret key and Ed25519 signing key live in your user config dir (`0600` on Unix; per-user
  profile ACLs on Windows). Protect your disk, and back them up: losing them means losing access.
* Not synced: symlinks, files matching `.tgsyncignore`. Empty folders are synced. A renamed,
  moved or copied file uploads no content again (the group already has it).
* Vaults made by older versions (protocol v1) keep working with the new CLI in a compatible mode
  (no merging, no admins) so old and new clients can share them (PROTOCOL.md section 14).
* Automating a user account is a grey area under Telegram's ToS; keep traffic modest. The limiter
  caps sends at 18/min with >=1.2 s gaps, spaces downloads, honours FloodWait and slows itself
  down after one. Telegram does not publish exact limits.
  Each flood wait doubles the account's slow-down (sends, downloads and how often Obsidian looks
  for changes); every calm 10 minutes halve it again, back to the set speed. It is kept in
  `<profile>/pace.json`.
* One tgsync command per Telegram account at a time (the session file is single-process); if you
  start two at once the second one says so and you just retry.
* Speed is bounded by Telegram and your network: ~100 MB took ~4 minutes each way through a proxy.

## Development

`make check` runs everything CI runs except the long simulation (needs Rust and Node).

Try the new CLI without building anything: every CI run on branch `rust-core` uploads `tgsync-cli`
(one file, the core embedded; needs Node 20+) and `tgsync-obsidian` (the plugin's `main.js` +
`manifest.json`): `gh run download -n tgsync-cli` then `node tgsync.mjs --help`.

The Rust core and the Node CLI on it (branch `rust-core`):
```bash
make rust                                  # core tests, test vectors, a short simulation
make sim                                   # 10 000 simulated seeds (a few minutes)
make wasm                                  # core -> WebAssembly (or fetches CI's build without the wasm32 target)
cd ts && npm install && npm run build      # Node CLI: node ts/dist/tgsync.mjs
cd obsidian && npm install && npm run build   # Obsidian plugin (desktop, engine inside): copy main.js + manifest.json
```
Try it offline with two people, no Telegram: `export TGSYNC_SANDBOX=~/tgs TGSYNC_PROFILE=alice`
(and `bob` in a second terminal). Code map, sandbox walkthrough, `--json` output for scripts and
plugins: see [HACKING.md](HACKING.md).

## License

Copyright (C) 2026 tgsync contributors. Licensed under the **GNU Affero General Public License
v3.0 or later** (see `LICENSE`). If you modify tgsync and run it for others as a service, you
must offer them your modified source.
