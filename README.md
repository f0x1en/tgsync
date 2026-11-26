# tgsync

A shared, end-to-end encrypted Obsidian vault that uses a private Telegram group as a dumb,
untrusted server: a replacement for Obsidian Sync. Each person uses their own Telegram account.
Notes that two people edit at the same time merge (CRDT); everything else keeps both versions. The
Obsidian plugin (desktop for now) syncs by itself; everything is set up inside Obsidian.

> Status: alpha. Use a throwaway vault first.

## Design in one picture

```
 your vault ──► host (Obsidian plugin)     ──► Rust core (WebAssembly, sans-IO) ──► sealed messages
                lists files, moves bytes,      all decisions: crypto, replay,         in one private
                talks to Telegram              merging, membership, push/pull plans   Telegram group
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
  tests for the core; the host's tests on an in-memory group; the plugin's tests (two people, each
  with the plugin, on a sandbox group); a live two-account test on real Telegram (`make live`); CI
  on Linux, Windows and macOS, plus a WebAssembly build smoke test.

Measured on one laptop core (`cargo run --release -p tgsync-sim --bin bench`): sealing/opening
32 MiB chunks 924/1247 MB/s; replaying 2000 signed records (50 000 files) 0.33 s; saving/loading
that state 224/192 ms; a note edit costs 2.2 ms to prepare and 0.2 ms to apply; joining after 200
add/remove cycles (402 membership messages) 0.09 s. End to end through
the host on a sandbox group (`cd ts && npm run bench`), a 1 GB file uploads at 83 MB/s and downloads
at 151 MB/s with flat memory (316 MB peak). A vault of 20 000 notes: first push 8 s, first pull
5 s, then one edited note 1.2 s to push and 1.0 s to pull (`npm run bench-notes`). Real transfer speed is
bounded by Telegram.

## Daily use

Work in Obsidian as usual. tgsync uploads your changes a few seconds after you stop typing and
looks for others' changes every 10 seconds (Settings → tgsync → "Look for changes every"), and
when you come back to Obsidian. The status bar shows the state; click it to sync now.

If two people change the same note, nothing is lost: the edits are merged into one note. Other
files keep both versions: the later one as `file (conflict ...).ext` next to it, and tgsync says
so. **Older versions:** command palette → "tgsync: Older versions of this file" lists the uploaded
versions (when, who); Restore puts one back (the current one stays in the history).

If Telegram cannot be reached, the status bar says "Offline" and the next sync finishes the job
(a big upload continues with the parts it had already sent). If Telegram asks tgsync to slow down,
it does so by itself and comes back to your setting once Telegram is calm.

## Setup

Install the plugin (each person): copy `main.js` and `manifest.json` (from a CI run's
`tgsync-obsidian` artifact, or built, see Development) into `<vault>/.obsidian/plugins/tgsync/`,
then turn tgsync on under Settings → Community plugins.

Then, in Settings → tgsync:

1. **Log in to Telegram** with your phone number and the code Telegram sends you.
2. **Owner:** Start (makes a private Telegram group for the vault and uploads it, encrypted), then
   Copy invite and send it to your friend (or to yourself, for another device).
3. **Friend:** paste the invite under "Join a vault" and click Join. Their tgsync asks to join and
   shows a short code like `f17d-13fd`.
4. **Owner:** a window "NAME (f17d-13fd) asks to join" opens by itself within seconds. Let in, or
   Refuse. "Not now" keeps it waiting in the status bar. Two people with the same name? Ask which
   code they see.
5. **Friend:** nothing to do; the vault joins by itself and downloads.

The invite carries the vault's key fingerprint, so the join is checked automatically. A join
request alone grants nothing: only an admin letting someone in adds their key.

**Members** (Settings → tgsync): every name with its code. Admins can make others admin, remove
someone, or stop being one. Removing changes the vault key, so they can't read anything new; they
keep what they had already synced.

**API key:** builds made with `TGSYNC_API_ID`/`TGSYNC_API_HASH` carry a shared Telegram API key.
Otherwise (or to use your own) create one at https://my.telegram.org → *API development tools* and
enter it under Advanced. Behind a firewall? set a Proxy there (for example `socks5://127.0.0.1:10808`).

**Several Telegram accounts on one machine** (say two vault windows): give each vault its own
Account name under Advanced before logging in. Account data lives in `~/.config/tgsync/<name>/`
(delete that folder to forget an account).

## Security model & limits

* Telegram (and anyone in the group without a key) cannot read or forge content. A malicious or
  compromised **member** has the vault key and can read everything and write anything until removed;
  records are signed, so the history shows who wrote what.
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
* Vaults made by older versions (protocol v1) keep working in a compatible mode (no merging, no
  admins) (PROTOCOL.md section 14).
* Automating a user account is a grey area under Telegram's ToS; keep traffic modest. The limiter
  caps sends at 18/min with >=1.2 s gaps, spaces downloads, honours FloodWait and slows itself
  down after one. Telegram does not publish exact limits.
  Each flood wait doubles the account's slow-down (sends, downloads and how often Obsidian looks
  for changes); every calm 10 minutes halve it again, back to the set speed. It is kept in
  `<profile>/pace.json`.
* Speed is bounded by Telegram and your network: ~100 MB took ~4 minutes each way through a proxy.

## Development

`make check` runs everything CI runs except the long simulation (needs Rust and Node). Every CI run
uploads `tgsync-obsidian` (the plugin's `main.js` + `manifest.json`).

```bash
make rust                                  # core tests, test vectors, a short simulation
make sim                                   # 10 000 simulated seeds (a few minutes)
make wasm                                  # core -> WebAssembly (or fetches CI's build without the wasm32 target)
cd ts && npm install && npm test           # the host (vault, Telegram, setup)
cd obsidian && npm install && npm run build   # the plugin: copy main.js + manifest.json
make live                                  # two accounts (default, b) on real Telegram
```
Code map: see [HACKING.md](HACKING.md).

## License

Copyright (C) 2026 tgsync contributors. Licensed under the **GNU Affero General Public License
v3.0 or later** (see `LICENSE`). If you modify tgsync and run it for others as a service, you
must offer them your modified source.
