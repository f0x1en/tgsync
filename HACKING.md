# Hacking on tgsync

## Setup and checks

```bash
npm install         # once; plus Rust (cargo)
make check          # Rust core tests, WebAssembly build (or CI's), host + plugin tests, main.js
make install VAULT=~/v   # build and copy the plugin into a vault
npm run dev         # rebuild main.js on every change
make sim            # 10 000 simulated seeds
make live           # two-person test on REAL Telegram (accounts `default` and `b`); KEEP=1 keeps folders
```

## Try it by hand without Telegram (sandbox)

A folder on disk plays the Telegram group. No accounts, no login, no network. Your real keys and
accounts are never touched (sandbox ones live in `$TGSYNC_SANDBOX/config`). Start Obsidian with
`TGSYNC_SANDBOX=~/tgs obsidian`, open two empty vaults, give them the Accounts `alice` and `bob`
(Settings → tgsync → Advanced), Start in one, Copy invite, Join in the other. Delete `~/tgs` to
start over. The plugin's tests (`test/plugin.test.ts`) do exactly this.

## Protocol

`PROTOCOL.md` describes every message format and the replay rules; `spec/vectors.json` has fixed examples
(written by the original Python version; fixed now).
The Rust core passes them too, plus `spec/vectors_v2.json` (protocol v2), natively and as WebAssembly.

**The host** (`host/src/`): `host/src/vault.ts` lists the folder, moves bytes and talks to the group around the
WebAssembly `Engine` (`host/src/core.ts` loads `core/pkg-web`, built by `make wasm`). Telegram goes through mtcute
(pinned exact version, `host/src/node/telegram.ts`); the login is a session string in `<profile>/mtcute.session`.
How fast an account may go is its Pace (`host/src/node/pace.ts`, `<profile>/pace.json`): each flood wait doubles a
slow-down factor, each calm 10 minutes halve it, down to 1; sends, downloads and the plugin's look interval follow it.
Profiles and age keys live in `~/.config/tgsync/<profile>/`; the Ed25519 signing key is `<profile>/signing.key` (made on first use). `<profile>/seqs/<vault id>` keeps the last record
seq posted in that vault, so a re-joined (fresh) folder never reuses one (one file per vault: runs in two
vaults never write the same file; the older `seqs.json` is still read).
Local state: `.tgsync/engine.json` (the engine's saved state; no keys) and `.tgsync/local.json` (stat cache, log,
note versions, problems). `.tgsync/lock` (the running process's id) lets one sync run at a time per
folder (two Obsidian windows on one vault); a lock left by a process that is gone is taken over.
`.tgsync/config.json` `chat` is the group's invite link (the group is found by it). Old versions of a file come
back from the group (notes: from the merged history); a version id is like `812.0` (record message, entry).

**The plugin** (`src/`, `make plugin`) runs the engine itself through `host/src/node/host.ts` (one
Telegram connection; the vault opened under the folder lock for each sync) and syncs automatically.
Setup (log in, start, join, invite, let in, members) is `src/setup.ts` over `host/src/node/setup.ts`;
the windows are `src/ui.ts`. Releases: push a tag equal to `manifest.json`'s version (bump `versions.json` too); `.github/workflows/release.yml` builds and publishes `main.js` + `manifest.json` (what BRAT installs). Releases carry no Telegram API key: each person makes their own. The shared Telegram API key is built in from `TGSYNC_API_ID`/`TGSYNC_API_HASH` at build time
and never committed: a build without them asks users for their own key (Advanced settings).

Big-file benchmark (sandbox, no network): `npm run bench -- 1024 ~/.cache`. Measured 2026-11-23 on this
machine with the Rust core (chunks sealed with the platform's AES-GCM): 1 GB push 83 MB/s, pull 151 MB/s, peak
memory 316 MB (memory stays flat: files stream in chunks). With AES inside WebAssembly it was 24 / 28 MB/s; the old
TypeScript engine (2026-11-11) did 55 / 126 MB/s.

Many notes (`npm run bench-notes -- 5000`, sandbox, notes written an hour earlier): 5000 notes, first push
4.3 s, first pull 1.5 s; then one edited note: push 0.44 s, pull 0.28 s; a push with nothing to send 0.21 s.
20 000 notes: 8.0 s / 5.1 s, one edit 1.2 s / 1.0 s. (Files changed within the last 2 s are always hashed again,
so a benchmark on freshly written files measures hashing.) Real Telegram speed is limited by Telegram, not by this. Change the protocol only together with both.

## Rust core (`core/`)

The rewrite: one Rust engine, compiled to WebAssembly for the Obsidian plugin. It is
**sans-IO**: no network, no files, no clock, no randomness inside. The host lists the folder, talks to
Telegram and passes in nonces, keys and timestamps; the core decides everything else.

```bash
make rust           # cargo test: spec/vectors.json, replica, members, sync plans, simulator smoke run
make sim            # 10000 seeds of the deterministic simulator (release build, a few minutes)
make sim SEEDS=500  # quicker
cd core && cargo run --release -p tgsync-sim -- --start 1234 --seeds 1   # replay one seed with its trace
```

| Crate / file | What it does |
|---|---|
| `tgsync-core/src/crypto.rs` | Seal/open, subkeys, key ring, fingerprints, member ids (PROTOCOL.md 2-3) |
| `descriptor.rs` | Descriptors v1 and v2 (admins, Ed25519), `accept`, `inspect` (membership history) |
| `members.rs` | Create a vault, add/remove members (key rotation), give/drop admin |
| `oplog.rs` | Records v1/v2 (signed), chunks |
| `tree.rs` | Deterministic replay of entries into the file tree, conflict copies |
| `text.rs` | Notes merged with the Loro CRDT (PROTOCOL.md 13) |
| `replica.rs` | One client's view: feeds messages in order, record checks (PROTOCOL.md 12), save/load |
| `sync.rs` | `plan_push` / `plan_materialize`: what to upload, what to write |
| `vault.rs` | Per-folder state between runs (replica, synced map, re-send queue, last seq) |
| `tgsync-sim` | N clients, one fake group, random edits and faults; checks convergence and that nothing is lost |
| `spec/vectors_v2.json` | A fixed v2 log (admins, signed records, merged notes, rejected messages) and the expected state; `tests/vectors_v2.rs` replays it |
| `tgsync-wasm` | JS API (`Engine`, `createVault`, invites); boundary is JSON + byte arrays; CI builds it for wasm32 |

**Simulator faults:** Telegram shows the newest messages late, refuses uploads (flood wait), delivers an
upload twice; a client crashes after posting but before marking files synced; clients restart (state
saved and loaded); the admin removes and re-adds members (key rotation) while others keep writing.
**Checks after settling:** every replica has the same tree and notes; every folder equals its tree;
every upload a member marked as done is in the tree or was knowingly replaced; every note edit is merged
into its document. A failing seed prints its whole trace and replays exactly.

**Does it catch bugs?** Each of these deliberate bugs in the core made the simulator fail within the
first two seeds (2026-11-23): a put that ignores its `base` ("edit lost"), conflict copies that all get
the same name (replicas differ), "edit beats delete" turned off ("edit lost"), re-sending of records
rejected for an old key turned off ("upload lost"), migrating no synced map or no seq after a re-join
(found real bugs before they were fixed). It also checks secrecy in v2 vaults: every applied record
is sealed with the newest key at its place in the log and signed by its author, a member there; turning
off the old-key rule or the membership rule each fails within two seeds (members also post forged records).



## Code map (`host/`, the host around the core)

| File | What it does |
|---|---|
| `src/vault.ts` | `Vault`: open/create/join, pull (feed the group's messages to the engine), push (scan the folder, upload big files, post records), materialize (write what the engine plans), status, log, restore, members. No printing, no prompts. |
| `src/core.ts` | Loads the WebAssembly core (`core/pkg-web`). |
| `src/node/telegram.ts` | Telegram transport (mtcute), login, rate limiting; `src/node/pace.ts` the learned pace. `src/node/sandbox.ts`: folder-on-disk transport. |
| `src/node/setup.ts`, `host.ts` | Start / join / invite for a folder; a vault kept open by the plugin. |
| `src/node/home.ts`, `files.ts` | Profiles (age key, signing key, Telegram login), join requests in progress; the folder as `Files`. |
| `src/protocol.ts`, `crypto.ts`, `paths.ts` | Invite codes and chunk sealing (platform AES-GCM), path rules, ignore rules. |
| `test/*.test.ts` | Vault behaviour with two people on an in-memory group, WebAssembly vs native vectors, the pace. |

## How pull / push / status flow

`pull`: `Vault.pullChanges()` -> `pull()` (each new message: `engine.wantsBody` -> fetch -> `engine.feed`; then
`finishPull`) -> `materialize()` (scan the folder, `engine.planMaterialize`, write/delete, `engine.materialized`).
`push`: `pull()` -> scan -> upload big files as chunks -> `engine.planPush` / `sealRecord` / post / `pushed`, as many
records as needed -> `pull()`. `status`: `fetchChanges()` -> `status()` + `incoming()`.

## Where to change what

- New setting or window: `src/ui.ts`; what it does: `src/setup.ts` (no windows there, so tests can drive it).
- New transport (another backend): implement the four `Transport` methods (`src/transport.ts`).
- Sync, merge, membership rules: the Rust core (`core/`), then `make sim` and `make rust`.

## Tests

| Where | Covers |
|---|---|
| `core/` (`make rust`, `make sim`) | Vectors, replay, membership, signed records, notes, plans; the deterministic simulator |
| `host/test/` (`npm test`) | The host with two people, WebAssembly conformance, the pace |
| `test/` (`npm test`) | Two plugins (stub `obsidian` module) sharing a sandbox group: setup, sync, conflicts, versions, members |
| `host/scripts/live.ts` (`make live`) | Start, join, let in, sync, remove on real Telegram (not in CI) |

## Known limits (not fixed yet)

- Each note keeps its newest 256 versions locally (to diff from, and for older versions); older ones are
  dropped from `.tgsync/engine.json`. A writer more than 256 versions behind gets a conflict copy instead of a merge.
- A record whose post failed after sealing keeps its seq (so a post that did go through is never doubled);
  readers then note a harmless "gap in ... history".
- Join short codes are 32 bits: they tell people apart by eye, they are not a secret. Two requests for one
  key with different signing keys are refused (one of them is not theirs).
- Every membership change carries all vault keys so far (wrapped for each member), so late joiners can
  read the whole history. Descriptors grow with each removal (one new key each), and joining replays
  them all: quadratic in removals. Measured: joining after 200 add/remove cycles takes 0.09 s.
- Unchanged files are not re-hashed: a file whose size and modification time match the last scan (taken
  more than a moment after that mtime) counts as unchanged. A tool that rewrites a file and then sets its
  old mtime back hides the edit; editors and sync tools do not do this. Edits within the same moment are
  detected (the file is hashed again).
- The Obsidian plugin is desktop only (it uses Node's files and network); phones need Obsidian's file API and mtcute's web build.

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
the host on a sandbox group (`npm run bench`), a 1 GB file uploads at 83 MB/s and downloads
at 151 MB/s with flat memory (316 MB peak). A vault of 20 000 notes: first push 8 s, first pull
5 s, then one edited note 1.2 s to push and 1.0 s to pull (`npm run bench-notes`). Real transfer speed is
bounded by Telegram.
