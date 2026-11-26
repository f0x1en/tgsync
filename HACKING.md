# Hacking on tgsync

## Setup and checks

```bash
(cd ts && npm install); (cd obsidian && npm install)   # once; plus Rust (cargo)
make check          # Rust core tests, WebAssembly build (or CI's), host tests, plugin tests
make sim            # 10 000 simulated seeds
make live           # two-person test on REAL Telegram (accounts `default` and `b`); KEEP=1 keeps folders
```

## Try it by hand without Telegram (sandbox)

A folder on disk plays the Telegram group. No accounts, no login, no network. Your real keys and
accounts are never touched (sandbox ones live in `$TGSYNC_SANDBOX/config`). Start Obsidian with
`TGSYNC_SANDBOX=~/tgs obsidian`, open two empty vaults, give them the Accounts `alice` and `bob`
(Settings → tgsync → Advanced), Start in one, Copy invite, Join in the other. Delete `~/tgs` to
start over. The plugin's tests (`obsidian/test/plugin.test.ts`) do exactly this.

## Protocol

`PROTOCOL.md` describes every message format and the replay rules; `spec/vectors.json` has fixed examples
(written by the original Python version; fixed now).
The Rust core passes them too, plus `spec/vectors_v2.json` (protocol v2), natively and as WebAssembly.

**The host** (`ts/src/`): `ts/src/vault.ts` lists the folder, moves bytes and talks to the group around the
WebAssembly `Engine` (`ts/src/core.ts` loads `core/pkg-web`, built by `make wasm`). Telegram goes through mtcute
(pinned exact version, `ts/src/node/telegram.ts`); the login is a session string in `<profile>/mtcute.session`.
How fast an account may go is its Pace (`ts/src/node/pace.ts`, `<profile>/pace.json`): each flood wait doubles a
slow-down factor, each calm 10 minutes halve it, down to 1; sends, downloads and the plugin's look interval follow it.
Profiles and age keys live in `~/.config/tgsync/<profile>/`; the Ed25519 signing key is `<profile>/signing.key` (made on first use). `<profile>/seqs/<vault id>` keeps the last record
seq posted in that vault, so a re-joined (fresh) folder never reuses one (one file per vault: runs in two
vaults never write the same file; the older `seqs.json` is still read).
Local state: `.tgsync/engine.json` (the engine's saved state; no keys) and `.tgsync/local.json` (stat cache, log,
note versions, problems). `.tgsync/lock` (the running process's id) lets one sync run at a time per
folder (two Obsidian windows on one vault); a lock left by a process that is gone is taken over.
`.tgsync/config.json` `chat` is the group's invite link (the group is found by it). Old versions of a file come
back from the group (notes: from the merged history); a version id is like `812.0` (record message, entry).

**The plugin** (`obsidian/`, `make plugin`) runs the engine itself through `ts/src/node/host.ts` (one
Telegram connection; the vault opened under the folder lock for each sync) and syncs automatically.
Setup (log in, start, join, invite, let in, members) is `obsidian/src/setup.ts` over `ts/src/node/setup.ts`;
the windows are `obsidian/src/ui.ts`. The shared Telegram API key is built in from `TGSYNC_API_ID`/`TGSYNC_API_HASH` at build time
and never committed: a build without them asks users for their own key (Advanced settings).

Big-file benchmark (sandbox, no network): `cd ts && npm run bench -- 1024 ~/.cache`. Measured 2026-11-23 on this
machine with the Rust core (chunks sealed with the platform's AES-GCM): 1 GB push 83 MB/s, pull 151 MB/s, peak
memory 316 MB (memory stays flat: files stream in chunks). With AES inside WebAssembly it was 24 / 28 MB/s; the old
TypeScript engine (2026-11-11) did 55 / 126 MB/s.

Many notes (`cd ts && npm run bench-notes -- 5000`, sandbox, notes written an hour earlier): 5000 notes, first push
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



## Code map (`ts/`, the host around the core)

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

- New setting or window: `obsidian/src/ui.ts`; what it does: `obsidian/src/setup.ts` (no windows there, so tests can drive it).
- New transport (another backend): implement the four `Transport` methods (`src/transport.ts`).
- Sync, merge, membership rules: the Rust core (`core/`), then `make sim` and `make rust`.

## Tests

| Where | Covers |
|---|---|
| `core/` (`make rust`, `make sim`) | Vectors, replay, membership, signed records, notes, plans; the deterministic simulator |
| `ts/test/` (`make ts`) | The host with two people, WebAssembly conformance, the pace |
| `obsidian/test/` | Two plugins (stub `obsidian` module) sharing a sandbox group: setup, sync, conflicts, versions, members |
| `obsidian/scripts/live.ts` (`make live`) | Start, join, let in, sync, remove on real Telegram (not in CI) |

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
