# Hacking on tgsync

## Setup and checks

```bash
(cd ts && npm install); (cd obsidian && npm install)   # once; plus Rust (cargo) and Python with pytest
make check          # Rust core tests, WebAssembly build (or CI's), Node CLI tests, sandbox tests, plugin tests
make sim            # 10 000 simulated seeds
make live           # two-person test on REAL Telegram (profiles `default` and `b`); KEEP=~/dir keeps folders
```

## Try it by hand without Telegram (sandbox)

A folder on disk plays the Telegram group. No accounts, no login, no network.
Your real keys and profiles are never touched (sandbox ones live in `$TGSYNC_SANDBOX/config`).

```bash
# terminal 1 (alice)                                # terminal 2 (bob)
export TGSYNC_SANDBOX=~/tgs TGSYNC_PROFILE=alice    export TGSYNC_SANDBOX=~/tgs TGSYNC_PROFILE=bob
tgsync new ~/tgs/alice                              mkdir ~/tgs/bob && cd ~/tgs/bob
                                                    tgsync join tgsync1-... .     # prints a code
cd ~/tgs/alice && tgsync accept <code>
                                                    tgsync join
echo hi > a.md && tgsync push                       tgsync && tgsync pull && cat a.md
```

Delete `~/tgs` to start over.

## Protocol

`PROTOCOL.md` describes every message format and the replay rules; `spec/vectors.json` has fixed examples
(written by the original Python version; fixed now).
The Rust core passes them too, plus `spec/vectors_v2.json` (protocol v2), natively and as WebAssembly.

**Node CLI** (`ts/src/cli/main.ts`, built to the single file `ts/dist/tgsync.mjs` by `npm run build`; CI uploads it
as `tgsync-cli`): the same commands, output and `--json` contract as the original Python CLI, which it replaced. It runs on
the Rust core: `ts/src/vault.ts` is only the host (lists the folder, moves bytes, talks to the group) around the
WebAssembly `Engine` (`ts/src/core.ts` loads `core/pkg-web`, built by `make wasm`). Telegram goes through mtcute
(pinned exact version, `ts/src/node/telegram.ts`); the login is a session string in `<profile>/mtcute.session`, and
`tgsync login [--profile P]` logs a profile in. Profiles, age keys and `telegram.json` are shared with Python
(`~/.config/tgsync/<profile>/`); the Ed25519 signing key is `<profile>/signing.key` (made on first use).
Local state: `.tgsync/engine.json` (the engine's saved state; no keys) and `.tgsync/local.json` (stat cache, log,
note versions, problems). A folder of the old TypeScript engine (`.tgsync/state.json`) is replayed from the group
with its vault id. `.tgsync/config.json` `chat` is the group's invite link (the group is found by it); `restore`
downloads old versions from the group (notes: from the merged history), so REV is a version id like `812.0` (record
message, entry). `make ts` also runs `tests/test_sandbox.py` against it, and
`make live` runs the live test with it (a copy in `ts/live/`, since `npm test` rebuilds `dist/`). Obsidian plugin, a thin layer over the CLI's `--json` that adds nothing
the CLI lacks: `obsidian/` (`make plugin`; tests run it against a fake `tgsync`). Run `npm install` once in each.

Big-file benchmark (sandbox, no network): `cd ts && npm run bench -- 1024 ~/.cache`. Measured 2026-11-23 on this
machine with the Rust core (chunks sealed with the platform's AES-GCM): 1 GB push 83 MB/s, pull 151 MB/s, peak
memory 316 MB (memory stays flat: files stream in chunks). With AES inside WebAssembly it was 24 / 28 MB/s; the old
TypeScript engine (2026-11-11) did 55 / 126 MB/s.

Many notes (`cd ts && npm run bench-notes -- 5000`, sandbox, notes written an hour earlier): 5000 notes, first push
4.3 s, first pull 1.5 s; then one edited note: push 0.44 s, pull 0.28 s; a push with nothing to send 0.21 s.
20 000 notes: 16.5 s / 5.2 s, one edit 1.7 s / 1.1 s. (Files changed within the last 2 s are always hashed again,
so a benchmark on freshly written files measures hashing.) Real Telegram speed is limited by Telegram, not by this. Change the protocol only together with both.

## Rust core (`core/`, branch `rust-core`)

The rewrite: one Rust engine, compiled to WebAssembly for the Node CLI and the Obsidian plugin. It is
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



## Code map (`ts/`, the host around the core)

| File | What it does |
|---|---|
| `src/cli/main.ts` | Every command, `--json` mode, vault config, remembered input, picking Telegram or the sandbox. |
| `src/vault.ts` | `Vault`: open/create/join, pull (feed the group's messages to the engine), push (scan the folder, upload big files, post records), materialize (write what the engine plans), status, log, restore, members. No printing, no prompts. |
| `src/core.ts` | Loads the WebAssembly core (`core/pkg-web`). |
| `src/node/telegram.ts` | Telegram transport (mtcute), login, rate limiting. `src/node/sandbox.ts`: folder-on-disk transport. |
| `src/node/home.ts`, `files.ts` | Profiles (age key, signing key, Telegram login), remembered input; the folder as `Files`. |
| `src/protocol.ts`, `crypto.ts`, `paths.ts` | Invite codes and chunk sealing (platform AES-GCM), path rules, ignore rules. |
| `test/*.test.ts` | Vault behaviour with two people on an in-memory group, the CLI on a sandbox group, WebAssembly vs native vectors. |

## How `tgsync pull` / `push` / `status` flow

`pull`: `Vault.pullChanges()` -> `pull()` (each new message: `engine.wantsBody` -> fetch -> `engine.feed`; then
`finishPull`) -> `materialize()` (scan the folder, `engine.planMaterialize`, write/delete, `engine.materialized`).
`push`: `pull()` -> scan -> upload big files as chunks -> `engine.planPush` / `sealRecord` / post / `pushed`, as many
records as needed -> `pull()`. `status`: `fetchChanges()` -> `status()` + `incoming()`.

## Where to change what

- New command: `src/cli/main.ts`; print with `emit(data, text_fn)`, ask only with `ask(...)`, so `--json` keeps working.
- New transport (another backend): implement the four `Transport` methods (`src/transport.ts`).
- Sync, merge, membership rules: the Rust core (`core/`), then `make sim` and `make rust`.

## Tests

| Where | Covers |
|---|---|
| `core/` (`make rust`, `make sim`) | Vectors, replay, membership, signed records, notes, plans; the deterministic simulator |
| `ts/test/` (`make ts`) | The host with two people, the CLI, WebAssembly conformance |
| `tests/test_sandbox.py` | Two real `tgsync` processes on a sandbox group, via `--json` |
| `obsidian/test/` | The plugin against a fake `tgsync` |
| `scripts/live_e2e.py` | The whole story on real Telegram (not in CI) |

## `--json`: the interface for other tools (e.g. an Obsidian plugin)

`tgsync --json <command> ...` prints exactly **one JSON object** on stdout and never asks questions.
Progress and human messages go to stderr. Exit code 0 on success, 1 on error.

- Success: `{"ok": true, ...}`. Failure: `{"ok": false, "error": "<message with the fix>"}`.
- If an answer is missing (account, folder, login), it fails and names the flag to pass.
- `pull` / `push`: `{"ok": true, "report": {"pushed_paths": [], "written": [], "deleted": [],
  "conflicts": [[path, copy]], "skipped": [], "problems": [], ...}}`
- `status`: `vault_id`, `epoch`, `fingerprint`, `profile`, `members`, `pending` (`[{op, path}]`),
  `incoming` (others' changes not in your folder: `[{op, path, who, also_local}]`; null with `--offline` or when
  the group could not be reached), `online_error`, `problems`,
  `checks` (with `--check`: `[{ok, what, detail}]`, else null).
- `members`: `members` (`[{name, id, you}]`), `waiting` (`[{code, name}]`).
- `new`: `folder`, `profile`, `vault_id`, `invite`. `join`: `state` (`"waiting"` + `code`, or `"joined"` + `report`).
- `accept`: `accepted`. `remove` (needs `--yes`): `removed`, `epoch`. `invite`: `invite`. `restore` (needs PATH and REV): `restored`, `rev` (a version id like `812.0`).
- `log`: `log` (`[{ts, who, op, path, copy}]`, newest first; op is `put`, `delete`, `conflict`, `mkdir`, `rmdir`).

A script can run e.g. `tgsync --json status -C <vault>` and read stdout. Desktop only: Obsidian
mobile cannot start processes, so a mobile plugin would need the sync logic itself.
Add fields freely; don't rename or remove them without bumping the version.
