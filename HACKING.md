# Hacking on tgsync

## Setup and checks

```bash
uv venv && uv pip install -e ".[dev]"
make check          # ruff + mypy + pytest, same as CI (~3 s)
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
(regenerate with `.venv/bin/python scripts/make_vectors.py`; `tests/test_vectors.py` checks Python against it).
The Rust core passes them too, plus `spec/vectors_v2.json` (protocol v2), natively and as WebAssembly.

**Node CLI** (`ts/src/cli/main.ts`, built to the single file `ts/dist/tgsync.mjs` by `npm run build`; CI uploads it
as `tgsync-cli`): the same commands, output and `--json` contract as the Python CLI, which it replaces. It runs on
the Rust core: `ts/src/vault.ts` is only the host (lists the folder, moves bytes, talks to the group) around the
WebAssembly `Engine` (`ts/src/core.ts` loads `core/pkg-web`, built by `make wasm`). Telegram goes through mtcute
(pinned exact version, `ts/src/node/telegram.ts`); the login is a session string in `<profile>/mtcute.session`, and
`tgsync login [--profile P]` logs a profile in. Profiles, age keys and `telegram.json` are shared with Python
(`~/.config/tgsync/<profile>/`); the Ed25519 signing key is `<profile>/signing.key` (made on first use). `<profile>/seqs/<vault id>` keeps the last record
seq posted in that vault, so a re-joined (fresh) folder never reuses one (one file per vault: runs in two
vaults never write the same file; the older `seqs.json` is still read).
Local state: `.tgsync/engine.json` (the engine's saved state; no keys) and `.tgsync/local.json` (stat cache, log,
note versions, problems). A folder of the old TypeScript engine (`.tgsync/state.json`) is replayed from the group
with its vault id. `.tgsync/config.json` `chat` is the group's invite link (the group is found by it); `restore`
downloads old versions from the group (notes: from the merged history), so REV is a version id like `812.0` (record
message, entry). `make ts` also runs `tests/test_sandbox.py` against it, and
`TGSYNC_CLI="node $PWD/ts/live/tgsync.mjs" python scripts/live_e2e.py` runs the live test with it (use a copy under
`ts/`, since `npm test` rebuilds `dist/`). Obsidian plugin, a thin layer over the CLI's `--json` that adds nothing
the CLI lacks: `obsidian/` (`make plugin`; tests run it against a fake `tgsync`). Run `npm install` once in each.

Big-file benchmark (sandbox, no network): `cd ts && npm run bench -- 1024 ~/.cache`. Measured 2026-11-23 on this
machine with the Rust core (chunks sealed with the platform's AES-GCM): 1 GB push 83 MB/s, pull 151 MB/s, peak
memory 316 MB (memory stays flat: files stream in chunks). With AES inside WebAssembly it was 24 / 28 MB/s; the old
TypeScript engine (2026-11-11) did 55 / 126 MB/s.

Many notes (`cd ts && npm run bench-notes -- 5000`, sandbox, notes written an hour earlier): 5000 notes, first push
4.3 s, first pull 1.5 s; then one edited note: push 0.44 s, pull 0.28 s; a push with nothing to send 0.21 s.
20 000 notes: 8.0 s / 5.1 s, one edit 1.2 s / 1.0 s. (Files changed within the last 2 s are always hashed again,
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

**Does it catch bugs?** Each of these deliberate bugs in the core made the simulator fail within the
first two seeds (2026-11-23): a put that ignores its `base` ("edit lost"), conflict copies that all get
the same name (replicas differ), "edit beats delete" turned off ("edit lost"), re-sending of records
rejected for an old key turned off ("upload lost"), migrating no synced map or no seq after a re-join
(found real bugs before they were fixed). It also checks secrecy in v2 vaults: every applied record
is sealed with the newest key at its place in the log and signed by its author, a member there; turning
off the old-key rule or the membership rule each fails within two seeds (members also post forged records).



| File | What it does |
|---|---|
| `cli/common.py` | The `tgsync` group, `--json` mode, vault config, remembered input, and the one place that picks Telegram or sandbox (`_transport`, `_new_group`, `_open`, `_ensure_ready`). |
| `cli/setup.py` | `new`, `join` |
| `cli/people.py` | `invite`, `members`, `accept`, `remove` |
| `cli/syncing.py` | `pull`, `push`, `status` (also plain `tgsync`) |
| `cli/restore.py` | `log`, `restore` (offline) |
| `engine.py` | `Vault`: create/join, pull (replay the log), push (scan + upload), materialize (write files), members. No printing, no prompts. |
| `oplog.py` | Message formats: records (batched file ops), chunks (big files). |
| `vaultkeys.py` | Descriptors: the vault key wrapped per member, roster, add/remove (key rotation). |
| `crypto.py` | AES-256-GCM sealing, key ring (epochs), fingerprints. |
| `identity.py` | Per-person age key, Telegram credentials, profile folders (`root_dir`). |
| `invites.py` | Invite codes (`tgsync1-...`) and join requests; short codes. |
| `tree.py`, `state.py` | The replicated file tree and the local SQLite state (`.tgsync/state.db`). |
| `history.py` | Local git snapshots in `.tgsync/history.git`. |
| `paths.py` | Path safety, ignore rules. `lock.py`: one process per vault. |
| `transport.py` | The `Transport` interface (`send`, `iter_after`, `fetch`, `close`) + in-memory fake for tests. |
| `telegram.py` | Real transport (Telethon), login, rate limiting. |
| `sandbox.py` | Folder-on-disk transport (`TGSYNC_SANDBOX`). |

## How `tgsync pull` / `push` / `status` flow

`cli/syncing.pull` -> `common._open` (load `.tgsync/config.json`, connect, build `Vault`) ->
`Vault.pull_changes()`: `pull()` (read new messages after the cursor, verify, apply to the tree) ->
`materialize()` (write the tree to disk) -> `SyncReport` -> `common.emit_report` prints text or JSON.
`push`: `Vault.push_changes()`: `pull()` (log only) -> `scan_local()` -> `push()` (records/chunks) -> `pull()`.
`status`: `Vault.fetch()` (log only) -> `status()` (your changes) + `incoming()` (others' changes).
`Vault.sync()` (all of it at once) remains for tests; the CLI has no `sync` command.

## Where to change what

- New command: add it to the matching `cli/*.py` file (or a new file imported in `cli/__init__.py`).
  Print results with `c.emit(data, text_fn)` and ask questions only with `c.ask(...)`, so `--json` keeps working.
- New transport (another backend): implement the four `Transport` methods; hook it into
  `common._transport` / `common._new_group`. The engine needs nothing else.
- Sync/conflict behavior: `engine.py` + `tree.py`; test with the in-memory fake (`tests/conftest.py`: `mk`, `pair`).

## Tests

| File | Covers |
|---|---|
| `tests/test_sync.py` | Sync, conflicts, deletes, big files (in-memory fake group) |
| `tests/test_members.py`, `test_invites_profiles.py` | Join/accept/remove, invites, profiles, remembered input |
| `tests/test_history_cli.py` | Local history, restore, CLI basics |
| `tests/test_crypto_paths.py` | Crypto and path safety |
| `tests/test_sandbox.py` | Two real `tgsync` processes on a sandbox group, via `--json` |
| `scripts/live_e2e.py` | The whole story on real Telegram (not in CI) |

## Known limits (not fixed yet)

- Each note keeps its newest 256 versions locally (to diff from, and for `restore`); older ones are
  dropped from `.tgsync/engine.json`. A writer more than 256 versions behind gets a conflict copy instead of a merge.
- A record whose post failed after sealing keeps its seq (so a post that did go through is never doubled);
  readers then note a harmless "gap in ... history".
- Join short codes are 32 bits. `accept` refuses a code two waiting requests share and also takes the full
  member id, which `tgsync join` prints.
- The Obsidian plugin is desktop only (it runs the CLI); a mobile plugin needs Telegram inside Obsidian.

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
- `members`: `members` (`[{name, id, you, admin}]`), `waiting` (`[{code, id, name}]`).
- `new`: `folder`, `profile`, `vault_id`, `invite`. `join`: `state` (`"waiting"` + `code`, or `"joined"` + `report`).
- `accept`: `accepted`. `remove` (needs `--yes`): `removed`, `epoch`. `invite`: `invite`. `restore` (needs PATH and REV): `restored`, `rev` (Python: a git snapshot id; Node: a version id like `812.0`).
- `log`: `log` (`[{ts, who, op, path, copy}]`, newest first; op is `put`, `delete`, `conflict`, `mkdir`, `rmdir`).

A script can run e.g. `tgsync --json status -C <vault>` and read stdout. Desktop only: Obsidian
mobile cannot start processes, so a mobile plugin would need the sync logic itself.
Add fields freely; don't rename or remove them without bumping the version.
