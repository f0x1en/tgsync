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
echo hi > a.md && tgsync                            tgsync pull && cat a.md
```

Delete `~/tgs` to start over.

## Protocol

`PROTOCOL.md` describes every message format and the replay rules; `spec/vectors.json` has fixed examples
(regenerate with `.venv/bin/python scripts/make_vectors.py`; `tests/test_vectors.py` checks Python against it).
The Obsidian plugin must pass the same vectors. Plugin code: `obsidian/` (`cd obsidian && npm install` once, then `make plugin`). Change the protocol only together with both.

## Code map (`src/tgsync/`)

| File | What it does |
|---|---|
| `cli/common.py` | The `tgsync` group, `--json` mode, vault config, remembered input, and the one place that picks Telegram or sandbox (`_transport`, `_new_group`, `_open`, `_ensure_ready`). |
| `cli/setup.py` | `new`, `join` |
| `cli/people.py` | `invite`, `members`, `accept`, `remove` |
| `cli/syncing.py` | `sync`, `pull`, `push`, `status` |
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

## How a `tgsync` (sync) flows

`cli/syncing.sync` -> `common._open` (load `.tgsync/config.json`, connect, build `Vault`) ->
`Vault.sync()`: pull (read new messages after the cursor, verify, apply to the tree) ->
scan local folder -> push changed files as records/chunks -> materialize -> `SyncReport` ->
`common.emit_report` prints text or JSON.

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

## `--json`: the interface for other tools (e.g. an Obsidian plugin)

`tgsync --json <command> ...` prints exactly **one JSON object** on stdout and never asks questions.
Progress and human messages go to stderr. Exit code 0 on success, 1 on error.

- Success: `{"ok": true, ...}`. Failure: `{"ok": false, "error": "<message with the fix>"}`.
- If an answer is missing (account, folder, login), it fails and names the flag to pass.
- `sync` / `pull` / `push`: `{"ok": true, "report": {"pushed_paths": [], "written": [], "deleted": [],
  "conflicts": [[path, copy]], "skipped": [], "problems": [], ...}}`
- `status`: `vault_id`, `epoch`, `fingerprint`, `profile`, `members`, `pending` (`[{op, path}]`), `problems`,
  `checks` (with `--check`: `[{ok, what, detail}]`, else null).
- `members`: `members` (`[{name, id, you}]`), `waiting` (`[{code, name}]`).
- `new`: `folder`, `profile`, `vault_id`, `invite`. `join`: `state` (`"waiting"` + `code`, or `"joined"` + `report`).
- `accept`: `accepted`. `remove` (needs `--yes`): `removed`, `epoch`. `invite`: `invite`. `restore` (needs PATH and REV): `restored`, `rev`.
- `log`: `log` (`[{ts, who, op, path, copy}]`, newest first; op is `put`, `delete`, `conflict`, `mkdir`, `rmdir`).

A plugin would run e.g. `tgsync --json sync -C <vault>` and read stdout. Desktop only: Obsidian
mobile cannot start processes, so a mobile plugin would need the sync logic itself.
Add fields freely; don't rename or remove them without bumping the version.
