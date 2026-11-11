# SPDX-License-Identifier: AGPL-3.0-or-later
"""Two people, two processes, one sandbox group on disk: the whole CLI story offline, via --json."""

import json
import os
import subprocess
import sys


def _tg(sandbox, profile, *args, cwd=None):
    env = {k: v for k, v in os.environ.items() if k != "TGSYNC_HOME"}
    env.update(TGSYNC_SANDBOX=str(sandbox), TGSYNC_PROFILE=profile)
    r = subprocess.run([sys.executable, "-m", "tgsync.cli", "--json", *args],
                       capture_output=True, text=True, env=env, cwd=cwd)
    return json.loads(r.stdout), r.returncode


def test_two_people_in_the_sandbox(tmp_path):
    sb, A, B = tmp_path / "sb", tmp_path / "alice", tmp_path / "bob"

    out, rc = _tg(sb, "alice", "new", str(A), "--no-git")
    assert rc == 0 and out["ok"] and out["invite"].startswith("tgsync1-"), out
    assert (sb / "config" / "alice").is_dir()          # keys live in the sandbox, not your real config

    out, _ = _tg(sb, "bob", "join", out["invite"], str(B), "--no-git")
    assert out["state"] == "waiting", out
    code = out["code"]

    out, _ = _tg(sb, "alice", "members", "-C", str(A))
    assert [w["code"] for w in out["waiting"]] == [code]
    out, rc = _tg(sb, "alice", "accept", code, "-C", str(A))
    assert rc == 0 and out["accepted"] == "bob"

    out, _ = _tg(sb, "bob", "join")                     # remembered: no code, folder or account needed
    assert out["state"] == "joined", out

    (A / "hello.md").write_text("hi bob\n")
    out, _ = _tg(sb, "alice", "push", "-C", str(A))
    assert "hello.md" in out["report"]["pushed_paths"]
    out, _ = _tg(sb, "bob", "pull", "-C", str(B))
    assert "hello.md" in out["report"]["written"] and (B / "hello.md").read_text() == "hi bob\n"

    # removed, then asks to come back from the SAME folder with plain `tgsync join`
    out, rc = _tg(sb, "alice", "remove", "bob", "--yes", "-C", str(A))
    assert rc == 0, out
    (A / "while_out.md").write_text("written while bob was out\n")
    _tg(sb, "alice", "sync", "-C", str(A))
    out, rc = _tg(sb, "bob", "sync", "-C", str(B))
    assert rc == 1 and "tgsync join" in out["error"], out
    out, _ = _tg(sb, "bob", "join", cwd=B)
    assert out["state"] == "waiting", out
    _tg(sb, "alice", "accept", out["code"], "-C", str(A))
    out, _ = _tg(sb, "bob", "join", cwd=B)
    assert out["state"] == "joined", out
    assert (B / "while_out.md").read_text() == "written while bob was out\n"
    assert (B / "hello.md").read_text() == "hi bob\n"
    assert not out["report"]["conflicts"], out
    assert out["report"]["pushed_paths"] == [], out           # files he already had are not uploaded again
    assert list((B / ".tgsync").glob("state.db.removed-*"))   # old state kept, not deleted


def test_json_errors_are_json_and_never_ask(tmp_path):
    out, rc = _tg(tmp_path / "sb", "alice", "push", "-C", str(tmp_path))
    assert rc == 1 and out["ok"] is False and "not a tgsync vault" in out["error"]
    out, rc = _tg(tmp_path / "sb", "alice", "join")
    assert rc == 1 and "Paste the invite line" in out["error"]


def test_status_warns_when_someone_else_changed_your_file(tmp_path):
    sb, A, B = tmp_path / "sb", tmp_path / "alice", tmp_path / "bob"
    inv = _tg(sb, "alice", "new", str(A), "--no-git")[0]["invite"]
    code = _tg(sb, "bob", "join", inv, str(B), "--no-git")[0]["code"]
    _tg(sb, "alice", "accept", code, "-C", str(A))
    _tg(sb, "bob", "join")
    (A / "plan.md").write_text("v1\n")
    _tg(sb, "alice", "push", "-C", str(A))
    _tg(sb, "bob", "pull", "-C", str(B))

    (B / "plan.md").write_text("bob's idea\n")        # bob edits, not uploaded yet
    (A / "plan.md").write_text("alice's idea\n")      # meanwhile alice uploads her edit
    _tg(sb, "alice", "push", "-C", str(A))

    out, rc = _tg(sb, "bob", "status", "-C", str(B))
    assert rc == 0 and out["online_error"] is None, out
    assert out["incoming"] == [{"op": "put", "path": "plan.md", "who": "alice", "also_local": True}]
    assert out["pending"] == [{"op": "put", "path": "plan.md"}]
    assert (B / "plan.md").read_text() == "bob's idea\n"   # status never touches files

    out, _ = _tg(sb, "bob", "status", "--offline", "-C", str(B))
    assert out["incoming"] is None
