#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Live two-person test against REAL Telegram, using two accounts you already logged in with.

It creates a throwaway private group, walks through the whole story (invite, join request,
approval, sync, conflict, delete-vs-edit, removal, re-join) with tiny files, then deletes the group.

    python scripts/live_e2e.py                      # profiles: default (owner) and b (friend)
    python scripts/live_e2e.py --owner me --friend you

Not part of CI (needs real accounts). Takes a few minutes because the rate limiter spaces sends.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FAILS: list[str] = []


def tg(*args: str, expect_ok: bool = True) -> str:
    cmd = [sys.executable, "-m", "tgsync.cli", *args]
    t = time.monotonic()
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    print(f"  $ tgsync {' '.join(args)}   [{time.monotonic() - t:.0f}s]")
    if expect_ok and r.returncode != 0:
        check(False, f"command failed: tgsync {' '.join(args)}\n{out}")
    return out


def sync(folder: Path) -> str:
    """What the old `tgsync sync` did: upload yours, then download others'."""
    return tg("push", "-C", str(folder)) + "\n" + tg("pull", "-C", str(folder))


def check(cond: bool, what: str) -> None:
    print(f"  {'PASS' if cond else 'FAIL'}  {what}")
    if not cond:
        FAILS.append(what)


def files(d: Path) -> dict[str, str]:
    return {p.relative_to(d).as_posix(): p.read_text() for p in sorted(d.rglob("*"))
            if p.is_file() and ".tgsync" not in p.parts and p.name != ".tgsyncignore"}


async def delete_group(profile: str, chat_id: int) -> None:
    from telethon.tl import functions

    from tgsync.telegram import connect, resolve_chat

    client = await connect(profile)
    try:
        entity = await resolve_chat(client, str(chat_id))
        await client(functions.channels.DeleteChannelRequest(entity))
        print("  throwaway group deleted")
    finally:
        await client.disconnect()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", default="default")
    ap.add_argument("--friend", default="b")
    ap.add_argument("--keep", type=Path, metavar="DIR",
                    help="Put the test folders in DIR and keep them (the Telegram group is still deleted).")
    a = ap.parse_args()

    if a.keep:
        a.keep.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="tgsync-e2e-", dir=a.keep))
    A, B, B2 = tmp / f"tgsync-e2e-{int(time.time())}", tmp / "friend", tmp / "friend_again"
    chat_id = None
    try:
        print("\n== 1. owner creates a vault in a brand-new private group")
        out = tg("new", str(A), "--profile", a.owner)
        m = re.search(r"tgsync1-[A-Za-z0-9_-]+", out)
        check(bool(m), "invite code printed")
        if not m:
            return 1
        code = m.group(0)
        chat_id = json.loads((A / ".tgsync" / "config.json").read_text())["chat"]

        print("\n== 2. friend asks to join (cannot read anything yet)")
        out = tg("join", code, str(B), "--profile", a.friend, "--name", "friend")
        c = re.search(r"code: ([0-9a-f]{4}-[0-9a-f]{4})", out)
        check(bool(c) and "Then you run:  tgsync join" in out, "friend got a short code and is waiting")
        check(not B.exists() or not files(B), "friend has no files before approval")
        if not c:
            return 1
        short = c.group(1)

        print("\n== 3. owner sees the request and accepts by typing the code")
        out = tg("members", "-C", str(A))
        check(short in out, "the members list shows the friend's waiting code")
        check("nobody is waiting" in tg("accept", "0000-0000", "-C", str(A), expect_ok=False),
              "accepting a wrong code is refused")
        tg("accept", short, "-C", str(A))
        out = tg("members", "-C", str(A))
        check("friend" in out and "waiting" not in out, "friend is a member and no longer waiting")

        print("\n== 4. owner shares a note; friend pulls it")
        (A / "welcome.md").write_text("hello friend\n")
        (A / "notes").mkdir()
        (A / "notes" / "idea.md").write_text("an idea\n")
        out = sync(A)
        check("^ welcome.md" in out, "push lists the uploaded files")
        out = tg("join", code, str(B), "--profile", a.friend)
        check("Joined" in out, "friend finishes joining after approval")
        check(files(B) == files(A), "friend received exactly the owner's files")

        print("\n== 4b. pull only downloads, push only uploads")
        (A / "from_owner.md").write_text("pushed by owner\n")
        (B / "draft.md").write_text("friend draft\n")
        out = tg("push", "-C", str(A))
        check("^ from_owner.md" in out, "owner's push lists the uploaded file")
        out = tg("pull", "-C", str(B))
        check("v from_owner.md" in out and (B / "from_owner.md").exists(), "friend's pull downloads it")
        check("draft.md" not in out, "friend's pull does not upload the local draft")
        out = tg("pull", "-C", str(A))
        check(not (A / "draft.md").exists(), "owner does not get the draft before the friend pushes")
        out = tg("push", "-C", str(B))
        check("^ draft.md" in out, "friend's push lists the draft")
        out = tg("pull", "-C", str(A))
        check(files(A).get("draft.md") == "friend draft\n", "owner's pull downloads the draft")
        check(files(A) == files(B), "folders identical after push/pull")

        print("\n== 5. both edit the same note: nothing is lost")
        (A / "shared.md").write_text("base\n")
        sync(A)
        sync(B)
        (A / "shared.md").write_text("owner edit\n")
        (B / "shared.md").write_text("friend edit\n")
        sync(A)
        out = sync(B)
        sync(A)
        check("conflict" in out, "friend's push/pull reports a conflict")
        check(files(A) == files(B), "both folders are identical after syncing")
        both = " ".join(files(A).values())
        check("owner edit" in both and "friend edit" in both, "both versions survive")

        print("\n== 6. owner deletes a note while friend edits it: the edit wins")
        (A / "keep.md").write_text("v1\n")
        sync(A)
        sync(B)
        (A / "keep.md").unlink()
        (B / "keep.md").write_text("friend kept working\n")
        sync(A)
        sync(B)
        sync(A)
        check((A / "keep.md").exists() and (A / "keep.md").read_text() == "friend kept working\n",
              "edited note survived the delete on the owner's side")
        check(files(A) == files(B), "folders identical again")

        print("\n== 7. owner removes the friend: new files stay private")
        tg("remove", "friend", "--yes", "-C", str(A))
        (A / "secret.md").write_text("after removal\n")
        sync(A)
        out = tg("pull", "-C", str(B), expect_ok=False)
        check("removed" in out, "friend's pull is refused with a clear message")
        check(not (B / "secret.md").exists(), "friend never received the new file")

        print("\n== 8. friend asks again and is let back in with full history")
        out = tg("join", code, str(B2), "--profile", a.friend, "--name", "friend")
        c = re.search(r"code: ([0-9a-f]{4}-[0-9a-f]{4})", out)
        check(bool(c), "friend gets a new short code")
        if c:
            tg("accept", c.group(1), "-C", str(A))
            out = tg("join", code, str(B2), "--profile", a.friend)
            check("Joined" in out, "friend rejoined")
            check(files(B2) == files(A), "friend has everything, including files written while removed")

        print("\n== 9. health check")
        out = tg("status", "--check", "-C", str(A), expect_ok=False)
        check("all good" in out, "status --check passes for the owner")
    finally:
        print("\n== cleanup")
        if chat_id is not None:
            try:
                asyncio.run(delete_group(a.owner, chat_id))
            except Exception as e:  # noqa: BLE001
                print(f"  could not delete the throwaway group (delete it by hand): {e}")
        if a.keep:
            print(f"  kept the test folders in {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'ALL PASSED' if not FAILS else str(len(FAILS)) + ' FAILED'}")
    for f in FAILS:
        print("  - " + f.splitlines()[0])
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
