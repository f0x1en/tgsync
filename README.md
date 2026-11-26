# tgsync

**Obsidian Sync, but free.** Your vault lives in a private Telegram group, end-to-end encrypted.
Telegram stores it and sees only gibberish. Share a vault with friends; when two people edit the
same note, the edits merge.

- Free, unlimited storage (Telegram's)
- End-to-end encrypted: AES-256-GCM, keys never leave your devices
- Syncs by itself, a few seconds after you type
- Notes merge (CRDT); other files keep both versions, nothing is lost
- Older versions of any file, one click back
- Desktop (Windows, macOS, Linux). Phones: not yet.

> Alpha. Try it on a copy of your vault first.

## Install (2 minutes)

1. In Obsidian: Settings → Community plugins → Browse → install and enable **BRAT**.
2. Command palette → **BRAT: Add a beta plugin** → paste `f0x1en/tgsync` → Add.
3. Settings → Community plugins → enable **tgsync**.

BRAT keeps it updated. No BRAT? Download `main.js` and `manifest.json` from the
[latest release](https://github.com/f0x1en/tgsync/releases/latest) into
`<vault>/.obsidian/plugins/tgsync/`.

## Use

Settings → tgsync:

1. **Log in to Telegram**: phone number, then the code Telegram sends you.
2. **Start** (you, the owner): makes the private group and uploads the vault.
3. **Copy invite** and send it to a friend (or to yourself, for another computer).
4. Friend: paste it under **Join a vault** → Join.
5. You get a window: *"Sam (f17d-13fd) asks to join"* → **Let in**. Their vault fills up by itself.

The code next to a name tells two Sams apart: ask your friend which code they see.

Then just write. The status bar shows ✓ Synced; click it to sync now. Command palette →
**tgsync: Older versions of this file** to bring one back. Members, admins and removing people
are in the settings. Removing someone changes the key: they can't read anything new.

**Two accounts on one computer** (say two vault windows): Settings → tgsync → Advanced →
Account, give each vault a name before logging in. **Telegram blocked?** Advanced → Proxy.

## How it works

```
 your vault ──► plugin: lists files, talks to Telegram ──► Rust core (WebAssembly) ──► sealed messages in
                                                           crypto, merging, members      your private group
```

The group is an append-only log of encrypted messages; every device replays it the same way and
reaches the same files, no server deciding anything. If Telegram says "slow down", tgsync does,
then speeds back up by itself. Details: [PROTOCOL.md](PROTOCOL.md), [HACKING.md](HACKING.md).

## Security and limits

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

## Build it yourself

```bash
npm install
make plugin                       # Rust core -> WebAssembly, tests, main.js
make install VAULT=~/my-vault     # copy it into a vault
```
`TGSYNC_API_ID`/`TGSYNC_API_HASH` in the environment build in a Telegram API key; without them,
people enter their own (my.telegram.org → API development tools) under Advanced.

## License

AGPL-3.0-or-later (see `LICENSE`). Change it and run it for others as a service: offer them your source.
