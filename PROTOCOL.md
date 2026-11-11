# tgsync protocol, version 1

What two tgsync programs must agree on to share a vault. The Python CLI (`src/tgsync/`) is the
reference. Any other implementation (the TypeScript Obsidian plugin) must read what Python writes
and write what Python reads. `spec/vectors.json` holds fixed examples; both sides test against them.

Local state (cursor, synced hashes, history) is private to each implementation and not part of
this document. Only the messages in the group are shared.

Notation: `||` is byte concatenation. `u32be(n)` is 4 bytes, big-endian. Text is UTF-8.
`b64` is standard base64 with padding. `b64url` is URL-safe base64 without padding. `hex` is lowercase.

## 1. Transport

The group is an ordered list of messages. Each message has an integer id (strictly increasing),
a one-letter **kind** and a byte body.

| Kind | Name | Body |
|---|---|---|
| `d` | descriptor | JSON, plaintext (section 4) |
| `r` | record | sealed (section 5) |
| `c` | chunk | sealed (section 6) |
| `j` | join request | JSON, plaintext (section 7) |

- **Telegram:** a private supergroup. Each tgsync message is a document (file name `x.bin`, sent as
  a document, not as media) with caption exactly `tgs1:` + kind. Messages with any other caption,
  or without a document, are not tgsync messages and are skipped. Message id = Telegram message id.
- **Sandbox** (development only): a folder; each message is a file `<id, 8 digits zero-padded>.<kind>`.
  The link is `sandbox:<absolute folder path>`.

Readers process messages in id order. Unknown kinds are skipped.

## 2. Crypto primitives

**Vault key:** 32 random bytes per **epoch** (integer, starts at 1, +1 on each member removal).
A key ring maps epoch -> key. New data is always sealed with the highest epoch.

**Subkey:** `HKDF-SHA256(ikm = vault_key, salt = empty (= 32 zero bytes), info = "tgsync/v1/" || purpose || 0x00 || ctx, length 32)`.

**Seal** (`purpose`, `ctx`, `plaintext`) with epoch `e`:
```
header = "TGS1" || u32be(e)                         # 8 bytes
nonce  = 12 random bytes
aad    = header || purpose || 0x00 || ctx
blob   = header || nonce || AES-256-GCM(subkey(key[e], purpose, ctx), nonce, plaintext, aad)   # ct || 16-byte tag
```
**Open:** check length >= 36, magic `TGS1`, that the ring has epoch `e`, then decrypt with the same aad.
Any failure means the blob is rejected.

| Use | purpose | ctx |
|---|---|---|
| record | `record` | empty |
| chunk | `chunk` | `<file_id>:<index>:<count>` |
| roster | `roster` | vault id |
| descriptor proof | `descproof` | `<vault_id>:<epoch>` |

**mac**(key, parts...) = `HMAC-SHA256(key, u32be(len(p1)) || p1 || u32be(len(p2)) || p2 ...)`.

**Fingerprint** of a key: `hex(SHA256("tgsync/fingerprint/v1" || key))[:20]`, split into 5 groups of 4
separated by single spaces. The vault's fingerprint is that of the epoch-1 key (if held), else of the
lowest epoch held.

## 3. People

Each person has an **age X25519 identity** (`AGE-SECRET-KEY-1...`, public recipient `age1...`).
- **member id** = `hex(SHA256(recipient))[:16]`.
- **short code** (read aloud to confirm a join request) = first 8 hex chars of the member id as `xxxx-xxxx`.
- **wrap** = standard age encryption to one recipient (binary format, not armored).

## 4. Descriptor (kind `d`)

Says who the members are and gives each of them the vault keys. Canonical JSON:
**keys sorted, separators `,` and `:` with no spaces, ASCII only** (all values are ASCII).

```json
{"created": 1762850000, "epoch": 2, "keycheck": "<hex>", "members": [{"id": "<member id>", "wrapped": "<b64>"}],
 "proof": "<b64>", "proof_epoch": 1, "roster": "<b64>", "v": 1, "vault_id": "<16 hex>"}
```
- `wrapped` = b64(wrap(recipient, JSON `{"keys": {"<epoch>": "<b64 key>", ...}}`)): every epoch key the vault has.
- `roster` = b64(seal(`roster`, vault_id, JSON `[{"id", "recipient", "name"}, ...]`, epoch)).
- `keycheck` = hex(mac(key[epoch], "descriptor", vault_id, str(epoch))).
- `proof_epoch` = `epoch` when adding a member; `epoch - 1` when the key was rotated (member removed).
- `proof` = b64(seal(`descproof`, `"<vault_id>:<epoch>"`, SHA256(canonical JSON of all other fields), proof_epoch)).

**Accepting a descriptor** (with our identity and our current ring):
1. Parse; `v` must be 1; all fields above present. If we know the vault id, it must match.
2. If our ring is not empty and `epoch` < our highest epoch: reject (replay).
3. Find our member id in `members`. Not there -> the descriptor is valid but **excludes us** (result: none).
4. Unwrap our keys. They must contain `epoch`. Every epoch we already hold must have the same key, else reject.
5. Check `keycheck`. `proof_epoch` must be `epoch` or `epoch - 1`.
6. Verify `proof` (open it, compare to the digest of the body without `proof`):
   - with our existing ring, if it is not empty (the proof epoch must be one we already hold);
   - with the keys from this descriptor, if we hold no keys yet (joining: trust on first use;
     the invite's fingerprint is the out-of-band check).
7. Add the keys to the ring, open the roster: that list is now the member list.

Creating a vault: random 8-byte vault id (hex), epoch 1 key, a descriptor with the creator as only member.
Adding a member: same keys, roster + new member, `proof_epoch = epoch`.
Removing a member: new epoch key, roster without them, `proof_epoch = old epoch`.
Any current member may post descriptors.

## 5. Record (kind `r`)

One batch of file operations from one author. Body = seal(`record`, empty, plain), where
```
plain  = u32be(len(header)) || header || payload
header = JSON {"v": 1, "author": "<member id>", "seq": <int>, "ts": <unix seconds, float>, "entries": [...]}
```
`payload` holds the bytes of small files, back to back. Readers must accept any key order and spacing.

- `seq` starts at 1 per author and goes up by 1 per record.
- At most 500 entries and about 4 MiB of payload per record (writer limits; readers accept more).

**Entries:**

| op | fields | meaning |
|---|---|---|
| `put` | `path`, `sha`, `size`, `mtime`, `base`, `blob` | file content is now `sha` (hex SHA-256 of the bytes) |
| `delete` | `path`, `base` | file deleted |
| `mkdir` | `path` | empty folder exists |
| `rmdir` | `path` | empty folder removed |

- `base` = the sha the author last synced for that path, or `null` for a new file.
- `mtime` = float unix seconds (the file's modification time).
- `blob` describes where the content is:
  - small file: `{"file_id": "<16 hex>", "chunks": null, "inline": [offset, length]}`: the bytes are
    `payload[offset : offset+length]` of the record message `payload_msg`;
  - big file: `{"file_id": "<16 hex>", "chunks": [msg ids], "chunk_size": n, "inline": null}`;
  - optional `payload_msg`: message id of the record that holds the inline payload. **Absent means
    this record.** A writer that re-uses content the group already has (rename, move, copy) copies the
    existing node's `blob` including its `payload_msg`, and sends no data.
- Small file = 256 KiB or less (writer choice; readers handle both forms).
- Readers always check SHA-256 of the downloaded bytes against `sha`.

## 6. Chunk (kind `c`)

Body = seal(`chunk`, `"<file_id>:<index>:<count>"`, bytes). A big file is `count` chunks of
`chunk_size` bytes (the last may be shorter), each its own message, sent **before** the record that
references them. Writer default chunk size: 32 MiB.

## 7. Join request (kind `j`) and invite code

Join request body (plaintext, from someone with no key yet):
`{"v": 1, "vault": "<vault id>", "recipient": "age1...", "name": "<at most 40 chars>"}`.
Ignore if malformed or the recipient does not start with `age1`. A member approves by posting a
descriptor that adds the recipient, after both sides compare the short code. Latest request per
recipient wins; requests from current members are ignored.

Invite code (shared out of band, e.g. in a chat): `"tgsync1-" || b64url(JSON {"l": "<group link>", "v": "<vault id>", "f": "<fingerprint>", "a": [api_id, "api_hash"]})`.
`a` is optional (Telegram app credentials). Whitespace inside a pasted code is removed before decoding.

## 8. Paths

Vault paths are relative, `/`-separated, NFC-normalized. A path is **unsafe** (entry skipped) if:
empty or longer than 240 chars; starts with `/` or a drive letter `X:`; contains `< > : " | ? * \`
or a control char (0x00-0x1f); has an empty, `.` or `..` component; a component ends with `.` or
space; a component's part before the first `.` is a reserved Windows name (`CON PRN AUX NUL COM1-9 LPT1-9`,
any case); the first component is `.tgsync` or `.git`; it ends with `.tgsync-tmp`.

**Conflict copy name** for `path` written by `author` (member id) at `ts`:
`<dir>/<stem> (conflict <author[:6]> <YYYY-MM-DD HHMM in UTC of ts>)<ext>`, where ext is the last
`.xxx` of the file name (none if no dot, and a leading dot does not count, as Python `splitext`).
If that name is taken (lowercase comparison, section 9), use `author[:5] + "2"`, then `"3"`, ... in place of `author[:6]`.

**Ignore rules** (gitignore syntax, not synced): the built-in list in `src/tgsync/paths.py`
(`DEFAULT_IGNORE`) plus the vault's `.tgsyncignore` file. `.tgsyncignore` itself is synced.

## 9. Replay: turning the log into the file tree

Every client applies the same messages in the same order, so all reach the same tree,
including the same conflict-copy names. The tree maps path -> node `{sha, size, mtime, blob, author, msg_id}`;
folders are nodes with `sha = "dir"`. Path clashes are checked case-insensitively, meaning
**Unicode lowercase** (Python `str.lower()`, JavaScript `toLowerCase()`; not `casefold`, so `ß` and `ss` differ).

For each message after the last processed id:
- **`d`:** accept (section 4). Excludes us and we already used this vault -> we were removed: stop
  applying records. Excludes us and we never synced -> forget keys (a later re-add is a fresh join).
  Rejected -> record a problem, continue.
- **`r`:** if we hold no keys, or the record's epoch (header bytes 4-8) is one we do not hold yet:
  stop advancing the cursor here (read it again once a descriptor gives the key). Else open it.
  Unreadable -> problem. `seq` <= last seq seen from that author -> duplicate, skip whole record.
  `seq` > last + 1 -> problem "gap" (still applied). Then apply each entry:
  - Unsafe path or missing fields -> skip the entry.
  - **put:** node = entry, `author`, `msg_id` = this message, `blob.payload_msg` = this message unless present.
    - another node's path equals this one case-insensitively but not exactly -> conflict;
    - no node, or current sha == new sha (no change), or current sha == `base` -> set node;
    - else -> conflict: node goes to the conflict-copy path, the original stays.
  - **delete:** only if current node's sha == `base`; else ignored (an edit beats a delete).
  - **mkdir:** only if no node at that path (exact or case-insensitive); creates a folder node.
  - **rmdir:** only if the current node is a folder.
- **`c`, `j`:** nothing to apply.

**Materialize** (write the tree to disk): write each file whose disk content differs from the tree,
unless the disk copy has local edits not yet pushed (then leave it; the next push sorts it out).
Delete files that left the tree (only if unchanged locally). Create folder nodes; remove folders that
left the tree if empty. When removing a file leaves empty parent folders, remove them too, but never
a folder that is a folder node. Write files via a temporary name (`<name>.tgsync-tmp`) and rename.

**Push** (local -> group): compare disk with what was last synced: changed or new files -> `put`
(with `base`), missing files -> `delete`, new empty folders -> `mkdir`, missing synced folders -> `rmdir`.
If the tree already holds a node with the same sha, re-use its blob (section 5). Send chunks, then
records. Then pull again: a put that lost a race appears as a conflict copy.

## 10. Versions

Messages carry `v: 1` (descriptor, record header, join request), `TGS1` (sealed blobs), `tgs1:`
(captions), `tgsync1-` (invites). Readers reject versions they do not know. New optional fields may
be added; readers ignore unknown fields. Changing the meaning of a field needs a new version.
