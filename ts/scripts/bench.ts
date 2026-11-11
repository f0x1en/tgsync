// SPDX-License-Identifier: AGPL-3.0-or-later
// Move one big file between two people through a sandbox group (folder on disk) and report
// speed and peak memory. No Telegram, so this measures tgsync itself, not the network.
//   npm run bench -- [size in MB, default 1024] [work dir, default a new temp folder]
import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, mkdtemp, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newIdentity } from "../src/crypto.ts";
import { NodeFiles } from "../src/node/files.ts";
import { DirTransport, PREFIX } from "../src/node/sandbox.ts";
import { Vault } from "../src/vault.ts";

const mb = Number(process.argv[2] ?? 1024);
const base = process.argv[3] ?? tmpdir();
await mkdir(base, { recursive: true });
const tmp = await mkdtemp(join(base, "tgsync-bench-"));
const A = join(tmp, "alice"), B = join(tmp, "bob"), G = join(tmp, "group");
for (const d of [A, B, G]) await mkdir(d);

let peak = 0;
const timer = setInterval(() => { peak = Math.max(peak, process.memoryUsage().rss); }, 20);
const sha = (p: string) => new Promise<string>((ok, fail) => {
  const h = createHash("sha256");
  createReadStream(p).on("data", (d) => h.update(d)).on("end", () => ok(h.digest("hex"))).on("error", fail);
});

try {
  const fh = await open(join(A, "big.bin"), "w");
  const piece = randomBytes(8 * 1024 * 1024);
  for (let left = mb * 1024 * 1024; left > 0; left -= piece.length) await fh.write(piece.subarray(0, Math.min(left, piece.length)));
  await fh.close();
  const want = await sha(join(A, "big.bin"));

  const link = PREFIX + G;
  const ia = await newIdentity(), ib = await newIdentity();
  const a = await Vault.create(new NodeFiles(A), ia, new DirTransport(link), "alice");
  await a.addMember(ib.recipient, "bob");
  const b = await Vault.join(new NodeFiles(B), ib, new DirTransport(link), a.vaultId!);
  peak = 0;

  let t = performance.now();
  await a.pushChanges();
  const up = (performance.now() - t) / 1000;
  t = performance.now();
  await b.pullChanges();
  const down = (performance.now() - t) / 1000;
  const got = await sha(join(B, "big.bin"));

  clearInterval(timer);
  const ok = got === want;
  console.log(JSON.stringify({
    file_mb: mb, push_s: +up.toFixed(1), pull_s: +down.toFixed(1),
    push_mb_s: +(mb / up).toFixed(0), pull_mb_s: +(mb / down).toFixed(0),
    peak_rss_mb: Math.round(peak / 1024 / 1024), identical: ok,
  }));
  if (!ok) process.exitCode = 1;
} finally {
  clearInterval(timer);
  await rm(tmp, { recursive: true, force: true });
}
