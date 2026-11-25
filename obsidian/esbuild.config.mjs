// Bundle src/main.ts into main.js (what Obsidian loads). `node esbuild.config.mjs --watch` rebuilds on change.
import esbuild from "esbuild";

// The shared Telegram API key, so people only type their phone number. Taken from the environment at
// build time and never committed: builds without TGSYNC_API_ID/TGSYNC_API_HASH carry none.
const id = Number(process.env.TGSYNC_API_ID), hash = process.env.TGSYNC_API_HASH;
const api = Number.isInteger(id) && id > 0 && hash ? JSON.stringify([id, hash]) : "null";

const ctx = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  format: "cjs",
  target: "node20", // no newer JavaScript than the desktop app's Node runs (e.g. Uint8Array.fromBase64)
  platform: "node", // the desktop app gives plugins Node's modules (files, network)
  external: ["obsidian", "electron"],
  loader: { ".wasm": "binary" }, // the Rust core and mtcute's crypto are inside main.js
  outfile: "main.js",
  define: { TGSYNC_API: api },
  sourcemap: process.argv.includes("--watch") ? "inline" : false,
  logLevel: "info",
  logOverride: { "empty-import-meta": "silent" }, // the core is given its bytes; it never looks up a URL
});
if (process.argv.includes("--watch")) await ctx.watch();
else { await ctx.rebuild(); await ctx.dispose(); }
