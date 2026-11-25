// Bundle src/main.ts into main.js (what Obsidian loads). `node esbuild.config.mjs --watch` rebuilds on change.
import esbuild from "esbuild";

const ctx = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  format: "cjs",
  target: "node20", // no newer JavaScript than the desktop app's Node runs (e.g. Uint8Array.fromBase64)
  platform: "node", // the desktop app gives plugins Node's modules (files, network)
  external: ["obsidian", "electron"],
  loader: { ".wasm": "binary" }, // the Rust core and mtcute's crypto are inside main.js
  outfile: "main.js",
  sourcemap: process.argv.includes("--watch") ? "inline" : false,
  logLevel: "info",
  logOverride: { "empty-import-meta": "silent" }, // the core is given its bytes; it never looks up a URL
});
if (process.argv.includes("--watch")) await ctx.watch();
else { await ctx.rebuild(); await ctx.dispose(); }
