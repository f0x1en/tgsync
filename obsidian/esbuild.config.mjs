// Bundle src/main.ts into main.js (what Obsidian loads). `node esbuild.config.mjs --watch` rebuilds on change.
import esbuild from "esbuild";

const ctx = await esbuild.context({
  entryPoints: ["src/main.ts"],
  bundle: true,
  format: "cjs",
  target: "es2022",
  platform: "browser",
  external: ["obsidian", "electron"],
  outfile: "main.js",
  sourcemap: process.argv.includes("--watch") ? "inline" : false,
  logLevel: "info",
});
if (process.argv.includes("--watch")) await ctx.watch();
else { await ctx.rebuild(); await ctx.dispose(); }
