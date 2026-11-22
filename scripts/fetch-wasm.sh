#!/bin/sh
# Download CI's WebAssembly build of the Rust core into core/pkg and core/pkg-web, for machines
# without the wasm32 target. Usage: scripts/fetch-wasm.sh [commit]  (default: the last commit that
# changed core/). Needs `gh` logged in.
set -eu
cd "$(dirname "$0")/.."
sha=$(git rev-parse "${1:-$(git log -1 --format=%H -- core)}")   # gh needs the full commit id
run=$(gh run list --commit "$sha" --workflow ci --json databaseId,status -q '.[0].databaseId')
[ -n "$run" ] || { echo "no CI run for $sha yet; push first"; exit 1; }
echo "CI run $run for ${sha%"${sha#???????}"}: waiting for its build if needed"
gh run watch "$run" --interval 20 >/dev/null 2>&1 || true
tmp=$(mktemp -d)
gh run download "$run" -n tgsync-wasm -D "$tmp"
rm -rf core/pkg core/pkg-web
mv "$tmp/pkg" "$tmp/pkg-web" core/
rmdir "$tmp"
ls -l core/pkg-web
