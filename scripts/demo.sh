#!/bin/sh
# Two people, one note, edited at the same time; offline (a sandbox folder plays the Telegram group).
# Usage: scripts/demo.sh   (needs `make wasm` and `cd ts && npm run build` once)
set -eu
cd "$(dirname "$0")/.."
TG="node $PWD/ts/dist/tgsync.mjs"
export TGSYNC_SANDBOX="$(mktemp -d)"
trap 'rm -rf "$TGSYNC_SANDBOX"' EXIT
A="$TGSYNC_SANDBOX/alice" B="$TGSYNC_SANDBOX/bob"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
as() { who=$1; shift; TGSYNC_PROFILE=$who $TG "$@"; }

step "alice makes a vault; bob asks to join; alice accepts his code"
invite=$(as alice --json new "$A" --name alice | node -pe 'JSON.parse(require("fs").readFileSync(0)).invite')
code=$(as bob --json join "$invite" "$B" --name bob | node -pe 'JSON.parse(require("fs").readFileSync(0)).code')
as alice accept "$code" -C "$A"
(cd "$B" && TGSYNC_PROFILE=bob $TG join) >/dev/null

step "alice writes a note and shares it"
printf '# Plan\n- buy milk\n- call mom\n' > "$A/plan.md"
as alice push -C "$A"; as bob pull -C "$B"

step "both edit the same note at the same time, offline from each other"
printf '# Plan\n- buy oat milk\n- call mom\n' > "$A/plan.md"
printf '# Plan\n- buy milk\n- call mom\n- book flights\n' > "$B/plan.md"
as alice push -C "$A"
as bob push -C "$B"; as bob pull -C "$B"; as alice pull -C "$A"

step "result: one note with both edits, the same for both, no conflict copy"
cat "$A/plan.md"
cmp "$A/plan.md" "$B/plan.md" && echo "(alice and bob have the same file)"
ls "$A"
