# Dev shortcuts. Once: `npm install` in ts/ and obsidian/; Python with pytest for the sandbox and live tests.
PY ?= python3

.PHONY: check live ts plugin rust sim wasm

check: rust ts plugin ## everything CI runs except the long simulation

live:   ## two-person test on REAL Telegram (needs profiles default + b); KEEP=dir keeps folders
	mkdir -p ts/live && cp ts/dist/tgsync.mjs ts/live/tgsync.mjs
	$(PY) scripts/live_e2e.py $(if $(KEEP),--keep $(KEEP))

ts: wasm ## TypeScript host + Node CLI on the Rust core: type check, tests, and two-process sandbox tests (pytest)
	cd ts && npm run typecheck && npm test
	$(PY) -m pytest -q tests/test_sandbox.py

plugin: ts ## Obsidian plugin (thin layer over ts/): type check + build. `npm install` in obsidian/ once
	cd obsidian && npm run build && npm test

rust:   ## Rust core (core/): tests, incl. spec/vectors.json
	cd core && cargo test

sim:    ## deterministic simulation: many clients, faults, convergence check. SEEDS=n (default 10000)
	cd core && cargo run --release -q -p tgsync-sim -- --seeds $(or $(SEEDS),10000)

wasm:   ## Rust core -> WebAssembly (core/pkg-web, used by ts/). Without the wasm32 target, fetches CI's build
	@if rustc --print target-libdir --target wasm32-unknown-unknown >/dev/null 2>&1 && command -v wasm-bindgen >/dev/null; then \
	  cd core && cargo build --profile wasm -p tgsync-wasm --target wasm32-unknown-unknown && \
	  wasm-bindgen --target web --out-dir pkg-web target/wasm32-unknown-unknown/wasm/tgsync_wasm.wasm && \
	  wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/wasm/tgsync_wasm.wasm; \
	else scripts/fetch-wasm.sh; fi
