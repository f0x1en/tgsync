# Dev shortcuts. Once: `npm install` in ts/ and obsidian/.

.PHONY: check live ts plugin rust sim wasm

check: rust ts plugin ## everything CI runs except the long simulation

live:   ## two-person test on REAL Telegram (needs accounts default + b logged in); KEEP=1 keeps folders
	cd obsidian && npm run -s live -- $(if $(KEEP),--keep)

ts: wasm ## TypeScript host on the Rust core (vault, Telegram, setup): type check and tests
	cd ts && npm run typecheck && npm test

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
