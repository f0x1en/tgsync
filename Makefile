# Dev shortcuts. Once: `npm install`.

.PHONY: check plugin live rust sim wasm install

check: rust plugin ## everything CI runs except the long simulation

plugin: wasm ## type check, tests (host + plugin), build main.js
	npm run build && npm test

install: ## build and copy the plugin into VAULT=~/path/to/vault
	@test -n "$(VAULT)" || { echo "usage: make install VAULT=~/path/to/vault"; exit 1; }
	npm run -s build && mkdir -p "$(VAULT)/.obsidian/plugins/tgsync" && cp main.js manifest.json "$(VAULT)/.obsidian/plugins/tgsync/"

live:   ## two-person test on REAL Telegram (accounts default + b logged in); KEEP=1 keeps folders
	npm run -s live -- $(if $(KEEP),--keep)

rust:   ## Rust core (core/): tests, incl. spec/vectors.json
	cd core && cargo test

sim:    ## deterministic simulation: many clients, faults, convergence check. SEEDS=n (default 10000)
	cd core && cargo run --release -q -p tgsync-sim -- --seeds $(or $(SEEDS),10000)

wasm:   ## Rust core -> WebAssembly (core/pkg-web). Without the wasm32 target, fetches CI's build
	@if rustc --print target-libdir --target wasm32-unknown-unknown >/dev/null 2>&1 && command -v wasm-bindgen >/dev/null; then \
	  cd core && cargo build --profile wasm -p tgsync-wasm --target wasm32-unknown-unknown && \
	  wasm-bindgen --target web --out-dir pkg-web target/wasm32-unknown-unknown/wasm/tgsync_wasm.wasm && \
	  wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/wasm/tgsync_wasm.wasm; \
	else scripts/fetch-wasm.sh; fi
