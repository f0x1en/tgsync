# Dev shortcuts. Run `uv venv && uv pip install -e ".[dev]"` once first.
PY ?= .venv/bin/python

.PHONY: check test live ts plugin rust sim wasm

check:  ## lint + types + tests (same as CI)
	$(PY) -m ruff check src tests scripts
	$(PY) -m mypy src
	$(PY) -m pytest -q

test:   ## tests only
	$(PY) -m pytest -q

live:   ## two-person test on REAL Telegram (needs profiles default + b); KEEP=dir keeps folders
	$(PY) scripts/live_e2e.py $(if $(KEEP),--keep $(KEEP))

ts: wasm ## TypeScript host + Node CLI on the Rust core: type check, tests, and the Python CLI's sandbox tests run against the Node CLI. `npm install` in ts/ once
	cd ts && npm run typecheck && npm test
	TGSYNC_CLI="node $(CURDIR)/ts/dist/tgsync.mjs" $(PY) -m pytest -q tests/test_sandbox.py

plugin: ts ## Obsidian plugin (thin layer over ts/): type check + build. `npm install` in obsidian/ once
	cd obsidian && npm run build

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
