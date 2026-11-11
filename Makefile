# Dev shortcuts. Run `uv venv && uv pip install -e ".[dev]"` once first.
PY ?= .venv/bin/python

.PHONY: check test live ts plugin

check:  ## lint + types + tests (same as CI)
	$(PY) -m ruff check src tests scripts
	$(PY) -m mypy src
	$(PY) -m pytest -q

test:   ## tests only
	$(PY) -m pytest -q

live:   ## two-person test on REAL Telegram (needs profiles default + b); KEEP=dir keeps folders
	$(PY) scripts/live_e2e.py $(if $(KEEP),--keep $(KEEP))

ts:     ## TypeScript engine + Node CLI: type check, tests, and the Python CLI's sandbox tests run against the Node CLI. `npm install` in ts/ once
	cd ts && npm run typecheck && npm test
	TGSYNC_CLI="node $(CURDIR)/ts/dist/tgsync.mjs" $(PY) -m pytest -q tests/test_sandbox.py

plugin: ts ## Obsidian plugin (thin layer over ts/): type check + build. `npm install` in obsidian/ once
	cd obsidian && npm run build
