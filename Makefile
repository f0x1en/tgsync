# Dev shortcuts. Run `uv venv && uv pip install -e ".[dev]"` once first.
PY ?= .venv/bin/python

.PHONY: check test live

check:  ## lint + types + tests (same as CI)
	$(PY) -m ruff check src tests scripts
	$(PY) -m mypy src
	$(PY) -m pytest -q

test:   ## tests only
	$(PY) -m pytest -q

live:   ## two-person test on REAL Telegram (needs profiles default + b); KEEP=dir keeps folders
	$(PY) scripts/live_e2e.py $(if $(KEEP),--keep $(KEEP))
