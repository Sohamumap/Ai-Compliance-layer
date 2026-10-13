# aicl v0. opencomplai 0.12.0 is a tool dependency (dev extra), reached only via subprocess, never imported.
PY := .venv/bin/python

.PHONY: install test demo boundary samples

install:
	@test -x $(PY) || uv venv .venv
	uv pip install --python $(PY) -e '.[dev,llm]'

test:
	.venv/bin/pytest -q

demo:
	.venv/bin/aicl demo

boundary:
	.venv/bin/pytest -q tests/test_boundary.py

samples:
	$(PY) scripts/capture_samples.py
