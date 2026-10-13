"""Shared fixtures: fixture repo copy, manifest/agent, opencomplai availability, captured samples, events."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

import aicl
from aicl.manifest import load_manifest, select_agent

PKG_FIXTURE = Path(aicl.__file__).parent / "fixture"
FIXTURE_SRC = PKG_FIXTURE / "shopper_insights"
EVENTS_DIR = PKG_FIXTURE / "events"
DATA_DIR = Path(__file__).parent / "data"


def _find_oc() -> str | None:
    p = Path(sys.executable).parent / "opencomplai"
    if p.is_file() and os.access(p, os.X_OK):
        return str(p)
    return shutil.which("opencomplai")


OC_BIN = _find_oc()
oc_available = pytest.mark.skipif(OC_BIN is None, reason="opencomplai binary not found")


def pytest_collection_modifyitems(config, items):
    if OC_BIN is None:
        for item in items:
            if "external" in item.keywords:
                item.add_marker(pytest.mark.skip(reason="opencomplai binary not found"))


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch):
    """Offline and deterministic: no credentials, no ambient manifest/agent selection."""
    for k in list(os.environ):
        if k.startswith("ANTHROPIC_") or k in ("AICL_MANIFEST", "AICL_AGENT_ID", "AICL_FAIL_CLOSED", "CLAUDE_PROJECT_DIR"):
            monkeypatch.delenv(k, raising=False)


@pytest.fixture
def fixture_repo(tmp_path) -> Path:
    """A private copy of the shopper-insights fixture (never write into src/aicl/fixture)."""
    dst = tmp_path / "shopper-insights"
    shutil.copytree(FIXTURE_SRC, dst)
    return dst


@pytest.fixture
def manifest(fixture_repo):
    return load_manifest(fixture_repo / "system-manifest.json")


@pytest.fixture
def agent(manifest):
    return select_agent(manifest, None, {})


@pytest.fixture
def oc_bin() -> str:
    if OC_BIN is None:
        pytest.skip("opencomplai binary not found")
    return OC_BIN


@pytest.fixture
def samples():
    """samples("check") -> parsed tests/data/check.sample.json (skips when not captured yet)."""
    def load(name: str):
        p = DATA_DIR / (name if name.endswith(".json") else f"{name}.sample.json")
        if not p.is_file():
            pytest.skip(f"sample {p.name} not captured (run make samples)")
        return json.loads(p.read_text("utf-8"))
    return load


@pytest.fixture
def events(fixture_repo) -> dict[str, dict]:
    """Every fixture hook event keyed by file stem, with cwd rewritten to the fixture copy."""
    out = {}
    for p in sorted(EVENTS_DIR.glob("*.json")):
        ev = json.loads(p.read_text("utf-8"))
        ev["cwd"] = str(fixture_repo)
        out[p.stem] = ev
    return out
