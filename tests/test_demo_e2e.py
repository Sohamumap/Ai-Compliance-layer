"""External: `aicl demo` end to end (real hook subprocesses, real opencomplai), plus the named-failure path."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from aicl import demo

pytestmark = pytest.mark.external

PHRASES = ("Art. 12 MISSING", "Art. 14 PARTIAL", "DENY [destructive_shell]", "<redacted:anthropic_key>",
           "[approved by human]", "chain broken at seq 3", "error: count", "Art. 12 PARTIAL",
           "PROHIBITED Art. 5(1)(g)", "EU_AIA_ART6_HIGH_RISK", "7/7 steps passed",
           # honest framing (review honesty-1, honesty-3)
           "classified the declared purpose high-risk (Art. 6", "its Art. 5 rule stayed silent",
           "which is an interpretation", "gaps finds agent-log.jsonl by path")
OVERCLAIMS = ("runtime decisions became EU AI Act evidence", "Opencomplai Art. 5 rule: still silent")


def test_demo_end_to_end(tmp_path, oc_bin):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}
    t0 = time.monotonic()
    p = subprocess.run([sys.executable, "-m", "aicl", "demo", "--no-color", "--workdir", str(tmp_path),
                        "--opencomplai", oc_bin], capture_output=True, text=True, timeout=120, env=env)
    elapsed = time.monotonic() - t0
    assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-2000:]
    assert elapsed < 60
    missing = [x for x in PHRASES if x not in p.stdout]
    assert not missing, missing
    assert not [x for x in OVERCLAIMS if x in p.stdout]
    assert "\033[" not in p.stdout and "sk-ant" not in p.stdout
    for n in demo.ARTIFACTS:                                        # --workdir keeps everything
        assert (tmp_path / "shopper-insights" / n).is_file(), n


def test_failing_step_is_named_and_exits_1(tmp_path, oc_bin, monkeypatch, capsys):
    def boom(self):
        raise demo.StepFailed("Art. 12 expected MISSING, got PARTIAL")
    monkeypatch.setattr(demo, "STEPS", (("Fixture and baseline", boom),) + demo.STEPS[1:])
    args = SimpleNamespace(workdir=None, keep=False, no_color=True, judge="off", opencomplai=oc_bin)
    assert demo.cmd_demo(args) == 1
    out = capsys.readouterr().out
    assert "FAILED [1/7] Fixture and baseline: StepFailed: Art. 12 expected MISSING" in out
    assert "steps passed" not in out and "deleted" in out
