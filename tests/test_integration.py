"""External: real opencomplai 0.12.0. Patched manifest moves the controls; full aicl ci after the hook replay."""
from __future__ import annotations

import json
import shutil

import pytest

from aicl import ci, decisionlog, llm, oc, remediation, semantic
from aicl.demo import BLOCKED, replay
from aicl.manifest import load_manifest
from aicl.report import invariant_holds

pytestmark = pytest.mark.external


def test_patched_manifest_moves_controls(fixture_repo, manifest, oc_bin, tmp_path):
    check = oc.check(fixture_repo, manifest.path, bin=oc_bin)
    assert check.exit_code == 1 and "CODE_CORROBORATION_GAP" in check.failed_controls
    cls = semantic.classify_repo(fixture_repo, manifest.intended_purpose, manifest.high_risk_presumption)
    rem = remediation.build(manifest, check, cls, llm.judge(cls, manifest, mode="off"))
    assert rem is not None and rem.patch["high_risk_presumption"] is True and not rem.cures_gate
    copy = tmp_path / "patched"
    shutil.copytree(fixture_repo, copy)
    (copy / "system-manifest.json").write_text(json.dumps(remediation.apply_merge_patch(manifest.raw, rem.patch)), "utf-8")
    c2 = oc.check(copy, copy / "system-manifest.json", bin=oc_bin)
    assert c2.exit_code == 1
    assert c2.failed_controls == ("EU_AIA_ART6_HIGH_RISK", "EU_AIA_ART6_PROFILING")
    assert c2.scan_severity == "none" and "EU_AIA_ART5_UNACCEPTABLE" not in c2.failed_controls


def test_run_ci_after_hook_replay(fixture_repo, oc_bin):
    rows = replay(fixture_repo)
    assert [r.decision for r in rows] == ["allow", "logged", "deny", "deny", "deny", "deny", "ask", "logged", "deny"]
    log = fixture_repo / "agent-log.jsonl"
    entries = decisionlog.read_entries(log)
    assert {e.seq for e in entries if e.payload.outcome == "blocked"} == BLOCKED
    assert entries[5].payload.intent.startswith("[approved by human] Bash: curl (2 args)")
    before = (fixture_repo / "system-manifest.json").read_bytes()
    r, code = ci.run_ci(ci.CiOptions(repo=fixture_repo, manifest=fixture_repo / "system-manifest.json", judge="off",
                                     oc_bin=oc_bin, quiet=True), env={})
    assert code == 1 and r.verdict == "FAIL"
    assert r.local_verify.ok and r.verify.chain_ok and set(r.verify.out_of_mandate_seqs) == BLOCKED
    assert invariant_holds(r) is True and not any("chain" in x or "out-of-mandate" in x for x in r.verdict_reasons)
    md = (fixture_repo / "aicl-report.md").read_text("utf-8")
    assert "every out-of-mandate seq was blocked: yes (out_of_mandate ⊆ blocked)" in md
    assert "artifact head matches local head" in md
    assert "| 6 | Bash | success | [approved by human] Bash: curl (2 args)" in md
    assert "sk-ant" not in md and "sk-ant" not in (fixture_repo / "aicl-report.json").read_text("utf-8")
    assert (fixture_repo / "system-manifest.json").read_bytes() == before      # proposal only, never applied
    assert load_manifest(fixture_repo / "system-manifest.proposed.json").high_risk_presumption is True
