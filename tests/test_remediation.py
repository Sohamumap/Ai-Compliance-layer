"""RFC 7386 remediation patch, code actions and writers (DESIGN 4.9)."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from aicl.core import CheckResult, GapRow, JudgeResult, Tier
from aicl.manifest import load_manifest, oversight_block
from aicl.remediation import apply_merge_patch, build, write
from aicl.semantic import CATEGORIES, classify_repo


def _check(exit_code=1, statuses=("missing", "missing", "missing"), discrepancies=("biometric",)) -> CheckResult:
    gaps = tuple(GapRow(a, s, "artifact", "", "") for a, s in zip(("Art. 12", "Art. 14", "Art. 15"), statuses))
    return CheckResult(exit_code, "control_fail" if exit_code else "pass", ("CODE_CORROBORATION_GAP",) if exit_code else (),
                       "major" if discrepancies else "none", discrepancies, discrepancies, gaps, "0.12.0", None, None,
                       Path("compliance-artifact.json"), Path("scan-report.json"), {})


def _off(cls) -> JudgeResult:
    return JudgeResult(False, "off", None, "mode=off", (), cls.findings, None, None, None)


def _cls(manifest):
    return classify_repo(manifest.root, manifest.intended_purpose, manifest.high_risk_presumption)


def test_none_when_nothing_to_fix(fixture_repo, manifest):
    (fixture_repo / "src" / "insights.py").write_text("def top(rows):\n    return rows[:3]\n")
    cls = _cls(manifest)
    assert build(manifest, _check(0, ("partial",) * 3, ()), cls, _off(cls)) is None
    assert build(manifest, _check(0, ("partial", "missing", "partial"), ()), cls, _off(cls)) is not None


def test_fixture_patch(manifest):
    cls = _cls(manifest)
    rem = build(manifest, _check(), cls, _off(cls))
    p = rem.patch
    assert set(p) == {"intended_purpose", "high_risk_presumption", "known_limitations", "human_oversight"}
    addenda = [c.addendum for c in CATEGORIES if c.id in ("art5_1g_biometric_categorisation", "art50_llm_user_interaction")]
    assert p["intended_purpose"] == manifest.intended_purpose + " " + " ".join(addenda)
    assert p["high_risk_presumption"] is True
    assert len(p["known_limitations"]) == 1 and p["known_limitations"][0].startswith("segment_shoppers (src/insights.py:20)")
    assert "Art. 5(1)(g)" in p["known_limitations"][0]
    assert p["human_oversight"] == oversight_block()
    assert "agent_inventory" not in p          # fixture already declares guardrails and logging
    assert rem.cures_gate is False
    assert rem.code_actions[0] == ("Remove or disable segment_shoppers (src/insights.py:20): "
                                   "Biometric categorisation inferring sensitive attributes — Art. 5(1)(g).")
    assert "Run aicl init and let the hook write agent-log.jsonl." in rem.code_actions
    assert not any(a.startswith("Reconcile") for a in rem.code_actions)
    pm = rem.patched_manifest
    assert pm["high_risk_presumption"] is True and pm["agent_inventory"] == manifest.raw["agent_inventory"]
    assert manifest.raw["high_risk_presumption"] is False     # the input is never mutated


def test_agent_inventory_patched_on_declaration_gap(fixture_repo):
    raw = json.loads((fixture_repo / "system-manifest.json").read_text())
    agent = raw["agent_inventory"]["agents"][0]
    del agent["guardrails"], agent["logging"]
    (fixture_repo / "system-manifest.json").write_text(json.dumps(raw))
    m = load_manifest(fixture_repo / "system-manifest.json")
    cls = _cls(m)
    rem = build(m, _check(), cls, _off(cls))
    a = rem.patch["agent_inventory"]["agents"][0]
    assert a["guardrails"] == [{"kind": "runtime_policy_hook", "evidence_ref": "docs/human_oversight.md"}]
    assert a["logging"]["decision_log_ref"] == "agent-log.jsonl" and a["tools"] == agent["tools"]


def test_cures_gate_and_judge_override(manifest):
    cls = _cls(manifest)
    seg = next(f for f in cls.findings if f.symbol == "segment_shoppers")
    hr = dataclasses.replace(seg, category_id="annex3_1a_biometric_identification", tier=Tier.HIGH_RISK,
                             article="Annex III 1(a) via Art. 6(2)", source="claude-judge")
    jr = JudgeResult(True, "auto", "m", None, ((1, "adjust", "x"),), (hr,), "It identifies shoppers by face.", None, None)
    rem = build(manifest, _check(discrepancies=()), cls, jr)
    assert rem.cures_gate is True
    assert rem.patch["intended_purpose"] == manifest.intended_purpose + " It identifies shoppers by face."
    assert rem.patch["high_risk_presumption"] is True and "known_limitations" not in rem.patch
    assert any(a.startswith("Complete Annex IV fields") for a in rem.code_actions)


def test_discrepancy_only_action(fixture_repo, manifest):
    (fixture_repo / "src" / "insights.py").write_text("def top(rows):\n    return rows[:3]\n")
    cls = _cls(manifest)
    rem = build(manifest, _check(1, ("partial",) * 3, ("biometric",)), cls, _off(cls))
    assert rem.patch == {} and rem.cures_gate
    assert rem.code_actions == ("Reconcile scan discrepancy categories: biometric.",)


def test_apply_merge_patch_rfc7386():
    doc = {"a": 1, "b": {"c": 1, "d": 2}, "l": [1]}
    assert apply_merge_patch(doc, {"a": None, "b": {"c": 9}, "l": [2, 3]}) == {"b": {"c": 9, "d": 2}, "l": [2, 3]}
    assert doc == {"a": 1, "b": {"c": 1, "d": 2}, "l": [1]}
    assert apply_merge_patch({"a": "x"}, {"a": {"b": "c", "z": None}}) == {"a": {"b": "c"}}
    assert apply_merge_patch({"a": [{"x": 1}]}, {"a": [{"y": 2}]}) == {"a": [{"y": 2}]}
    assert apply_merge_patch({"k": 1}, {"missing": None}) == {"k": 1}


def test_write_three_files_original_untouched(fixture_repo, manifest, tmp_path):
    before = (fixture_repo / "system-manifest.json").read_bytes()
    cls = _cls(manifest)
    rem = build(manifest, _check(), cls, _off(cls))
    out = tmp_path / "out"
    patch_p, md_p, proposed_p = write(rem, out, manifest.path)
    assert (fixture_repo / "system-manifest.json").read_bytes() == before
    assert json.loads(patch_p.read_text()) == rem.patch
    assert json.loads(proposed_p.read_text()) == rem.patched_manifest
    md = md_p.read_text()
    assert "opencomplai check -m" in md and str(proposed_p.resolve()) in md
    assert "cannot be cured by declaration" in md and "Remove or disable segment_shoppers" in md
    assert sorted(p.name for p in out.iterdir()) == ["aicl-remediation.md", "aicl-remediation.patch.json",
                                                    "system-manifest.proposed.json"]
