"""report.py: verdict matrix, markdown structure, terminal summary, JSON (dataclasses built directly)."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from aicl import report
from aicl.core import (Anchor, CheckResult, CiReport, Classification, Entry, Finding, GapRow, JudgeResult, OutOfMandate,
                       Payload, PendingRecord, Remediation, Tier, VerifyLogResult, VerifyResult, tier_rank)

HEAD = "sha256:" + "ab" * 32
KEY = "sk-ant-api03-" + "Q" * 40


def _check(code: int = 1, head_hex: str | None = "ab" * 32) -> CheckResult:
    gaps = tuple(GapRow(a, "partial" if a in ("Art. 12", "Art. 14") else "missing", "artifact", "ref", f"{a} rationale")
                 for a in ("Art. 5", "Art. 6", "Art. 12", "Art. 14", "Art. 15", "Art. 26", "Art. 50"))
    return CheckResult(code, "control_fail" if code else "pass", ("CODE_CORROBORATION_GAP",) if code else (), "major",
                       ("biometric",), ("biometric",), gaps, "0.12.0", 7, head_hex, Path("/r/compliance-artifact.json"),
                       Path("/r/scan-report.json"), {"disclaimer": "Opencomplai is not legal advice either.",
                                                     "summaries": {"agents": {"chain_valid": True}}})


def _finding(tier: Tier, symbol: str = "segment_shoppers", article: str = "Art. 5(1)(g)") -> Finding:
    return Finding("cat", tier, article, "Title", "src/insights.py", 20, symbol, ("face_encodings", "ethnicity"), 0.85,
                   "why")


def _cls(*findings: Finding, declared: Tier = Tier.MINIMAL) -> Classification:
    tier = max((f.tier for f in findings), key=tier_rank, default=Tier.MINIMAL)
    gap = tier_rank(tier) > tier_rank(declared) or any(f.tier is Tier.PROHIBITED for f in findings)
    return Classification(tier, findings, 1, 4, (), declared, (), gap, "summary")


def _judge(cls: Classification, used: bool = False, adjusted=None) -> JudgeResult:
    if not used:
        return JudgeResult(False, "auto", None, "no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN", (), cls.findings,
                           None, None, None)
    return JudgeResult(True, "auto", "claude-opus-5-5", None, ((0, "adjust", "ok"),), adjusted, None, None, None)


def _report(**kw) -> CiReport:
    cls = _cls(_finding(Tier.PROHIBITED), _finding(Tier.LIMITED, "summarise_sales", "Art. 50(1)"))
    oom = (OutOfMandate(2, "claude-code", "Bash", ("self_reported",)),
           OutOfMandate(4, "claude-code", "WebFetch", ("prohibited_action", "not_permitted", "self_reported")))
    base = dict(system_id="shopper-insights", repo="/r", manifest="/r/system-manifest.json",
                generated_at="2026-10-13T10:00:00+00:00", aicl_version="0.1.0", opencomplai_version="0.12.0",
                check=_check(), classification=cls,
                verify=VerifyLogResult(1, "invalid", True, 7, HEAD, None, None, oom, {}),
                local_verify=VerifyResult(True, 7, HEAD, None, None), anchor=Anchor(HEAD, 7, "t", "agent-log.jsonl"),
                unresolved_pending=(PendingRecord("tu-09", "Bash", "Bash: curl (1 args) | aicl:ask:network_egress",
                                                  "sha256:x", "network_egress", "t"),),
                remediation=Remediation({"high_risk_presumption": True}, {}, ("Remove or disable segment_shoppers.",),
                                        "Manifest patch sets high_risk_presumption.", False),
                judge=_judge(cls), verdict="FAIL", verdict_reasons=("opencomplai check exit 1 (control_fail)",),
                reproduce=("/bin/opencomplai check -m /r/system-manifest.json",))
    return CiReport(**{**base, **kw})


@pytest.mark.parametrize("code,findings,fail_on,want", [
    (0, (), "high_risk", "PASS"),
    (0, (_finding(Tier.PROHIBITED),), "high_risk", "FAIL"),
    (0, (_finding(Tier.HIGH_RISK, "match_faces", "Annex III 1(a)"),), "none", "PASS"),
    (0, (_finding(Tier.HIGH_RISK, "match_faces", "Annex III 1(a)"),), "high_risk", "FAIL"),
    (0, (_finding(Tier.LIMITED, "chat", "Art. 50(1)"),), "high_risk", "PASS"),
    (0, (_finding(Tier.LIMITED, "chat", "Art. 50(1)"),), "limited", "FAIL"),
    (1, (), "high_risk", "FAIL"),
])
def test_decide_verdict_matrix(code, findings, fail_on, want):
    cls = _cls(*findings)
    verdict, reasons = report.decide_verdict(_check(code), cls, _judge(cls), fail_on)
    assert verdict == want and bool(reasons) == (want == "FAIL")


def test_decide_verdict_reasons_text():
    cls = _cls(_finding(Tier.PROHIBITED))
    _, reasons = report.decide_verdict(_check(1), cls, _judge(cls), "high_risk")
    assert reasons == ("opencomplai check exit 1 (control_fail)", "prohibited finding: segment_shoppers Art. 5(1)(g)",
                       "declaration gap: code prohibited > declared minimal")


def test_decide_verdict_uses_judge_adjusted():
    cls = _cls(_finding(Tier.PROHIBITED))
    adjusted = (dataclasses.replace(cls.findings[0], tier=Tier.HIGH_RISK, source="claude-judge"),)
    verdict, reasons = report.decide_verdict(_check(0), cls, _judge(cls, True, adjusted), "prohibited")
    assert verdict == "PASS" and reasons == ()
    _, reasons = report.decide_verdict(_check(0), cls, _judge(cls, True, adjusted), "high_risk")
    assert reasons == ("declaration gap: code high_risk > declared minimal",)


def test_markdown_headings_in_order_and_blocks():
    md = report.render_markdown(_report())
    pos = [md.index(h + "\n") for h in report.HEADINGS]
    assert pos == sorted(pos) and md.startswith("# aicl compliance report\n")
    assert "| file:line | symbol | tier | article | evidence | confidence | source |" in md
    assert "| src/insights.py:20 | segment_shoppers | prohibited | Art. 5(1)(g) | face_encodings, ethnicity | 0.85 |" in md
    assert "| seq | tool | reasons |" in md and "| 4 | WebFetch | prohibited_action, not_permitted, self_reported |" in md
    assert "every out-of-mandate seq was blocked: yes (out_of_mandate ⊆ blocked)" in md
    assert report.VERIFY_EXIT_SENTENCE in md
    assert "artifact head matches local head" in md
    assert "Unresolved asks (pending > 10 min): 1" in md and "tu-09" in md
    assert "Judge: skipped (no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN; deterministic classification only)" in md
    assert "Heuristic evidence, not legal advice." in md and "Opencomplai is not legal advice either." in md
    assert "| Opencomplai said | aicl said |" in md
    for art in report.ARTICLES:
        assert f"| {art} |" in md
    assert "/bin/opencomplai check -m /r/system-manifest.json" in md


def test_markdown_variants():
    md = report.render_markdown(_report(verdict_reasons=("x", report.OOM_REASON), check=_check(head_hex="cd" * 32),
                                        remediation=None))
    assert "every out-of-mandate seq was blocked: no" in md
    assert "differs from local head" in md and "No remediation needed." in md
    md = report.render_markdown(_report(verify=None, local_verify=None, anchor=None, unresolved_pending=()))
    assert "No decision log found" in md and "out-of-mandate seq" not in md


def test_markdown_lists_log_entries():
    intent = "[approved by human] Bash: curl (2 args): Fetch pricing | aicl:ask:network_egress"
    e = Entry(6, "t", Payload("claude-code", "mandate:claude-code", intent, "Bash", "sha256:x", "success", False), HEAD, HEAD)
    md = report.render_markdown(_report(log_entries=(e,)))
    assert "| seq | tool | outcome | intent |" in md and f"| 6 | Bash | success | {intent.replace('|', chr(92) + '|')} |" in md
    assert "Decision log entries" not in report.render_markdown(_report())


def test_markdown_redacts_secrets():
    cls = _cls(dataclasses.replace(_finding(Tier.PROHIBITED), evidence=(KEY,)))
    md = report.render_markdown(_report(classification=cls, judge=_judge(cls)))
    assert KEY not in md and "<redacted:anthropic_key>" in md


def test_terminal_short_and_colour():
    plain = report.render_terminal(_report(), color=False)
    assert len(plain.splitlines()) <= 25 and "\033[" not in plain
    assert plain.splitlines()[0] == "aicl ci: FAIL (shopper-insights)"
    assert "segment_shoppers PROHIBITED Art. 5(1)(g) (face_encodings + ethnicity) 0.85" in plain
    assert "out_of_mandate ⊆ blocked: yes" in plain and "Judge: skipped" in plain
    assert "\033[31mFAIL\033[0m" in report.render_terminal(_report(), color=True)
    many = _cls(*[_finding(Tier.LIMITED, f"f{i}", "Art. 50(1)") for i in range(40)])
    lines = report.render_terminal(_report(classification=many, judge=_judge(many),
                                           verdict_reasons=tuple(f"r{i}" for i in range(20))), False).splitlines()
    assert len(lines) <= 25


def test_to_json_and_write(tmp_path):
    r = _report()
    data = json.loads(report.to_json(r))
    assert data["classification"]["findings"][0]["tier"] == "prohibited"
    assert data["classification"]["declared_tier"] == "minimal"
    assert data["check"]["artifact_path"] == "/r/compliance-artifact.json"
    assert data["verify"]["out_of_mandate"][1]["reasons"] == ["prohibited_action", "not_permitted", "self_reported"]
    md, js = report.write(r, tmp_path)
    assert md.name == "aicl-report.md" and js.name == "aicl-report.json"
    assert json.loads(js.read_text("utf-8"))["verdict"] == "FAIL"
