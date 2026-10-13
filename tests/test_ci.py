"""aicl ci orchestration against tests/fake_opencomplai.py (offline, no credentials)."""
from __future__ import annotations

import json
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from aicl import decisionlog, report
from aicl.ci import CiOptions, blocked_seqs, cmd_ci, oc_exit_code, run_ci
from aicl.core import OcError, OcNotFound
from aicl.remediation import PATCH_NAME, PROPOSED_NAME

FAKE = Path(__file__).parent / "fake_opencomplai.py"


def _exe(tmp_path: Path, name: str, body: str) -> str:
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body + "\n", "utf-8")
    p.chmod(0o755)
    return str(p)


@pytest.fixture
def fake_oc(tmp_path, monkeypatch) -> str:
    path = _exe(tmp_path, "opencomplai", f'exec "{sys.executable}" "{FAKE}" "$@"')
    monkeypatch.setenv("AICL_OPENCOMPLAI", path)
    for k in ("FAKE_OC_EXIT", "FAKE_OC_GAPS", "NO_COLOR"):
        monkeypatch.delenv(k, raising=False)
    return path


def _opts(repo: Path, **kw) -> CiOptions:
    return CiOptions(repo=repo, manifest=repo / "system-manifest.json", **kw)


def _args(repo: Path, **kw) -> Namespace:
    base = dict(repo=repo, manifest=repo / "system-manifest.json", fail_on="major", semantic_fail_on="high_risk",
                judge="off", out_dir=None, opencomplai=None, quiet=True, no_color=True)
    return Namespace(**{**base, **kw})


def _log(repo: Path, agent, outcomes: list[tuple[str, str]]) -> Path:
    log = repo / "agent-log.jsonl"
    for tool, outcome in outcomes:
        p = decisionlog.make_payload(agent, f"{tool}: test | aicl:x:y", tool, {"t": tool}, outcome, outcome == "blocked")
        decisionlog.append(log, p)
    return log


def test_run_ci_fixture_fail_writes_everything(fixture_repo, fake_oc):
    rep, code = run_ci(_opts(fixture_repo, judge="auto"))
    assert code == 1 and rep.verdict == "FAIL"
    assert rep.check.exit_code == 1 and "CODE_CORROBORATION_GAP" in rep.check.failed_controls
    assert "opencomplai check exit 1 (control_fail)" in rep.verdict_reasons
    assert "prohibited finding: segment_shoppers Art. 5(1)(g)" in rep.verdict_reasons
    assert rep.judge.used is False and "ANTHROPIC_API_KEY" in rep.judge.skipped_reason
    assert rep.verify is None and rep.local_verify is None
    assert len(rep.reproduce) == 1 and rep.reproduce[0].startswith(fake_oc + " check -m ")
    for name in ("aicl-report.md", "aicl-report.json", PATCH_NAME, "aicl-remediation.md", PROPOSED_NAME):
        assert (fixture_repo / name).is_file(), name
    md = (fixture_repo / "aicl-report.md").read_text("utf-8")
    assert "Judge: skipped (no ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN; deterministic classification only)" in md
    assert fake_oc in md
    data = json.loads((fixture_repo / "aicl-report.json").read_text("utf-8"))
    assert data["verdict"] == "FAIL" and data["classification"]["tier"] == "prohibited"
    assert json.loads((fixture_repo / "system-manifest.json").read_text("utf-8")).get("high_risk_presumption") is False


def test_out_dir(fixture_repo, fake_oc, tmp_path):
    out = tmp_path / "out"
    run_ci(_opts(fixture_repo, judge="off", out_dir=out))
    assert (out / "aicl-report.md").is_file() and (out / PROPOSED_NAME).is_file()
    assert not (fixture_repo / "aicl-report.md").exists()


def test_semantic_fail_on_none_still_fails_on_gate(fixture_repo, fake_oc):
    rep, code = run_ci(_opts(fixture_repo, judge="off", semantic_fail_on="none"))
    assert code == 1 and not any(r.startswith("declaration gap") for r in rep.verdict_reasons)


def test_log_with_good_anchor_invariant_holds(fixture_repo, fake_oc, agent):
    log = _log(fixture_repo, agent, [("Edit", "success"), ("WebFetch", "blocked")])
    assert blocked_seqs(log) == frozenset({2})
    rep, code = run_ci(_opts(fixture_repo, judge="off"))
    assert rep.local_verify.ok and rep.anchor.count == 2 and rep.verify.out_of_mandate_seqs == (2,)
    assert report.CHAIN_REASON not in rep.verdict_reasons and report.OOM_REASON not in rep.verdict_reasons
    assert any(" agents verify-log " in x and "--expected-count 2" in x for x in rep.reproduce)
    md = (fixture_repo / "aicl-report.md").read_text("utf-8")
    assert "every out-of-mandate seq was blocked: yes (out_of_mandate ⊆ blocked)" in md
    assert "| 2 | WebFetch | prohibited_action, not_permitted, self_reported |" in md


def test_tampered_anchor_fails(fixture_repo, fake_oc, agent):
    log = _log(fixture_repo, agent, [("Edit", "success"), ("WebFetch", "blocked")])
    a = decisionlog.anchor_path(log)
    d = json.loads(a.read_text("utf-8"))
    d["count"] = 5
    a.write_text(json.dumps(d), "utf-8")
    rep, code = run_ci(_opts(fixture_repo, judge="off"))
    assert code == 1 and report.CHAIN_REASON in rep.verdict_reasons
    assert rep.local_verify.error == "anchor_count" and rep.verify.chain_ok is False
    assert "chain broken or anchor mismatch" in (fixture_repo / "aicl-report.md").read_text("utf-8")


def test_out_of_mandate_executed_fails(fixture_repo, fake_oc, agent):
    _log(fixture_repo, agent, [("Edit", "success"), ("WebFetch", "success")])
    rep, _ = run_ci(_opts(fixture_repo, judge="off"))
    assert report.OOM_REASON in rep.verdict_reasons
    assert "every out-of-mandate seq was blocked: no" in (fixture_repo / "aicl-report.md").read_text("utf-8")


def test_blocked_seqs_missing_or_bad_log(tmp_path):
    assert blocked_seqs(tmp_path / "none.jsonl") == frozenset()
    (tmp_path / "bad.jsonl").write_text("{not json\n", "utf-8")
    assert blocked_seqs(tmp_path / "bad.jsonl") == frozenset()


def test_cmd_ci_exit_codes(fixture_repo, fake_oc, monkeypatch, capsys):
    assert cmd_ci(_args(fixture_repo)) == 1
    assert capsys.readouterr().out.strip() == "aicl ci: FAIL"
    assert cmd_ci(_args(fixture_repo, quiet=False)) == 1
    out = capsys.readouterr().out
    assert len(out.strip().splitlines()) <= 25 and "\033[" not in out
    monkeypatch.setenv("FAKE_OC_EXIT", "2")
    assert cmd_ci(_args(fixture_repo)) == 2                     # validation_fail is a config error
    monkeypatch.delenv("FAKE_OC_EXIT")
    assert cmd_ci(_args(fixture_repo, judge="llm")) == 2        # no credential
    assert cmd_ci(_args(fixture_repo, manifest=fixture_repo / "nope.json")) == 2


def test_missing_binary_exit_3(fixture_repo, monkeypatch):
    monkeypatch.setenv("AICL_OPENCOMPLAI", "/nonexistent/opencomplai")
    with pytest.raises(OcNotFound):
        run_ci(_opts(fixture_repo, judge="off"))
    assert cmd_ci(_args(fixture_repo)) == 3


def test_unparseable_output_exit_3(fixture_repo, tmp_path, monkeypatch):
    monkeypatch.setenv("AICL_OPENCOMPLAI", _exe(tmp_path, "garbage-oc", "echo not json; exit 1"))
    assert cmd_ci(_args(fixture_repo)) == 3


def test_oc_exit_code():
    assert oc_exit_code(OcError("opencomplai check -m exit 2: bad manifest")) == 2
    assert oc_exit_code(OcError("timeout")) is None
    e = OcError("x")
    e.exit_code = 4
    assert oc_exit_code(e) == 4

