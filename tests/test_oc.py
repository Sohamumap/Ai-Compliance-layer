"""oc.py: parsers over captured samples (no binary), subprocess plumbing via a tiny fake, and external runs."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from aicl import oc
from aicl.core import OcError, OcNotFound
from aicl.init_cmd import run_init

GOLDEN_HEAD = "sha256:6296df0b804ee2e68dba9bfe8e0be342547f04f8470e5fb1abe8e79d7c99a2ad"
GOLDEN_LINE = (
    '{"hash": "sha256:6296df0b804ee2e68dba9bfe8e0be342547f04f8470e5fb1abe8e79d7c99a2ad", "payload": {"agent_id": '
    '"claude-code", "input_hash": "sha256:fd226d98d55cbca664a0584f63c4d8089992012089f935deed358ca13700ecab", '
    '"intent": "fix typo in README", "mandate_ref": "mandate:claude-code", "outcome": "success", "outside_mandate": '
    'false, "tool": "Edit"}, "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000", '
    '"seq": 1, "signature": null, "ts": "2026-10-13T10:00:00+00:00"}\n')


def fake_bin(tmp_path: Path, body: str, name: str = "fake-oc") -> str:
    p = tmp_path / name
    p.write_text(f"#!{sys.executable}\nimport json, os, sys, time\n{body}\n", "utf-8")
    p.chmod(0o755)
    return str(p)


# ---- parsers over captured samples --------------------------------------------------------------
def test_parse_check_sample(samples, tmp_path):
    c = oc.parse_check(samples("check"), 1, tmp_path)
    assert c.exit_code == 1 and c.result == "control_fail"
    assert c.failed_controls == ("CODE_CORROBORATION_GAP",)
    assert c.scan_severity == "major" and c.detected_categories == ("biometric",) and c.discrepancies == ("biometric",)
    assert c.gap("Art. 12").status == "partial" and c.gap("Art. 14").status == "partial"
    assert c.gap("Art. 15").status == "partial" and c.gap("Art. 99") is None
    assert c.log_entries == 1 and "sha256:" + c.log_head_hex == GOLDEN_HEAD
    assert c.cli_version == "0.12.0"
    assert c.artifact_path == tmp_path / "compliance-artifact.json" and c.scan_report_path == tmp_path / "scan-report.json"


def test_parse_check_patched_sample(samples, tmp_path):
    c = oc.parse_check(samples("check_patched"), 1, tmp_path)
    assert c.failed_controls == ("EU_AIA_ART6_HIGH_RISK", "EU_AIA_ART6_PROFILING")
    assert c.scan_severity == "none" and c.discrepancies == ()
    assert "EU_AIA_ART5_UNACCEPTABLE" not in c.failed_controls


def test_parse_check_tolerates_missing_keys(tmp_path):
    c = oc.parse_check({}, 3, tmp_path)
    assert c.result == "policy_block" and c.failed_controls == () and c.gaps == ()
    assert c.scan_severity == "none" and c.log_entries is None and c.log_head_hex is None


def test_parse_verify_log_sample(samples):
    v = oc.parse_verify_log(samples("verify_log"), 1)
    assert v.status == "invalid" and v.chain_ok and v.count == 2 and v.error is None and v.bad_seq is None
    assert v.head.startswith("sha256:") and v.out_of_mandate_seqs == (2,)
    o = v.out_of_mandate[0]
    assert (o.agent_id, o.tool) == ("claude-code", "WebFetch")
    assert o.reasons == ("prohibited_action", "not_permitted", "self_reported")


def test_parse_gap_rows_samples(samples):
    before = {g.article: g.status for g in oc.parse_gap_rows(samples("gaps_before")["payload"]["articles"])}
    after = {g.article: g.status for g in oc.parse_gap_rows(samples("gaps_after")["payload"]["articles"])}
    assert [before[a] for a in ("Art. 12", "Art. 14", "Art. 15")] == ["missing"] * 3
    assert [after[a] for a in ("Art. 12", "Art. 14", "Art. 15")] == ["partial"] * 3


def test_agents_check_sample(samples):
    s = samples("agents_check")
    assert s["exit_code"] == 0 and s["findings"] == [] and s["expired_mandates"] == []


def test_parse_gap_rows_missing_keys():
    rows = oc.parse_gap_rows([{"article": "Art. 12"}, {"status": None}, "junk"])
    assert rows[0].article == "Art. 12" and rows[0].status == "" and rows[0].rationale == ""
    assert rows[1].article == "" and rows[1].status == "" and len(rows) == 2


def test_ocrun_payload():
    mk = lambda j: oc.OcRun(("x",), 0, "", "", j, 0.0)  # noqa: E731
    assert mk({"payload": {"a": 1}}).payload == {"a": 1}
    assert mk({"a": 1}).payload == {"a": 1}
    assert mk(None).payload == {} and mk([1]).payload == {}


# ---- subprocess plumbing (fake executable, no opencomplai) ---------------------------------------
def test_run_raw_decode_and_child_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key-000000000000")
    monkeypatch.setenv("AICL_KEEP_ME", "1")
    b = fake_bin(tmp_path, 'print(json.dumps({"argv": sys.argv[1:], "anth": [k for k in os.environ if k.startswith("ANTHROPIC_")],'
                           ' "keep": os.environ.get("AICL_KEEP_ME"), "cwd": os.getcwd()}))\nprint("WARN trailing text")')
    r = oc.run(["gaps", "-m", "m.json"], tmp_path, bin=b)
    assert r.exit_code == 0 and r.json["argv"] == ["gaps", "-m", "m.json"]
    assert r.json["anth"] == [] and r.json["keep"] == "1" and Path(r.json["cwd"]) == tmp_path
    assert r.argv == (b, "gaps", "-m", "m.json") and r.duration_s >= 0
    assert "ANTHROPIC_API_KEY" not in oc.child_env({"ANTHROPIC_API_KEY": "x", "ANTHROPIC_AUTH_TOKEN": "y", "PATH": "/b"})


def test_run_non_json_and_timeout(tmp_path):
    r = oc.run([], tmp_path, bin=fake_bin(tmp_path, 'print("Error: nope"); sys.exit(2)'))
    assert r.json is None and r.exit_code == 2
    with pytest.raises(OcError, match="timeout"):
        oc.run([], tmp_path, timeout=0.5, bin=fake_bin(tmp_path, "time.sleep(5)", "slow"))


def test_check_argv_and_errors(tmp_path):
    b = fake_bin(tmp_path, 'print(json.dumps({"result": "pass", "failed_controls": [], "argv": sys.argv[1:]}))')
    c = oc.check(tmp_path, tmp_path / "m.json", bin=b)
    assert c.exit_code == 0 and c.raw["argv"] == ["check", "-m", str(tmp_path / "m.json"), "--scan", "--repo-root",
                                                  str(tmp_path), "--with-gaps", "--fail-on", "major",
                                                  "--no-emit-evidence", "--output", "json"]
    with pytest.raises(OcError):
        oc.check(tmp_path, tmp_path / "m.json", bin=fake_bin(tmp_path, 'print(json.dumps({"result": "x"})); sys.exit(2)', "e2"))
    with pytest.raises(OcError, match="boom"):
        oc.check(tmp_path, tmp_path / "m.json", bin=fake_bin(tmp_path, 'sys.stderr.write("boom"); sys.exit(1)', "nojson"))


def test_verify_log_and_gaps_argv(tmp_path, monkeypatch):
    b = fake_bin(tmp_path, 'print(json.dumps({"status": "verified", "chain": {"ok": True, "count": 0, "head": ""},'
                           ' "payload": {"articles": [{"article": "Art. 12", "status": "missing"}]}, "argv": sys.argv[1:]}))')
    monkeypatch.chdir(tmp_path)   # relative paths are resolved against the caller's cwd before the child runs
    log, m = str(tmp_path / "log.jsonl"), str(tmp_path / "m.json")
    v = oc.verify_log(Path("log.jsonl"), Path("m.json"), tmp_path, expected_head="sha256:ab", expected_count=0, bin=b)
    assert v.raw["argv"] == ["agents", "verify-log", log, "-m", m, "-o", "json",
                             "--expected-head", "sha256:ab", "--expected-count", "0"]
    v = oc.verify_log(Path("log.jsonl"), Path("m.json"), tmp_path, bin=b)
    assert v.raw["argv"] == ["agents", "verify-log", log, "-m", m, "-o", "json"] and v.chain_ok
    rows = oc.gaps(Path("."), Path("m.json"), scan_report=Path("s.json"), bin=b)
    assert rows[0].article == "Art. 12" and rows[0].evidence_ref == ""
    with pytest.raises(OcError):
        oc.verify_log(Path("x"), Path("m"), tmp_path, bin=fake_bin(tmp_path, 'print("Error: cannot read"); sys.exit(2)', "e"))


def test_version(tmp_path):
    assert oc.version(fake_bin(tmp_path, 'print("opencomplai 9.9.9")')) == "9.9.9"
    assert oc.version(fake_bin(tmp_path, "sys.exit(1)", "bad")) == "unknown"
    assert oc.version(str(tmp_path / "missing")) == "unknown"


def test_opencomplai_bin_precedence(tmp_path, monkeypatch):
    a, e, s = (fake_bin(tmp_path, "pass", n) for n in ("a", "e", "opencomplai"))
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python"))
    assert oc.opencomplai_bin(a, {"AICL_OPENCOMPLAI": e}) == a
    assert oc.opencomplai_bin(None, {"AICL_OPENCOMPLAI": e}) == e
    assert oc.opencomplai_bin(None, {}) == s
    with pytest.raises(OcNotFound):
        oc.opencomplai_bin(str(tmp_path / "nope"), {})
    with pytest.raises(OcNotFound):
        oc.opencomplai_bin(None, {"AICL_OPENCOMPLAI": str(tmp_path / "nope")})
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(sys, "executable", str(empty / "python"))
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(OcNotFound):
        oc.opencomplai_bin(None, {})
    which_dir = tmp_path / "onpath"
    which_dir.mkdir()
    w = fake_bin(which_dir, "pass", "opencomplai")
    monkeypatch.setenv("PATH", str(which_dir))
    assert oc.opencomplai_bin(None, {}) == w


# ---- external: the real CLI on our fixture -----------------------------------------------------
@pytest.mark.external
def test_agents_check_fixture(fixture_repo, oc_bin):
    r = oc.agents_check(fixture_repo, fixture_repo / "system-manifest.json", bin=oc_bin)
    assert r.exit_code == 0 and r.json["findings"] == []


@pytest.mark.external
def test_check_fixture(fixture_repo, oc_bin):
    c = oc.check(fixture_repo, fixture_repo / "system-manifest.json", bin=oc_bin)
    assert c.exit_code == 1 and "CODE_CORROBORATION_GAP" in c.failed_controls
    assert c.scan_severity == "major" and "biometric" in c.detected_categories
    assert c.artifact_path.is_file() and c.scan_report_path.is_file()


@pytest.mark.external
def test_version_real(oc_bin):
    assert oc.version(oc_bin) == "0.12.0"


@pytest.mark.external
def test_verify_log_real(fixture_repo, oc_bin):
    log, m = fixture_repo / "agent-log.jsonl", fixture_repo / "system-manifest.json"
    log.write_text(GOLDEN_LINE, "utf-8")
    v = oc.verify_log(log, m, fixture_repo, expected_head=GOLDEN_HEAD, expected_count=1, bin=oc_bin)
    assert v.exit_code == 0 and v.status == "verified" and v.chain_ok and v.count == 1 and v.head == GOLDEN_HEAD
    v = oc.verify_log(log, m, fixture_repo, expected_count=2, bin=oc_bin)
    assert v.exit_code == 1 and v.error == "count" and not v.chain_ok
    with pytest.raises(OcError):
        oc.verify_log(fixture_repo / "missing.jsonl", m, fixture_repo, bin=oc_bin)


@pytest.mark.external
def test_gaps_lift(fixture_repo, oc_bin):
    m = fixture_repo / "system-manifest.json"

    def status() -> tuple[str, str, str]:
        rows = {g.article: g.status for g in oc.gaps(fixture_repo, m, bin=oc_bin)}
        return rows["Art. 12"], rows["Art. 14"], rows["Art. 15"]

    assert status() == ("missing", "missing", "missing")
    r = run_init(fixture_repo, m, oc_bin=oc_bin)
    assert r.agents_check_exit == 0 and r.oversight_written and r.manifest_changed
    assert status() == ("missing", "partial", "partial")
    (fixture_repo / "agent-log.jsonl").write_text(GOLDEN_LINE, "utf-8")
    assert status() == ("partial", "partial", "partial")
    # probe-drift guards. Verified 0.12.0: Art. 15 needs the guardrail evidence file; Art. 14 needs the manifest
    # human_oversight block (a tool requires approval), and the block alone keeps it PARTIAL without the doc.
    doc, raw = fixture_repo / "docs" / "human_oversight.md", json.loads(m.read_text("utf-8"))
    doc.unlink()
    assert status() == ("partial", "partial", "missing")
    m.write_text(json.dumps({k: v for k, v in raw.items() if k != "human_oversight"}), "utf-8")
    assert status() == ("partial", "missing", "missing")
