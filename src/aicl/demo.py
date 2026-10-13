"""aicl demo: the seven-step acceptance narrative (DESIGN section 7), every beat asserted, offline, real subprocesses."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Callable

from aicl import ci, decisionlog, oc, semantic
from aicl.core import AiclError, Entry, OcNotFound, Tier
from aicl.init_cmd import run_init
from aicl.manifest import MANIFEST_NAME, load_manifest, log_path, select_agent
from aicl.report import invariant_holds, render_terminal

__all__ = ["StepFailed", "ReplayRow", "REPLAY", "BLOCKED", "copy_fixture", "replay", "cmd_demo"]

# (event file stem, expected decision, expected rule id) in replay order; DESIGN section 6
REPLAY = (("01_pre_edit", "allow", None), ("01_post_edit", "logged", None),
          ("02_pre_bash_rm", "deny", "destructive_shell"), ("03_pre_bash_secret", "deny", "secret_in_input"),
          ("04_pre_webfetch", "deny", "tool_prohibited"), ("05_pre_mcp", "deny", "mcp_server_not_allowed"),
          ("06_pre_bash_curl", "ask", "network_egress"), ("06_post_bash_curl", "logged", None),
          ("07_pre_edit_settings", "deny", "self_protect"))
BLOCKED = frozenset({2, 3, 4, 5, 7})
ARTS = ("Art. 12", "Art. 14", "Art. 15")
ART6 = ("EU_AIA_ART6_HIGH_RISK", "EU_AIA_ART6_PROFILING")
ARTIFACTS = ("agent-log.jsonl", ".aicl/log-anchor.json", "docs/human_oversight.md", "scan-report.json",
             "compliance-artifact.json", "aicl-report.md", "aicl-report.json", "aicl-remediation.patch.json",
             "system-manifest.proposed.json")


class StepFailed(AiclError):
    """An asserted demo beat did not match."""


def expect(cond: Any, msg: str) -> None:
    if not cond:
        raise StepFailed(msg)


@dataclass(frozen=True)
class ReplayRow:
    stem: str; tool: str; decision: str; rule: str | None; stdout: str; exit_code: int; entries: tuple[Entry, ...]
    pending: bool              # a pending ASK record for this tool_use_id exists right after the hook ran


def _fixture(*parts: str) -> Any:
    return resources.files("aicl").joinpath("fixture", *parts)


def _copy_tree(src: Any, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for c in src.iterdir():
        if c.is_dir():
            if c.name != "__pycache__":
                _copy_tree(c, dst / c.name)
        else:
            (dst / c.name).write_bytes(c.read_bytes())


def copy_fixture(workdir: Path) -> Path:
    """Copy the packaged shopper_insights fixture to <workdir>/shopper-insights (via importlib.resources)."""
    repo = workdir / "shopper-insights"
    shutil.rmtree(repo, ignore_errors=True)
    _copy_tree(_fixture("shopper_insights"), repo)
    return repo


def replay(repo: Path) -> list[ReplayRow]:
    """Feed every fixture event (cwd rewritten to repo) to a real `python -m aicl hook pre|post` subprocess."""
    m = load_manifest(repo / MANIFEST_NAME)
    log = log_path(m, select_agent(m, None, {}))
    env = {k: v for k, v in os.environ.items() if k not in ("AICL_MANIFEST", "AICL_AGENT_ID", "AICL_FAIL_CLOSED")}
    env["CLAUDE_PROJECT_DIR"] = str(repo)
    rows = []
    for stem, _, _ in REPLAY:
        ev = json.loads(_fixture("events", f"{stem}.json").read_text("utf-8"))
        ev["cwd"] = str(repo)
        before = len(decisionlog.read_entries(log))
        p = subprocess.run([sys.executable, "-m", "aicl", "hook", "pre" if "_pre_" in stem else "post"],
                           input=json.dumps(ev), capture_output=True, text=True, env=env, cwd=repo, timeout=60)
        out = p.stdout.strip()
        if out:
            hso = json.loads(out)["hookSpecificOutput"]
            decision, reason = hso["permissionDecision"], hso["permissionDecisionReason"]
            rule = (re.search(r"\[(\w+)\]", reason) or [None, None])[1]
        else:
            decision, rule = ("allow" if "_pre_" in stem else "logged"), None
        rows.append(ReplayRow(stem, ev["tool_name"], decision, rule, out, p.returncode,
                              tuple(decisionlog.read_entries(log)[before:]),
                              (decisionlog.pending_dir(log) / f"{ev.get('tool_use_id')}.json").exists()))
    return rows


class Demo:
    def __init__(self, workdir: Path, bin_: str, judge: str, color: bool) -> None:
        self.workdir, self.bin, self.judge, self.color = workdir, bin_, judge, color
        self.repo = workdir / "shopper-insights"
        self.manifest = self.repo / MANIFEST_NAME
        self.log = self.repo / "agent-log.jsonl"
        self.report: Any = None

    def gaps(self, want: dict[str, str]) -> dict[str, Any]:
        rows = {r.article: r for r in oc.gaps(self.repo, self.manifest, bin=self.bin)}
        print("  opencomplai gaps: " + " | ".join(
            f"{a} {rows[a].status.upper() if a in rows else '?'} ({rows[a].evidence_ref if a in rows else ''})" for a in ARTS))
        for a, status in want.items():
            expect(a in rows and rows[a].status == status, f"{a} expected {status.upper()}, got "
                   f"{rows[a].status.upper() if a in rows else 'no row'}")
        return rows

    def step1(self) -> None:
        copy_fixture(self.workdir)
        m = load_manifest(self.manifest)
        a = select_agent(m, None, {})
        print(f"  purpose: {m.intended_purpose}")
        print(f"  agent {a.id}: permitted {', '.join(a.mandate.permitted_actions)}; prohibited "
              f"{', '.join(a.mandate.prohibited_actions)}; {len(a.mandate.limits)} limits knobs; log {a.decision_log_ref}")
        self.gaps({art: "missing" for art in ARTS})

    def step2(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            r = run_init(self.repo, self.manifest, oc_bin=self.bin)
        print("".join(f"  {line}\n" for line in buf.getvalue().splitlines()), end="")
        expect(r.settings_changed and r.oversight_written and r.manifest_changed, "aicl init changed nothing")
        expect(r.agents_check_exit == 0, f"opencomplai agents check exit {r.agents_check_exit}, expected 0")
        self.gaps({"Art. 12": "missing", "Art. 14": "partial", "Art. 15": "partial"})
        print("  declaration lift (Art. 14, 15) vs evidence lift (Art. 12, needs the log) is now visible")

    def step3(self) -> None:
        shown = False
        for i, (row, (stem, want, rule)) in enumerate(zip(replay(self.repo), REPLAY), 1):
            label = row.decision.upper() + (f" [{row.rule}]" if row.rule else "")
            print(f"  #{i} {stem:<21} {row.tool:<25} -> {label}")
            for e in row.entries:
                print(f"       seq={e.seq} {e.payload.outcome} outside_mandate={str(e.payload.outside_mandate).lower()}"
                      f"  intent: {e.payload.intent}")
            if row.decision == "deny" and not shown:
                print(f"       hook stdout: {row.stdout}")
                shown = True
            expect(row.exit_code == 0, f"{stem}: hook exit {row.exit_code}")
            expect((row.decision, row.rule) == (want, rule), f"{stem}: got {label}, expected {want} {rule or ''}")
            expect(len(row.entries) == (1 if want in ("deny", "logged") else 0), f"{stem}: {len(row.entries)} log entries")
            if want == "deny":
                expect(row.entries[0].payload.outcome == "blocked" and row.entries[0].payload.outside_mandate,
                       f"{stem}: not logged as blocked")
            if want == "logged":
                expect(row.entries[0].payload.outcome == "success", f"{stem}: outcome {row.entries[0].payload.outcome}")
            expect(row.pending == (want == "ask"), f"{stem}: pending ASK record {'missing' if want == 'ask' else 'left'}")
            if stem.startswith("03"):
                intent = row.entries[0].payload.intent
                expect("<redacted:anthropic_key>" in intent and "sk-ant" not in intent, "03: intent not redacted")
            if stem == "06_post_bash_curl":
                expect(row.entries[0].payload.intent.startswith("[approved by human] Bash: curl (2 args)"),
                       "06: missing [approved by human] prefix")
        entries = decisionlog.read_entries(self.log)
        blocked = {e.seq for e in entries if e.payload.outcome == "blocked"}
        print(f"  {len(entries)} chained entries; blocked seqs {sorted(blocked)}")
        expect(len(entries) == 7 and blocked == BLOCKED, f"expected 7 entries with blocked {sorted(BLOCKED)}")

    def step4(self) -> None:
        a = decisionlog.read_anchor(self.log)
        expect(a is not None and a.count == 7, "anchor missing or count != 7")
        v = oc.verify_log(self.log, self.manifest, self.repo, a.head, a.count, bin=self.bin)
        print(f"  opencomplai agents verify-log --expected-head {a.head[:19]}... --expected-count {a.count}: "
              f"exit {v.exit_code} ({v.status}); chain {'ok' if v.chain_ok else 'BROKEN'}, count {v.count}")
        for o in v.out_of_mandate:
            print(f"    out_of_mandate seq {o.seq} {o.tool} [{', '.join(o.reasons)}]")
        expect(v.chain_ok and v.count == 7, f"verify-log chain not ok ({v.error})")
        expect(set(v.out_of_mandate_seqs) == BLOCKED, f"out_of_mandate {v.out_of_mandate_seqs} != blocked {sorted(BLOCKED)}")
        expect(v.exit_code == 1, f"verify-log exit {v.exit_code}, expected 1")
        print("  exit 1 is expected: blocked actions are outside mandate; invariant holds")
        p = subprocess.run([sys.executable, "-m", "aicl", "log", "verify", str(self.log), "--anchor"],
                           capture_output=True, text=True, timeout=60)
        print("".join(f"  aicl log verify --anchor: {line}\n" for line in p.stdout.splitlines()), end="")
        expect(p.returncode == 0 and "chain ok: 7 entries" in p.stdout, f"aicl log verify --anchor exit {p.returncode}")
        lines = self.log.read_text("utf-8").splitlines(keepends=True)
        flipped, trunc = self.workdir / "tamper" / "flipped.jsonl", self.workdir / "tamper" / "truncated.jsonl"
        flipped.parent.mkdir(parents=True, exist_ok=True)
        i = lines[2].index('"intent": "') + len('"intent": "')
        flipped.write_text("".join(lines[:2] + [lines[2][:i] + ("X" if lines[2][i] != "X" else "Y")
                                                + lines[2][i + 1:]] + lines[3:]), "utf-8")
        local, vf = decisionlog.verify(flipped), oc.verify_log(flipped, self.manifest, self.repo, bin=self.bin)
        expect(local.bad_seq == 3 and vf.bad_seq == 3 and not vf.chain_ok, "flipped byte not detected at seq 3")
        print(f"  tamper copy, one byte flipped in seq 3 intent: chain broken at seq 3 "
              f"(aicl: {local.error}; opencomplai: {vf.error}, exit {vf.exit_code})")
        trunc.write_text("".join(lines[:-1]), "utf-8")
        vt = oc.verify_log(trunc, self.manifest, self.repo, expected_count=a.count, bin=self.bin)
        expect(vt.error == "count" and vt.exit_code == 1, f"truncation: error {vt.error}, exit {vt.exit_code}")
        print(f"  tamper copy, last line dropped: verify-log --expected-count {a.count} -> error: count "
              f"(exit {vt.exit_code}; aicl: {decisionlog.verify(trunc, a.head, a.count).error})")

    def step5(self) -> None:
        rows = self.gaps({a: "partial" for a in ARTS})
        expect("agent-log.jsonl" in rows["Art. 12"].evidence_ref, "Art. 12 evidence is not agent-log.jsonl")
        print("  runtime decisions became EU AI Act evidence without importing Opencomplai")

    def step6(self) -> None:
        r, code = ci.run_ci(ci.CiOptions(repo=self.repo, manifest=self.manifest, judge=self.judge,
                                         oc_bin=self.bin, quiet=True))
        self.report = r
        print("".join(f"  {line}\n" for line in render_terminal(r, self.color, self.repo).splitlines()), end="")
        c, by = r.check, {f.symbol: f for f in r.classification.findings}
        expect(c.exit_code == 1 and "CODE_CORROBORATION_GAP" in c.failed_controls, f"check exit {c.exit_code} "
               f"{c.failed_controls}")
        expect(c.scan_severity == "major" and "biometric" in c.detected_categories, f"scan {c.scan_severity}")
        f = by.get("segment_shoppers")
        expect(f and f.tier is Tier.PROHIBITED and f.article == "Art. 5(1)(g)", "segment_shoppers not PROHIBITED")
        f = by.get("summarise_sales")
        expect(f and f.tier is Tier.LIMITED and f.article == "Art. 50(1)", "summarise_sales not LIMITED Art. 50(1)")
        expect("top_products" not in by, "top_products should have no finding")
        print("  top_products: no finding (deterministic co-occurrence needs two signals)")
        expect(self.judge != "off" or not r.judge.used, "judge ran with --judge off")
        expect(code == 1 and r.verdict == "FAIL", f"verdict {r.verdict}, expected FAIL")
        expect(invariant_holds(r) is True, "out_of_mandate ⊆ blocked does not hold in the CI report")
        missing = [n for n in ARTIFACTS[3:] if not (self.repo / n).is_file()]
        expect(not missing, f"not written: {missing}")

    def step7(self) -> None:
        rem = self.report.remediation
        expect(rem is not None and rem.patch.get("high_risk_presumption") is True, "no remediation patch")
        orig = load_manifest(self.manifest).intended_purpose
        print(f"  patch intended_purpose += {rem.patch['intended_purpose'][len(orig):].strip()!r}")
        print("  patch high_risk_presumption: true")
        for k in rem.patch.get("known_limitations", []):
            print(f"  patch known_limitations: {k}")
        print(f"  code action: {rem.code_actions[0]}")
        copy = self.workdir / "patched" / "shopper-insights"
        shutil.rmtree(copy.parent, ignore_errors=True)
        shutil.copytree(self.repo, copy)
        shutil.copyfile(self.repo / "system-manifest.proposed.json", copy / MANIFEST_NAME)
        c = oc.check(copy, copy / MANIFEST_NAME, bin=self.bin)
        print(f"  opencomplai check on the patched copy: exit {c.exit_code}; severity {c.scan_severity}; "
              f"failed_controls {', '.join(c.failed_controls)}")
        expect(c.scan_severity == "none", f"severity {c.scan_severity}, expected none")
        expect(c.failed_controls == ART6, f"failed_controls {c.failed_controls}, expected {ART6}")
        expect("EU_AIA_ART5_UNACCEPTABLE" not in c.failed_controls, "Opencomplai Art. 5 rule fired")
        pm = load_manifest(copy / MANIFEST_NAME)
        cls = semantic.classify_repo(copy, pm.intended_purpose, pm.high_risk_presumption)
        expect(any(f.tier is Tier.PROHIBITED for f in cls.findings) and not rem.cures_gate, "aicl would pass")
        print("  Opencomplai Art. 5 rule: still silent on the declared ethnicity inference | "
              "aicl: still FAIL (fixed in code, not in paperwork)")


STEPS: tuple[tuple[str, Callable[[Demo], None]], ...] = (
    ("Fixture and baseline", Demo.step1), ("aicl init", Demo.step2), ("Runtime guardrail replay", Demo.step3),
    ("Evidence", Demo.step4), ("Regulatory lift", Demo.step5), ("aicl ci", Demo.step6), ("Remediation", Demo.step7))


def cmd_demo(args: Any) -> int:
    """Exit 0 every beat matched | 1 an assertion failed (step named) | 3 opencomplai not found."""
    color = not getattr(args, "no_color", False) and "NO_COLOR" not in os.environ and sys.stdout.isatty()
    paint = (lambda s, c: f"\033[{c}m{s}\033[0m") if color else (lambda s, c: s)
    try:
        bin_ = oc.opencomplai_bin(getattr(args, "opencomplai", None))
    except OcNotFound as e:
        print(f"aicl demo: {e}", file=sys.stderr)
        return 3
    given = getattr(args, "workdir", None)
    workdir = Path(given).resolve() if given else Path(tempfile.mkdtemp(prefix="aicl-demo-"))
    workdir.mkdir(parents=True, exist_ok=True)
    d = Demo(workdir, bin_, getattr(args, "judge", None) or "off", color)
    print(f"aicl demo — AI Compliance Layer v0 | offline | opencomplai {oc.version(bin_)} via subprocess | "
          f"workdir {d.repo}")
    t0, rc = time.monotonic(), 0
    try:
        for n, (title, fn) in enumerate(STEPS, 1):
            print(f"\n[{n}/7] {title}")
            ts = time.monotonic()
            try:
                fn(d)
            except Exception as e:   # any failure names its step; exit 1
                print(paint(f"FAILED [{n}/7] {title}: {type(e).__name__}: {e}", "31"))
                rc = 1
                break
            print(f"  {paint('ok', '32')} ({time.monotonic() - ts:.1f}s)")
        if rc == 0:
            print(f"\n{paint('7/7 steps passed', '32')} in {time.monotonic() - t0:.1f}s")
            print("artifacts in " + str(d.repo) + ":\n" + "".join(f"  {n}\n" for n in ARTIFACTS), end="")
    finally:
        if not given and not getattr(args, "keep", False):
            shutil.rmtree(workdir, ignore_errors=True)
            print(f"(workdir {workdir} deleted; use --keep or --workdir to inspect it)")
    return rc
