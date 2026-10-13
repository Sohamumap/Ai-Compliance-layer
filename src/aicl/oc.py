"""Subprocess boundary to the opencomplai CLI: the only module that knows its argv and JSON shapes.

Opencomplai is never imported; it is reached through argv, stdout JSON, exit codes and the files it writes.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from aicl.core import CheckResult, GapRow, OcError, OcNotFound, OutOfMandate, VerifyLogResult

__all__ = ["EXIT_NAMES", "VERIFY_EXIT_NAMES", "OcRun", "opencomplai_bin", "child_env", "run", "version",
           "agents_check", "check", "parse_check", "verify_log", "parse_verify_log", "gaps", "parse_gap_rows"]

EXIT_NAMES = {0: "pass", 1: "control_fail", 2: "validation_fail", 3: "policy_block", 4: "trap_detected"}
VERIFY_EXIT_NAMES = {0: "ok", 1: "invalid", 2: "bad_input"}


@dataclass(frozen=True)
class OcRun:
    argv: tuple[str, ...]; exit_code: int; stdout: str; stderr: str; json: Any | None; duration_s: float

    @property
    def payload(self) -> Mapping[str, Any]:
        if isinstance(self.json, dict):
            return self.json["payload"] if isinstance(self.json.get("payload"), dict) else self.json
        return {}


def _resolve(cand: str) -> str | None:
    p = Path(cand).expanduser()
    if p.is_file() and os.access(p, os.X_OK):
        return str(p)
    return shutil.which(cand)


def opencomplai_bin(explicit: str | None = None, env: Mapping[str, str] = os.environ) -> str:
    """explicit -> $AICL_OPENCOMPLAI -> <sys.executable dir>/opencomplai -> PATH; OcNotFound otherwise."""
    for label, cand in (("--opencomplai", explicit), ("AICL_OPENCOMPLAI", env.get("AICL_OPENCOMPLAI"))):
        if cand:
            found = _resolve(cand)
            if not found:
                raise OcNotFound(f"opencomplai not found at {cand} ({label})")
            return found
    sibling = Path(sys.executable).parent / "opencomplai"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    found = shutil.which("opencomplai")
    if found:
        return found
    raise OcNotFound("opencomplai not found (set AICL_OPENCOMPLAI or pip install opencomplai==0.12.0)")


def child_env(env: Mapping[str, str] = os.environ) -> dict[str, str]:
    """Environment for Opencomplai children: never forward our Anthropic credential."""
    return {k: v for k, v in env.items() if not k.startswith("ANTHROPIC_")}


def _decode(stdout: str) -> Any | None:
    text = stdout.lstrip()
    if not text.startswith("{"):
        return None
    try:
        return json.JSONDecoder().raw_decode(text)[0]
    except json.JSONDecodeError:
        return None


def run(args: Sequence[str], cwd: Path, timeout: float = 180.0, bin: str | None = None) -> OcRun:
    argv = (opencomplai_bin(bin), *[str(a) for a in args])
    t0 = time.monotonic()
    try:
        cp = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=child_env())
    except subprocess.TimeoutExpired as e:
        raise OcError("timeout") from e
    except OSError as e:
        raise OcNotFound(f"cannot execute {argv[0]}: {e}") from e
    return OcRun(argv, cp.returncode, cp.stdout, cp.stderr, _decode(cp.stdout), time.monotonic() - t0)


def _abs(p: Path) -> str:
    return str(Path(p).expanduser().resolve())


def version(bin: str | None = None) -> str:
    try:
        r = run(["--version"], Path.cwd(), timeout=30.0, bin=bin)
    except (OcError, OcNotFound):
        return "unknown"
    toks = (r.stdout.strip() or r.stderr.strip()).split()
    return toks[-1] if r.exit_code == 0 and toks else "unknown"


def agents_check(repo: Path, manifest: Path, bin: str | None = None) -> OcRun:
    """json keys: exit_code, findings[], expired_mandates[]."""
    return run(["agents", "check", "-m", _abs(manifest), "-o", "json"], Path(repo).resolve(), bin=bin)


def _fail(r: OcRun) -> OcError:
    detail = (r.stderr.strip() or r.stdout.strip())[:500]
    e = OcError(f"opencomplai {' '.join(r.argv[1:3])} exit {r.exit_code}: {detail}")
    e.exit_code = r.exit_code
    return e


def _strs(v: Any) -> tuple[str, ...]:
    return tuple(str(x) for x in v) if isinstance(v, list) else ()


def _d(v: Any) -> Mapping[str, Any]:
    return v if isinstance(v, dict) else {}


def parse_gap_rows(rows: Sequence[Mapping]) -> tuple[GapRow, ...]:
    def s(r: Mapping, k: str) -> str:
        v = r.get(k)
        return "" if v is None else str(v)
    return tuple(GapRow(s(r, "article"), s(r, "status"), s(r, "source"), s(r, "evidence_ref"), s(r, "rationale"))
                 for r in rows if isinstance(r, Mapping))


def parse_check(obj: Mapping[str, Any], exit_code: int, repo: Path) -> CheckResult:
    """Parse the FLAT check artifact (no payload envelope)."""
    scan, agents = _d(obj.get("scan_summary")), _d(_d(obj.get("summaries")).get("agents"))
    entries = agents.get("log_entries")
    head = agents.get("log_head_sha256")
    return CheckResult(
        exit_code=exit_code, result=str(obj.get("result") or EXIT_NAMES.get(exit_code, "unknown")),
        failed_controls=_strs(obj.get("failed_controls")),
        scan_severity=str(scan.get("severity") or "none"),
        detected_categories=_strs(scan.get("detected_categories")), discrepancies=_strs(scan.get("discrepancies")),
        gaps=parse_gap_rows(_d(obj.get("gap_report")).get("articles") or []),
        cli_version=str(obj.get("cli_version") or ""),
        log_entries=entries if isinstance(entries, int) and not isinstance(entries, bool) else None,
        log_head_hex=str(head) if head else None,
        artifact_path=repo / "compliance-artifact.json", scan_report_path=repo / "scan-report.json", raw=obj)


def check(repo: Path, manifest: Path, fail_on: str = "major", bin: str | None = None) -> CheckResult:
    """Side effects (expected): repo/.ocignore, repo/scan-report.json, repo/compliance-artifact.json."""
    repo = Path(repo).resolve()
    r = run(["check", "-m", _abs(manifest), "--scan", "--repo-root", str(repo), "--with-gaps", "--fail-on", fail_on,
             "--no-emit-evidence", "--output", "json"], repo, bin=bin)
    if r.exit_code == 2 or not isinstance(r.json, dict):
        raise _fail(r)
    return parse_check(r.json, r.exit_code, repo)


def parse_verify_log(obj: Mapping[str, Any], exit_code: int) -> VerifyLogResult:
    chain = _d(obj.get("chain"))
    bad = chain.get("bad_seq")
    oom = tuple(OutOfMandate(int(o.get("seq") or 0), str(o.get("agent_id") or ""), str(o.get("tool") or ""),
                             _strs(o.get("reasons")))
                for o in (obj.get("out_of_mandate") or []) if isinstance(o, dict))
    return VerifyLogResult(
        exit_code=exit_code, status=str(obj.get("status") or VERIFY_EXIT_NAMES.get(exit_code, "unknown")),
        chain_ok=chain.get("ok") is True, count=int(chain.get("count") or 0), head=str(chain.get("head") or ""),
        error=str(chain["error"]) if chain.get("error") else None, bad_seq=bad if isinstance(bad, int) else None,
        out_of_mandate=oom, raw=obj)


def verify_log(log: Path, manifest: Path, repo: Path, expected_head: str | None = None,
               expected_count: int | None = None, bin: str | None = None) -> VerifyLogResult:
    args = ["agents", "verify-log", _abs(log), "-m", _abs(manifest), "-o", "json"]
    if expected_head:
        args += ["--expected-head", expected_head]
    if expected_count is not None:
        args += ["--expected-count", str(expected_count)]
    r = run(args, Path(repo).resolve(), bin=bin)
    if r.exit_code == 2 or not isinstance(r.json, dict):
        raise _fail(r)
    return parse_verify_log(r.json, r.exit_code)


def gaps(repo: Path, manifest: Path, scan_report: Path | None = None, bin: str | None = None) -> tuple[GapRow, ...]:
    repo = Path(repo).resolve()
    args = ["gaps", "-m", _abs(manifest), "--repo-root", str(repo), "--output", "json"]
    if scan_report:
        args += ["--scan-report", _abs(scan_report)]
    r = run(args, repo, bin=bin)
    rows = r.payload.get("articles")
    if r.exit_code == 2 or not isinstance(rows, list):
        raise _fail(r)
    return parse_gap_rows(rows)
