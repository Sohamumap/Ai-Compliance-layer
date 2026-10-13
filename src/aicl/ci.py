"""aicl ci: opencomplai check + verify-log via subprocess, semantic classification, optional judge, report, remediation."""
from __future__ import annotations

import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import aicl
from aicl import decisionlog, llm, oc, remediation, report, semantic
from aicl.core import (GENESIS, CiReport, JudgeUnavailable, LogError, ManifestError, OcError, OcNotFound,
                       PendingRecord, VerifyResult, now_ts)
from aicl.manifest import load_manifest, log_path, select_agent

__all__ = ["CiOptions", "run_ci", "blocked_seqs", "oc_exit_code", "cmd_ci"]


@dataclass(frozen=True)
class CiOptions:
    repo: Path; manifest: Path; fail_on: str = "major"; semantic_fail_on: str = "high_risk"
    judge: str = "auto"; out_dir: Path | None = None; oc_bin: str | None = None; quiet: bool = False


def blocked_seqs(log: Path) -> frozenset[int]:
    try:
        return frozenset(e.seq for e in decisionlog.read_entries(log) if e.payload.outcome == "blocked")
    except LogError:
        return frozenset()


def oc_exit_code(e: OcError) -> int | None:
    """Opencomplai's exit code carried by an OcError (attribute if present, else parsed from 'exit N:')."""
    code = getattr(e, "exit_code", None)
    if isinstance(code, int):
        return code
    m = re.search(r"\bexit (\d+)\b", str(e))
    return int(m.group(1)) if m else None


def _warn(o: CiOptions, msg: str) -> None:
    if not o.quiet:
        print(f"aicl ci: warning: {msg}", file=sys.stderr)


def run_ci(o: CiOptions, env: Mapping[str, str] = os.environ) -> tuple[CiReport, int]:
    """Steps 1-8 of DESIGN 4.12. Raises ManifestError, JudgeUnavailable, OcNotFound, OcError (cmd_ci maps them)."""
    repo, manifest = Path(o.repo).resolve(), Path(o.manifest).resolve()
    m = load_manifest(manifest)                                   # 1
    log = log_path(m, select_agent(m, None, env))
    bin_ = oc.opencomplai_bin(o.oc_bin, env)
    reproduce = [shlex.join([bin_, "check", "-m", str(manifest), "--scan", "--repo-root", str(repo), "--with-gaps",
                             "--fail-on", o.fail_on, "--no-emit-evidence", "--output", "json"])]
    check = oc.check(repo, manifest, o.fail_on, bin=bin_)          # 2
    local = anchor = verify = None
    unresolved: tuple[PendingRecord, ...] = ()
    entries: tuple = ()
    stored = decisionlog.read_anchor(log)
    if not log.exists() and stored is not None and stored.count > 0:   # anchored entries, but the log is gone
        local, anchor = VerifyResult(False, 0, GENESIS, "anchor_count", None), stored
    if log.exists():                                              # 3
        local, anchor = decisionlog.verify_with_anchor(log), decisionlog.read_anchor(log)
        argv = [bin_, "agents", "verify-log", str(log.resolve()), "-m", str(manifest), "-o", "json"]
        if anchor:
            argv += ["--expected-head", anchor.head, "--expected-count", str(anchor.count)]
        reproduce.append(shlex.join(argv))
        try:
            verify = oc.verify_log(log, manifest, repo, anchor.head if anchor else None,
                                   anchor.count if anchor else None, bin=bin_)
        except OcError as e:
            _warn(o, f"opencomplai agents verify-log failed: {e}")
        unresolved = decisionlog.stale_pending(log)
        try:
            entries = tuple(decisionlog.read_entries(log))
        except LogError:
            entries = ()
    cls = semantic.classify_repo(repo, m.intended_purpose, m.high_risk_presumption)   # 4
    jr = llm.judge(cls, m, mode=o.judge)                          # 5 (JudgeUnavailable propagates)
    verdict, reasons = report.decide_verdict(check, cls, jr, o.semantic_fail_on)    # 6
    extra = []
    if (local is not None and not local.ok) or (verify is not None and not verify.chain_ok):
        extra.append(report.CHAIN_REASON)
    if verify is not None and not set(verify.out_of_mandate_seqs) <= blocked_seqs(log):
        extra.append(report.OOM_REASON)
    reasons = reasons + tuple(extra)
    verdict = "FAIL" if reasons else "PASS"
    rem = remediation.build(m, check, cls, jr)                    # 7 (also on PASS with Art. 12/14/15 missing)
    r = CiReport(system_id=m.system_id, repo=str(repo), manifest=str(manifest), generated_at=now_ts(),
                 aicl_version=aicl.__version__, opencomplai_version=check.cli_version or "unknown",
                 check=check, classification=cls, verify=verify, local_verify=local, anchor=anchor,
                 unresolved_pending=unresolved, remediation=rem, judge=jr, verdict=verdict, verdict_reasons=reasons,
                 reproduce=tuple(reproduce), log_entries=entries)
    out_dir = Path(o.out_dir).resolve() if o.out_dir else repo    # 8
    if rem is not None:
        remediation.write(rem, out_dir, manifest)
    report.write(r, out_dir)
    return r, 0 if verdict == "PASS" else 1


def _a(args: Any, name: str, default: Any = None) -> Any:
    v = getattr(args, name, None)
    return default if v is None else v


def cmd_ci(args: Any) -> int:
    """Exit 0 PASS | 1 FAIL | 2 config error | 3 opencomplai unavailable (missing, timeout, unparseable)."""
    repo = Path(_a(args, "repo", "."))
    manifest = Path(_a(args, "manifest", repo / "system-manifest.json"))
    o = CiOptions(repo=repo, manifest=manifest, fail_on=_a(args, "fail_on", "major"),
                  semantic_fail_on=_a(args, "semantic_fail_on", "high_risk"), judge=_a(args, "judge", "auto"),
                  out_dir=Path(args.out_dir) if getattr(args, "out_dir", None) else None,
                  oc_bin=_a(args, "opencomplai"), quiet=bool(_a(args, "quiet", False)))
    try:
        r, code = run_ci(o)
    except (ManifestError, JudgeUnavailable) as e:
        print(f"aicl ci: {e}", file=sys.stderr)
        return 2
    except OcNotFound as e:
        print(f"aicl ci: {e}", file=sys.stderr)
        return 3
    except OcError as e:
        print(f"aicl ci: {e}", file=sys.stderr)
        return 2 if oc_exit_code(e) == 2 else 3
    if o.quiet:
        print(f"aicl ci: {r.verdict}")
    else:
        color = not getattr(args, "no_color", False) and "NO_COLOR" not in os.environ and sys.stdout.isatty()
        print(report.render_terminal(r, color, o.out_dir or Path(r.repo)))
    return code
