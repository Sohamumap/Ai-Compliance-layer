"""CI verdict and report rendering: Markdown, terminal summary and JSON for a CiReport."""
from __future__ import annotations

import dataclasses
import enum
import json
from pathlib import Path
from typing import Any, Mapping

from aicl.core import (CheckResult, CiReport, Classification, JudgeResult, Tier, assert_no_secrets, atomic_write_text,
                       redact, tier_rank)
from aicl.oc import EXIT_NAMES

__all__ = ["REPORT_MD", "REPORT_JSON", "CHAIN_REASON", "OOM_REASON", "HEADINGS", "ARTICLES", "DISCLAIMER", "VERIFY_EXIT_SENTENCE",
           "decide_verdict", "invariant_holds", "render_markdown", "render_terminal", "to_json", "write"]

REPORT_MD = "aicl-report.md"
REPORT_JSON = "aicl-report.json"
HEADINGS = ("# aicl compliance report", "## Verdict", "## Gate (opencomplai check)", "## Semantic classification (aicl)",
            "## Opencomplai said / aicl said", "## Runtime evidence (agent decision log)",
            "## Article status (5, 6, 12, 14, 15, 26, 50)", "## Remediation", "## Judge", "## Reproduce", "## Disclaimer")
ARTICLES = ("Art. 5", "Art. 6", "Art. 12", "Art. 14", "Art. 15", "Art. 26", "Art. 50")
DISCLAIMER = "Heuristic evidence, not legal advice."
VERIFY_EXIT_SENTENCE = ("opencomplai agents verify-log exits 1 whenever blocked entries exist; "
                        "that is the expected signal, not a failure of the log.")
CHAIN_REASON = "decision log chain broken or anchor mismatch"
OOM_REASON = "an out-of-mandate action executed"
_COLORS = {"PASS": "32", "FAIL": "31", "prohibited": "31", "high_risk": "33", "limited": "36", "minimal": "0"}


def _findings(cls: Classification, judge: JudgeResult) -> tuple:
    return judge.adjusted if judge.used else cls.findings


def _code_tier(cls: Classification, judge: JudgeResult) -> Tier:
    if not judge.used:
        return cls.tier
    return max((f.tier for f in judge.adjusted), key=tier_rank, default=Tier.MINIMAL)


def decide_verdict(check: CheckResult, cls: Classification, judge: JudgeResult,
                   semantic_fail_on: str) -> tuple[str, tuple[str, ...]]:
    findings = _findings(cls, judge)
    reasons: list[str] = []
    if check.exit_code != 0:
        reasons.append(f"opencomplai check exit {check.exit_code} ({EXIT_NAMES.get(check.exit_code, 'unknown')})")
    reasons += [f"prohibited finding: {f.symbol} {f.article}" for f in findings if f.tier is Tier.PROHIBITED]
    tier = _code_tier(cls, judge)
    gap = cls.declaration_gap if not judge.used else (
        tier_rank(tier) > tier_rank(cls.declared_tier) or any(f.tier is Tier.PROHIBITED for f in findings))
    if semantic_fail_on != "none" and gap and tier_rank(tier) >= tier_rank(Tier(semantic_fail_on)):
        reasons.append(f"declaration gap: code {tier.value} > declared {cls.declared_tier.value}")
    return ("FAIL" if reasons else "PASS"), tuple(reasons)


def invariant_holds(r: CiReport) -> bool | None:
    """out_of_mandate ⊆ blocked; ci.py records a violation as OOM_REASON (None when verify-log did not run)."""
    return None if r.verify is None else OOM_REASON not in r.verdict_reasons


def _cell(v: Any, limit: int = 160) -> str:
    s = " ".join(str(v).split())
    s = s if len(s) <= limit else s[:limit - 1] + "…"
    return s.replace("|", "\\|") or "-"


def _table(head: tuple[str, ...], rows: list[tuple]) -> list[str]:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    return out + ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]


def _judge_line(j: JudgeResult) -> str:
    if not j.used:
        return f"Judge: skipped ({j.skipped_reason or j.mode}; deterministic classification only)"
    if j.error:
        return f"Judge: {j.model} failed ({j.error}); deterministic findings stand"
    return f"Judge: {j.model} reviewed {len(j.verdicts)} finding(s)"


def _head_line(r: CiReport) -> str:
    local = r.anchor.head if r.anchor else (r.local_verify.head if r.local_verify else None)
    art = r.check.log_head_hex
    if not art or not local:
        return "artifact head cross-check: not available"
    if local == "sha256:" + art:
        return "artifact head matches local head"
    return f"artifact head sha256:{art} differs from local head {local}"


def _runtime(r: CiReport) -> list[str]:
    if r.local_verify is None and r.verify is None:
        return ["No decision log found; Art. 12 runtime evidence appears once the aicl hook appends agent-log.jsonl.", ""]
    lv, v, a = r.local_verify, r.verify, r.anchor
    out = []
    if lv is not None:
        out.append(f"- log: head `{lv.head}` count {lv.count}")
        state = "ok" if lv.ok else (f"BROKEN: {lv.error}" + (f" at seq {lv.bad_seq}" if lv.bad_seq is not None else ""))
        out.append(f"- local chain (aicl, against the anchor): {state}")
    anchor = "missing" if a is None else (
        "mismatch" if lv is not None and lv.error in ("anchor_head", "anchor_count") else f"ok (head `{a.head}` count {a.count})")
    out.append(f"- anchor `.aicl/log-anchor.json`: {anchor}")
    if v is not None:
        oc_state = "ok" if v.chain_ok else f"not ok ({v.error})" + (f" at seq {v.bad_seq}" if v.bad_seq is not None else "")
        out.append(f"- Opencomplai chain (agents verify-log, exit {v.exit_code} {v.status}): {oc_state}, count {v.count}")
    else:
        out.append("- Opencomplai chain: not run")
    out += [f"- {_head_line(r)}", ""]
    if r.log_entries:
        out += ["Decision log entries:", ""] + _table(
            ("seq", "tool", "outcome", "intent"),
            [(e.seq, e.payload.tool, e.payload.outcome, e.payload.intent) for e in r.log_entries]) + [""]
    if v is not None:
        out += ["Out-of-mandate entries (Opencomplai agents verify-log):", ""]
        out += _table(("seq", "tool", "reasons"), [(o.seq, o.tool, ", ".join(o.reasons)) for o in v.out_of_mandate]) \
            if v.out_of_mandate else ["None."]
        holds = invariant_holds(r)
        out += ["", f"every out-of-mandate seq was blocked: {'yes' if holds else 'no'} (out_of_mandate ⊆ blocked)", "",
                VERIFY_EXIT_SENTENCE, ""]
    out.append(f"Unresolved asks (pending > 10 min): {len(r.unresolved_pending)}")
    if r.unresolved_pending:
        out += [""] + _table(("tool_use_id", "tool", "rule", "ts", "intent"),
                             [(p.tool_use_id, p.tool, p.rule_id, p.ts, p.intent) for p in r.unresolved_pending])
    return out + [""]


def _comparison(r: CiReport) -> list[str]:
    c, cls = r.check, r.classification
    findings = _findings(cls, r.judge)
    tier = _code_tier(cls, r.judge)
    top = max(findings, key=lambda f: tier_rank(f.tier), default=None)
    art5 = c.gap("Art. 5")
    summ = c.raw.get("summaries")
    agents = summ.get("agents") if isinstance(summ, Mapping) else None
    agents = agents if isinstance(agents, Mapping) else {}
    prohibited = [f"{f.symbol} {f.article}" for f in findings if f.tier is Tier.PROHIBITED]
    lv = r.local_verify
    rows = [
        ("Gate", f"exit {c.exit_code} {c.result} [{', '.join(c.failed_controls) or 'none'}]", r.verdict),
        ("Risk signal", f"scan severity {c.scan_severity}; categories {', '.join(c.detected_categories) or 'none'}",
         f"code tier {tier.value}" + (f" ({top.symbol} {top.article})" if top else "")),
        ("Declared vs. code", f"discrepancies: {', '.join(c.discrepancies) or 'none'}",
         f"declared {cls.declared_tier.value} vs. code {tier.value} (gap: {'yes' if cls.declaration_gap else 'no'})"),
        ("Art. 5", f"{art5.status} ({art5.rationale})" if art5 else "no row",
         "; ".join(prohibited) if prohibited else "no prohibited finding"),
        ("Decision log", f"log_entries {c.log_entries if c.log_entries is not None else 'none'}, "
                         f"chain_valid {agents.get('chain_valid', '-')}" if agents else "no agents summary",
         (f"local chain {'ok' if lv.ok else 'BROKEN'}, count {lv.count}" if lv else "no log")),
    ]
    return _table(("", "Opencomplai said", "aicl said"), rows) + [""]


def render_markdown(r: CiReport) -> str:
    c, cls, j = r.check, r.classification, r.judge
    findings = _findings(cls, j)
    L = [HEADINGS[0], "",
         f"System `{r.system_id}` | repo `{r.repo}` | manifest `{r.manifest}` | generated {r.generated_at} | "
         f"aicl {r.aicl_version} | opencomplai {r.opencomplai_version}", "",
         HEADINGS[1], "", f"**{r.verdict}**", ""]
    L += [f"- {x}" for x in r.verdict_reasons] or ["- no blocking reasons"]
    L += ["", HEADINGS[2], "",
          f"- exit {c.exit_code} ({EXIT_NAMES.get(c.exit_code, 'unknown')}), result `{c.result}`",
          f"- failed controls: {', '.join(c.failed_controls) or 'none'}",
          f"- scan severity: {c.scan_severity}; detected categories: {', '.join(c.detected_categories) or 'none'}; "
          f"discrepancies: {', '.join(c.discrepancies) or 'none'}",
          f"- artifact: `{c.artifact_path}`; scan report: `{c.scan_report_path}`", "",
          HEADINGS[3], "",
          f"Deterministic heuristic (aicl): code tier **{_code_tier(cls, j).value}**, declared tier "
          f"**{cls.declared_tier.value}**, declaration gap: {'yes' if cls.declaration_gap else 'no'}. "
          f"{cls.files_scanned} file(s), {cls.units_scanned} unit(s) scanned.", ""]
    if cls.skipped:
        L += [f"Skipped: {', '.join(cls.skipped)}", ""]
    L += _table(("file:line", "symbol", "tier", "article", "evidence", "confidence", "source"),
                [(f"{f.file}:{f.line}", f.symbol, f.tier.value, f.article, ", ".join(f.evidence), f"{f.confidence:.2f}",
                  f.source) for f in findings]) if findings else ["No findings."]
    L += ["", HEADINGS[4], ""] + _comparison(r)
    L += [HEADINGS[5], ""] + _runtime(r)
    L += [HEADINGS[6], ""]
    rows = []
    for art in ARTICLES:
        g = c.gap(art)
        rows.append((art, g.status, g.source, g.evidence_ref, g.rationale) if g else (art, "not reported", "-", "-", "-"))
    L += _table(("article", "status", "source", "evidence_ref", "rationale"), rows) + ["", HEADINGS[7], ""]
    rem = r.remediation
    if rem is None:
        L += ["No remediation needed.", ""]
    else:
        L += [rem.summary, "", f"Patch keys: {', '.join(rem.patch) or 'none'}", ""]
        L += [f"- {a}" for a in rem.code_actions] or ["- no code actions"]
        L += ["", "Files: `aicl-remediation.patch.json`, `aicl-remediation.md`, `system-manifest.proposed.json` "
                  "(the original manifest is never modified).", ""]
        if not rem.cures_gate:
            L += ["Prohibited findings cannot be cured by declaration; the code must change.", ""]
    L += [HEADINGS[8], "", _judge_line(j), ""]
    L += [f"- finding {i}: {verdict} ({why})" for i, verdict, why in j.verdicts]
    L += [f"- purpose addendum: {j.purpose_addendum}"] if j.purpose_addendum else []
    L += [f"- notes: {j.notes}"] if j.notes else []
    L += [HEADINGS[9], "", "```"] + list(r.reproduce) + ["```", "", HEADINGS[10], "", DISCLAIMER]
    oc_disc = c.raw.get("disclaimer")
    if isinstance(oc_disc, str) and oc_disc.strip():
        L += ["", f"Opencomplai: {oc_disc.strip()}"]
    text = redact("\n".join(L) + "\n")
    assert_no_secrets(text)
    return text


def _paint(s: str, key: str, color: bool) -> str:
    return f"\033[{_COLORS.get(key, '0')}m{s}\033[0m" if color else s


def render_terminal(r: CiReport, color: bool, out_dir: Path | None = None) -> str:
    c, cls, j = r.check, r.classification, r.judge
    L = [f"aicl ci: {_paint(r.verdict, r.verdict, color)} ({r.system_id})"]
    L += [f"  - {x}" for x in r.verdict_reasons[:5]]
    L.append(f"gate: opencomplai check exit {c.exit_code} {c.result} [{', '.join(c.failed_controls) or 'none'}]; "
             f"scan {c.scan_severity} {', '.join(c.detected_categories) or 'none'}")
    L.append(f"semantic: code {_code_tier(cls, j).value} vs declared {cls.declared_tier.value}"
             + (" (declaration gap)" if cls.declaration_gap else ""))
    for f in _findings(cls, j)[:8]:
        L.append(f"  {f.symbol} {_paint(f.tier.value.upper(), f.tier.value, color)} {f.article} "
                 f"({' + '.join(f.evidence)}) {f.confidence:.2f}  {f.file}:{f.line}")
    if r.local_verify is not None or r.verify is not None:
        lv, holds = r.local_verify, invariant_holds(r)
        L.append(f"runtime: local chain {'ok' if lv and lv.ok else 'BROKEN' if lv else 'n/a'}"
                 + (f", {lv.count} entries" if lv else "")
                 + ("" if holds is None else f"; out_of_mandate ⊆ blocked: {'yes' if holds else 'no'}")
                 + (f"; unresolved asks: {len(r.unresolved_pending)}" if r.unresolved_pending else ""))
    else:
        L.append("runtime: no decision log")
    L.append(_judge_line(j))
    names = [REPORT_MD, REPORT_JSON] + (["aicl-remediation.patch.json", "aicl-remediation.md",
                                          "system-manifest.proposed.json"] if r.remediation else [])
    L.append(f"written in {out_dir or r.repo}: {', '.join(names)}")
    if len(L) > 25:
        L = L[:24] + ["... see aicl-report.md"]
    return redact("\n".join(L))


def _plain(o: Any) -> Any:
    if isinstance(o, enum.Enum):
        return o.value
    if isinstance(o, Path):
        return str(o)
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return {f.name: _plain(getattr(o, f.name)) for f in dataclasses.fields(o)}
    if isinstance(o, Mapping):
        return {str(k): _plain(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_plain(x) for x in o]
    if isinstance(o, (set, frozenset)):
        return sorted(_plain(x) for x in o)
    return o


def to_json(r: CiReport) -> str:
    return redact(json.dumps(_plain(r), indent=2, ensure_ascii=False, default=str)) + "\n"


def write(r: CiReport, out_dir: Path) -> tuple[Path, Path]:
    md, js = Path(out_dir) / REPORT_MD, Path(out_dir) / REPORT_JSON
    atomic_write_text(md, render_markdown(r))
    atomic_write_text(js, to_json(r))
    return md, js
