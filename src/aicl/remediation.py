"""Remediation proposal: a true RFC 7386 merge patch on the manifest, code actions, and the files that carry them."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Mapping

from aicl.core import CheckResult, Classification, JudgeResult, Manifest, Remediation, Tier, atomic_write_text, tier_rank
from aicl.manifest import merge_manifest, oversight_block
from aicl.semantic import CATEGORIES

PATCH_NAME = "aicl-remediation.patch.json"
MD_NAME = "aicl-remediation.md"
PROPOSED_NAME = "system-manifest.proposed.json"
DEFAULT_DOC = "docs/human_oversight.md"
HIGH_RISK_ACTION = ("Complete Annex IV fields (training_data_description, human_oversight_measures, performance_metrics, "
                    "known_limitations) and add docs/risk_register.md before re-running opencomplai check.")


def _missing(check: CheckResult, article: str) -> bool:
    row = check.gap(article)
    return row is not None and row.status.strip().casefold() == "missing"


def apply_merge_patch(doc: Mapping, patch: Mapping) -> dict:
    """RFC 7386: null deletes, objects merge recursively, anything else (arrays included) replaces. Returns a new dict."""
    if not isinstance(patch, Mapping):
        return copy.deepcopy(patch)
    out = copy.deepcopy(dict(doc)) if isinstance(doc, Mapping) else {}
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        elif isinstance(v, Mapping):
            out[k] = apply_merge_patch(out.get(k) if isinstance(out.get(k), Mapping) else {}, v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def build(manifest: Manifest, check: CheckResult, cls: Classification, judge: JudgeResult) -> Remediation | None:
    missing = {a: _missing(check, a) for a in ("Art. 12", "Art. 14", "Art. 15")}
    if check.exit_code == 0 and not cls.declaration_gap and not any(missing.values()):
        return None
    findings = judge.adjusted if judge.used else cls.findings
    prohibited = [f for f in findings if f.tier is Tier.PROHIBITED]
    high = any(tier_rank(f.tier) >= tier_rank(Tier.HIGH_RISK) for f in findings)
    raw = manifest.raw
    patch: dict[str, Any] = {}

    fired = {f.category_id for f in findings}
    addenda = [c.addendum for c in CATEGORIES if c.id in fired]
    addendum = (judge.purpose_addendum or "").strip() if judge.used else ""
    addendum = addendum or " ".join(addenda)
    if addendum and addendum not in manifest.intended_purpose:
        patch["intended_purpose"] = f"{manifest.intended_purpose} {addendum}".strip()
    if high and not manifest.high_risk_presumption:
        patch["high_risk_presumption"] = True
    if prohibited:
        existing = list(raw.get("known_limitations") or [])
        new = [f"{f.symbol} ({f.file}:{f.line}) {f.title} is a prohibited practice under {f.article} "
               f"and must be removed before release." for f in prohibited]
        patch["known_limitations"] = existing + [n for n in new if n not in existing]
    if missing["Art. 14"] and not manifest.has_human_oversight:
        patch["human_oversight"] = oversight_block()
    if missing["Art. 12"] or missing["Art. 15"]:
        merged: dict = copy.deepcopy(dict(raw))
        for a in manifest.agents:
            merged, _ = merge_manifest(merged, a.id, a.guardrail_refs[0] if a.guardrail_refs else DEFAULT_DOC)
        if merged.get("agent_inventory") != raw.get("agent_inventory"):
            patch["agent_inventory"] = merged["agent_inventory"]

    actions = [f"Remove or disable {f.symbol} ({f.file}:{f.line}): {f.title} — {f.article}." for f in prohibited]
    if any(f.tier is Tier.HIGH_RISK for f in findings):
        actions.append(HIGH_RISK_ACTION)
    if check.discrepancies and not high:
        actions.append(f"Reconcile scan discrepancy categories: {', '.join(check.discrepancies)}.")
    if missing["Art. 12"]:
        actions.append("Run aicl init and let the hook write agent-log.jsonl.")
    if missing["Art. 14"] or missing["Art. 15"]:
        actions.append("Run aicl init to write docs/human_oversight.md and the human_oversight block.")

    cures = not prohibited
    summary = (f"Manifest patch sets {', '.join(patch) or 'nothing'}; {len(actions)} code action(s). "
               + ("Declaring the findings can clear the gate." if cures else
                  f"{len(prohibited)} prohibited finding(s) cannot be cured by declaration; the code must change."))
    return Remediation(patch=patch, patched_manifest=apply_merge_patch(raw, patch), code_actions=tuple(actions),
                       summary=summary, cures_gate=cures)


def _render_md(rem: Remediation, proposed: Path, repo: Path) -> str:
    lines = ["# aicl remediation proposal", "", rem.summary, "", "## Manifest merge patch (RFC 7386)", "",
             "```json", json.dumps(rem.patch, indent=2, ensure_ascii=False), "```", "", "## Code actions", ""]
    lines += [f"- {a}" for a in rem.code_actions] or ["- none"]
    lines += ["", "## Re-check", "", "```",
              f"opencomplai check -m {proposed} --scan --repo-root {repo} --with-gaps --fail-on major "
              "--no-emit-evidence --output json", "```", ""]
    if not rem.cures_gate:
        lines += ["Prohibited practices (Art. 5) cannot be cured by declaration: the patch makes the manifest honest, "
                  "but the code must be removed or disabled before release.", ""]
    lines += ["The original manifest is never modified; the patched copy is written next to this file.",
              "", "Heuristic evidence, not legal advice.", ""]
    return "\n".join(lines)


def write(rem: Remediation, out_dir: Path, manifest_path: Path) -> tuple[Path, Path, Path]:
    out_dir = Path(out_dir)
    patch_p, md_p, proposed_p = out_dir / PATCH_NAME, out_dir / MD_NAME, out_dir / PROPOSED_NAME
    if proposed_p.resolve() == Path(manifest_path).resolve():
        raise ValueError("refusing to overwrite the original manifest")
    atomic_write_text(patch_p, json.dumps(rem.patch, indent=2, ensure_ascii=False) + "\n")
    atomic_write_text(proposed_p, json.dumps(rem.patched_manifest, indent=2, ensure_ascii=False) + "\n")
    atomic_write_text(md_p, _render_md(rem, proposed_p.resolve(), Path(manifest_path).resolve().parent))
    return patch_p, md_p, proposed_p
