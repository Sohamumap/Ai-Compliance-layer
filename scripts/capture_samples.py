"""Regenerate tests/data/*.sample.json by running the pinned opencomplai CLI on our own fixture (make samples).

Sequence on a temp copy of the fixture: gaps (before) -> aicl init -> agents check -> one golden log line ->
gaps (after) -> check -> check on the patched manifest -> a blocked second entry -> agents verify-log.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aicl import oc  # noqa: E402
from aicl.core import DOMAIN, GENESIS, canonical, sha256_prefixed  # noqa: E402
from aicl.init_cmd import run_init  # noqa: E402

DATA = ROOT / "tests" / "data"
FIXTURE = ROOT / "src" / "aicl" / "fixture" / "shopper_insights"
PLACEHOLDER = "/__aicl_samples__/shopper-insights"
# Golden entry 1 (DESIGN.md 4.3), written as a literal so the samples never depend on decisionlog.py.
GOLDEN_LINE = (
    '{"hash": "sha256:6296df0b804ee2e68dba9bfe8e0be342547f04f8470e5fb1abe8e79d7c99a2ad", "payload": {"agent_id": '
    '"claude-code", "input_hash": "sha256:fd226d98d55cbca664a0584f63c4d8089992012089f935deed358ca13700ecab", '
    '"intent": "fix typo in README", "mandate_ref": "mandate:claude-code", "outcome": "success", "outside_mandate": '
    'false, "tool": "Edit"}, "prev_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000", '
    '"seq": 1, "signature": null, "ts": "2026-10-13T10:00:00+00:00"}\n')
# The two category addenda (semantic.py art5_1g + art50) applied by the remediation patch.
ADDENDA = ("It categorises natural persons by inferring ethnicity or other sensitive attributes from biometric face data. "
           "It generates text with a general-purpose language model (LLM) and shows it to users.")


def save(name: str, obj, repo: Path) -> None:
    text = json.dumps(obj, indent=2) + "\n"
    (DATA / f"{name}.sample.json").write_text(text.replace(str(repo), PLACEHOLDER), "utf-8")
    print(f"wrote tests/data/{name}.sample.json")


def expect(cond: bool, what: str) -> None:
    if not cond:
        raise SystemExit(f"capture_samples: unexpected opencomplai behaviour: {what}")


def blocked_entry(prev: str) -> str:
    payload = {"agent_id": "claude-code", "mandate_ref": "mandate:claude-code",
               "intent": "WebFetch: example.com | aicl:deny:tool_prohibited", "tool": "WebFetch",
               "input_hash": sha256_prefixed(canonical({"input": {"url": "https://example.com/pricing", "prompt": "prices"}})),
               "outcome": "blocked", "outside_mandate": True}
    ts = "2026-10-13T10:00:04+00:00"
    h = sha256_prefixed(DOMAIN + canonical({"seq": 2, "ts": ts, "payload": payload, "prev_hash": prev}))
    return json.dumps({"seq": 2, "ts": ts, "payload": payload, "prev_hash": prev, "hash": h, "signature": None},
                      sort_keys=True) + "\n"


def rows(run: oc.OcRun) -> dict[str, str]:
    return {r["article"]: r["status"] for r in run.payload["articles"]}


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aicl-samples-") as td:
        repo = Path(td) / "shopper-insights"
        shutil.copytree(FIXTURE, repo)
        mpath = repo / "system-manifest.json"
        gaps_args = ["gaps", "-m", str(mpath), "--repo-root", str(repo), "--output", "json"]

        before = oc.run(gaps_args, repo)
        expect({rows(before)[a] for a in ("Art. 12", "Art. 14", "Art. 15")} == {"missing"}, "baseline 12/14/15 missing")
        save("gaps_before", before.json, repo)

        init = run_init(repo, mpath)
        expect(init.agents_check_exit == 0, "agents check exit 0 after init")
        ac = oc.agents_check(repo, mpath)
        save("agents_check", ac.json, repo)

        log = repo / "agent-log.jsonl"
        log.write_text(GOLDEN_LINE, "utf-8")
        after = oc.run(gaps_args, repo)
        expect(all(rows(after)[a] == "partial" for a in ("Art. 12", "Art. 14", "Art. 15")), "12/14/15 partial")
        save("gaps_after", after.json, repo)

        chk = oc.run(["check", "-m", str(mpath), "--scan", "--repo-root", str(repo), "--with-gaps", "--fail-on",
                      "major", "--no-emit-evidence", "--output", "json"], repo)
        expect(chk.exit_code == 1 and "CODE_CORROBORATION_GAP" in chk.json["failed_controls"], "check exit 1 gap")
        save("check", chk.json, repo)

        raw = json.loads(mpath.read_text("utf-8"))
        raw["intended_purpose"] = f"{raw['intended_purpose']} {ADDENDA}"
        raw["high_risk_presumption"] = True
        proposed = repo / "system-manifest.proposed.json"
        proposed.write_text(json.dumps(raw, indent=2) + "\n", "utf-8")
        pchk = oc.run(["check", "-m", str(proposed), "--scan", "--repo-root", str(repo), "--with-gaps", "--fail-on",
                       "major", "--no-emit-evidence", "--output", "json"], repo)
        expect(pchk.exit_code == 1 and pchk.json["failed_controls"] == ["EU_AIA_ART6_HIGH_RISK", "EU_AIA_ART6_PROFILING"],
               "patched check moves controls to EU_AIA_ART6_*")
        save("check_patched", pchk.json, repo)

        head1 = json.loads(GOLDEN_LINE)["hash"]
        line2 = blocked_entry(head1)
        with log.open("a", encoding="utf-8") as f:
            f.write(line2)
        vl = oc.run(["agents", "verify-log", str(log), "-m", str(mpath), "-o", "json",
                     "--expected-head", json.loads(line2)["hash"], "--expected-count", "2"], repo)
        expect(vl.exit_code == 1 and vl.json["chain"]["ok"] and [o["seq"] for o in vl.json["out_of_mandate"]] == [2],
               "verify-log chain ok, out_of_mandate == [2]")
        save("verify_log", vl.json, repo)
        expect(GENESIS == json.loads(GOLDEN_LINE)["prev_hash"], "golden prev_hash")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
