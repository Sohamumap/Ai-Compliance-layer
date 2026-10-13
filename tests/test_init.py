"""init_cmd.py: settings merge, oversight doc, manifest merge, .aicl/.gitignore, exit codes (offline)."""
from __future__ import annotations

import json
import sys
from argparse import Namespace
from pathlib import Path

from aicl.core import HOOK_MATCHER
from aicl.init_cmd import KNOBS, cmd_init, hook_command, hooks_block, merge_settings, render_oversight_doc, run_init
from aicl.manifest import load_manifest, select_agent


def no_oc(tmp_path: Path) -> str:
    return str(tmp_path / "no-opencomplai")


def fake_oc(tmp_path: Path, code: int) -> str:
    p = tmp_path / "fake-oc"
    p.write_text(f"#!{sys.executable}\nimport json, sys\nprint(json.dumps({{'exit_code': {code}, 'findings': "
                 f"[{{'code': 'x'}}] if {code} else [], 'expired_mandates': []}}))\nsys.exit({code})\n", "utf-8")
    p.chmod(0o755)
    return str(p)


def test_hooks_block_shape():
    b = hooks_block("/py")
    assert b["PreToolUse"][0]["matcher"] == b["PostToolUse"][0]["matcher"] == HOOK_MATCHER
    assert b["PreToolUse"][0]["hooks"] == [{"type": "command", "command": '"/py" -m aicl hook pre', "timeout": 20}]
    assert b["PostToolUse"][0]["hooks"][0]["command"] == hook_command("post", "/py") == '"/py" -m aicl hook post'


def test_merge_settings_idempotent_and_preserving():
    other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo audit"}]}
    existing = {"permissions": {"deny": ["Read(.env)"]}, "hooks": {"PreToolUse": [other], "Stop": [other]}}
    once = merge_settings(existing, hooks_block("/py"))
    assert once["permissions"] == {"deny": ["Read(.env)"]} and once["hooks"]["Stop"] == [other]
    assert once["hooks"]["PreToolUse"][0] == other and len(once["hooks"]["PreToolUse"]) == 2
    assert len(once["hooks"]["PostToolUse"]) == 1
    assert merge_settings(once, hooks_block("/py")) == once
    assert merge_settings(once, hooks_block("/other/python")) == once      # already installed from another interpreter
    assert existing["hooks"]["PreToolUse"] == [other]                      # input not mutated


def test_run_init_writes_everything(fixture_repo, capsys):
    m = fixture_repo / "system-manifest.json"
    r = run_init(fixture_repo, m, oc_bin=no_oc(fixture_repo))
    assert r.agents_check_exit is None and r.settings_changed and r.oversight_written and r.manifest_changed
    settings = json.loads(r.settings_path.read_text())
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == settings["hooks"]["PostToolUse"][0]["matcher"] == HOOK_MATCHER
    assert r.oversight_doc == fixture_repo / "docs" / "human_oversight.md"
    raw = json.loads(m.read_text())
    assert raw["human_oversight"]["roles"][0]["can_intervene"] is True
    assert m.read_text().startswith('{\n  "system_id"')                     # indent 2
    assert (fixture_repo / ".aicl" / ".gitignore").read_text() == "*\n!.gitignore\n!log-anchor.json\n"
    out = capsys.readouterr().out
    assert "Cursor: enable third-party hook import" in out and "Grep, Glob, Task, TodoWrite, WebSearch, NotebookEdit" in out
    assert "agents check: skipped" in out
    r2 = run_init(fixture_repo, m, oc_bin=no_oc(fixture_repo))
    assert not r2.settings_changed and not r2.oversight_written and not r2.manifest_changed
    assert json.loads(r2.settings_path.read_text()) == settings


def test_doc_not_overwritten_without_force(fixture_repo):
    m = fixture_repo / "system-manifest.json"
    doc = fixture_repo / "docs" / "human_oversight.md"
    doc.parent.mkdir()
    doc.write_text("ours\n")
    assert not run_init(fixture_repo, m, oc_bin=no_oc(fixture_repo)).oversight_written
    assert doc.read_text() == "ours\n"
    assert run_init(fixture_repo, m, force=True, oc_bin=no_oc(fixture_repo)).oversight_written
    assert doc.read_text().startswith("# Human oversight and runtime guardrail (aicl)")


def test_doc_at_guardrail_ref_and_manifest_adds_only_absent(fixture_repo):
    m = fixture_repo / "system-manifest.json"
    raw = json.loads(m.read_text())
    raw["agent_inventory"]["agents"][0]["guardrails"] = [{"kind": "runtime_policy_hook", "evidence_ref": "governance/oversight.md"}]
    raw["human_oversight"] = {"roles": [{"role": "owner", "can_intervene": True}], "evidence_refs": []}
    m.write_text(json.dumps(raw))
    r = run_init(fixture_repo, m, oc_bin=no_oc(fixture_repo))
    assert r.oversight_doc == fixture_repo / "governance" / "oversight.md" and r.oversight_doc.is_file()
    assert not r.manifest_changed and json.loads(m.read_text())["human_oversight"]["roles"][0]["role"] == "owner"

    agent = raw["agent_inventory"]["agents"][0]
    del agent["guardrails"], agent["logging"], raw["human_oversight"]
    m.write_text(json.dumps(raw))
    r = run_init(fixture_repo, m, oc_bin=no_oc(fixture_repo))
    new = json.loads(m.read_text())
    a = new["agent_inventory"]["agents"][0]
    assert r.manifest_changed and len(r.manifest_changes) == 3
    assert a["guardrails"] == [{"kind": "runtime_policy_hook", "evidence_ref": "docs/human_oversight.md"}]
    assert a["logging"] == {"decision_log_ref": "agent-log.jsonl", "captures_intent": True}
    assert r.oversight_doc == fixture_repo / "docs" / "human_oversight.md"


def test_oversight_doc_content(manifest, agent):
    doc = render_oversight_doc(manifest, agent)
    assert doc.startswith("# Human oversight and runtime guardrail (aicl)")
    for knob in agent.mandate.limits:
        assert f"`{knob}`" in doc and f"`{KNOBS[knob][0]}`" in doc
    assert "agent-log.jsonl" in doc and "aicl log verify agent-log.jsonl --anchor" in doc
    assert "opencomplai agents verify-log agent-log.jsonl -m system-manifest.json" in doc
    assert "| deny |" in doc and "| ask |" in doc and "regenerated by aicl init" in doc
    assert "claude-code" in doc and "tool:WebFetch" in doc


def test_oversight_doc_unknown_knob(manifest):
    raw = json.loads(manifest.path.read_text())
    raw["agent_inventory"]["agents"][0]["mandate"]["limits"]["max_cost_eur"] = 5
    manifest.path.write_text(json.dumps(raw))
    m = load_manifest(manifest.path)
    doc = render_oversight_doc(m, select_agent(m, None, {}))
    assert "`max_cost_eur`" in doc and "not evaluated by aicl" in doc


def test_cmd_init_exit_codes(fixture_repo, tmp_path):
    ns = lambda **kw: Namespace(**{"repo": str(fixture_repo), "manifest": None, "force": False,  # noqa: E731
                                   "opencomplai": no_oc(tmp_path), **kw})
    assert cmd_init(ns(manifest=str(tmp_path / "missing.json"))) == 2
    assert cmd_init(ns()) == 0
    assert cmd_init(ns(opencomplai=fake_oc(tmp_path, 0))) == 0
    assert cmd_init(ns(opencomplai=fake_oc(tmp_path, 1))) == 3
    (fixture_repo / ".claude" / "settings.json").write_text("not json")
    assert cmd_init(ns()) == 2
