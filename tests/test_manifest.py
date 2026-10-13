import json
from pathlib import Path

import pytest

from aicl.core import AgentSpec, Mandate, ManifestError, ToolSpec
from aicl.manifest import (find_manifest, limit_bool, limit_list, load_manifest, log_path, mandate_reasons,
                           merge_manifest, oversight_block, select_agent, tool_matches)

TS = "2026-10-13T10:00:00+00:00"


def _write(p: Path, raw) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(raw if isinstance(raw, str) else json.dumps(raw))
    return p


def test_load_fixture(manifest, agent, fixture_repo):
    assert manifest.system_id == "shopper-insights" and manifest.root == fixture_repo.resolve()
    assert manifest.path == (fixture_repo / "system-manifest.json").resolve()
    assert manifest.intended_purpose.startswith("retail analytics") and manifest.high_risk_presumption is False
    assert manifest.has_human_oversight is False
    assert agent.id == "claude-code" and agent.mandate_ref == "mandate:claude-code"
    assert len(agent.tools) == 6
    assert agent.tools[0] == ToolSpec("Bash", "function", True, True)
    assert agent.tools[-1].kind == "mcp"
    lim = agent.mandate.limits
    assert lim["deny_destructive_shell"] is True and lim["mcp_allowed_servers"] == "filesystem"
    assert lim["allowed_hosts"] == "" and agent.mandate.expires_at is None
    assert agent.mandate.prohibited_actions == ("tool:WebFetch",)
    assert agent.decision_log_ref == "agent-log.jsonl" and agent.guardrail_refs == ("docs/human_oversight.md",)
    assert log_path(manifest, agent) == fixture_repo.resolve() / "agent-log.jsonl"


@pytest.mark.parametrize("raw, msg", [
    ("{not json", "valid JSON"), ("[]", "JSON object"), ({"x": 1}, "system_id"),
    ({"system_id": "s"}, "no agent"), ({"system_id": "s", "agent_inventory": {"agents": []}}, "no agent"),
    ({"system_id": "s", "agent_inventory": {"agents": [{"name": "noid"}]}}, "id"),
])
def test_load_errors(tmp_path, raw, msg):
    with pytest.raises(ManifestError, match=msg):
        load_manifest(_write(tmp_path / "system-manifest.json", raw))
    with pytest.raises(ManifestError, match="not found"):
        load_manifest(tmp_path / "missing.json")


def test_defaults_and_oversight(tmp_path):
    raw = {"system_id": "s", "unknown_key": 1,
           "human_oversight": {"roles": [{"role": "r", "can_intervene": True}]},
           "agent_inventory": {"agents": [{"id": "a", "tools": [{"name": "Bash"}],
                                           "logging": {"decision_log_ref": "logs/x.jsonl#head"}}]}}
    m = load_manifest(_write(tmp_path / "system-manifest.json", raw))
    a = m.agents[0]
    assert a.tools[0].kind == "function" and a.mandate is None and a.mandate_ref is None and a.name == "a"
    assert m.has_human_oversight is True
    assert log_path(m, a) == m.root / "logs" / "x.jsonl"
    raw["human_oversight"]["roles"][0]["can_intervene"] = False
    assert load_manifest(_write(tmp_path / "system-manifest.json", raw)).has_human_oversight is False


def test_find_manifest_order(tmp_path):
    walk = _write(tmp_path / "repo" / "system-manifest.json", "{}")
    deep = tmp_path / "repo" / "src" / "pkg"
    deep.mkdir(parents=True)
    proj = _write(tmp_path / "proj" / "system-manifest.json", "{}")
    explicit = _write(tmp_path / "other" / "m.json", "{}")
    assert find_manifest(deep, {}) == walk
    assert find_manifest(deep, {"CLAUDE_PROJECT_DIR": str(proj.parent)}) == proj
    env = {"AICL_MANIFEST": str(explicit), "CLAUDE_PROJECT_DIR": str(proj.parent)}
    assert find_manifest(deep, env) == explicit
    env["AICL_MANIFEST"] = str(tmp_path / "nope.json")          # missing explicit falls through
    assert find_manifest(deep, env) == proj
    assert find_manifest(deep, {"CLAUDE_PROJECT_DIR": str(tmp_path / "empty")}) == walk
    assert find_manifest(tmp_path / "nowhere", {}) is None


def test_select_agent(tmp_path):
    raw = {"system_id": "s", "agent_inventory": {"agents": [{"id": "a"}, {"id": "b"}]}}
    m = load_manifest(_write(tmp_path / "system-manifest.json", raw))
    assert select_agent(m, None, {}).id == "a"
    assert select_agent(m, None, {"AICL_AGENT_ID": "b"}).id == "b"
    assert select_agent(m, "a", {"AICL_AGENT_ID": "b"}).id == "a"
    with pytest.raises(ManifestError, match="'zzz'"):
        select_agent(m, "zzz", {})


def _mandate(limits=None, permitted=(), prohibited=(), expires_at=None):
    return Mandate(tuple(permitted), tuple(prohibited), limits or {}, expires_at)


def test_limit_bool_and_list():
    m = _mandate({"t": True, "f": False, "st": "TRUE", "sf": " false ", "junk": "yes", "n": 1,
                  "servers": " Filesystem , GitHub,, ", "empty": "", "num": 3})
    assert limit_bool(m, "t", False) is True and limit_bool(m, "f", True) is False
    assert limit_bool(m, "st", False) is True and limit_bool(m, "sf", True) is False
    assert limit_bool(m, "junk", True) is True and limit_bool(m, "n", False) is False
    assert limit_bool(m, "missing", True) is True and limit_bool(None, "t", False) is False
    assert limit_list(m, "servers") == ("filesystem", "github")
    assert limit_list(m, "empty", ("d",)) == ()
    assert limit_list(m, "num", ("d",)) == ("d",) and limit_list(m, "missing") == () and limit_list(None, "x", ("d",)) == ("d",)


def test_tool_matches():
    assert tool_matches("tool:Bash", "bash") and tool_matches("Bash", "BASH") and tool_matches("TOOL:bash", "Bash")
    assert not tool_matches("tool:Bash", "Edit") and not tool_matches("tool:Bash", "tool:Bash")


@pytest.mark.parametrize("tool, expected", [
    ("Bash", ()), ("Edit", ()), ("mcp__filesystem__read_file", ()),
    ("WebFetch", ("prohibited_action", "not_permitted")),
    ("mcp__github__create_issue", ("tool_not_declared", "not_permitted")),
    ("bash", ()),
])
def test_mandate_reasons_fixture(agent, tool, expected):
    assert mandate_reasons(agent, tool, TS) == expected


def test_mandate_reasons_expiry_and_casefold():
    tools = (ToolSpec("Bash", "function"),)
    a = AgentSpec("a", "a", tools, _mandate(permitted=["tool:bash"], expires_at="2026-10-13"), None, ())
    assert mandate_reasons(a, "Bash", "2026-10-12T23:59:59+00:00") == ()
    assert mandate_reasons(a, "Bash", "2026-10-13T00:00:00+00:00") == ()
    assert mandate_reasons(a, "Bash", "2026-10-13T00:00:01+00:00") == ("mandate_expired",)
    assert mandate_reasons(a, "Edit", "2026-10-14T00:00:00+00:00") == ("tool_not_declared", "not_permitted",
                                                                       "mandate_expired")
    no_permitted = AgentSpec("a", "a", tools, _mandate(), None, ())
    assert mandate_reasons(no_permitted, "Bash", TS) == ()
    no_mandate = AgentSpec("a", "a", tools, None, None, ())
    assert mandate_reasons(no_mandate, "Bash", TS) == ()
    assert mandate_reasons(no_mandate, "Edit", TS) == ("tool_not_declared",)   # Opencomplai checks tools regardless


def test_oversight_block_shape():
    b = oversight_block()
    assert b["roles"][0]["can_intervene"] is True and b["roles"][0]["role"] == "repository maintainer"
    assert b["evidence_refs"] == ["docs/human_oversight.md"] and "aicl log status" in b["escalation"]
    assert set(b["roles"][0]) == {"role", "authority", "can_intervene", "conditions"}


def test_merge_manifest_adds_never_overwrites(manifest):
    raw = json.loads(json.dumps(manifest.raw))
    new, changes = merge_manifest(raw, "claude-code", "docs/human_oversight.md")
    assert raw == manifest.raw and "human_oversight" not in raw          # pure
    assert new["human_oversight"] == oversight_block() and len(changes) == 1
    again, changes2 = merge_manifest(new, "claude-code", "docs/human_oversight.md")
    assert again == new and changes2 == []
    bare = {"system_id": "s", "human_oversight": {"roles": [{"role": "x", "can_intervene": False}]},
            "agent_inventory": {"agents": [{"id": "a", "guardrails": []}]}}
    new, changes = merge_manifest(bare, "a", "docs/g.md")
    assert new["human_oversight"] == bare["human_oversight"]
    agent = new["agent_inventory"]["agents"][0]
    assert agent["guardrails"] == [{"kind": "runtime_policy_hook", "evidence_ref": "docs/g.md"}]
    assert agent["logging"] == {"decision_log_ref": "agent-log.jsonl", "captures_intent": True}
    assert len(changes) == 2 and bare["agent_inventory"]["agents"][0]["guardrails"] == []
    with pytest.raises(ManifestError):
        merge_manifest(bare, "missing", "docs/g.md")


def test_merged_fixture_still_loads(fixture_repo, manifest):
    new, _ = merge_manifest(manifest.raw, "claude-code", "docs/human_oversight.md")
    p = _write(fixture_repo / "system-manifest.json", new)
    assert load_manifest(p).has_human_oversight is True


@pytest.mark.external
def test_fixture_and_merged_manifest_pass_agents_check(fixture_repo, manifest, oc_bin):
    import subprocess
    for raw in (manifest.raw, merge_manifest(manifest.raw, "claude-code", "docs/human_oversight.md")[0]):
        _write(fixture_repo / "system-manifest.json", raw)
        r = subprocess.run([oc_bin, "agents", "check", "-m", str(fixture_repo / "system-manifest.json"), "-o", "json"],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0 and json.loads(r.stdout)["exit_code"] == 0, r.stdout + r.stderr
