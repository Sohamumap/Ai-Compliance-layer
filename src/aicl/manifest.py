"""Opencomplai system-manifest.json: discovery, loading, agent selection, mandate checks, oversight merge."""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from aicl.core import AgentSpec, Mandate, Manifest, ManifestError, ToolSpec

MANIFEST_NAME = "system-manifest.json"
DEFAULT_LOG = "agent-log.jsonl"


def find_manifest(start: Path, env: Mapping[str, str]) -> Path | None:
    """AICL_MANIFEST, then $CLAUDE_PROJECT_DIR/system-manifest.json, then walk up from start."""
    if env.get("AICL_MANIFEST"):
        p = Path(env["AICL_MANIFEST"]).expanduser()
        if p.is_file():
            return p
    if env.get("CLAUDE_PROJECT_DIR"):
        p = Path(env["CLAUDE_PROJECT_DIR"]).expanduser() / MANIFEST_NAME
        if p.is_file():
            return p
    cur = Path(start).expanduser().resolve()
    for d in (cur, *cur.parents):
        p = d / MANIFEST_NAME
        if p.is_file():
            return p
    return None


def _list(v: Any, what: str) -> list:
    if v is None:
        return []
    if not isinstance(v, list):
        raise ManifestError(f"{what} must be a list")
    return v


def _agent(a: Any) -> AgentSpec:
    if not isinstance(a, dict) or not isinstance(a.get("id"), str) or not a["id"]:
        raise ManifestError("agent_inventory.agents[] entries need a string 'id'")
    tools = tuple(
        ToolSpec(name=str(t["name"]), kind=str(t.get("kind") or "function"),
                 side_effects=bool(t.get("side_effects", False)), requires_approval=bool(t.get("requires_approval", False)))
        for t in _list(a.get("tools"), "tools") if isinstance(t, dict) and t.get("name"))
    m = a.get("mandate")
    mandate = None
    if isinstance(m, dict):
        limits = m.get("limits") if isinstance(m.get("limits"), dict) else {}
        exp = m.get("expires_at")
        mandate = Mandate(tuple(str(x) for x in _list(m.get("permitted_actions"), "permitted_actions")),
                          tuple(str(x) for x in _list(m.get("prohibited_actions"), "prohibited_actions")),
                          dict(limits), str(exp) if exp else None)
    logging = a.get("logging") if isinstance(a.get("logging"), dict) else {}
    guardrails = _list(a.get("guardrails"), "guardrails")
    return AgentSpec(id=a["id"], name=str(a.get("name") or a["id"]), tools=tools, mandate=mandate,
                     decision_log_ref=logging.get("decision_log_ref") or None,
                     guardrail_refs=tuple(g["evidence_ref"] for g in guardrails
                                          if isinstance(g, dict) and isinstance(g.get("evidence_ref"), str)))


def load_manifest(path: Path) -> Manifest:
    path = Path(path).expanduser()
    if not path.is_file():
        raise ManifestError(f"manifest not found: {path}")
    try:
        raw = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ManifestError(f"manifest is not valid JSON: {path}: {e}") from e
    if not isinstance(raw, dict):
        raise ManifestError(f"manifest is not a JSON object: {path}")
    if not isinstance(raw.get("system_id"), str) or not raw["system_id"]:
        raise ManifestError(f"manifest has no system_id: {path}")
    inv = raw.get("agent_inventory")
    agents = tuple(_agent(a) for a in _list(inv.get("agents") if isinstance(inv, dict) else None, "agents"))
    if not agents:
        raise ManifestError(f"manifest declares no agent_inventory.agents: {path}")
    ho = raw.get("human_oversight")
    has_ho = isinstance(ho, dict) and any(isinstance(r, dict) and r.get("can_intervene")
                                          for r in (ho.get("roles") or []))
    path = path.resolve()
    return Manifest(path=path, root=path.parent, system_id=raw["system_id"],
                    intended_purpose=str(raw.get("intended_purpose") or ""),
                    high_risk_presumption=bool(raw.get("high_risk_presumption", False)),
                    agents=agents, has_human_oversight=has_ho, raw=raw)


def select_agent(m: Manifest, agent_id: str | None, env: Mapping[str, str]) -> AgentSpec:
    want = agent_id or env.get("AICL_AGENT_ID")
    if not want:
        return m.agents[0]
    for a in m.agents:
        if a.id == want:
            return a
    raise ManifestError(f"agent {want!r} not in agent_inventory (have: {', '.join(a.id for a in m.agents)})")


def limit_bool(mandate: Mandate | None, key: str, default: bool) -> bool:
    v = mandate.limits.get(key) if mandate else None
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().casefold() in ("true", "false"):
        return v.strip().casefold() == "true"
    return default


def limit_list(mandate: Mandate | None, key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    v = mandate.limits.get(key) if mandate else None
    if not isinstance(v, str):
        return default
    return tuple(s.strip().casefold() for s in v.split(",") if s.strip())


def log_path(m: Manifest, agent: AgentSpec) -> Path:
    ref = (agent.decision_log_ref or DEFAULT_LOG).split("#", 1)[0] or DEFAULT_LOG
    return m.root / ref


def tool_matches(action: str, tool_name: str) -> bool:
    a = str(action).casefold()
    if a.startswith("tool:"):
        a = a[5:]
    return a == tool_name.casefold()


def _parse_ts(value: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def mandate_reasons(agent: AgentSpec, tool_name: str, ts: str) -> tuple[str, ...]:
    """Opencomplai verify-log reason codes this (agent, tool, ts) would earn, in its order (minus self_reported)."""
    out: list[str] = []
    if tool_name.casefold() not in {t.name.casefold() for t in agent.tools}:
        out.append("tool_not_declared")
    m = agent.mandate
    if m is not None:
        if any(tool_matches(a, tool_name) for a in m.prohibited_actions):
            out.append("prohibited_action")
        if m.permitted_actions and not any(tool_matches(a, tool_name) for a in m.permitted_actions):
            out.append("not_permitted")
        if m.expires_at:
            now, exp = _parse_ts(ts), _parse_ts(m.expires_at)
            if now is None or exp is None:
                out.append("bad_timestamp")
            elif now > exp:
                out.append("mandate_expired")
    return tuple(out)


def oversight_block() -> dict:
    return {
        "roles": [{"role": "repository maintainer",
                   "authority": "approve or deny agent actions that aicl routes to ask; review every deny",
                   "can_intervene": True,
                   "conditions": ["any aicl decision with permissionDecision ask",
                                  "any blocked entry in the decision log"]}],
        "escalation": "aicl hook returns permissionDecision=ask; the maintainer answers in Claude Code; "
                      "unresolved asks are listed by aicl log status",
        "evidence_refs": ["docs/human_oversight.md"],
    }


def merge_manifest(raw: Mapping, agent_id: str, doc_rel: str) -> tuple[dict, list[str]]:
    """Pure: deep copy of raw with the oversight block, agent guardrail and logging added where absent."""
    new = copy.deepcopy(dict(raw))
    changes: list[str] = []
    if "human_oversight" not in new:
        new["human_oversight"] = {**oversight_block(), "evidence_refs": [doc_rel]}
        changes.append("human_oversight: added maintainer role (can_intervene: true)")
    agents = (new.get("agent_inventory") or {}).get("agents") or []
    agent = next((a for a in agents if isinstance(a, dict) and a.get("id") == agent_id), None)
    if agent is None:
        raise ManifestError(f"agent {agent_id!r} not in agent_inventory")
    if not agent.get("guardrails"):
        agent["guardrails"] = [{"kind": "runtime_policy_hook", "evidence_ref": doc_rel}]
        changes.append(f"agent {agent_id}: guardrails += runtime_policy_hook ({doc_rel})")
    if "logging" not in agent:
        agent["logging"] = {"decision_log_ref": DEFAULT_LOG, "captures_intent": True}
        changes.append(f"agent {agent_id}: logging.decision_log_ref = {DEFAULT_LOG}")
    return new, changes
