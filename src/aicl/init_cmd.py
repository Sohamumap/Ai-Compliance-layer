"""aicl init: install the hooks, write the oversight doc, merge the human_oversight block, run agents check."""
from __future__ import annotations

import copy
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from aicl import oc
from aicl.core import (HOOK_MATCHER, HOOK_TIMEOUT_S, AgentSpec, AiclError, Manifest, ManifestError, OcError,
                       OcNotFound, atomic_write_text, read_json)
from aicl.manifest import MANIFEST_NAME, load_manifest, log_path, merge_manifest, select_agent

__all__ = ["DEFAULT_DOC", "UNGOVERNED_TOOLS", "CURSOR_NOTE", "KNOBS", "hook_command", "hooks_block",
           "merge_settings", "render_oversight_doc", "InitResult", "run_init", "cmd_init"]

DEFAULT_DOC = "docs/human_oversight.md"
AICL_GITIGNORE = "*\n!.gitignore\n!log-anchor.json\n"
UNGOVERNED_TOOLS = ("Grep", "Glob", "Task", "TodoWrite", "WebSearch", "NotebookEdit")
CURSOR_NOTE = "Cursor: enable third-party hook import to reuse .claude/settings.json (not verified in this environment)"

# limits knob -> (rule it governs, decision when it fires, what it does)
KNOBS: dict[str, tuple[str, str, str]] = {
    "deny_destructive_shell": ("destructive_shell", "deny", "recursive rm, find -delete, force push, hard reset, disk writes, piping a download into sh"),
    "deny_secrets_in_input": ("secret_in_input", "deny", "an API key, token or private key anywhere in the tool input"),
    "deny_secret_file_read": ("secret_file_read", "deny", "reading .env, *.pem, *.key, ~/.ssh/id_*, ~/.aws/credentials and similar"),
    "deny_undeclared_tools": ("tool_not_declared", "deny", "a governed tool the agent does not declare in tools[]"),
    "mcp_allowed_servers": ("mcp_server_not_allowed", "deny", "an MCP tool whose server is not in this comma-separated list"),
    "ask_obfuscated_shell": ("obfuscated_shell", "ask", "base64-decoded or eval'd shell, hex-escaped payloads"),
    "ask_network_egress": ("network_egress", "ask", "curl, wget, nc, ssh, scp or rsync to a host outside allowed_hosts"),
    "allowed_hosts": ("network_egress", "ask", "comma-separated hosts exempt from the network egress ask"),
    "protected_paths": ("protected_path_write", "ask", "Edit/Write to these comma-separated globs or prefixes"),
}


def hook_command(sub: str, python: str = sys.executable) -> str:
    return f'"{python}" -m aicl hook {sub}'


def hooks_block(python: str = sys.executable) -> dict:
    def group(sub: str) -> list[dict]:
        return [{"matcher": HOOK_MATCHER,
                 "hooks": [{"type": "command", "command": hook_command(sub, python), "timeout": HOOK_TIMEOUT_S}]}]
    # PostToolUse runs only after a successful tool; a failed tool fires PostToolUseFailure instead
    return {"PreToolUse": group("pre"), "PostToolUse": group("post"), "PostToolUseFailure": group("post")}


def merge_settings(existing: Mapping, block: Mapping) -> dict:
    """Append our hook group per event unless an aicl hook command for that event is already installed."""
    new = copy.deepcopy(dict(existing))
    hooks = new.get("hooks") if isinstance(new.get("hooks"), dict) else {}
    new["hooks"] = hooks
    for event, groups in block.items():
        cur = hooks.get(event) if isinstance(hooks.get(event), list) else []
        for g in groups:
            sub = g["hooks"][0]["command"].rsplit(" ", 1)[-1]
            marker = f"aicl hook {sub}"   # matches "<python>" -m aicl hook pre and the .venv/bin/aicl hook pre form
            if not any(marker in str(h.get("command", "")) for eg in cur if isinstance(eg, dict)
                       for h in (eg.get("hooks") or []) if isinstance(h, dict)):
                cur.append(copy.deepcopy(g))
        hooks[event] = cur
    return new


def render_oversight_doc(m: Manifest, agent: AgentSpec) -> str:
    md = agent.mandate
    limits = dict(md.limits) if md else {}
    lp = log_path(m, agent)
    rel_log = lp.relative_to(m.root).as_posix() if lp.is_relative_to(m.root) else str(lp)
    rel_manifest = m.path.name
    tools = ", ".join(f"`{t.name}`" + (" (requires approval)" if t.requires_approval else "") for t in agent.tools)
    lines = [
        "# Human oversight and runtime guardrail (aicl)", "",
        f"System `{m.system_id}`. Agent `{agent.id}` ({agent.name}). "
        "Every governed tool call of this agent passes through the aicl Claude Code hook "
        f"(`PreToolUse`, `PostToolUse` and `PostToolUseFailure`, matcher `{HOOK_MATCHER}`).", "",
        "## Mandate", "",
        f"- Declared tools: {tools or 'none'}",
        f"- Permitted actions: {', '.join(f'`{a}`' for a in md.permitted_actions) if md and md.permitted_actions else 'not restricted'}",
        f"- Prohibited actions: {', '.join(f'`{a}`' for a in md.prohibited_actions) if md and md.prohibited_actions else 'none'}",
        f"- Mandate expires: {md.expires_at if md and md.expires_at else 'no expiry declared'}", "",
        "## Limits knobs (`mandate.limits`)", "",
        "| Knob | Value | Rule it governs | Decision | Scope |", "|---|---|---|---|---|",
    ]
    for k in sorted(set(KNOBS) | set(limits)):
        rule, dec, what = KNOBS.get(k, ("(none)", "-", "not evaluated by aicl"))
        val = json.dumps(limits[k]) if k in limits else "(default)"
        lines.append(f"| `{k}` | `{val}` | `{rule}` | {dec} | {what} |")
    lines += [
        "", "## What is denied and what goes to a human", "",
        "Denied outright (logged as `blocked`, `outside_mandate: true`): `self_protect` (built in, writes to "
        "`.claude/settings*.json`, `.cursor/hooks.json`, `system-manifest.json`, `.aicl/**`, the decision log and its lock), "
        "`tool_prohibited`, `mcp_server_not_allowed`, `tool_not_declared`, `tool_not_permitted` (also expired mandate), "
        "`destructive_shell`, `secret_in_input`, `secret_file_read`.", "",
        "Routed to a human (`permissionDecision: ask`): `obfuscated_shell`, `network_egress`, `protected_path_write`, and any "
        "internal hook error (unless `AICL_FAIL_CLOSED=1`, which denies instead). The repository maintainer answers the "
        "prompt in Claude Code. An approved action is logged with the intent prefix `[approved by human]`; a declined one "
        "stays as an unresolved pending record under `.aicl/pending/` (listed by `aicl log status`).", "",
        f"Tools outside the matcher are not governed in v0: {', '.join(UNGOVERNED_TOOLS)}.", "",
        "## Decision log", "",
        f"Decisions are appended to `{rel_log}` in Opencomplai's hash-chained agent decision log format "
        "(raw tool input is only hashed). The head and count are anchored in `.aicl/log-anchor.json` after every append.", "",
        "Verify it with both commands:", "",
        f"    aicl log verify {rel_log} --anchor",
        f"    opencomplai agents verify-log {rel_log} -m {rel_manifest}", "",
        "`verify-log` exits 1 whenever blocked entries exist; they are evidence of enforcement. The invariant is that "
        "every out-of-mandate entry was blocked.", "",
        "_This file is regenerated by aicl init (`aicl init --force`)._", "",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class InitResult:
    settings_path: Path; settings_changed: bool; oversight_doc: Path; oversight_written: bool
    manifest_changed: bool; manifest_changes: tuple[str, ...]; aicl_dir: Path; agents_check_exit: int | None


def _first_line(text: str) -> str:
    return next((x.strip() for x in (text or "").splitlines() if x.strip()), "no detail")[:200]


def _doc_rel(repo: Path, agent: AgentSpec) -> str:
    ref = agent.guardrail_refs[0] if agent.guardrail_refs else ""
    if ref and not Path(ref).is_absolute() and (repo / ref).resolve().is_relative_to(repo):
        return Path(ref).as_posix()
    return DEFAULT_DOC


def run_init(repo: Path, manifest_path: Path, force: bool = False, oc_bin: str | None = None) -> InitResult:
    repo = Path(repo).resolve()
    m = load_manifest(manifest_path)
    agent = select_agent(m, None, os.environ)

    settings_path = repo / ".claude" / "settings.json"
    try:
        existing: Any = read_json(settings_path) if settings_path.is_file() else {}
    except (OSError, ValueError) as e:
        raise AiclError(f"cannot read {settings_path}: {e}") from e
    if not isinstance(existing, dict):
        raise AiclError(f"{settings_path} is not a JSON object")
    merged = merge_settings(existing, hooks_block())
    settings_changed = merged != existing
    if settings_changed:
        atomic_write_text(settings_path, json.dumps(merged, indent=2) + "\n")

    doc_rel = _doc_rel(repo, agent)
    doc = repo / doc_rel
    oversight_written = force or not doc.exists()
    if oversight_written:
        atomic_write_text(doc, render_oversight_doc(m, agent))

    new_raw, changes = merge_manifest(m.raw, agent.id, doc_rel)
    if changes:
        atomic_write_text(m.path, json.dumps(new_raw, indent=2) + "\n")

    aicl_dir = repo / ".aicl"
    atomic_write_text(aicl_dir / ".gitignore", AICL_GITIGNORE)

    try:
        ac = oc.agents_check(repo, m.path, bin=oc_bin)
        ac_exit: int | None = ac.exit_code
        ac_line = f"opencomplai agents check: exit {ac.exit_code}" + (
            "" if ac.exit_code == 0 else f" (manifest rejected by opencomplai as invalid: {_first_line(ac.stderr)})"
            if ac.exit_code == 2
            else f" ({len((ac.json or {}).get('findings') or [])} finding(s))")
    except (OcNotFound, OcError) as e:
        ac_exit, ac_line = None, f"opencomplai agents check: skipped ({e})"

    print(f"hooks: {settings_path} ({'updated' if settings_changed else 'already installed'})")
    print(f"oversight doc: {doc} ({'written' if oversight_written else 'kept existing; --force to regenerate'})")
    print(f"manifest: {m.path} ({'; '.join(changes) if changes else 'unchanged'})")
    print(f"evidence dir: {aicl_dir} (.gitignore keeps only log-anchor.json)")
    print(f"decision log: {log_path(m, agent)} (created by the first governed tool call)")
    print(ac_line)
    print(f"ungoverned in v0 (outside the hook matcher): {', '.join(UNGOVERNED_TOOLS)}")
    print(CURSOR_NOTE)
    return InitResult(settings_path, settings_changed, doc, oversight_written, bool(changes), tuple(changes),
                      aicl_dir, ac_exit)


def cmd_init(args) -> int:
    repo = Path(getattr(args, "repo", None) or ".")
    manifest = Path(getattr(args, "manifest", None) or repo / MANIFEST_NAME)
    try:
        r = run_init(repo, manifest, force=bool(getattr(args, "force", False)), oc_bin=getattr(args, "opencomplai", None))
    except (ManifestError, AiclError) as e:
        print(f"aicl init: error: {e}", file=sys.stderr)
        return 2
    if r.agents_check_exit == 2:   # Opencomplai validation failure = manifest invalid (DESIGN 4.13)
        return 2
    return 3 if r.agents_check_exit not in (None, 0) else 0
