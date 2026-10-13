"""Claude Code PreToolUse/PostToolUse hook: parse stdin, evaluate policy, log, answer (allow = silence)."""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from aicl.core import HOOK_BUDGET_S, Decision, HookEvent, HookInputError, PendingRecord, now_ts, redact
from aicl.decisionlog import append, input_hash, make_payload, pop_pending, put_pending, write_deadletter
from aicl.manifest import find_manifest, load_manifest, log_path, select_agent
from aicl.policy import RuleCtx, derive_intent, evaluate

__all__ = ["HookResult", "parse_event", "pre_output", "post_outcome", "run_pre", "run_post", "cmd_hook", "add_parser",
           "NOT_GOVERNED"]

NOT_GOVERNED = "aicl: no system-manifest.json found; not governed\n"


@dataclass(frozen=True)
class HookResult:
    stdout: str | None; stderr: str; exit_code: int


def parse_event(text: str, default_event: str) -> HookEvent:
    try:
        raw = json.loads(text)
    except (TypeError, ValueError) as e:
        raise HookInputError(f"hook payload is not JSON: {e}") from None
    if not isinstance(raw, dict):
        raise HookInputError("hook payload is not a JSON object")
    tool = raw.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise HookInputError("hook payload has no tool_name")
    ti = raw.get("tool_input")
    ti = {} if ti is None else ti if isinstance(ti, dict) else {"value": ti}
    ev, tid = raw.get("hook_event_name"), raw.get("tool_use_id")
    return HookEvent(event=ev if isinstance(ev, str) and ev else default_event,
                     session_id=str(raw.get("session_id") or ""), cwd=Path(str(raw.get("cwd") or os.getcwd())),
                     tool_name=tool, tool_input=ti, tool_use_id=tid if isinstance(tid, str) and tid else None,
                     tool_response=raw.get("tool_response"), raw=raw)


def pre_output(decision: Decision, reason: str) -> str | None:
    if decision is Decision.ALLOW:
        return None   # silence: Claude Code's own permission flow continues; we never emit "allow"
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision.value,
                                              "permissionDecisionReason": reason}})


def post_outcome(tool_response: Any) -> str:
    if isinstance(tool_response, dict) and any(tool_response.get(k) for k in ("is_error", "error", "interrupted")):
        return "failure"
    if isinstance(tool_response, str) and tool_response.startswith("Error"):
        return "failure"
    return "success"


def _evaluate(ev: HookEvent, mpath: Path, agent_id: str | None, env: Mapping[str, str], check: Callable[[], None],
              state: dict[str, Any]):
    m = load_manifest(mpath)
    agent = select_agent(m, agent_id, env)
    state["log"] = log = log_path(m, agent)
    check()
    ctx = RuleCtx(agent, ev.tool_name, ev.tool_input, ev.cwd, m.root, log, now_ts())
    ev2 = evaluate(ctx)
    state["decision"] = ev2.decision
    check()
    return agent, log, ev2, derive_intent(ctx, ev2)


def _deadline(clock: Callable[[], float]) -> Callable[[], None]:
    deadline = clock() + HOOK_BUDGET_S

    def check() -> None:
        if clock() > deadline:
            raise TimeoutError(f"hook budget of {HOOK_BUDGET_S:g}s exceeded")
    return check


def _deadletter(state: dict[str, Any], reason: str) -> None:
    if state.get("log") is not None:
        try:
            write_deadletter(state["log"], reason, state.get("payload"))
        except Exception:   # best effort: the answer to Claude Code matters more than the deadletter line
            pass


def run_pre(stdin_text: str, *, env: Mapping[str, str], manifest_override: Path | None, agent_id: str | None,
            fail_closed: bool, clock: Callable[[], float] = time.monotonic) -> HookResult:
    try:
        ev = parse_event(stdin_text, "PreToolUse")
    except HookInputError:
        reason = "aicl: ask [hook_input] malformed hook payload"
        return HookResult(pre_output(Decision.ASK, reason), reason + "\n", 0)
    mpath = manifest_override or find_manifest(ev.cwd, env)
    if mpath is None:
        return HookResult(None, NOT_GOVERNED, 0)
    state: dict[str, Any] = {}
    try:
        check = _deadline(clock)
        agent, log, ev2, intent = _evaluate(ev, Path(mpath), agent_id, env, check, state)
        if ev2.decision is Decision.DENY:
            state["payload"] = payload = make_payload(agent, intent, ev.tool_name, ev.tool_input, "blocked", True)
            check()
            append(log, payload)
        elif ev2.decision is Decision.ASK:
            check()
            put_pending(log, PendingRecord(ev.tool_use_id or "", ev.tool_name, intent, input_hash(ev.tool_input),
                                           ev2.rule_id, now_ts()))
        return HookResult(pre_output(ev2.decision, ev2.reason), "", 0)
    except Exception as e:   # governed repo + internal error -> a human decides (or deny when fail-closed)
        closed = fail_closed or env.get("AICL_FAIL_CLOSED") == "1" or state.get("decision") is Decision.DENY
        fail = Decision.DENY if closed else Decision.ASK
        reason = f"aicl: {fail.value} [internal_error] {type(e).__name__}: {redact(str(e))[:120]}"
        _deadletter(state, reason)
        return HookResult(pre_output(fail, reason), reason + "\n", 0)


def run_post(stdin_text: str, *, env: Mapping[str, str], manifest_override: Path | None, agent_id: str | None,
             fail_closed: bool, clock: Callable[[], float] = time.monotonic) -> HookResult:
    try:
        ev = parse_event(stdin_text, "PostToolUse")
    except HookInputError as e:
        return HookResult(None, f"aicl: error: {e}\n", 1)
    mpath = manifest_override or find_manifest(ev.cwd, env)
    if mpath is None:
        return HookResult(None, NOT_GOVERNED, 0)
    state: dict[str, Any] = {}
    try:
        check = _deadline(clock)
        agent, log, ev2, intent = _evaluate(ev, Path(mpath), agent_id, env, check, state)
        approved = pop_pending(log, ev.tool_use_id) is not None
        if ev2.decision is Decision.ASK or approved:   # the tool ran after an ask, so the human approved it
            intent = "[approved by human] " + intent
        state["payload"] = payload = make_payload(agent, intent, ev.tool_name, ev.tool_input,
                                                  post_outcome(ev.tool_response), ev2.outside_mandate)
        check()
        append(log, payload)
        return HookResult(None, "", 0)
    except Exception as e:   # PostToolUse never blocks: record and report
        reason = f"aicl: error: {type(e).__name__}: {redact(str(e))[:120]}"
        _deadletter(state, reason)
        return HookResult(None, reason + "\n", 1)


def add_parser(sub: Any) -> Any:
    """Optional helper for cli.py: registers `hook pre|post` with the flags cmd_hook reads."""
    p = sub.add_parser("hook", help="Claude Code PreToolUse/PostToolUse hook (reads the event JSON on stdin)")
    p.add_argument("phase", choices=("pre", "post"))
    p.add_argument("--manifest", type=Path)
    p.add_argument("--agent")
    p.add_argument("--fail-closed", action="store_true")
    return p


def cmd_hook(args: Any) -> int:
    phase = next((v for n in ("phase", "hook_cmd", "hook_phase", "event", "which", "cmd")
                  if (v := getattr(args, n, None)) in ("pre", "post")), None)
    if phase is None:
        print("usage: aicl hook pre|post < event.json", file=sys.stderr)
        return 2
    run = run_pre if phase == "pre" else run_post
    m = getattr(args, "manifest", None)
    r = run(sys.stdin.read(), env=os.environ, manifest_override=Path(m) if m else None,
            agent_id=getattr(args, "agent", None) or getattr(args, "agent_id", None),
            fail_closed=bool(getattr(args, "fail_closed", False)))
    if r.stdout is not None:
        sys.stdout.write(r.stdout + "\n")
        sys.stdout.flush()
    if r.stderr:
        sys.stderr.write(r.stderr)
    return r.exit_code
