"""Hook I/O and runner: all nine fixture events in-process, fail paths, deadline, real subprocess for 01/02."""
from __future__ import annotations

import importlib.util
import itertools
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aicl import hook
from aicl.core import Decision, LogError
from aicl.decisionlog import pending_dir, read_anchor, read_entries, tail, verify
from aicl.hook import parse_event, post_outcome, pre_output, run_post, run_pre

PRE = {
    "01_pre_edit": None,
    "02_pre_bash_rm": ("deny", "aicl: deny [destructive_shell] rm with a recursive flag; "
                               "mandate limit deny_destructive_shell=true for agent claude-code"),
    "03_pre_bash_secret": ("deny", "aicl: deny [secret_in_input] secret-like value (anthropic_key) in tool input; "
                                   "mandate limit deny_secrets_in_input=true for agent claude-code"),
    "04_pre_webfetch": ("deny", "aicl: deny [tool_prohibited] tool WebFetch is in prohibited_actions of the mandate "
                                "for agent claude-code"),
    "05_pre_mcp": ("deny", "aicl: deny [mcp_server_not_allowed] MCP server github not in mcp_allowed_servers "
                           "(filesystem) for agent claude-code"),
    "06_pre_bash_curl": ("ask", "aicl: ask [network_egress] network egress via curl to example.com (not in "
                                "allowed_hosts); mandate limit ask_network_egress=true for agent claude-code"),
    "07_pre_edit_settings": ("deny", "aicl: deny [self_protect] write to protected path .claude/settings.json "
                                     "(guardrail configuration or evidence)"),
}
ORDER = ["01_pre_edit", "01_post_edit", "02_pre_bash_rm", "03_pre_bash_secret", "04_pre_webfetch", "05_pre_mcp",
         "06_pre_bash_curl", "06_post_bash_curl", "07_pre_edit_settings"]
KW = dict(env={}, manifest_override=None, agent_id=None, fail_closed=False)


def expected_stdout(name):
    exp = PRE[name]
    if exp is None:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": exp[0],
                                   "permissionDecisionReason": exp[1]}}


def test_full_replay(events, fixture_repo):
    log = fixture_repo / "agent-log.jsonl"
    count = 0
    for name in ORDER:
        text = json.dumps(events[name])
        r = (run_post if "_post_" in name else run_pre)(text, **KW)
        assert r.exit_code == 0, (name, r)
        if "_post_" in name:
            assert r.stdout is None
            count += 1
        else:
            exp = expected_stdout(name)
            assert (None if r.stdout is None else json.loads(r.stdout)) == exp, name
            if exp and exp["hookSpecificOutput"]["permissionDecision"] == "deny":
                count += 1
        assert tail(log)[1] == count, name
        if count:
            a = read_anchor(log)
            assert (a.head, a.count) == tail(log) and a.log == "agent-log.jsonl"
        if name == "06_pre_bash_curl":
            rec = json.loads((pending_dir(log) / "tu-06.json").read_text())
            assert rec["rule_id"] == "network_egress" and rec["tool"] == "Bash"
            assert rec["intent"] == "Bash: curl (2 args): Fetch competitor pricing page | aicl:ask:network_egress"
        if name == "06_post_bash_curl":
            assert not (pending_dir(log) / "tu-06.json").exists()

    entries = read_entries(log)
    assert [e.seq for e in entries] == [1, 2, 3, 4, 5, 6, 7]
    assert {e.seq for e in entries if e.payload.outcome == "blocked"} == {2, 3, 4, 5, 7}
    assert [e.payload.outside_mandate for e in entries] == [False, True, True, True, True, False, True]
    assert [e.payload.tool for e in entries] == ["Edit", "Bash", "Bash", "WebFetch", "mcp__github__create_issue",
                                                 "Bash", "Edit"]
    assert entries[0].payload.outcome == "success" and entries[0].payload.intent == "Edit: src/insights.py | aicl:allow:ok"
    assert entries[1].payload.intent == "Bash: rm (2 args): Delete cached data | aicl:deny:destructive_shell"
    assert "<redacted:anthropic_key>" in entries[2].payload.intent
    assert entries[5].payload.outcome == "success"
    assert entries[5].payload.intent == \
        "[approved by human] Bash: curl (2 args): Fetch competitor pricing page | aicl:ask:network_egress"
    assert entries[6].payload.intent == "Edit: .claude/settings.json | aicl:deny:self_protect"
    assert all(e.payload.mandate_ref == "mandate:claude-code" for e in entries)
    assert verify(log).ok
    raw = log.read_text()
    assert "sk-ant" not in raw and "nlargest" not in raw and "example.com/pricing" not in raw


def test_allow_and_ask_do_not_grow_log(events, fixture_repo):
    log = fixture_repo / "agent-log.jsonl"
    assert run_pre(json.dumps(events["01_pre_edit"]), **KW) == hook.HookResult(None, "", 0)
    assert json.loads(run_pre(json.dumps(events["06_pre_bash_curl"]), **KW).stdout)[
        "hookSpecificOutput"]["permissionDecision"] == "ask"
    assert not log.exists()


def test_post_failure_outcome(events, fixture_repo):
    ev = dict(events["06_post_bash_curl"], tool_response={"stdout": "", "stderr": "boom", "is_error": True})
    assert run_post(json.dumps(ev), **KW).exit_code == 0
    e = read_entries(fixture_repo / "agent-log.jsonl")[0]
    assert e.payload.outcome == "failure" and e.payload.intent.startswith("[approved by human] Bash: curl")


def test_malformed_stdin():
    for bad in ("not json", "[1, 2]", json.dumps({"cwd": "/"}), json.dumps({"tool_name": ""})):
        r = run_pre(bad, **KW)
        assert r.exit_code == 0
        assert json.loads(r.stdout) == {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                        "permissionDecision": "ask",
                                        "permissionDecisionReason": "aicl: ask [hook_input] malformed hook payload"}}
        p = run_post(bad, **KW)
        assert p.exit_code == 1 and p.stdout is None and p.stderr.startswith("aicl: error:")


def test_not_governed(events, tmp_path):
    ev = dict(events["02_pre_bash_rm"], cwd=str(tmp_path / "elsewhere"))
    for run in (run_pre, run_post):
        r = run(json.dumps(ev), **KW)
        assert r.stdout is None and r.exit_code == 0 and "not governed" in r.stderr


def test_env_discovery_and_manifest_override(events, fixture_repo, tmp_path):
    ev = dict(events["02_pre_bash_rm"], cwd=str(tmp_path))
    r = run_pre(json.dumps(ev), **dict(KW, env={"CLAUDE_PROJECT_DIR": str(fixture_repo)}))
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    r = run_pre(json.dumps(ev), **dict(KW, manifest_override=fixture_repo / "system-manifest.json"))
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert tail(fixture_repo / "agent-log.jsonl")[1] == 2


def _boom(ctx):
    raise RuntimeError(f"kaboom sk-ant-api03-{'X' * 30}")


def _reason(r):
    return json.loads(r.stdout)["hookSpecificOutput"]


def test_internal_error_routes_to_ask_with_deadletter(events, fixture_repo, monkeypatch):
    monkeypatch.setattr(hook, "evaluate", _boom)
    r = run_pre(json.dumps(events["01_pre_edit"]), **KW)
    out = _reason(r)
    assert r.exit_code == 0 and out["permissionDecision"] == "ask"
    assert out["permissionDecisionReason"].startswith("aicl: ask [internal_error] RuntimeError: kaboom <redacted:")
    dl = (fixture_repo / ".aicl" / "deadletter.jsonl").read_text().splitlines()
    assert len(dl) == 1 and "internal_error" in json.loads(dl[0])["reason"] and "sk-ant" not in dl[0]
    r = run_pre(json.dumps(events["01_pre_edit"]), **dict(KW, fail_closed=True))
    assert _reason(r)["permissionDecision"] == "deny"
    r = run_pre(json.dumps(events["01_pre_edit"]), **dict(KW, env={"AICL_FAIL_CLOSED": "1"}))
    assert _reason(r)["permissionDecision"] == "deny"
    assert not (fixture_repo / "agent-log.jsonl").exists()


def test_bad_manifest_routes_to_ask(events, fixture_repo):
    (fixture_repo / "system-manifest.json").write_text("{not json")
    r = run_pre(json.dumps(events["01_pre_edit"]), **KW)
    assert r.exit_code == 0 and _reason(r)["permissionDecisionReason"].startswith("aicl: ask [internal_error] ManifestError")


def test_deny_stays_deny_when_logging_fails(events, fixture_repo, monkeypatch):
    def fail(*a, **k):
        raise LogError("lock_timeout")
    monkeypatch.setattr(hook, "append", fail)
    r = run_pre(json.dumps(events["02_pre_bash_rm"]), **KW)
    assert _reason(r)["permissionDecision"] == "deny"
    assert "LogError: lock_timeout" in _reason(r)["permissionDecisionReason"]
    rec = json.loads((fixture_repo / ".aicl" / "deadletter.jsonl").read_text().splitlines()[0])
    assert rec["payload"]["outcome"] == "blocked"


def test_deadline_exceeded_routes_to_ask(events, fixture_repo):
    clock = itertools.count(0.0, 100.0).__next__
    r = run_pre(json.dumps(events["02_pre_bash_rm"]), **KW, clock=clock)
    out = _reason(r)
    assert out["permissionDecision"] == "ask" and "TimeoutError" in out["permissionDecisionReason"]
    assert not (fixture_repo / "agent-log.jsonl").exists()
    r = run_post(json.dumps(events["01_post_edit"]), **KW, clock=itertools.count(0.0, 100.0).__next__)
    assert r.exit_code == 1 and r.stdout is None and "TimeoutError" in r.stderr


def test_post_error_is_recorded_not_blocking(events, fixture_repo, monkeypatch):
    monkeypatch.setattr(hook, "evaluate", _boom)
    r = run_post(json.dumps(events["01_post_edit"]), **KW)
    assert r.exit_code == 1 and r.stdout is None and r.stderr.startswith("aicl: error: RuntimeError")
    assert (fixture_repo / ".aicl" / "deadletter.jsonl").is_file()


def test_parse_event_and_outputs(tmp_path):
    ev = parse_event(json.dumps({"tool_name": "Bash", "tool_input": "ls"}), "PreToolUse")
    assert ev.tool_input == {"value": "ls"} and ev.cwd == Path(os.getcwd()) and ev.event == "PreToolUse"
    assert ev.tool_use_id is None and ev.tool_response is None
    ev = parse_event(json.dumps({"tool_name": "Read", "cwd": str(tmp_path), "hook_event_name": "PostToolUse",
                                 "tool_use_id": "t1", "tool_response": "ok"}), "PreToolUse")
    assert (ev.event, ev.cwd, ev.tool_input, ev.tool_use_id) == ("PostToolUse", tmp_path, {}, "t1")
    assert pre_output(Decision.ALLOW, "") is None
    assert json.loads(pre_output(Decision.DENY, "r")) == {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "r"}}
    assert '"permissionDecision": "ask"' in pre_output(Decision.ASK, "r")


@pytest.mark.parametrize("resp,outcome", [({"stdout": "x", "is_error": False, "interrupted": False}, "success"),
                                          ({"is_error": True}, "failure"), ({"error": "nope"}, "failure"),
                                          ({"interrupted": True}, "failure"), ("Error: no such file", "failure"),
                                          ("fine", "success"), (None, "success"), ({"filePath": "a"}, "success")])
def test_post_outcome(resp, outcome):
    assert post_outcome(resp) == outcome


# ---- real subprocess: `python -m aicl hook pre` (falls back to hook.cmd_hook until cli.py lands) ----------------
def _hook_argv(phase):
    if importlib.util.find_spec("aicl.cli") is not None:
        return [sys.executable, "-m", "aicl", "hook", phase]
    code = ("import sys, types; from aicl.hook import cmd_hook; "
            f"sys.exit(cmd_hook(types.SimpleNamespace(phase={phase!r}, manifest=None, agent=None, fail_closed=False)))")
    return [sys.executable, "-c", code]


@pytest.mark.parametrize("name", ["02_pre_bash_rm", "01_pre_edit"])
def test_subprocess_matches_in_process(events, fixture_repo, name):
    env = {**os.environ, "CLAUDE_PROJECT_DIR": str(fixture_repo)}
    p = subprocess.run(_hook_argv("pre"), input=json.dumps(events[name]), capture_output=True, text=True, env=env,
                       timeout=60, cwd=fixture_repo)
    assert p.returncode == 0, p.stderr
    exp = expected_stdout(name)
    if exp is None:
        assert p.stdout == ""
        assert not (fixture_repo / "agent-log.jsonl").exists()
    else:
        assert json.loads(p.stdout) == exp
        assert p.stdout == hook.pre_output(Decision.DENY, exp["hookSpecificOutput"]["permissionDecisionReason"]) + "\n"
        assert read_entries(fixture_repo / "agent-log.jsonl")[0].payload.outcome == "blocked"
