"""cli.py: argparse tree, --version, --no-color precedence, dispatch, log verify exit codes, hook stdout discipline."""
from __future__ import annotations

import importlib
import io
import json
import subprocess
import sys

import pytest

from aicl import cli, decisionlog
from aicl.decisionlog import make_payload

COMMANDS = (["init"], ["hook", "pre"], ["hook", "post"], ["log", "verify"], ["log", "status"], ["ci"], ["demo"])


@pytest.mark.parametrize("argv", COMMANDS, ids=" ".join)
def test_help_for_every_subcommand(argv, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main([*argv, "--help"])
    assert e.value.code == 0
    assert capsys.readouterr().out.startswith("usage: aicl")


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0 and capsys.readouterr().out.strip() == "aicl 0.1.0"


def test_no_command_is_usage_error():
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 2


@pytest.mark.parametrize("argv", [*COMMANDS[:1], *COMMANDS[2:3], ["log", "verify", "x"], *COMMANDS[4:]], ids=" ".join)
def test_every_command_dispatches_to_a_real_function(argv):
    args = cli.build_parser().parse_args(argv)
    mod, fn = args.func.split(":")
    assert callable(getattr(importlib.import_module(mod), fn))


def test_defaults_and_no_color_precedence():
    p = cli.build_parser()
    a = p.parse_args(["ci"])
    assert (a.fail_on, a.semantic_fail_on, a.judge, a.quiet, a.no_color) == ("major", "high_risk", "auto", False, False)
    assert p.parse_args(["demo"]).judge == "off"
    assert p.parse_args(["--no-color", "demo"]).no_color is True     # global flag survives the subparser
    assert p.parse_args(["ci", "--no-color"]).no_color is True
    with pytest.raises(SystemExit):
        p.parse_args(["demo", "--judge", "llm"])


def test_color_enabled(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli.color_enabled() is False
    monkeypatch.delenv("NO_COLOR")
    assert cli.color_enabled(no_color=True) is False
    assert cli.color_enabled() is sys.stdout.isatty()


def _log(fixture_repo, agent, n=3):
    log = fixture_repo / "agent-log.jsonl"
    for i in range(n):
        decisionlog.append(log, make_payload(agent, f"Edit: f{i}.py | aicl:allow:ok", "Edit", {"i": i}, "success", False))
    return log


def test_log_verify_exit_codes(fixture_repo, agent, capsys):
    log = _log(fixture_repo, agent)
    assert cli.main(["log", "verify", str(log), "--anchor"]) == 0
    assert "chain ok: 3 entries" in capsys.readouterr().out
    lines = log.read_text("utf-8").splitlines(keepends=True)
    log.write_text("".join(lines[:-1]), "utf-8")                   # truncation: chain ok, anchor count mismatch
    assert cli.main(["log", "verify", str(log)]) == 0
    assert cli.main(["log", "verify", str(log), "--anchor"]) == 1
    log.write_text(lines[0] + lines[1].replace("f1.py", "f9.py"), "utf-8")
    assert cli.main(["log", "verify", str(log)]) == 1
    assert "at seq 2" in capsys.readouterr().out
    assert cli.main(["log", "verify", str(fixture_repo / "nope.jsonl")]) == 2
    log.write_text("{not json\n", "utf-8")
    assert cli.main(["log", "verify", str(log)]) == 2


def test_log_status(fixture_repo, agent, capsys, tmp_path):
    _log(fixture_repo, agent, 2)
    assert cli.main(["log", "status", "--repo", str(fixture_repo)]) == 0
    assert "anchor: ok" in capsys.readouterr().out
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main(["log", "status", "--repo", str(empty)]) == 2


def test_hook_stdout_is_one_json_object_or_nothing(fixture_repo, events, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(events["02_pre_bash_rm"])))
    assert cli.main(["hook", "pre"]) == 0
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(events["01_pre_edit"])))
    assert cli.main(["hook", "pre"]) == 0
    assert capsys.readouterr().out == ""


def test_hook_not_governed_subprocess(tmp_path):
    ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(tmp_path),
          "session_id": "s"}
    p = subprocess.run([sys.executable, "-m", "aicl", "hook", "pre"], input=json.dumps(ev), capture_output=True,
                       text=True, timeout=60, env={"PATH": "/usr/bin:/bin"})
    assert (p.returncode, p.stdout) == (0, "") and "not governed" in p.stderr


def test_demo_missing_binary_exits_3(capsys):
    assert cli.main(["demo", "--opencomplai", "/nonexistent/opencomplai"]) == 3
    assert "opencomplai not found" in capsys.readouterr().err
