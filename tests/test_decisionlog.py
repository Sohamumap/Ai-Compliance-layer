"""decisionlog: golden vector, chain verify + tamper codes, anchor truncation guard, locking, pending, deadletter, cmd_log."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aicl.core import GENESIS, LogError, Payload, PendingRecord
from aicl.decisionlog import (add_parser, anchor_path, append, cmd_log, entry_hash, input_hash, make_payload,
                              pending_dir, pop_pending, put_pending, read_anchor, read_entries, stale_pending, tail,
                              verify, verify_with_anchor, write_deadletter)

GOLD_INPUT = {"file_path": "README.md", "old_string": "teh", "new_string": "the"}
GOLD_INPUT_HASH = "sha256:fd226d98d55cbca664a0584f63c4d8089992012089f935deed358ca13700ecab"
GOLD_HASH = "sha256:6296df0b804ee2e68dba9bfe8e0be342547f04f8470e5fb1abe8e79d7c99a2ad"
TS = "2026-10-13T10:00:00+00:00"


def _gold() -> Payload:
    return Payload("claude-code", "mandate:claude-code", "fix typo in README", "Edit", GOLD_INPUT_HASH, "success", False)


def _chain(log: Path, agent, n: int = 3) -> list:
    out = []
    for i in range(n):
        blocked = i == 1
        p = make_payload(agent, f"step {i}" + (" | aicl:deny:tool_prohibited" if blocked else ""),
                         "WebFetch" if blocked else "Edit", {"i": i}, "blocked" if blocked else "success", blocked)
        out.append(append(log, p, ts=f"2026-10-13T10:00:0{i}+00:00"))
    return out


def _rewrite(log: Path, seq: int, fn) -> None:
    lines = log.read_text("utf-8").splitlines()
    lines[seq - 1] = fn(lines[seq - 1])
    log.write_text("\n".join(lines) + "\n", "utf-8")


# ---- golden vector -----------------------------------------------------------------
def test_golden_vector(tmp_path, agent):
    assert input_hash(GOLD_INPUT) == GOLD_INPUT_HASH
    assert entry_hash(1, TS, _gold(), GENESIS) == GOLD_HASH
    p = make_payload(agent, "fix typo in README", "Edit", GOLD_INPUT, "success", False)
    assert p == _gold()
    e = append(tmp_path / "agent-log.jsonl", p, ts=TS)
    assert (e.seq, e.prev_hash, e.hash, e.signature) == (1, GENESIS, GOLD_HASH, None)
    assert read_entries(tmp_path / "agent-log.jsonl") == [e]
    assert (tmp_path / "agent-log.jsonl").read_text("utf-8") == e.to_line()
    assert json.loads(e.to_line())["payload"]["outside_mandate"] is False


def test_make_payload_rejects(agent):
    with pytest.raises(LogError):
        make_payload(agent, "x", "Edit", {}, "maybe", False)
    with pytest.raises(LogError):
        make_payload(agent, "x" * 1001, "Edit", {}, "success", False)
    make_payload(agent, "x" * 1000, "Edit", {}, "success", False)
    with pytest.raises(LogError):
        make_payload(agent, "key sk-ant-" + "a" * 30, "Bash", {}, "blocked", True)


# ---- chain and tamper -----------------------------------------------------------------
def test_chain_ok_and_tail(tmp_path, agent):
    log = tmp_path / "agent-log.jsonl"
    assert tail(log) == (GENESIS, 0)
    es = _chain(log, agent)
    assert [e.seq for e in es] == [1, 2, 3] and es[1].prev_hash == es[0].hash
    assert tail(log) == (es[-1].hash, 3)
    r = verify(log)
    assert (r.ok, r.count, r.head, r.error, r.bad_seq) == (True, 3, es[-1].hash, None, None)
    a = read_anchor(log)
    assert (a.head, a.count, a.log) == (es[-1].hash, 3, "agent-log.jsonl")
    assert anchor_path(log) == tmp_path / ".aicl" / "log-anchor.json"
    assert verify_with_anchor(log).ok


def test_tamper_intent(tmp_path, agent):
    log = tmp_path / "agent-log.jsonl"
    _chain(log, agent)
    _rewrite(log, 2, lambda s: s.replace("step 1", "step X"))
    r = verify(log)
    assert (r.ok, r.error, r.bad_seq, r.count) == (False, "hash", 2, 1)


def _edit_json(key, value):
    def fn(line):
        e = json.loads(line)
        if key == "payload.extra":
            e["payload"]["extra"] = value
        else:
            e[key] = value
        return json.dumps(e, sort_keys=True)
    return fn


@pytest.mark.parametrize("seq, fn, error", [
    (3, _edit_json("prev_hash", "sha256:" + "1" * 64), "prev_hash"),
    (2, _edit_json("payload.extra", 1), "payload_keys"),
    (2, _edit_json("seq", 7), "bad_seq"),
    (3, _edit_json("hash", "sha256:" + "2" * 64), "hash"),
    (2, lambda s: s[:-5], "bad_json"),
])
def test_tamper_codes(tmp_path, agent, seq, fn, error):
    log = tmp_path / "agent-log.jsonl"
    _chain(log, agent)
    _rewrite(log, seq, fn)
    r = verify(log)
    assert (r.ok, r.error, r.bad_seq) == (False, error, seq)
    if error == "bad_json":
        with pytest.raises(LogError, match="bad_json"):
            read_entries(log)


def test_flip_one_byte(tmp_path, agent):
    log = tmp_path / "agent-log.jsonl"
    _chain(log, agent)
    raw = log.read_bytes()
    i = raw.index(b"step 2")
    log.write_bytes(raw[:i] + b"Step 2" + raw[i + 6:])
    r = verify(log)
    assert (r.error, r.bad_seq) == ("hash", 3)


def test_truncation_caught_only_by_anchor(tmp_path, agent):
    log = tmp_path / "agent-log.jsonl"
    es = _chain(log, agent)
    log.write_text("".join(log.read_text("utf-8").splitlines(keepends=True)[:-1]), "utf-8")
    assert verify(log).ok
    r = verify_with_anchor(log)
    assert (r.ok, r.error, r.bad_seq, r.count) == (False, "anchor_count", None, 2)
    r = verify(log, expected_head=es[-1].hash)
    assert r.error == "anchor_head"
    anchor_path(log).unlink()
    assert verify_with_anchor(log).error == "anchor_missing"


# ---- locking --------------------------------------------------------------------------------
_WORKER = """
import sys
from pathlib import Path
from aicl.core import Payload
from aicl.decisionlog import append
for i in range(50):
    append(Path(sys.argv[1]), Payload("claude-code", None, f"w{sys.argv[2]}-{i}", "Edit", "sha256:" + "0" * 64,
                                      "success", False), lock_timeout_s=30)
"""


def test_two_processes_append(tmp_path):
    log = tmp_path / "agent-log.jsonl"
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, str(log), str(k)]) for k in (1, 2)]
    assert [p.wait(timeout=120) for p in procs] == [0, 0]
    r = verify_with_anchor(log)
    assert (r.ok, r.count) == (True, 100)
    assert [e.seq for e in read_entries(log)] == list(range(1, 101))


def test_lock_timeout(tmp_path):
    log = tmp_path / "agent-log.jsonl"
    fd = os.open(log.with_name(log.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        t0 = time.monotonic()
        with pytest.raises(LogError, match="lock_timeout"):
            append(log, _gold(), ts=TS)
        assert time.monotonic() - t0 < 2.5
        assert not log.exists()
    finally:
        os.close(fd)
    assert append(log, _gold(), ts=TS).hash == GOLD_HASH


# ---- pending and deadletter --------------------------------------------------------------------
def test_pending(tmp_path):
    log = tmp_path / "agent-log.jsonl"
    rec = PendingRecord("tu-06", "Bash", "Bash: curl (2 args)", GOLD_INPUT_HASH, "network_egress", TS)
    put_pending(log, rec)
    put_pending(log, PendingRecord("", "Bash", "x", GOLD_INPUT_HASH, "r", TS))      # no id -> no-op
    assert [p.name for p in pending_dir(log).iterdir()] == ["tu-06.json"]
    assert stale_pending(log) == ()
    old = time.time() - 3600
    os.utime(pending_dir(log) / "tu-06.json", (old, old))
    assert stale_pending(log) == (rec,)
    assert pop_pending(log, "tu-06") == rec
    assert pop_pending(log, "tu-06") is None and pop_pending(log, None) is None
    assert stale_pending(log) == ()


def test_deadletter(tmp_path):
    log = tmp_path / "agent-log.jsonl"
    write_deadletter(log, "boom with sk-ant-" + "b" * 30, None)
    write_deadletter(log, "second", _gold())
    lines = [json.loads(x) for x in (tmp_path / ".aicl" / "deadletter.jsonl").read_text("utf-8").splitlines()]
    assert len(lines) == 2 and "payload" not in lines[0] and lines[1]["payload"]["tool"] == "Edit"
    assert "sk-ant" not in lines[0]["reason"] and "<redacted:anthropic_key>" in lines[0]["reason"]
    assert set(lines[0]) == {"ts", "reason"}


# ---- aicl log verify | status -----------------------------------------------------------------------
def _parse(*argv: str):
    p = argparse.ArgumentParser()
    add_parser(p.add_subparsers(dest="command"))
    return p.parse_args(["log", *argv])


def test_cmd_log_verify(tmp_path, agent, capsys):
    log = tmp_path / "agent-log.jsonl"
    es = _chain(log, agent)
    assert cmd_log(_parse("verify", str(log), "--anchor")) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == ["chain ok: 3 entries", f"head={es[-1].hash} count=3"]
    assert cmd_log(_parse("verify", str(log), "--expected-count", "4")) == 1
    assert "chain BROKEN: anchor_count" in capsys.readouterr().out
    _rewrite(log, 2, lambda s: s.replace("step 1", "step X"))
    assert cmd_log(_parse("verify", str(log))) == 1
    assert capsys.readouterr().out.splitlines()[0] == "chain BROKEN: hash at seq 2"
    assert cmd_log(_parse("verify", str(tmp_path / "missing.jsonl"))) == 2
    _rewrite(log, 1, lambda s: "{not json")
    assert cmd_log(_parse("verify", str(log))) == 2


def test_cmd_log_verify_anchor_missing(tmp_path, agent, capsys):
    log = tmp_path / "agent-log.jsonl"
    _chain(log, agent)
    anchor_path(log).unlink()
    assert cmd_log(_parse("verify", str(log))) == 0
    assert cmd_log(_parse("verify", str(log), "--anchor")) == 1
    assert "chain BROKEN: anchor_missing" in capsys.readouterr().out


def test_cmd_log_status(fixture_repo, agent, capsys):
    log = fixture_repo / "agent-log.jsonl"
    assert cmd_log(_parse("status", "--repo", str(fixture_repo))) == 0
    assert "anchor: missing" in capsys.readouterr().out
    _chain(log, agent)
    put_pending(log, PendingRecord("tu-x", "Bash", "i", GOLD_INPUT_HASH, "network_egress", TS))
    old = time.time() - 3600
    os.utime(pending_dir(log) / "tu-x.json", (old, old))
    write_deadletter(log, "oops", None)
    assert cmd_log(_parse("status", "--repo", str(fixture_repo))) == 0
    out = capsys.readouterr().out
    for s in ("count=3", "anchor: ok", "unresolved pending asks (>10 min): 1", "tu-x Bash [network_egress]",
              "deadletter: 1 entries"):
        assert s in out
    assert cmd_log(_parse("status", "--repo", str(fixture_repo.parent))) == 2


@pytest.mark.external
def test_opencomplai_accepts_our_log(fixture_repo, agent, oc_bin):
    log = fixture_repo / "agent-log.jsonl"
    es = _chain(log, agent)
    p = subprocess.run([oc_bin, "agents", "verify-log", str(log), "-m", str(fixture_repo / "system-manifest.json"),
                        "-o", "json", "--expected-head", es[-1].hash, "--expected-count", "3"],
                       capture_output=True, text=True, timeout=60)
    d = json.loads(p.stdout[p.stdout.index("{"):])
    assert d["chain"]["ok"] is True and d["chain"]["count"] == 3 and d["chain"]["head"] == es[-1].hash
    assert [o["seq"] for o in d["out_of_mandate"]] == [2]       # only the blocked WebFetch


@pytest.mark.external
def test_cmd_log_verify_external(fixture_repo, agent, oc_bin, monkeypatch, capsys):
    pytest.importorskip("aicl.oc")
    monkeypatch.setenv("AICL_OPENCOMPLAI", oc_bin)
    log = fixture_repo / "agent-log.jsonl"
    _chain(log, agent)
    rc = cmd_log(_parse("verify", str(log), "--anchor", "--external", "--manifest",
                        str(fixture_repo / "system-manifest.json")))
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "out_of_mandate seqs: [2]" in out
    assert "every out-of-mandate seq was blocked: yes" in out
