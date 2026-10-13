import json
import re
from pathlib import Path

import pytest

from aicl import core
from aicl.core import (DOMAIN, GENESIS, SECRET_PATTERNS, CheckResult, Decision, Entry, GapRow, LogError, OutOfMandate,
                       Payload, Tier, VerifyLogResult, assert_no_secrets, atomic_write_text, canonical, find_secret,
                       mcp_server, now_ts, read_json, redact, relpath, sha256_prefixed, tier_rank)

GOLDEN_INPUT = {"file_path": "README.md", "old_string": "teh", "new_string": "the"}
GOLDEN_INPUT_HASH = "sha256:fd226d98d55cbca664a0584f63c4d8089992012089f935deed358ca13700ecab"
GOLDEN_ENTRY_HASH = "sha256:6296df0b804ee2e68dba9bfe8e0be342547f04f8470e5fb1abe8e79d7c99a2ad"
FAKE_KEY = "sk-ant-api03-DEMOFAKEKEY0000000000000000000000000000"

SECRET_SAMPLES = {  # name: (positive, negative)
    "anthropic_key": (FAKE_KEY, "sk-ant-short"),
    "openai_key": ("sk-abcdefghijklmnopqrstuvwx", "sk-short1"),
    "aws_access_key": ("AKIAABCDEFGHIJKLMNOP", "AKIA1234"),
    "github_token": ("ghp_" + "a1" * 18, "ghp_short"),
    "slack_token": ("xoxb-1234567890-abcdef", "xoxz-1234567890"),
    "google_key": ("AIza" + "B" * 35, "AIza" + "B" * 10),
    "private_key": ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PUBLIC KEY-----"),
    "jwt": ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij", "eyJhbGciOi.short"),
    "bearer": ("Authorization: Bearer abcdefghijklmnop1234", "the bearer token is in vault"),
    "generic_assignment": ("api_key=abcdefghijklmnop1234", "api_key = short"),
}
GLOBAL_NEGATIVES = ("sha256:" + "ab" * 32, "123e4567-e89b-12d3-a456-426614174000", "requests==2.0", GENESIS)


def test_golden_input_hash():
    assert sha256_prefixed(canonical({"input": GOLDEN_INPUT})) == GOLDEN_INPUT_HASH
    assert canonical({"b": 1, "a": Path("x")}) == b'{"a": "x", "b": 1}'


def test_golden_entry_hash_with_domain():
    payload = Payload("claude-code", "mandate:claude-code", "fix typo in README", "Edit", GOLDEN_INPUT_HASH,
                      "success", False)
    body = {"seq": 1, "ts": "2026-10-13T10:00:00+00:00", "payload": payload.to_dict(), "prev_hash": GENESIS}
    h = sha256_prefixed(DOMAIN + canonical(body))
    assert h == GOLDEN_ENTRY_HASH
    e = Entry(1, body["ts"], payload, GENESIS, h)
    line = e.to_line()
    assert line.endswith("\n") and json.loads(line) == {**body, "hash": h, "signature": None}
    assert list(json.loads(line)) == sorted(json.loads(line))
    assert set(payload.to_dict()) == {"agent_id", "mandate_ref", "intent", "tool", "input_hash", "outcome",
                                      "outside_mandate"}


def test_now_ts_format():
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", now_ts())


def test_enums_and_tiers():
    assert json.dumps({"d": Decision.DENY, "t": Tier.HIGH_RISK}) == '{"d": "deny", "t": "high_risk"}'
    assert str(Decision.ASK) == "ask" and f"{Tier.LIMITED}" == "limited"
    assert [tier_rank(t) for t in core.TIER_ORDER] == [0, 1, 2, 3]
    assert tier_rank(Tier.PROHIBITED) > tier_rank(Tier.HIGH_RISK)


def test_constants():
    assert GENESIS == "sha256:" + "0" * 64
    assert DOMAIN == b"opencomplai.log.v1\x00agent-log\x00"
    assert core.OUTCOMES == ("success", "failure", "blocked") and core.MAX_INTENT == 1000
    assert core.HOOK_BUDGET_S < core.HOOK_TIMEOUT_S
    assert core.ANCHOR_REL == Path(".aicl/log-anchor.json")
    assert {n for n, _ in SECRET_PATTERNS} == set(SECRET_SAMPLES)
    assert all(hasattr(core, n) for n in core.__all__)


@pytest.mark.parametrize("name", sorted(SECRET_SAMPLES))
def test_secret_pattern_positive_negative(name):
    pat = dict(SECRET_PATTERNS)[name]
    pos, neg = SECRET_SAMPLES[name]
    assert pat.search(f"prefix {pos} suffix"), name
    assert not pat.search(neg), name
    for g in GLOBAL_NEGATIVES:
        assert not pat.search(g), (name, g)


@pytest.mark.parametrize("name", sorted(SECRET_SAMPLES))
def test_redact_never_contains_value(name):
    pos = SECRET_SAMPLES[name][0]
    out = redact(f"before {pos} after")
    assert pos not in out and "<redacted:" in out and find_secret(out) is None
    assert out.startswith("before ")


def test_redact_fake_key_names_pattern():
    assert redact(f"Call the Anthropic API with key {FAKE_KEY}") == "Call the Anthropic API with key <redacted:anthropic_key>"
    assert redact("plain text") == "plain text"


def test_find_secret_recurses():
    assert find_secret({"a": [1, {"b": ("x", f"key {FAKE_KEY}")}]}) == "anthropic_key"
    assert find_secret({FAKE_KEY: 1}) == "anthropic_key"
    assert find_secret({"a": [1, 2.5, None, {"b": "clean"}]}) is None
    assert find_secret(42) is None


def test_assert_no_secrets():
    assert_no_secrets("all good | aicl:deny:secret_in_input")
    with pytest.raises(LogError, match="anthropic_key"):
        assert_no_secrets(FAKE_KEY)


def test_relpath(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    assert relpath(str(root / "src" / "a.py"), root) == "src/a.py"
    assert relpath("src/a.py", root) == "src/a.py"
    assert relpath("src/../src/a.py", root) == "src/a.py"
    assert relpath(str(tmp_path / "elsewhere" / "b.txt"), root) == "b.txt"
    assert relpath("../outside.txt", root) == "outside.txt"
    assert relpath("x/y.txt", None) == "y.txt"
    monkeypatch.setenv("HOME", str(root))
    assert relpath("~/src/a.py", root) == "src/a.py"
    assert relpath("~/.ssh/id_rsa", tmp_path / "other") == "id_rsa"


def test_mcp_server():
    assert mcp_server("mcp__github__create_issue") == "github"
    assert mcp_server("mcp__filesystem__read_file") == "filesystem"
    assert mcp_server("Bash") is None and mcp_server("mcp__") is None


def test_atomic_write_and_read_json(tmp_path):
    p = tmp_path / "a" / "b" / "x.json"
    atomic_write_text(p, '{"k": 1}')
    atomic_write_text(p, '{"k": 2}')
    assert read_json(p) == {"k": 2}
    assert [q.name for q in p.parent.iterdir()] == ["x.json"]


def test_result_helpers():
    rows = (GapRow("Art. 12", "missing", "artifact", "", "no log"), GapRow("Art. 14", "partial", "artifact", "x", ""))
    c = CheckResult(1, "fail", (), "major", ("biometric",), (), rows, "0.12.0", None, None,
                    Path("a"), Path("b"), {})
    assert c.gap("Art. 14").status == "partial" and c.gap("art. 12").status == "missing" and c.gap("Art. 99") is None
    v = VerifyLogResult(1, "invalid", True, 7, GENESIS, None, None,
                        (OutOfMandate(2, "claude-code", "Bash", ("self_reported",)),
                         OutOfMandate(4, "claude-code", "WebFetch", ("prohibited_action",))), {})
    assert v.out_of_mandate_seqs == (2, 4)
