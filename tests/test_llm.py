"""Optional Claude judge (DESIGN 4.10): offline skips, FakeClient verdict paths, refusal, errors, redaction."""
from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from aicl.core import SECRET_PATTERNS, JudgeUnavailable, Tier
from aicl.llm import (DEFAULT_MODEL, NO_CREDENTIAL, SYSTEM_PROMPT, build_user_prompt, credential_present, judge,
                      merge_verdicts)
from aicl.semantic import classify_repo

FAKE_KEY = "sk-ant-api03-DEMOFAKEKEY0000000000000000000000000000"


class FakeMessages:
    def __init__(self, result=None, error=None, fail_first_with=None):
        self.result, self.error, self.fail_first_with, self.calls = result, error, fail_first_with, []

    def parse(self, **kw):
        self.calls.append(kw)
        if self.fail_first_with is not None and len(self.calls) == 1:
            raise self.fail_first_with
        if self.error:
            raise self.error
        return self.result


class FakeClient:
    def __init__(self, **kw):
        self.messages = FakeMessages(**kw)


def _resp(verdicts, addendum="", notes="", stop="end_turn"):
    out = NS(findings=[NS(index=i, verdict=v, tier=t, article=a, rationale=r) for i, v, t, a, r in verdicts],
             purpose_addendum=addendum, notes=notes)
    return NS(stop_reason=stop, parsed_output=out)


@pytest.fixture
def cls(manifest):
    c = classify_repo(manifest.root, manifest.intended_purpose, manifest.high_risk_presumption)
    assert [f.symbol for f in c.findings] == ["summarise_sales", "segment_shoppers"]
    return c


@pytest.fixture
def keyed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-credential")


def test_auto_without_credential_skips(cls, manifest):
    assert not credential_present()
    j = judge(cls, manifest, mode="auto")
    assert j.used is False and j.skipped_reason == NO_CREDENTIAL and j.adjusted == cls.findings and j.error is None


def test_llm_without_credential_raises(cls, manifest):
    with pytest.raises(JudgeUnavailable):
        judge(cls, manifest, mode="llm")


def test_off(cls, manifest, keyed):
    client = FakeClient(result=_resp([]))
    j = judge(cls, manifest, mode="off", client=client)
    assert (j.used, j.mode, j.skipped_reason, j.adjusted) == (False, "off", "mode=off", cls.findings)
    assert client.messages.calls == []


def test_no_findings(cls, manifest, keyed):
    from dataclasses import replace
    j = judge(replace(cls, findings=()), manifest, mode="auto", client=FakeClient(result=_resp([])))
    assert j.used is False and j.skipped_reason == "no findings to review"


def test_confirm_adjust_and_call_shape(cls, manifest, keyed):
    client = FakeClient(result=_resp([(0, "adjust", "high_risk", "Annex III 5(a)", "really about benefits"),
                                      (1, "confirm", "prohibited", "Art. 5(1)(g)", "clear ethnicity inference")],
                                     addendum="It infers ethnicity from faces.", notes="ok"))
    j = judge(cls, manifest, mode="auto", client=client)
    assert j.used and j.error is None and j.model == DEFAULT_MODEL
    assert j.verdicts == ((0, "adjust", "really about benefits"), (1, "confirm", "clear ethnicity inference"))
    a0, a1 = j.adjusted
    assert (a0.tier, a0.article, a0.source) == (Tier.HIGH_RISK, "Annex III 5(a)", "claude-judge")
    assert a1 == cls.findings[1]
    assert j.purpose_addendum == "It infers ethnicity from faces." and j.notes == "ok"
    kw = client.messages.calls[0]
    assert kw["model"] == DEFAULT_MODEL and kw["max_tokens"] == 16000 and kw["system"] == SYSTEM_PROMPT
    assert kw["extra_headers"] == {"anthropic-beta": "server-side-fallback-2026-07-01"}
    assert kw["extra_body"] == {"fallbacks": "default"}
    assert kw["output_format"].__name__ == "JudgeOutput"
    assert not {"thinking", "tool_choice"} & set(kw)


def test_reject_keeps_prohibited_at_high_risk(cls, manifest, keyed):
    client = FakeClient(result=_resp([(0, "reject", "minimal", "-", "not user facing"),
                                      (1, "reject", "minimal", "-", "fine")]))
    j = judge(cls, manifest, mode="auto", client=client)
    assert len(j.adjusted) == 1
    f = j.adjusted[0]
    assert f.symbol == "segment_shoppers" and f.tier is Tier.HIGH_RISK and f.source == "claude-judge"


def test_adjust_cannot_lower_prohibited_below_high_risk(cls):
    out = NS(findings=[NS(index=1, verdict="adjust", tier="minimal", article="none", rationale="x"),
                       NS(index=99, verdict="reject", tier="minimal", article="", rationale="")],
             purpose_addendum="", notes="")
    res = merge_verdicts(cls.findings, out)
    assert res[0] == cls.findings[0] and res[1].tier is Tier.HIGH_RISK and res[1].article == "none"


def test_client_error_never_raises(cls, manifest, keyed):
    j = judge(cls, manifest, mode="llm", client=FakeClient(error=RuntimeError("boom")))
    assert j.used is True and j.error == "RuntimeError: boom" and j.adjusted == cls.findings


def test_400_retries_without_fallbacks(cls, manifest, keyed):
    class BadRequest(Exception):
        status_code = 400
    client = FakeClient(result=_resp([(1, "confirm", "prohibited", "Art. 5(1)(g)", "ok")]), fail_first_with=BadRequest("x"))
    j = judge(cls, manifest, mode="auto", client=client)
    assert j.error is None and len(client.messages.calls) == 2
    assert "extra_headers" in client.messages.calls[0] and "extra_headers" not in client.messages.calls[1]
    assert "extra_body" not in client.messages.calls[1]


def test_refusal(cls, manifest, keyed):
    j = judge(cls, manifest, mode="auto", client=FakeClient(result=_resp([], stop="refusal")))
    assert j.used is True and j.error == "refusal" and j.adjusted == cls.findings


def test_prompt_is_redacted_and_bounded(fixture_repo, manifest, keyed):
    src = fixture_repo / "src" / "insights.py"
    src.write_text(src.read_text().replace('"unknown"', f'"{FAKE_KEY}"') + "\n# padding\n" * 3000)
    cls = classify_repo(manifest.root, manifest.intended_purpose, False)
    client = FakeClient(result=_resp([]))
    j = judge(cls, manifest, mode="auto", client=client)
    assert j.error is None
    sent = repr(client.messages.calls[0])
    assert not any(p.search(sent) for _, p in SECRET_PATTERNS) and "<redacted:anthropic_key>" in sent
    prompt = build_user_prompt(cls, manifest)
    assert len(prompt) <= 20_000 and '<repo_snippets untrusted="true">' in prompt and "</repo_snippets>" in prompt
    assert "[1] src/insights.py:20 symbol=segment_shoppers" in prompt


def test_prompt_budget_with_many_findings(fixture_repo, manifest):
    body = "".join(f"def seg{i}(frame):\n    return face_encodings(frame), 'ethnicity'\n\n" for i in range(400))
    (fixture_repo / "src" / "many.py").write_text(body)
    cls = classify_repo(manifest.root, manifest.intended_purpose, False)
    assert len(cls.findings) > 400
    prompt = build_user_prompt(cls, manifest)
    assert len(prompt) <= 20_000 and prompt.rstrip().endswith("notes: terse.")
