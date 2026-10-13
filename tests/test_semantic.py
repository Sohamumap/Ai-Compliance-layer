"""Deterministic AST co-occurrence classifier (DESIGN 4.8)."""
from __future__ import annotations

from aicl.core import Tier
from aicl.semantic import CATEGORIES, classify_repo, classify_unit, declared_classification, extract_units, tokenize
from aicl.core import Unit

PURPOSE = "retail analytics assistant that summarises anonymised sales data for store managers"


def test_fixture_complete_finding_set(fixture_repo):
    c = classify_repo(fixture_repo, PURPOSE, False)
    assert {(f.symbol, f.category_id) for f in c.findings} == {
        ("segment_shoppers", "art5_1g_biometric_categorisation"),
        ("summarise_sales", "art50_llm_user_interaction"),
    }
    assert len(c.findings) == 2
    by = {f.symbol: f for f in c.findings}
    seg, summ = by["segment_shoppers"], by["summarise_sales"]
    assert {"face_encodings", "ethnicity"} <= set(seg.evidence)
    assert seg.tier is Tier.PROHIBITED and seg.article == "Art. 5(1)(g)" and seg.confidence == 0.85
    assert seg.file == "src/insights.py" and seg.line == 20 and seg.source == "aicl-deterministic"
    assert seg.rationale.endswith("co-occur in segment_shoppers")
    assert {"anthropic", "messages", "reply", "dashboard"} <= set(summ.evidence)
    assert summ.tier is Tier.LIMITED and summ.article == "Art. 50(1)"
    assert c.tier is Tier.PROHIBITED and c.declared_tier is Tier.MINIMAL and c.declaration_gap
    assert c.files_scanned == 1 and c.units_scanned == 4 and c.skipped == ()
    assert c.summary == "2 finding(s); code tier prohibited; declared minimal; gap=True"


def test_module_and_top_products_yield_nothing(fixture_repo):
    units, files, skipped = extract_units(fixture_repo)
    by = {u.symbol: u for u in units}
    assert set(by) == {"<module>", "top_products", "summarise_sales", "segment_shoppers"}
    assert classify_unit(by["<module>"]) == [] and classify_unit(by["top_products"]) == []
    # imports are excluded from the module unit, so the SDK names never reach it
    assert not by["<module>"].words & {"anthropic", "face_recognition", "pandas"}
    assert by["segment_shoppers"].snippet.startswith("def segment_shoppers(frame):")


def test_declared_tiers():
    assert declared_classification(PURPOSE, False) == (Tier.MINIMAL, ())
    assert declared_classification(PURPOSE, True)[0] is Tier.HIGH_RISK
    addenda = " ".join(c.addendum for c in CATEGORIES if c.id in ("art5_1g_biometric_categorisation",
                                                                    "art50_llm_user_interaction"))
    tier, cats = declared_classification(PURPOSE + " " + addenda, False)
    assert tier is Tier.PROHIBITED and "art5_1g_biometric_categorisation" in cats
    assert declared_classification("biometric identification of visitors", False)[0] is Tier.HIGH_RISK


def test_declared_purpose_closes_limited_gap(fixture_repo):
    (fixture_repo / "src" / "insights.py").write_text(
        'def summarise(rows):\n    """Reply to the user."""\n    return client.messages.create(prompt=rows)\n')
    c = classify_repo(fixture_repo, "an LLM assistant that answers users", False)
    assert c.tier is Tier.LIMITED and c.declared_tier is Tier.LIMITED and not c.declaration_gap


def test_syntax_error_and_ignored_dirs(fixture_repo):
    (fixture_repo / "broken.py").write_text("def x(:\n")
    (fixture_repo / "latin.py").write_bytes(b"x = '\xff'\n")
    for d in ("tests", ".venv", "node_modules"):
        (fixture_repo / d).mkdir()
        (fixture_repo / d / "f.py").write_text("def f(face, ethnicity):\n    pass\n")
    c = classify_repo(fixture_repo, PURPOSE, False)
    assert set(c.skipped) == {"broken.py", "latin.py"}
    assert c.files_scanned == 1 and len(c.findings) == 2


def test_prohibited_suppresses_lower_tiers():
    u = Unit("a.py", 3, "match_faces", frozenset({"face", "ethnicity", "match", "gallery"}), "")
    found = classify_unit(u)
    assert [f.category_id for f in found] == ["art5_1g_biometric_categorisation"]
    u2 = Unit("a.py", 3, "match_faces", frozenset({"face", "match", "gallery"}), "")
    f2 = classify_unit(u2)
    assert [f.category_id for f in f2] == ["annex3_1a_biometric_identification"]
    assert f2[0].evidence == ("face", "gallery", "match")


def test_nested_scopes_are_separate_units(fixture_repo):
    (fixture_repo / "src" / "more.py").write_text(
        "class Scorer:\n    def rank_candidates(self, applicants):\n        return sorted(applicants)\n"
        "if True:\n    def helper():\n        return 1\n")
    units, _, _ = extract_units(fixture_repo)
    syms = {u.symbol for u in units if u.file == "src/more.py"}
    assert syms == {"<module>", "Scorer", "Scorer.rank_candidates", "helper"}
    c = classify_repo(fixture_repo, PURPOSE, False)
    emp = [f for f in c.findings if f.category_id == "annex3_4_employment"]
    assert [f.symbol for f in emp] == ["Scorer.rank_candidates"]


def test_tokenize():
    assert tokenize("face_recognition") == {"face_recognition", "face", "recognition"}
    assert {"faceencodings", "face", "encodings"} <= tokenize("faceEncodings")
    assert {"http", "server"} <= tokenize("HTTPServer")
    assert tokenize("claude-opus 5") >= {"claude", "opus", "5"}
    assert "_" not in tokenize("for _ in x")
    assert tokenize("Ethnicity") == {"ethnicity"}
