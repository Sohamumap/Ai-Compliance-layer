"""Deterministic AST word co-occurrence classifier: EU AI Act tiers for code units and for the declared purpose."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from aicl.core import Classification, Finding, Tier, Unit, tier_rank

PROHIBITED, HIGH_RISK, LIMITED = Tier.PROHIBITED, Tier.HIGH_RISK, Tier.LIMITED


@dataclass(frozen=True)
class Category:
    id: str; tier: Tier; article: str; title: str
    primary: frozenset[str]; secondary: frozenset[str]; confidence: float; addendum: str


# word sets (casefolded tokens)
BIOMETRIC      = frozenset({"face","facial","faces","face_recognition","face_encodings","face_locations","deepface","insightface","retinaface","facenet","fingerprint","iris","retina","voiceprint","gait","biometric","biometrics"})
SENSITIVE_ATTR = frozenset({"ethnicity","ethnic","race","racial","religion","religious","belief","beliefs","sexual","orientation","political","union","trade_union","disability"})
EMOTION        = frozenset({"emotion","emotions","emotional","affect","mood","facial_expression","fer","anger","happiness","sadness","stress","engagement"})
WORKPLACE_EDU  = frozenset({"employee","employees","worker","workers","workplace","staff","student","students","classroom","school","exam","proctor","lecture"})
SOCIAL_SCORE   = frozenset({"social_score","social_credit","trustworthiness","citizen","citizens","behaviour_score","behavior_score"})
SCORING        = frozenset({"score","scores","scoring","rank","ranking","rating","grade","predict","classify","screen","eligibility","eligible","approve","reject","decide"})
IDENTIFY       = frozenset({"identify","identification","match","matching","verify","verification","compare","gallery","watchlist","enroll","enrol","lookup"})
EMPLOYMENT     = frozenset({"candidate","candidates","applicant","applicants","resume","resumes","cv","hiring","hire","recruit","recruitment","promotion","termination","interview"})
CREDIT         = frozenset({"credit","creditworthiness","loan","loans","mortgage","lending","borrower"})
EDUCATION      = frozenset({"student","students","admission","admissions","exam","exams","grading","proctoring","cheating"})
ESSENTIAL      = frozenset({"benefit","benefits","welfare","housing","unemployment","pension","asylum","visa","migration"})
LLM_CALL       = frozenset({"messages","completions","chat","generate_content","anthropic","openai","prompt","llm","completion"})
USER_FACING    = frozenset({"user","users","customer","customers","reply","respond","response","assistant","chatbot","conversation","message","dashboard"})

CATEGORIES: tuple[Category, ...] = (
  Category("art5_1g_biometric_categorisation", PROHIBITED, "Art. 5(1)(g)", "Biometric categorisation inferring sensitive attributes", BIOMETRIC, SENSITIVE_ATTR, 0.85,
           "It categorises natural persons by inferring ethnicity or other sensitive attributes from biometric face data."),
  Category("art5_1f_emotion_recognition_work_edu", PROHIBITED, "Art. 5(1)(f)", "Emotion recognition in workplace or education", EMOTION, WORKPLACE_EDU, 0.75,
           "It infers emotions of persons in a workplace or education setting."),
  Category("art5_1c_social_scoring", PROHIBITED, "Art. 5(1)(c)", "Social scoring", SOCIAL_SCORE, SCORING, 0.70, "It scores natural persons based on social behaviour."),
  Category("annex3_1a_biometric_identification", HIGH_RISK, "Annex III 1(a) via Art. 6(2)", "Remote biometric identification", BIOMETRIC, IDENTIFY, 0.70,
           "It performs biometric identification of natural persons from camera images."),
  Category("annex3_4_employment", HIGH_RISK, "Annex III 4", "Employment decisions", EMPLOYMENT, SCORING, 0.65, "It scores or ranks candidates or employees."),
  Category("annex3_5b_credit", HIGH_RISK, "Annex III 5(b)", "Creditworthiness", CREDIT, SCORING, 0.65, "It evaluates creditworthiness of natural persons."),
  Category("annex3_3_education", HIGH_RISK, "Annex III 3", "Education access and assessment", EDUCATION, SCORING, 0.60, "It assesses students or admissions."),
  Category("annex3_5a_essential_services", HIGH_RISK, "Annex III 5(a)", "Access to essential public services", ESSENTIAL, SCORING, 0.60, "It evaluates eligibility for public benefits or services."),
  Category("art50_llm_user_interaction", LIMITED, "Art. 50(1)", "Generative AI output shown to users", LLM_CALL, USER_FACING, 0.50,
           "It generates text with a general-purpose language model (LLM) and shows it to users."),
)
CATEGORY_BY_ID = {c.id: c for c in CATEGORIES}

IGNORE_DIRS = (".git", ".venv", "venv", "node_modules", ".aicl", "__pycache__", "tests", "test", "build", "dist")
MAX_FILE_BYTES = 1_048_576
SNIPPET_LINES = 40

_IDENT = re.compile(r"[A-Za-z0-9_]+")
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def tokenize(text: str) -> frozenset[str]:
    """Casefolded tokens: every identifier-like chunk, plus its "_" and camelCase parts."""
    out: set[str] = set()
    for ident in _IDENT.findall(text or ""):
        if not ident.strip("_"):
            continue
        out.add(ident.casefold())
        for part in ident.split("_"):
            if part:
                out.add(part.casefold())
                out.update(p.casefold() for p in _CAMEL.findall(part))
    return frozenset(out)


def _own_nodes(nodes: list[ast.AST]):
    """Walk nodes, skipping nested defs/classes entirely: each is a unit of its own."""
    stack = [n for n in nodes if not isinstance(n, _SCOPES)]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, _SCOPES))


def _words(nodes: list[ast.AST]) -> set[str]:
    w: set[str] = set()
    for n in _own_nodes(nodes):
        if isinstance(n, ast.Name):
            w |= tokenize(n.id)
        elif isinstance(n, ast.Attribute):
            w |= tokenize(n.attr)
        elif isinstance(n, ast.keyword) and n.arg:
            w |= tokenize(n.arg)
        elif isinstance(n, ast.arg):
            w |= tokenize(n.arg)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            w |= tokenize(n.value)
    return w


def _scope_words(node: ast.AST) -> set[str]:
    w = set(tokenize(node.name))
    parts: list[ast.AST] = list(node.body)
    if isinstance(node, ast.ClassDef):
        parts += [*node.bases, *node.keywords, *node.decorator_list]
    else:
        parts += [node.args, *node.decorator_list] + ([node.returns] if node.returns else [])
    return w | _words(parts)


def _snippet(lines: list[str], start: int) -> str:
    return "\n".join(lines[max(start - 1, 0):max(start - 1, 0) + SNIPPET_LINES])


def _walk_py(repo: Path):
    for p in sorted(repo.rglob("*.py")):
        rel = p.relative_to(repo)
        if any(part in IGNORE_DIRS for part in rel.parts[:-1]) or not p.is_file():
            continue
        yield p, rel.as_posix()


def extract_units(repo: Path) -> tuple[list[Unit], int, list[str]]:
    repo = Path(repo)
    units: list[Unit] = []
    skipped: list[str] = []
    files = 0
    for path, rel in _walk_py(repo):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append(rel)
                continue
            source = path.read_bytes().decode("utf-8")
            tree = ast.parse(source, filename=rel)
        except (SyntaxError, UnicodeDecodeError, ValueError, OSError):
            skipped.append(rel)
            continue
        files += 1
        lines = source.splitlines()
        module_stmts = [s for s in tree.body if not isinstance(s, (ast.Import, ast.ImportFrom))]
        units.append(Unit(rel, 1, "<module>", frozenset(_words(module_stmts)), _snippet(lines, 1)))

        def visit(nodes, prefix: str) -> None:
            for n in nodes:
                if isinstance(n, _SCOPES):
                    qual = f"{prefix}{n.name}"
                    units.append(Unit(rel, n.lineno, qual, frozenset(_scope_words(n)), _snippet(lines, n.lineno)))
                    visit(n.body, qual + ".")
                else:   # defs nested in if/try/with blocks keep the enclosing prefix
                    visit(ast.iter_child_nodes(n), prefix)
        visit(tree.body, "")
    return units, files, skipped


def _fire(words: frozenset[str]) -> list[tuple[Category, tuple[str, ...]]]:
    out = []
    for c in CATEGORIES:
        p, s = words & c.primary, words & c.secondary
        if p and s:
            out.append((c, tuple(sorted(p)) + tuple(sorted(s))))
    return out


def classify_unit(u: Unit) -> list[Finding]:
    fired = _fire(u.words)
    if any(c.tier is PROHIBITED for c, _ in fired):
        fired = [(c, ev) for c, ev in fired if c.tier is PROHIBITED]
    return [Finding(c.id, c.tier, c.article, c.title, u.file, u.line, u.symbol, ev, c.confidence,
                    f"{c.title}: {', '.join(ev)} co-occur in {u.symbol}") for c, ev in fired]


def _max_tier(tiers) -> Tier:
    return max(tiers, key=tier_rank, default=Tier.MINIMAL)


def declared_classification(purpose: str, high_risk_presumption: bool) -> tuple[Tier, tuple[str, ...]]:
    fired = _fire(tokenize(purpose))
    tier = _max_tier(c.tier for c, _ in fired)
    if high_risk_presumption and tier_rank(tier) < tier_rank(HIGH_RISK):
        tier = HIGH_RISK
    return tier, tuple(c.id for c, _ in fired)


def classify_repo(repo: Path, purpose: str, high_risk_presumption: bool) -> Classification:
    units, files, skipped = extract_units(repo)
    findings = tuple(f for u in units for f in classify_unit(u))
    tier = _max_tier(f.tier for f in findings)
    declared_tier, declared_cats = declared_classification(purpose, high_risk_presumption)
    gap = tier_rank(tier) > tier_rank(declared_tier) or any(f.tier is PROHIBITED for f in findings)
    return Classification(tier=tier, findings=findings, files_scanned=files, units_scanned=len(units),
                          skipped=tuple(skipped), declared_tier=declared_tier, declared_categories=declared_cats,
                          declaration_gap=gap,
                          summary=f"{len(findings)} finding(s); code tier {tier.value}; declared {declared_tier.value}; gap={gap}")
