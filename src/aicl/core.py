"""Shared contracts: exceptions, enums, constants, pure helpers and every cross-module type."""
from __future__ import annotations

import enum
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

__all__ = [
    "AiclError", "ManifestError", "HookInputError", "LogError", "OcNotFound", "OcError", "JudgeUnavailable",
    "Decision", "Tier", "TIER_ORDER", "tier_rank",
    "GENESIS", "DOMAIN", "OUTCOMES", "MAX_INTENT", "ANCHOR_REL", "PENDING_REL", "DEADLETTER_REL",
    "HOOK_MATCHER", "HOOK_TIMEOUT_S", "HOOK_BUDGET_S", "PROTECTED_PATHS", "SECRET_PATTERNS", "SECRET_FILE_GLOBS",
    "canonical", "sha256_prefixed", "now_ts", "atomic_write_text", "read_json", "find_secret", "redact",
    "assert_no_secrets", "relpath", "mcp_server",
    "ToolSpec", "Mandate", "AgentSpec", "Manifest", "HookEvent", "RuleHit", "Evaluation", "Payload", "Entry",
    "Anchor", "VerifyResult", "PendingRecord",
    "GapRow", "CheckResult", "OutOfMandate", "VerifyLogResult", "Unit", "Finding", "Classification",
    "Remediation", "JudgeResult", "CiReport",
]


# ---- exceptions -------------------------------------------------------------
class AiclError(Exception): ...
class ManifestError(AiclError): ...       # manifest missing/invalid/no agents
class HookInputError(AiclError): ...      # stdin not JSON / missing tool_name
class LogError(AiclError): ...            # malformed log line, lock timeout, intent too long
class OcNotFound(AiclError): ...          # opencomplai binary not found
class OcError(AiclError): ...             # timeout, exit 2 without JSON, unparseable stdout
class JudgeUnavailable(AiclError): ...    # --judge llm but no credential / SDK


# ---- enums ------------------------------------------------------------------
class Decision(str, enum.Enum):
    ALLOW = "allow"; DENY = "deny"; ASK = "ask"
    def __str__(self) -> str: return self.value


class Tier(str, enum.Enum):
    MINIMAL = "minimal"; LIMITED = "limited"; HIGH_RISK = "high_risk"; PROHIBITED = "prohibited"
    def __str__(self) -> str: return self.value


TIER_ORDER: tuple[Tier, ...] = (Tier.MINIMAL, Tier.LIMITED, Tier.HIGH_RISK, Tier.PROHIBITED)
def tier_rank(t: Tier) -> int: return TIER_ORDER.index(t)


# ---- constants: decision log -------------------------------------------------
GENESIS = "sha256:" + "0" * 64
DOMAIN = b"opencomplai.log.v1\x00" + b"agent-log" + b"\x00"
OUTCOMES = ("success", "failure", "blocked")
MAX_INTENT = 1000
ANCHOR_REL = Path(".aicl") / "log-anchor.json"
PENDING_REL = Path(".aicl") / "pending"
DEADLETTER_REL = Path(".aicl") / "deadletter.jsonl"

# ---- constants: hooks ---------------------------------------------------------
HOOK_MATCHER = "^(Bash|Edit|Write|Read|WebFetch|mcp__.*)$"   # IDENTICAL for every event; anchored, since Claude
                                                           # Code tests regex matchers unanchored (TodoWrite, NotebookEdit)
HOOK_TIMEOUT_S = 20                                         # settings.json "timeout"
HOOK_BUDGET_S = 8.0                                         # internal deadline, < HOOK_TIMEOUT_S

# ---- constants: protection ------------------------------------------------------
# repo-relative globs; the agent may READ these but never WRITE them (rule self_protect, built-in, DENY)
PROTECTED_PATHS: tuple[str, ...] = (
    ".claude/settings.json", ".claude/settings.local.json", ".cursor/hooks.json",
    "system-manifest.json", ".aicl", ".aicl/**",
)   # plus the resolved decision log path and "<log>.lock", added at evaluation time

# ---- constants: secrets -----------------------------------------------------------
_SECRET_NAME = r"(?<![\w-])(?=[\w-]*?(?:api[_-]?key|secret|token|passw(?:or)?d|credential))[\w-]++"   # DB_PASSWORD, aws_secret_access_key
_SECRET_VAL = r"[^\s'\"`(),;\[\]{}<>]"
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic_key",  re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key",     re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token",   re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_pat",     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("slack_token",    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("google_key",     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # the whole PEM block (to END, or to the end of the text), so redaction never leaves the key body behind
    ("private_key",    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)")),
    ("jwt",            re.compile(r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")),
    ("bearer",         re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{16,}")),
    ("url_credentials", re.compile(r"://[^/\s:@]+:[^@\s/]+@")),
    ("generic_assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=!@#$%^&*~]{16,}")),
    # a secret-named identifier (any prefix/suffix) assigned a value with a digit, a letter and an upper-case letter or
    # symbol; constant names (API_KEY_V2) and calls (TokenizerV2(...)) are not values
    # (lookaheads bounded to 256 chars so scanning stays linear on large Write content)
    ("named_secret",   re.compile(rf"(?i:{_SECRET_NAME})['\"]?\s*[:=]\s*['\"]?(?={_SECRET_VAL}{{0,256}}?\d)"
                                  rf"(?={_SECRET_VAL}{{0,256}}?[A-Za-z])(?={_SECRET_VAL}{{0,256}}?[A-Z!@#$%^&*~+=])"
                                  rf"(?![A-Z0-9_]{{1,256}}(?!{_SECRET_VAL})){_SECRET_VAL}{{8,}}+(?!\()")),
)
SECRET_FILE_GLOBS: tuple[str, ...] = (".env", ".env.*", "*.pem", "*.key", "~/.ssh/id_*",
                                      "~/.aws/credentials", "~/.netrc", "~/.config/gh/hosts.yml")


# ---- helpers ---------------------------------------------------------------------
def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, default=str).encode("utf-8")


def sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def atomic_write_text(path: Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")   # per-process tmp so concurrent writers never collide
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path) -> Any:
    return json.loads(Path(path).read_text("utf-8"))


def _find_secret(value: Any) -> str | None:
    if isinstance(value, str):
        for name, pat in SECRET_PATTERNS:
            if pat.search(value):
                return name
        return None
    if isinstance(value, Mapping):
        items: Any = [x for kv in value.items() for x in kv]
    elif isinstance(value, (list, tuple)):
        items = value
    else:
        return None
    for item in items:
        hit = _find_secret(item)
        if hit:
            return hit
    return None


def find_secret(value: Any) -> str | None:
    """Name of the first SECRET_PATTERNS entry found anywhere in value (dict keys and values, lists, tuples, str).
    Input nested too deep to walk counts as a hit ("nested_too_deep"), so it can never turn a DENY into an error."""
    try:
        return _find_secret(value)
    except RecursionError:
        return "nested_too_deep"


def redact(text: str) -> str:
    for name, pat in SECRET_PATTERNS:
        text = pat.sub(f"<redacted:{name}>", text)
    return text


def assert_no_secrets(text: str) -> None:
    name = find_secret(text)
    if name:
        raise LogError(f"secret in outbound text: {name}")


def relpath(path: str, root: Path | None) -> str:
    """POSIX repo-relative path if path (relative paths resolve against root) lies inside root, else its basename."""
    p = Path(os.path.expanduser(str(path)))
    if root is not None:
        r = Path(root).expanduser().resolve()
        full = (p if p.is_absolute() else r / p).resolve()
        try:
            return full.relative_to(r).as_posix() or "."
        except ValueError:
            pass
    return p.name


def mcp_server(tool_name: str) -> str | None:
    if not tool_name.startswith("mcp__"):
        return None
    server = tool_name[5:].split("__", 1)[0]
    return server or None


# ---- Layer A types ------------------------------------------------------------------
@dataclass(frozen=True)
class ToolSpec:
    name: str; kind: str; side_effects: bool = False; requires_approval: bool = False


@dataclass(frozen=True)
class Mandate:
    permitted_actions: tuple[str, ...]; prohibited_actions: tuple[str, ...]
    limits: Mapping[str, str | int | float | bool]; expires_at: str | None


@dataclass(frozen=True)
class AgentSpec:
    id: str; name: str; tools: tuple[ToolSpec, ...]; mandate: Mandate | None
    decision_log_ref: str | None; guardrail_refs: tuple[str, ...]

    @property
    def mandate_ref(self) -> str | None:
        return f"mandate:{self.id}" if self.mandate else None


@dataclass(frozen=True)
class Manifest:
    path: Path; root: Path; system_id: str; intended_purpose: str; high_risk_presumption: bool
    agents: tuple[AgentSpec, ...]; has_human_oversight: bool; raw: Mapping[str, Any]


@dataclass(frozen=True)
class HookEvent:
    event: str                 # "PreToolUse" | "PostToolUse"
    session_id: str; cwd: Path; tool_name: str
    tool_input: Mapping[str, Any]      # {} when absent; non-dict wrapped as {"value": x}
    tool_use_id: str | None; tool_response: Any | None; raw: Mapping[str, Any]


@dataclass(frozen=True)
class RuleHit:
    rule_id: str; decision: Decision; message: str      # message is redacted, <= 200 chars, never raw input


@dataclass(frozen=True)
class Evaluation:
    decision: Decision; hits: tuple[RuleHit, ...]
    reason: str                # "aicl: deny [rule_id] message" | "aicl: ask [rule_id] message" | ""
    rule_id: str               # winning hit's rule_id, "ok" when ALLOW
    outside_mandate: bool      # == (decision is DENY)


@dataclass(frozen=True)
class Payload:
    agent_id: str; mandate_ref: str | None; intent: str; tool: str; input_hash: str
    outcome: str; outside_mandate: bool

    def to_dict(self) -> dict[str, Any]:
        return {"agent_id": self.agent_id, "mandate_ref": self.mandate_ref, "intent": self.intent,
                "tool": self.tool, "input_hash": self.input_hash, "outcome": self.outcome,
                "outside_mandate": self.outside_mandate}


@dataclass(frozen=True)
class Entry:
    seq: int; ts: str; payload: Payload; prev_hash: str; hash: str; signature: None = None

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "payload": self.payload.to_dict(),
                "prev_hash": self.prev_hash, "hash": self.hash, "signature": self.signature}

    def to_line(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True) + "\n"


@dataclass(frozen=True)
class Anchor:
    head: str; count: int; updated_at: str; log: str      # log = repo-relative log path


@dataclass(frozen=True)
class VerifyResult:
    ok: bool; count: int; head: str
    error: str | None          # None | "bad_json" | "bad_seq" | "prev_hash" | "hash" | "payload_keys" | "anchor_head" | "anchor_count" | "anchor_missing"
    bad_seq: int | None


@dataclass(frozen=True)
class PendingRecord:
    tool_use_id: str; tool: str; intent: str; input_hash: str; rule_id: str; ts: str


# ---- Layer B types -------------------------------------------------------------------
@dataclass(frozen=True)
class GapRow:
    article: str; status: str; source: str; evidence_ref: str; rationale: str


@dataclass(frozen=True)
class CheckResult:
    exit_code: int; result: str; failed_controls: tuple[str, ...]
    scan_severity: str; detected_categories: tuple[str, ...]; discrepancies: tuple[str, ...]
    gaps: tuple[GapRow, ...]; cli_version: str
    log_entries: int | None; log_head_hex: str | None     # summaries.agents.{log_entries, log_head_sha256} (bare hex)
    artifact_path: Path; scan_report_path: Path; raw: Mapping[str, Any]

    def gap(self, article: str) -> GapRow | None:          # article like "Art. 12"
        want = article.strip().casefold()
        return next((g for g in self.gaps if g.article.strip().casefold() == want), None)


@dataclass(frozen=True)
class OutOfMandate:
    seq: int; agent_id: str; tool: str; reasons: tuple[str, ...]


@dataclass(frozen=True)
class VerifyLogResult:
    exit_code: int; status: str; chain_ok: bool; count: int; head: str; error: str | None
    bad_seq: int | None; out_of_mandate: tuple[OutOfMandate, ...]; raw: Mapping[str, Any]

    @property
    def out_of_mandate_seqs(self) -> tuple[int, ...]:
        return tuple(o.seq for o in self.out_of_mandate)


@dataclass(frozen=True)
class Unit:
    file: str; line: int; symbol: str; words: frozenset[str]; snippet: str


@dataclass(frozen=True)
class Finding:
    category_id: str; tier: Tier; article: str; title: str
    file: str; line: int; symbol: str; evidence: tuple[str, ...]
    confidence: float; rationale: str; source: str = "aicl-deterministic"


@dataclass(frozen=True)
class Classification:
    tier: Tier; findings: tuple[Finding, ...]; files_scanned: int; units_scanned: int
    skipped: tuple[str, ...]; declared_tier: Tier; declared_categories: tuple[str, ...]
    declaration_gap: bool; summary: str


@dataclass(frozen=True)
class Remediation:
    patch: Mapping[str, Any]; patched_manifest: Mapping[str, Any]
    code_actions: tuple[str, ...]; summary: str; cures_gate: bool


@dataclass(frozen=True)
class JudgeResult:
    used: bool; mode: str; model: str | None; skipped_reason: str | None
    verdicts: tuple[tuple[int, str, str], ...]     # (finding index, "confirm"|"reject"|"adjust", rationale)
    adjusted: tuple[Finding, ...]                  # the post-judge finding list (== input when not used)
    purpose_addendum: str | None; notes: str | None; error: str | None


@dataclass(frozen=True)
class CiReport:
    system_id: str; repo: str; manifest: str; generated_at: str
    aicl_version: str; opencomplai_version: str
    check: CheckResult; classification: Classification
    verify: VerifyLogResult | None; local_verify: VerifyResult | None; anchor: Anchor | None
    unresolved_pending: tuple[PendingRecord, ...]
    remediation: Remediation | None; judge: JudgeResult
    verdict: str; verdict_reasons: tuple[str, ...]
    reproduce: tuple[str, ...]                     # exact argv lines of every subprocess run
    log_entries: tuple[Entry, ...] = ()            # decision log entries (intents already redacted by the hook)
