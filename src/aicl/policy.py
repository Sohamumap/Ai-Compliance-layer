"""Deterministic rule catalog for the runtime guardrail: regex tables, evaluate(), derive_intent(). No I/O."""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse

from aicl.core import (PROTECTED_PATHS, SECRET_FILE_GLOBS, AgentSpec, Decision, Evaluation, RuleHit, find_secret,
                       mcp_server, redact, relpath)
from aicl.manifest import limit_bool, limit_list, mandate_reasons

__all__ = ["RuleCtx", "RuleFn", "RULES", "evaluate", "derive_intent", "DESTRUCTIVE_SHELL", "DESTRUCTIVE_LABELS",
           "OBFUSCATION", "EGRESS", "BASH_WRITE_HINTS", "FILE_TOOLS", "WRITE_TOOLS"]

FILE_TOOLS = ("Edit", "Write", "Read", "NotebookEdit")
WRITE_TOOLS = ("Edit", "Write", "NotebookEdit")


@dataclass(frozen=True)
class RuleCtx:
    agent: AgentSpec; tool_name: str; tool_input: Mapping[str, Any]; cwd: Path; root: Path
    log_path: Path; ts: str

    @property
    def command(self) -> str:
        c = self.tool_input.get("command", "") if self.tool_name == "Bash" else ""
        return c if isinstance(c, str) else ""

    @property
    def file_path(self) -> str | None:
        if self.tool_name not in FILE_TOOLS:
            return None
        p = self.tool_input.get("file_path") or self.tool_input.get("notebook_path")
        return p if isinstance(p, str) and p else None


RuleFn = Callable[[RuleCtx], "RuleHit | None"]

# ---- regex tables (module constants; every entry has a positive and a negative test) --------------------
DESTRUCTIVE_SHELL: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\brm\s+(?:--?[a-z-]*\s+)*-[a-z]*r[a-z]*\b"),   # any -r/-R flag in any position (-Rf, -v -rf, --force -r)
    re.compile(r"(?i)\brm\s+(?:--?[a-z-]*\s+)*--recursive\b"),
    re.compile(r"\bfind\b.*\s-delete\b"), re.compile(r"shutil\.rmtree\("),
    re.compile(r"\bgit\s+push\b.*\s(--force|-f)\b"), re.compile(r"\bgit\s+reset\s+--hard\b"),
    re.compile(r"\bgit\s+clean\s+-[a-zA-Z]*f"), re.compile(r"\bgit\s+checkout\s+--\s+\."),
    re.compile(r"\bmkfs(\.|\s)"), re.compile(r"\bdd\s+if="), re.compile(r">\s*/dev/(sd|nvme|hd)"),
    re.compile(r"\bchmod\s+-R\s+777\s+/"), re.compile(r":\(\)\s*\{.*:\|:&\s*\};:"),
    re.compile(r"\b(shutdown|reboot|halt)\b"), re.compile(r"(?i)\b(drop\s+(table|database)|truncate\s+table)\b"),
    re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"), re.compile(r"\bsudo\s+rm\b"),
)
DESTRUCTIVE_LABELS: tuple[str, ...] = (
    "rm with a recursive flag", "rm with a recursive flag", "find -delete", "shutil.rmtree",
    "git push --force", "git reset --hard", "git clean -f", "git checkout -- .",
    "mkfs", "dd if=", "write to a raw block device",
    "chmod -R 777 /", "fork bomb",
    "shutdown/reboot/halt", "SQL drop/truncate",
    "download piped to a shell", "sudo rm",
)
OBFUSCATION: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bbase64\s+(-d|--decode)\b.*\|\s*(ba|z)?sh\b"), re.compile(r"\beval\s+[\"'$]"),
    re.compile(r"\$\([^)]*\)\s*\|\s*(ba|z)?sh\b"), re.compile(r"\bpython[0-9.]*\s+-c\s+[\"'].*\b(exec|compile)\("),
    re.compile(r"\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}"),
)
EGRESS = re.compile(r"\b(curl|wget|nc|ncat|ssh|scp|rsync)\b\s+(?:-\S+\s+)*(?:\S+\s+)*?(?P<url>https?://[^\s'\"]+|(?:[^\s@'\"]+@)?[a-zA-Z0-9.-]+\.[a-z]{2,}(?::\d+)?)")
BASH_WRITE_HINTS = re.compile(r"(>{1,2}|\brm\b|\bmv\b|\bcp\b|\bsed\s+-i|\btee\b|\btruncate\b|\bchmod\b|\bgit\s+(checkout|restore|rm|clean)\b|\bpython[0-9.]*\s+-c)")
assert len(DESTRUCTIVE_SHELL) == len(DESTRUCTIVE_LABELS)

_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", ">&"})
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


# ---- helpers ----------------------------------------------------------------------------------------------------
def _tokens(command: str) -> list[str]:
    """Shell-ish tokens with operators split off (`x>f` -> x, >, f); falls back to str.split on bad quoting."""
    try:
        lx = shlex.shlex(command, posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        return list(lx)
    except ValueError:
        return command.split()


def _resolve(ctx: RuleCtx, raw: str) -> Path | None:
    try:
        p = Path(os.path.expanduser(raw))
        return (p if p.is_absolute() else Path(ctx.cwd) / p).resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _protected(ctx: RuleCtx, raw: str) -> str | None:
    """Repo-relative name when raw (cwd-relative) is a self-protected path: PROTECTED_PATHS, the log, its lock."""
    full = _resolve(ctx, raw)
    if full is None:
        return None
    log = Path(ctx.log_path).resolve()
    fold = str(full).casefold()
    if fold in (str(log).casefold(), str(log).casefold() + ".lock"):
        return relpath(str(full), ctx.root)
    try:
        rel = full.relative_to(Path(ctx.root).resolve()).as_posix()
    except ValueError:
        return None
    return rel if any(fnmatch.fnmatchcase(rel.casefold(), g.casefold()) for g in PROTECTED_PATHS) else None


def _candidates(tokens: list[str]) -> list[str]:
    return [x for t in tokens for x in ((t, t.split("=", 1)[1]) if "=" in t else (t,)) if x]


def _hit(rule_id: str, decision: Decision, message: str) -> RuleHit:
    return RuleHit(rule_id, decision, redact(message)[:200])


def _mandate_hit(ctx: RuleCtx, code: str) -> bool:
    return code in mandate_reasons(ctx.agent, ctx.tool_name, ctx.ts)


def _who(ctx: RuleCtx, knob: str, value: str = "true") -> str:
    return f"mandate limit {knob}={value} for agent {ctx.agent.id}"


# ---- DENY rules -------------------------------------------------------------------------------------------------
def _self_protect(ctx: RuleCtx) -> RuleHit | None:
    rel = None
    if ctx.tool_name in WRITE_TOOLS and ctx.file_path:
        rel = _protected(ctx, ctx.file_path)
    elif ctx.tool_name == "Bash" and ctx.command:
        toks = _tokens(ctx.command)
        targets = [toks[i + 1] for i, t in enumerate(toks[:-1]) if t in _REDIRECTS]
        rel = next((r for t in targets if (r := _protected(ctx, t))), None)
        if rel is None:   # other write verbs: judged on the command without redirections (so `cat x 2>/dev/null` stays a read)
            rest = [t for i, t in enumerate(toks) if t not in _REDIRECTS and not (i and toks[i - 1] in _REDIRECTS)]
            if BASH_WRITE_HINTS.search(" ".join(rest)):
                rel = next((r for t in _candidates(rest) if (r := _protected(ctx, t))), None)
    if rel is None:
        return None
    return _hit("self_protect", Decision.DENY, f"write to protected path {rel} (guardrail configuration or evidence)")


def _tool_prohibited(ctx: RuleCtx) -> RuleHit | None:
    if _mandate_hit(ctx, "prohibited_action"):
        return _hit("tool_prohibited", Decision.DENY,
                    f"tool {ctx.tool_name} is in prohibited_actions of the mandate for agent {ctx.agent.id}")
    return None


def _mcp_server_not_allowed(ctx: RuleCtx) -> RuleHit | None:
    server = mcp_server(ctx.tool_name)
    allowed = limit_list(ctx.agent.mandate, "mcp_allowed_servers")
    if server is not None and server.casefold() not in allowed:
        return _hit("mcp_server_not_allowed", Decision.DENY,
                    f"MCP server {server} not in mcp_allowed_servers ({', '.join(allowed) or 'none'}) for agent {ctx.agent.id}")
    return None


def _tool_not_declared(ctx: RuleCtx) -> RuleHit | None:
    if _mandate_hit(ctx, "tool_not_declared") and limit_bool(ctx.agent.mandate, "deny_undeclared_tools", True):
        return _hit("tool_not_declared", Decision.DENY,
                    f"tool {ctx.tool_name} is not declared in tools[]; {_who(ctx, 'deny_undeclared_tools')}")
    return None


def _tool_not_permitted(ctx: RuleCtx) -> RuleHit | None:
    reasons = mandate_reasons(ctx.agent, ctx.tool_name, ctx.ts)
    if "not_permitted" in reasons:
        return _hit("tool_not_permitted", Decision.DENY,
                    f"tool {ctx.tool_name} is not in permitted_actions of the mandate for agent {ctx.agent.id}")
    if "mandate_expired" in reasons:
        exp = ctx.agent.mandate.expires_at if ctx.agent.mandate else "?"
        return _hit("mandate_expired", Decision.DENY, f"mandate for agent {ctx.agent.id} expired at {exp}")
    return None


def _destructive_shell(ctx: RuleCtx) -> RuleHit | None:
    if not ctx.command or not limit_bool(ctx.agent.mandate, "deny_destructive_shell", True):
        return None
    label = next((lb for p, lb in zip(DESTRUCTIVE_SHELL, DESTRUCTIVE_LABELS) if p.search(ctx.command)), None)
    return _hit("destructive_shell", Decision.DENY, f"{label}; {_who(ctx, 'deny_destructive_shell')}") if label else None


def _secret_in_input(ctx: RuleCtx) -> RuleHit | None:
    name = find_secret(ctx.tool_input)
    if name and limit_bool(ctx.agent.mandate, "deny_secrets_in_input", True):
        return _hit("secret_in_input", Decision.DENY,
                    f"secret-like value ({name}) in tool input; {_who(ctx, 'deny_secrets_in_input')}")
    return None


def _is_secret_file(ctx: RuleCtx, raw: str) -> bool:
    full = _resolve(ctx, raw)
    if full is None:
        return False
    for g in SECRET_FILE_GLOBS:
        if g.startswith("~"):
            if fnmatch.fnmatchcase(str(full), str(Path(os.path.expanduser(g)).resolve())):
                return True
        elif fnmatch.fnmatchcase(full.name, g):
            return True
    return False


def _secret_file_read(ctx: RuleCtx) -> RuleHit | None:
    if not limit_bool(ctx.agent.mandate, "deny_secret_file_read", True):
        return None
    if ctx.tool_name == "Read" and ctx.file_path:
        cands = [ctx.file_path]
    elif ctx.command:
        cands = _candidates(_tokens(ctx.command))
    else:
        return None
    for c in cands:
        if _is_secret_file(ctx, c):
            return _hit("secret_file_read", Decision.DENY,
                        f"read of secret file {Path(c).name}; {_who(ctx, 'deny_secret_file_read')}")
    return None


# ---- ASK rules --------------------------------------------------------------------------------------------------
def _obfuscated_shell(ctx: RuleCtx) -> RuleHit | None:
    if ctx.command and limit_bool(ctx.agent.mandate, "ask_obfuscated_shell", True) \
            and any(p.search(ctx.command) for p in OBFUSCATION):
        return _hit("obfuscated_shell", Decision.ASK,
                    f"obfuscated or dynamically evaluated shell; {_who(ctx, 'ask_obfuscated_shell')}")
    return None


def _host(url: str) -> str:
    if "://" in url:
        return (urlparse(url).hostname or "").casefold()
    url = url.rsplit("@", 1)[-1]   # ssh/scp user@host
    return url.rsplit(":", 1)[0].casefold() if re.search(r":\d+$", url) else url.casefold()


def _network_egress(ctx: RuleCtx) -> RuleHit | None:
    if not ctx.command or not limit_bool(ctx.agent.mandate, "ask_network_egress", True):
        return None
    allowed = limit_list(ctx.agent.mandate, "allowed_hosts")
    for m in EGRESS.finditer(ctx.command):
        host = _host(m.group("url"))
        if not any(host == a or host.endswith("." + a) for a in allowed):
            return _hit("network_egress", Decision.ASK,
                        f"network egress via {m.group(1)} to {host or '?'} (not in allowed_hosts); {_who(ctx, 'ask_network_egress')}")
    return None


def _protected_path_write(ctx: RuleCtx) -> RuleHit | None:
    if ctx.tool_name not in WRITE_TOOLS or not ctx.file_path:
        return None
    full = _resolve(ctx, ctx.file_path)
    if full is None:
        return None
    try:
        rel = full.relative_to(Path(ctx.root).resolve()).as_posix().casefold()
    except ValueError:
        return None
    for g in limit_list(ctx.agent.mandate, "protected_paths"):
        g = g.rstrip("/")
        if fnmatch.fnmatchcase(rel, g) or rel == g or rel.startswith(g + "/"):
            return _hit("protected_path_write", Decision.ASK,
                        f"write to {rel} under protected_paths glob {g} for agent {ctx.agent.id}")
    return None


RULES: tuple[tuple[str, RuleFn], ...] = (   # evaluation order; ALL run; DENY beats ASK beats ALLOW
    ("self_protect", _self_protect),
    ("tool_prohibited", _tool_prohibited),
    ("mcp_server_not_allowed", _mcp_server_not_allowed),
    ("tool_not_declared", _tool_not_declared),
    ("tool_not_permitted", _tool_not_permitted),
    ("destructive_shell", _destructive_shell),
    ("secret_in_input", _secret_in_input),
    ("secret_file_read", _secret_file_read),
    ("obfuscated_shell", _obfuscated_shell),
    ("network_egress", _network_egress),
    ("protected_path_write", _protected_path_write),
)


def evaluate(ctx: RuleCtx) -> Evaluation:
    hits = tuple(h for _, rule in RULES if (h := rule(ctx)) is not None)
    for decision in (Decision.DENY, Decision.ASK):
        win = next((h for h in hits if h.decision is decision), None)
        if win is not None:
            return Evaluation(decision, hits, f"aicl: {decision.value} [{win.rule_id}] {win.message}", win.rule_id,
                              decision is Decision.DENY)
    return Evaluation(Decision.ALLOW, hits, "", "ok", False)


def derive_intent(ctx: RuleCtx, ev: Evaluation) -> str:
    """Safe, attributable intent: program + arg count + redacted description; path only; hostname; server.tool."""
    tool, ti = ctx.tool_name, ctx.tool_input
    if tool == "Bash":
        try:
            argv = shlex.split(ctx.command)
        except ValueError:
            argv = ctx.command.split()
        while argv and _ENV_ASSIGN.match(argv[0]):   # VAR=value prefixes carry values, never the program
            argv = argv[1:]
        body = f"Bash: {os.path.basename(argv[0])[:60] if argv else '?'} ({max(len(argv) - 1, 0)} args)"
        desc = ti.get("description")
        if isinstance(desc, str) and desc.strip():
            body += f": {redact(' '.join(desc.split()))[:120]}"
    elif tool in FILE_TOOLS:
        fp = ctx.file_path
        full = _resolve(ctx, fp) if fp else None
        body = f"{tool}: {relpath(str(full), ctx.root) if full else '?'}"
    elif tool == "WebFetch":
        url = ti.get("url")
        try:
            host = urlparse(url).hostname if isinstance(url, str) else None
        except ValueError:
            host = None
        body = f"WebFetch: {host or '?'}"
    elif mcp_server(tool) is not None:
        server, _, name = tool[5:].partition("__")
        body = f"MCP: {server}.{name}"
    else:
        body = tool
    body = redact(body)[:200]
    if find_secret(body):
        body = f"{tool}: <redacted>"
    return f"{body} | aicl:{ev.decision.value}:{ev.rule_id}"
