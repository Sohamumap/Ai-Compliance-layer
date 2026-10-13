# aicl: AI Compliance Layer (v0 prototype)

aicl sits between a runtime security control for AI coding agents and a regulatory evidence gate.
It talks to [Opencomplai](https://pypi.org/project/opencomplai/) (EU AI Act CI gate) only through its CLI.

- **Runtime guardrail.** `aicl hook pre|post` is a Claude Code `PreToolUse`/`PostToolUse` hook. It decides
  allow / deny / ask against the agent mandate declared in `system-manifest.json` plus a deterministic rule
  set (destructive shell, secrets in input, prohibited or undeclared tools, MCP server allow-list, network
  egress, self-protection). It appends every deny and every executed tool to `agent-log.jsonl` in
  Opencomplai's hash-chain format (checked by `opencomplai agents verify-log`). `opencomplai gaps` finds the
  log by path, which moves Art. 12 from MISSING to PARTIAL; it does not read the log's content.
- **Agentic CI.** `aicl ci` runs `opencomplai check --scan --with-gaps` and `agents verify-log`, adds an AST
  classifier (Python only: other languages are reported as "not assessed") that flags what the declaration
  hides (for example Art. 5(1)(g) biometric categorisation), optionally asks Claude to review the findings
  (only when `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set; `--judge off` disables it), and writes
  `aicl-report.md/.json` plus an RFC 7386 manifest patch and code actions.

**What it is not.** It is not legal advice, a sandbox, or a replacement for Claude Code permissions. Log
entries are not signed, and there is no remote anchor: anyone who can rewrite both the log and
`.aicl/log-anchor.json` can forge history. No model runs in the hook path. The remediation patch is never
applied to your manifest; aicl writes `system-manifest.proposed.json` next to it. The classifier is a keyword
heuristic: its Art. 5/Annex III mappings are flagged for legal review (ethnicity is read as "race" under
Art. 5(1)(g), which is an interpretation), and it has no Annex III 1(b)/1(c) categories. Other known v0
limits: shell rules are pattern checks, not a shell parser (a command the shell expands in ways aicl cannot
see, such as `$VAR` targets without `cd`, is not resolved; Bash commands over 16 KB go to a human); MCP tools
are checked for secret-file paths but not for writes to protected files; `input_hash` is an unsalted SHA-256
of the tool input (Opencomplai's format), so a low-entropy secret in a command can be guessed offline; several
agents whose logs share a directory share one anchor file and will report an anchor mismatch; a torn last log
line stops logging until fixed by hand (loud: hook exit 1, deadletter, CI FAIL); a profile from `ant auth
login` is not detected as a judge credential.

## Install and demo

```sh
make install        # uv venv + editable install with the dev extra (pins opencomplai==0.12.0) and llm extra
make demo           # .venv/bin/aicl demo: 7 asserted steps, offline, about 10 s
make test           # pytest; tests marked external need the opencomplai binary (auto-skipped without it)
```

`aicl demo` copies the bundled `shopper-insights` fixture to a temp dir, runs `aicl init`, replays nine
synthetic Claude Code hook payloads (hand-written to the documented contract) through the real hook
subprocess, verifies the chain (and two tampered copies), runs `aicl ci` and re-checks the proposed manifest.

## Use it on your repo (Claude Code)

1. Declare your agent in `system-manifest.json` under `agent_inventory` (tools, `mandate.permitted_actions`,
   `prohibited_actions`, scalar `limits` knobs, `guardrails`, `logging.decision_log_ref`).
2. `aicl init --repo .` merges the hooks into `.claude/settings.json` (`PreToolUse`, `PostToolUse` and
   `PostToolUseFailure`; matcher `^(Bash|Edit|Write|Read|WebFetch|mcp__.*)$`, anchored so `TodoWrite` and
   `NotebookEdit` stay out; command `"<python>" -m aicl hook pre|post`, timeout 20 s).
   It also writes `docs/human_oversight.md` (Art. 15 guardrail evidence) and adds a `human_oversight` block
   to the manifest (on Opencomplai 0.12.0 the block moves Art. 14 to PARTIAL), then runs `opencomplai agents check`.
3. Run `aicl log verify agent-log.jsonl --anchor --external` and `aicl log status` locally, and `aicl ci` in CI.
   Exit codes: 0 PASS, 1 FAIL, 2 config error, 3 opencomplai unavailable.

A repo without `system-manifest.json` is not governed: the hook prints nothing and exits 0. In a governed
repo, an internal error becomes `ask`, or `deny` with `--fail-closed` / `AICL_FAIL_CLOSED=1`. The hook never
emits `allow`, so your own permission prompts stay in force; add `permissions.deny` rules as a second layer.

**Ungoverned in v0** (outside the matcher, not logged): Grep, Glob, Task, TodoWrite, WebSearch, NotebookEdit.
**Cursor:** enable its third-party hook import to reuse `.claude/settings.json` (not verified here; no native writer).

## Licence boundary

aicl never imports `opencomplai`, `opencomplai_core`, `opencomplai_cli` or `opencomplai_ai`. It only calls the
`opencomplai` executable (subprocess argv, stdout JSON, exit codes, files it writes). The decision-log format
is reimplemented with `hashlib`/`json`. `tests/test_boundary.py` enforces this (`make boundary`). The fixture
and samples are our own. aicl's own licence is not decided yet.

## Read more

- `docs/design/DESIGN.md`: the v0 design (contracts, policy and evidence model, demo script, decisions).
- `docs/research/`: Opencomplai vs Kirin, and the verified integration facts this prototype is built on.
