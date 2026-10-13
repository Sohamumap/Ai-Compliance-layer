# Integration facts for the prototype

Date: 2026-10-13. Verified facts the prototype is built on. Every item below was checked in this
environment against Opencomplai 0.12.0 installed from PyPI, the Claude Code hooks reference, and
the Claude API skill. Read `01-opencomplai-vs-kirin.md` first for the why; this file is the how.

## Decisions already made (from the alignment questions)

| Question | Decision |
|---|---|
| Purpose | Working prototype to compare notes with Vidhi. End-to-end demo beats polish. |
| Layers | Both from day one: (A) runtime guardrail that writes regulatory evidence, (B) agentic CI wrapper around `opencomplai check` / `scan`. |
| Licence | Undecided, so **strict boundary**: our code never imports `opencomplai`, `opencomplai_core`, `opencomplai_cli` or `opencomplai_ai`. We talk to Opencomplai only through its CLI (subprocess), its JSON / SARIF / JSONL files and, later, its REST gateway. Reimplementing a documented file format is fine; copying their code is not. |
| Target | Quickest convincing demo. Chosen: a developer team using Claude Code or Cursor on an AI product, with EU AI Act articles as the evidence model. India DPDP can come later as a framework pack. |

## Environment

| Item | Value |
|---|---|
| Python | 3.13 in `.venv` (project target 3.11+). `uv` 0.11 available, fast installs. |
| Installed in `.venv` | `opencomplai` 0.12.0 (+ core, cli), `opencomplai-ai` 0.12.0, `anthropic` 1.13.0 (Python SDK 1.x), `pytest` 9.1, `cryptography` 50, `pydantic` 2.14. |
| Claude Code CLI | 2.1.296 present at `/opt/node22/bin/claude`. Hooks can be exercised by feeding hook JSON on stdin; a live interactive session is not needed for tests. |
| Anthropic credentials | **None in this environment** (no `ANTHROPIC_API_KEY`, no `ant` CLI). Every LLM-backed path must degrade to a deterministic offline mode and the demo must run with no key. |
| Network | Outbound HTTPS via proxy works (PyPI, GitHub). |

## Opencomplai CLI contract (verified by running it)

- `opencomplai init --system-id X --intended-purpose "..."` writes `system-manifest.json` with the
  keys shown in `docs/research/smoke/` style output: `system_id`, `intended_purpose`,
  `compliance_target`, `high_risk_presumption`, `commit_ref`, plus many nullable Annex IV fields.
  We may add an `agent_inventory` block to it (see schema below).
- `opencomplai scan --manifest system-manifest.json --repo-root . --no-emit-evidence --output json`
  prints a JSON envelope: `schema_version "1.0"`, `tool_version`, `disclaimer`, `scan_errors`,
  `payload{scan_id, system_id, detector_versions, declared_purpose, declared_categories,
  evidence[], findings[], ...}`. Each evidence item has `evidence_kind` (dependency / import),
  `category` (e.g. `ai_sdk`), `token_label` (e.g. `openai`), `locations` (`file:line`), `scope`,
  `confidence`, `detector_id`.
- `opencomplai scan ... --ai-intent --ai-model codebert-onnx` adds an `eu_ai_scan` block
  (capabilities, prohibited, high_risk, limited_risk, candidates, rationale per flagged line).
  Deterministic, no download. On a file that imports `openai` and calls `chat.completions.create`
  it reports two Art. 50 limited-risk findings and zero prohibited / high-risk.
- `opencomplai check [--scan] [--with-gaps] [--output json] [--sarif-output f] [--report-junit f]`
  writes `compliance-artifact.json`. Exit codes: `0` pass, `1` control_fail, `2` validation_fail,
  `3` policy_block (Art. 5), `4` trap_detected.
- `opencomplai gaps [--output json]` prints per-article rows: `article`, `status`
  (`met | partial | missing | unverified`), `source`, `evidence_ref`, `rationale`, `confidence`.
- `opencomplai agents check -m system-manifest.json` validates the inventory. A mandate entry
  `tool:<name>` must name a tool declared by the same agent, else `invalid_inventory: unknown tool ref`.
- `opencomplai agents verify-log agent-log.jsonl -m system-manifest.json [-o json]` verifies the
  hash chain and recomputes out-of-mandate entries. Exit `0` = chain ok and nothing out of mandate,
  `1` = broken chain or any out-of-mandate entry (including `self_reported`), `2` = bad input.
  Output ends with `head=sha256:... count=N`. JSON output has `status`, `chain{ok,count,head,
  error,bad_seq,signed_count,verified_signatures}`, `mandate_checked`, `out_of_mandate[]`.
  Reason codes: `unknown_agent`, `tool_not_declared`, `prohibited_action`, `not_permitted`,
  `mandate_expired`, `bad_timestamp`, `self_reported`.

## Agent inventory schema (manifest key `agent_inventory`, strict: unknown keys are rejected)

```json
{
  "agent_inventory": {
    "agents": [{
      "id": "claude-code", "name": "Claude Code (IDE agent)", "parent_id": null,
      "tools": [{"name": "Bash", "kind": "function", "scope": null, "side_effects": true, "requires_approval": true}],
      "models": [{"provider": "anthropic", "model": "claude-opus-5-5", "via": null}],
      "mandate": {"permitted_actions": ["tool:Bash"], "prohibited_actions": ["tool:WebFetch"],
                  "limits": {}, "granted_by": "soham", "granted_at": "2026-10-13",
                  "expires_at": null, "review_cadence": null},
      "delegation": {"may_delegate_to": [], "max_depth": 0},
      "guardrails": [{"kind": "runtime_policy_hook", "evidence_ref": "docs/guardrail.md"}],
      "logging": {"decision_log_ref": "agent-log.jsonl", "captures_intent": true}
    }],
    "responsibility_map": {"customer_obligations": [], "upstream_provider_obligations": []}
  }
}
```

`kind` is one of `mcp | function | api`. Tool names are matched casefolded against the log's
`tool` field, as `<name>` or `tool:<name>`. `mandate.limits` is not evaluated by Opencomplai.
`logging.decision_log_ref` must name a regular file inside the repository for the Article 12 row
to read Partial (never Met).

## Agent decision log format (JSON lines; we reimplement it, verified byte-for-byte)

Each line is one JSON object with keys `seq, ts, payload, prev_hash, hash, signature`, written with
`json.dumps(entry, sort_keys=True)` and a trailing newline.

- `seq` starts at 1 and increments. `ts` is an ISO 8601 string (UTC recommended).
- `payload` has exactly: `agent_id` (str), `mandate_ref` (str or null), `intent` (str, max 1000),
  `tool` (str), `input_hash` (str), `outcome` (`success | failure | blocked`), `outside_mandate` (bool).
  Extra or missing keys fail the schema check.
- `input_hash = "sha256:" + sha256(canonical({"input": tool_input}))` where
  `canonical(d) = json.dumps(d, sort_keys=True, default=str).encode("utf-8")`. The raw tool input
  is never stored.
- `prev_hash` of the first entry is `"sha256:" + "0" * 64`.
- `hash = "sha256:" + sha256(b"opencomplai.log.v1\x00" + b"agent-log" + b"\x00" + canonical({"seq": seq, "ts": ts, "payload": payload, "prev_hash": prev_hash}))`.
- `signature` is `null` when unsigned. Signed entries use Ed25519 over a domain-separated digest;
  signing is optional for the prototype (verify-log without `--require-signed` accepts unsigned).
- A standard-library reimplementation of this recipe reproduces the golden log in the scratch
  directory `scratchpad/smoke/agent-log.jsonl` hash for hash (checked 2026-10-13).
- Ceiling: a chain cannot detect truncation of the newest entries. Store `head` and `count`
  somewhere else (we will print and persist them) and pass `--expected-head/--expected-count`.

## Claude Code hooks contract (from the hooks reference)

- Registered in `.claude/settings.json` (project) or `~/.claude/settings.json` (user):

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash|Edit|Write|Read|WebFetch|mcp__.*",
   "hooks": [{"type": "command", "command": "${CLAUDE_PROJECT_DIR}/.venv/bin/aicl hook pre", "timeout": 20}]}],
 "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "${CLAUDE_PROJECT_DIR}/.venv/bin/aicl hook post", "timeout": 20}]}]}}
```

- Stdin JSON for PreToolUse: `session_id, transcript_path, cwd, permission_mode, hook_event_name,
  tool_name, tool_input, tool_use_id` (plus `agent_id`/`agent_type` inside subagents). PostToolUse
  adds `tool_response`.
- Known `tool_input` shapes: Bash `{command, description?, timeout?, run_in_background?}`;
  Edit `{file_path, old_string, new_string, replace_all?}`; Write `{file_path, content}`;
  Read `{file_path, offset?, limit?}`; WebFetch `{url, prompt}`; MCP tools are named
  `mcp__<server>__<tool>` with arbitrary input.
- Output: exit `0` with a single JSON object on stdout is applied:
  `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow|deny|ask",
  "permissionDecisionReason": "...", "updatedInput": {...}?, "additionalContext": "..."?}}`.
  Exit `2` blocks and stderr becomes the reason Claude sees. Exit `1` or other does not block.
  Prefer exit 0 + JSON `deny` (gives a structured reason) and reserve exit 2 for hard failures of
  the hook itself when a fail-closed posture is configured.
- Cursor reads `.cursor/hooks.json` and can import Claude Code hook configs when third-party
  imports are enabled. One executable can serve both.

## Claude API (for the optional strong-model judge and the CI remediation agent)

- Use the official `anthropic` Python SDK (1.x is installed). Default model `claude-opus-5-5`;
  omit `thinking` or pass `{type: "adaptive"}`; never `budget_tokens`; no assistant prefill; no
  forced `tool_choice`. Use structured outputs (`client.messages.parse()` or
  `output_config.format`) for JSON verdicts. Include `fallbacks: "default"` with beta
  `server-side-fallback-2026-07-01` per the skill, and check `stop_reason == "refusal"`.
- Reference docs on this machine (read before writing SDK code):
  `/tmp/claude-0/bundled-skills/2.1.296/f4d436017525492514c6de56fc9ec524/claude-api/python/claude-api/README.md`
  and `tool-use.md` (section "Structured Outputs", line ~514) and `sdk-upgrade.md` (1.x changes).
- Credentials resolve from `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or an `ant auth login`
  profile. None exist here, so the LLM path must be optional: `--judge llm` only when a credential
  is present, otherwise the deterministic path runs and the report says the LLM step was skipped.

## Demo narrative to prove (the acceptance test for the prototype)

1. A sample AI project (our own fixture, not copied from Opencomplai) has a manifest declaring a
   coding agent with a mandate and `decision_log_ref`.
2. `aicl hook pre` receives simulated Claude Code PreToolUse events: a normal Edit (allow), a
   `rm -rf` Bash (deny), a command containing an API key (deny, secret), a WebFetch (deny, outside
   mandate), an MCP tool from an unapproved server (deny). Each decision is appended to the chained
   log with the right `outcome` and `outside_mandate`.
3. `opencomplai agents verify-log` reports chain ok and lists exactly the blocked entries as out of
   mandate; `opencomplai gaps` shows the Article 12 row lifted from Missing to Partial by the log.
4. `aicl ci` runs `opencomplai scan` and `opencomplai check` on the fixture, merges the results
   with our own semantic classification (deterministic offline; LLM when a key exists), and writes
   a Markdown report plus a remediation proposal (a manifest patch) when the gate fails.
5. The whole thing runs with `pytest` and a single `make demo` (or `aicl demo`) command, offline.

## Smoke results that shape the design (2026-10-13, scratchpad/smoke)

- With the manifest above and a 3-entry log, `opencomplai gaps` shows `Art. 12 PARTIAL (artifact, agent-log.jsonl, Found)`.
  Art. 14 reads `MISSING (artifact, human_oversight...)` and Art. 15 reads `MISSING (manifest, agent guardrails)`:
  the design should say which files or manifest fields lift those two (read
  `opencomplai_core/gap_probes.py` and `agent_inventory` handling in the source clone, read-only).
- `opencomplai check --scan --with-gaps` on the fixture exits `0` (PASS), writes `scan-report.json` and
  `compliance-artifact.json`, and prints a regulatory timeline. The gate only fails when a discrepancy
  reaches `--fail-on` severity or an Article 5 / Annex III rule fires.
- `opencomplai gaps --output json` is an envelope whose row list is not at the top-level `articles` key;
  implementers must inspect the real output rather than assume.
- Opencomplai source clone (read-only, AGPL, never copy code from it):
  `/tmp/claude-0/-home-user-Ai-Compliance-layer/715ca474-4316-5bfe-b2c0-57eb296ed278/scratchpad/opencomplai-src`.
- Golden decision log and manifest produced during the smoke test:
  `/tmp/claude-0/-home-user-Ai-Compliance-layer/715ca474-4316-5bfe-b2c0-57eb296ed278/scratchpad/smoke/`.
