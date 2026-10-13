# Opencomplai vs Kirin: research notes

Date: 2026-10-13. Written to answer three questions from the LinkedIn thread with Vidhi:

1. Is Opencomplai "like Kirin"? Is it as strong?
2. Can a strong wrapper be built on top of Opencomplai?
3. Where could agentic capabilities (a Herald-style harness) add real value?

Everything below comes from reading the Opencomplai source at commit `6ae20f0` (v0.12.0, released
today), its own docs and benchmark page, Knostic's public pages, and a third-party vendor wiki.
Kirin is closed source, so its internals are inferred from vendor material only.

---

## TL;DR

- **They are not the same product category.** Kirin is a *runtime security control* for AI coding
  agents. Opencomplai is a *regulatory compliance gate* for CI/CD, focused on the EU AI Act.
  Kirin asks "should this agent action run right now?". Opencomplai asks "can we prove this AI
  system meets its legal obligations at release time?".
- **Opencomplai is bigger than the LinkedIn post suggests, but its "intelligence" is shallow.**
  About 118k lines of Python and TypeScript, 652 Python files, 364 test files, daily releases.
  But the risk engine is four rules doing keyword matching on the declared `intended_purpose`,
  and the code scanner is a token dictionary over imports and call names. The demo that "caught
  biometric categorisation" is a dictionary hit on the `face_recognition` import.
- **Opencomplai's own benchmark says the scanner is weak.** On its held-out set the intent path
  gets 50% precision and 33% recall. The default scan path gets 25% and 8%. It found 1 of 4
  prohibited-practice programs. The maintainers publish this themselves, which is to their credit.
- **Where Opencomplai is genuinely deep:** the regulatory machinery around the engine. Per-article
  gap reports, controls lifecycle, Annex IV dossier drafts, Ed25519-signed artifacts, a
  hash-chained evidence ledger, SARIF and JUnit output, a strict exit-code contract, and a growing
  "agent inventory" model with mandates, attestations and a tamper-evident `AgentDecisionLog`.
  Kirin has none of this.
- **Where Kirin is deep:** real-time interception inside the agent (hooks, IDE extension, endpoint
  client), prompt-injection and secret detection, MCP governance, malicious-package checks, SOC
  alerts. Opencomplai has none of this. Everything in Opencomplai is declared or post-hoc.
- **The wrapper opportunity is the gap between them.** Nobody in the thread's list of tools
  connects runtime agent behaviour to regulatory evidence. A layer that hooks the coding agent
  (like Kirin), judges each action against security *and* compliance policy with a strong model,
  and writes signed evidence into Opencomplai's ledger mapped to Articles 12, 14 and 15 would be
  new. It is feasible with components that already exist today.
- **Biggest non-technical risk: the AGPL-3.0 licence plus a CLA.** Importing `opencomplai_core`
  into a distributed or hosted wrapper makes the wrapper AGPL too. Talking to Opencomplai only
  across a process or HTTP boundary (CLI, JSON, SARIF, REST) keeps our options open.

---

## 1. What Opencomplai actually is

### Positioning (in its own words)

"A CI gate plus an evidence trail for the EU AI Act. It is a tripwire over a declared manifest,
not a legal opinion or certification." Target users: teams that build, fine-tune or substantially
modify AI systems and need a per-release EU AI Act check in CI. Explicitly *not* for teams that
only use an AI product and need vendor-risk workflows.

### The workflow

```
opencomplai init     -> writes system-manifest.json (system id, intended purpose, modality,
                        deployment context, optional agent_inventory, compliance_targets)
opencomplai scan     -> corroboration scanner: cross-checks the manifest's declaration against
                        AI signals found in the repo (imports, packages, model files, endpoints)
opencomplai check    -> rule engine classifies risk tier from the manifest, runs controls,
                        writes compliance-artifact.json (optionally Ed25519 signed), exits 0-4
opencomplai gaps     -> per-article status: met / partial / missing / unverified
opencomplai docs generate -> Annex IV technical documentation draft with honest placeholders
```

Exit codes are a contract: `0` pass, `1` control_fail, `2` validation_fail, `3` policy_block
(Article 5 prohibited practice), `4` trap_detected (substantial modification or profiling).

### Architecture

| Layer | Component | Tech | Size (LOC) |
|---|---|---|---|
| Engine | `opencomplai-core` | Python 3.11, Pydantic v2, no HTTP | ~23.8k |
| CLI | `opencomplai-cli` | Typer, Rich | ~13.4k |
| SDK | `opencomplai` (meta-package) | re-exports `assess`, `evaluate_targets`, `AgentDecisionLog` | ~0.2k |
| Plugin | `opencomplai-ai` | optional intent classifier, llama.cpp GGUF models | ~2.5k |
| Services | risk-engine, evidence-vault, doc-generator, egress-proxy | FastAPI, Postgres, Redis | ~7.3k |
| Gateway | gateway-api | Node.js / Fastify | TS |
| Deploy | Docker Compose, read-only containers, non-root, egress allowlist | | |
| CI | GitHub Action, GitLab, Azure templates, pre-commit hook, SARIF, JUnit | | |

Local mode runs fully in-process with no network. Service-backed mode adds a 10-step flow through
the gateway, a hash-chained ledger, and a human-in-the-loop review queue.

### How risk classification really works

`packages/core/src/opencomplai_core/rules.py` holds `RULE_REGISTRY` with four rules:

| Rule | What it does |
|---|---|
| `AnnexIIIClassifierRule` | Keyword-matches the declared `use_case` text against Annex III area phrase lists |
| `UnacceptableRiskRule` | Keyword-matches the declared text against Article 5 prohibited-practice signals |
| `ProfilingDetectionRule` | Keyword-matches for profiling of natural persons |
| `SubstantialModificationRule` | Flags change-context inputs that can make you a provider |

So the "regulatory engine" is a keyword classifier over what *you declared*. The docs say this
plainly: "the declaration stays authoritative; the scanner never auto-classifies risk."

### How the scanner really works

- Inventories files (respecting `.ocignore`), extracts imports and call sites (regex plus a light
  AST extractor), and matches them against `scanner/data/ai_signals.json`, a token dictionary
  with 22 provider SDKs plus Annex III and Article 5 code signals. Dictionary version 1.6.0.
- Produces a *discrepancy* between declared and detected categories with severity
  `none / minor / major / critical`. `--fail-on major` turns a discrepancy into exit `1`.
- `--ai-intent` adds a call-site gate and a three-dimension classification
  (`decision_autonomy`, `subject_type`, `consequential`) that maps to a list of articles.
- MCP: `.mcp.json` servers are inventoried *by name only*. Agent frameworks are detected by package
  name. Both surface as `UNVERIFIED` rows for Articles 14 and 15, never a verdict.

### The LinkedIn demo, decoded

Vidhi's demo PR (`Vidhi1290/shopper-insights#1`) adds `face_recognition==1.3.0` and a 12-line
`segment_shoppers()` function. The manifest declares a "customer support chatbot". The scanner
hits the `face_recognition` token, maps it to Annex III area 1 (biometrics), reports a `major`
discrepancy against the declaration, and the workflow's `--fail-on major` turns that into exit
`1`. That is the whole mechanism. Useful, but it is a lookup, not understanding.

### Their own benchmark (synthetic programs, single labeller)

| Set | Path | Precision | Recall |
|---|---|---|---|
| Training (n=46) | intent (`--ai-intent`) | 73.3% | 75.9% |
| Training (n=46) | default scan | 54.5% | 20.7% |
| Held-out (n=24) | intent | 50.0% | 33.3% |
| Held-out (n=24) | default scan | 25.0% | 8.3% |

Article 5 on held-out: 1 true positive, 3 misses out of 4. The default path "reads area 1
(biometrics) and reads areas 2 to 8 poorly or not at all" (their words). The proposal picked the
right Annex III area for 1 of 12 held-out programs.

### The "AI" plugin, honestly

`codebert-onnx` is *not* a neural model. It is a deterministic signal matcher; the name is kept for
config compatibility. The real LLM path uses local GGUF models through llama.cpp, default
`qwen2.5-coder-1.5b` (about 1 GB). Confidence values are fixed per match type, not calibrated.
The 0.12.0 changelog explicitly stopped calling the feature "AI-powered".

### Agent features (the part most relevant to us)

Opencomplai already has an *agent governance* vocabulary, all declarative and offline:

- `agent_inventory` in the manifest: agents, tools (kind `mcp` / `function` / `api`, side effects,
  needs approval), models, **mandate** (`permitted_actions`, `prohibited_actions`, `limits`,
  grantor, expiry), delegation graph, guardrails, logging reference.
- `opencomplai agents inventory | check | report | attest | verify-log | import-log | dispute-report`.
- `AgentDecisionLog` in the SDK: hash-chained JSONL of agent decisions. The raw tool input is hashed,
  never stored. `verify-log` recomputes which entries fell outside the declared mandate.
- `import-log` reads Microsoft Agent Governance Toolkit audit sinks as a preview, capped at Partial.
- Feeds Articles 12 (logging), 14 (oversight), 15 (robustness), 26 (deployer) in the gap report.

What it does **not** have: any runtime interception, any live policy decision, any IDE or agent
hook. It records what you say your agents may do and verifies logs after the fact.

### Project health

| Signal | Value |
|---|---|
| Latest release | v0.12.0 on 2026-10-13 (daily cadence, Keep-a-Changelog discipline) |
| GitHub | 17 stars, 10 forks, 22 open issues, 79 commits shown |
| Tests | 364 test files, CI for Python and Node, CodeQL, DCO, actionlint |
| Licence | AGPL-3.0-only (Community Edition) plus commercial Enterprise Edition |
| CLA | Required. Section 4 grants Opencomplai the right to relicense contributions commercially |
| Tone | Every heuristic is labelled; many outputs say `needs_founder_review` or "a lawyer is to confirm" |

Reading: a single-vendor project with serious engineering discipline and a small community.
Schemas and dictionaries version-bump often, so results for the same input change between releases.

---

## 2. What Kirin actually is

### Positioning

Knostic's "security for AI coding agents". It sits at the agent's action boundary and checks each
action against policy *before* it executes. Outcomes: allow, block, downgrade, or route to a human.
Monitor mode first, then Enforce.

### Mechanism (from vendor pages)

| Agent | Install |
|---|---|
| Claude Code CLI, Claude Desktop, Cowork | Lightweight endpoint client plus agent hooks |
| Cursor, Windsurf, VS Code + Copilot | IDE extension (sits inside the agent) plus the client for shadow-AI visibility |
| Roadmap | IntelliJ, VS Code + Claude Code, WebStorm, Kiro, Codex, Gemini CLI |

The client runs in user space, needs no admin rights, watches network traffic for connections to
AI services, and ships policy to a central console. macOS and Windows supported, Linux in beta.

### What it intercepts and detects

- Tool calls and shell commands (destructive commands scored against a risk threshold).
- Prompts: secrets and API keys blocked before they reach the model.
- Files the agent reads: prompt injection, including instructions hidden in MCP tool descriptions.
- MCP connections: allow and block lists, unapproved-server alerts, usage tracking.
- Package installs: hallucinated, typosquatted or vulnerable packages via OSV data.
- Instruction files (`CLAUDE.md`, `.cursorrules`): a 60-check catalog.
- Policy drift, shadow AI inventory, extension and plugin monitoring.
- Logging to a dashboard, SOC "Prevented" alerts, SIEM and Slack in Enterprise.

Companion product AgentMesh is a supply-chain reputation engine for skills, MCP servers and
extensions. It feeds VirusTotal's Crowdsourced AI.

### Business

- Knostic, founded 2023. HQ Herndon, Virginia. R&D in Tel Aviv.
- About $19.3M raised: $3.3M pre-seed (Apr 2024), $11M Series A (Mar 2025), $5M tied to RSAC 2025
  Innovation Sandbox finalist status.
- Public bios describe the founders as security veterans: CEO Gadi Evron (serial security
  entrepreneur) and CTO Sounil Yu (creator of the Cyber Defense Matrix, formerly Bank of America).
- Pricing: Free for 1 to 5 users. Team $15 per user per month. Enterprise on request.
- Closed source. No independent benchmark, detection rate or bypass report found in public sources.
  The third-party wiki rates the agentic products "young and unproven in production".

---

## 3. Side by side

| Dimension | Opencomplai | Kirin |
|---|---|---|
| Question answered | Does this AI system meet EU AI Act obligations at release? | Should this agent action be allowed right now? |
| When it acts | CI time, per release | Runtime, per action, milliseconds |
| Where it runs | CI runner or dev shell; optional Docker services | Inside the agent (hooks, IDE extension) plus endpoint client |
| Unit of enforcement | Exit code on a pipeline | Block, downgrade, or human routing of one tool call |
| Detection method | Keyword rules on declaration, token dictionary on code, optional small local LLM | Proprietary detectors, risk scoring, OSV feeds, rule catalogs |
| Runtime interception | None | Core feature |
| MCP | Inventories server names from config | Inspects live connections and tool descriptions |
| Prompt injection, secrets | Not in scope | Core feature |
| Regulatory mapping | Deep: articles, Annex III and IV, controls, dossier | None named; "compliance-ready reporting" only |
| Evidence | Signed artifacts, hash-chained ledger, offline verify | Dashboard, audit logs, SIEM export |
| Agent model | Declared inventory, mandates, attestations, decision log verification | Observed behaviour, policies, drift detection |
| Openness | AGPL-3.0 source, published schemas | Closed; one old VSIX repo returns 404 |
| Maturity | v0.12.0, tiny community, honest about weak detection | Funded, RSAC finalist, no public benchmarks |
| Price | Free; Enterprise dashboard commercial | Free up to 5 users; $15 per user after |

---

## 4. So, is Opencomplai "strong enough like Kirin"?

It is the wrong comparison, and the thread already sensed this ("one with data lineage, one in
real time, some targeting laws"). They sit at different layers:

- **Security layer (Kirin):** stops a coding agent from running `rm -rf`, leaking a key, or
  installing a typosquatted package. Needs to be fast, inline, and adversarially robust.
- **Regulatory layer (Opencomplai):** proves to an auditor that a system was classified, controls
  were run, documentation exists, and evidence is tamper-evident. Needs to be legally literate,
  deterministic and reproducible.

On its own job, Kirin looks strong: real interception, a serious security team, funding. We cannot
verify detection quality because nothing is public. The bugs found during the pilot testing
(API issues, missed real-time malicious commands) fit the "young and unproven" read.

On its own job, Opencomplai is **structurally impressive and semantically weak**. The regulatory
skeleton is further along than anything else open source in this niche. The brain inside it is
keyword matching, and the maintainers say so. Anyone can run it, read it, and improve it, which is
the opposite of Kirin.

Neither does the other's job at all.

---

## 5. Can we build a strong wrapper? Yes, and here is where

### The gap

Kirin produces runtime security events with no regulatory meaning. Opencomplai produces regulatory
evidence with no runtime signal. The EU AI Act's Articles 12 (automatic logging), 14 (human
oversight) and 15 (robustness) are exactly about runtime behaviour. Nothing in the thread's list
of tools closes that loop.

### Building blocks that already exist

- **Claude Code hooks**: `PreToolUse` and `PostToolUse` hooks receive the tool name and input as
  JSON. A hook that exits `2` blocks the action and returns a reason to the agent.
- **Cursor hooks**: `.cursor/hooks.json`, and Cursor can load Claude Code hook configs when
  third-party imports are enabled. One hook script can cover both agents.
- **Opencomplai SDK**: `assess()`, `evaluate_targets()`, and `AgentDecisionLog` (hash-chained
  JSONL, verifiable with `opencomplai agents verify-log`).
- **Opencomplai contracts**: `scan-report.json`, `compliance-artifact.json`, SARIF 2.1.0, JUnit,
  exit codes, published JSON schemas, and the REST gateway in service-backed mode.
- **Manifest `agent_inventory`**: a place to declare each coding agent's mandate
  (`permitted_actions`, `prohibited_actions`, `limits`) that the runtime layer can enforce.

### Three candidate shapes

**A. Runtime guardrail that writes regulatory evidence (the "missing middle").**
A hook-based policy engine for Claude Code and Cursor. Each tool call is judged against (1) a
security policy similar to Kirin's categories and (2) the agent's declared Opencomplai mandate.
Decisions are recorded in `AgentDecisionLog`, so `opencomplai check` can lift Articles 12, 14 and
15 from Missing to Partial with real evidence instead of a declaration. Differentiator: Kirin-like
protection that also produces audit-grade compliance evidence. Risk: we would be competing on
detection quality with a funded security company.

**B. Agentic CI wrapper on top of `opencomplai check`.**
Replace the token-dictionary brain with a strong-model semantic classifier (the benchmark shows
the headroom: 8% to 33% recall today), keep Opencomplai as the deterministic evidence and gate
layer, and add an agent that proposes manifest fixes, control evidence and dossier text when the
gate fails. Differentiator: makes Opencomplai actually catch what the LinkedIn post claims it
catches. Risk: lowest novelty; the maintainers could ship this themselves.

**C. New framework packs.**
Opencomplai has an ADR for adding framework packs and currently ships EU AI Act (native), NIST AI
RMF (derived), ISO 42001 (attestations), DORA and EBA (mapped). India's DPDP Act 2023 and sector
guidance are absent. A pack is the cheapest way to contribute upstream and to learn the engine,
but the CLA means contributions can be relicensed commercially by them.

### Where a Herald-style agentic harness fits

The harness pattern (an agent with tools, a policy, and a human-escalation path) maps cleanly onto
shape A plus B:

```
coding agent (Claude Code / Cursor)
      | PreToolUse / PostToolUse hook (JSON on stdin)
      v
compliance-layer daemon
      |-- fast path: deterministic rules (secrets, destructive commands, MCP allowlist, mandate)
      |-- slow path: strong-model judge for ambiguous actions (prompt injection, intent)
      |-- decision: allow / block (exit 2 with reason) / ask human
      |-- evidence: AgentDecisionLog entry (hashed input, intent, outcome, article refs)
      v
opencomplai check --scan  (CI)  -> Articles 12/14/15 rows read Partial with verified log
opencomplai verify --kind agent-log           -> offline tamper check
```

Python is the natural implementation language because the SDK and the engine are Python, and
hooks are just executables reading JSON from stdin.

---

## 6. Risks and caveats

1. **Licence.** AGPL-3.0 with a network clause. Importing `opencomplai_core` into a wrapper that is
   distributed or offered as a service makes the wrapper AGPL. Options: open-source the wrapper
   under AGPL; keep Opencomplai behind a process or HTTP boundary (shell out to the CLI, consume
   JSON, SARIF and the REST gateway); or take their commercial licence. The default safe posture is
   the boundary.
2. **CLA.** Anything contributed upstream can be relicensed commercially by Opencomplai. Fine for
   goodwill and learning, not for anything we consider our moat.
3. **Do not trust the scanner as ground truth.** Its own benchmark says recall is low. Treat it as
   one signal and build our own classification for anything that blocks a developer.
4. **Single-vendor churn.** Dictionaries and schema versions bump on most releases. Pin versions and
   depend only on the published contracts (exit codes, JSON schemas, SARIF).
5. **Legal claims.** Opencomplai never claims to be a legal opinion. A wrapper should not either.
6. **Market reality from the thread.** Vidhi's point that enterprises are not adopting yet, and
   Soham's point that service companies will resist, both hold. Realistic early users are small and
   mid-size product teams shipping AI to EU customers, and developer teams already using coding
   agents who want guardrails with an audit trail.
7. **Kirin is a moving target.** Free tier up to 5 users, hooks for Claude Code already shipped,
   roadmap covers most agents. Competing head-on on security detection alone is the weakest play.
   Competing on security plus regulatory evidence is the open lane.

---

## 7. Decisions to make before building

1. Purpose of the prototype: product direction, technical prototype to compare notes, break-and-report
   testing like the Kirin pilot, or portfolio piece.
2. First layer: runtime guardrail feeding evidence (A), agentic CI wrapper (B), both, or analysis only.
3. Licence posture: AGPL-open wrapper, or proprietary-capable with a strict boundary.
4. Target users and regime: EU AI Act only, EU plus India DPDP, security-first, or coding-agent teams.

---

## Sources

- Opencomplai source and docs, commit `6ae20f0` (2026-10-13): https://github.com/Opencomplai/opencomplai
- Opencomplai docs: https://docs.opencomplai.com/ (scanner, agents, works-alongside, Annex III benchmark)
- Vidhi Waghela's post: https://www.linkedin.com/posts/vidhi-waghela-434663198_opencomplai-a-technical-breakdown-ugcPost-7504163628099727361-IY5a/
- Demo PR: https://github.com/Vidhi1290/shopper-insights/pull/1
- Kirin product page: https://www.knostic.ai/kirin
- Knostic pricing (install model, tiers): https://www.knostic.ai/pricing/
- Knostic coding agents use case: https://www.knostic.ai/coding-assistants-agents-mcp
- Knostic threat model blog: https://www.knostic.ai/blog/ai-coding-agent-security
- Third-party vendor wiki on Knostic: https://druce.ai/governance/wiki/vendors/knostic
- Cursor third-party hooks: https://cursor.com/docs/reference/third-party-hooks
