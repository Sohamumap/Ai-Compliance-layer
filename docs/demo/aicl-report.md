# aicl compliance report

System `shopper-insights` | repo `<demo-workdir>/shopper-insights` | manifest `<demo-workdir>/shopper-insights/system-manifest.json` | generated 2026-10-14T09:07:41+00:00 | aicl 0.1.0 | opencomplai 0.12.0

## Verdict

**FAIL**

- opencomplai check exit 1 (control_fail)
- prohibited finding: segment_shoppers Art. 5(1)(g)
- declaration gap: code prohibited > declared minimal

## Gate (opencomplai check)

- exit 1 (control_fail), result `control_fail`
- failed controls: CODE_CORROBORATION_GAP
- scan severity: major; detected categories: biometric; discrepancies: biometric
- artifact: `<demo-workdir>/shopper-insights/compliance-artifact.json`; scan report: `<demo-workdir>/shopper-insights/scan-report.json`

## Semantic classification (aicl)

Deterministic heuristic (aicl): code tier **prohibited**, declared tier **minimal**, declaration gap: yes. 1 file(s), 4 unit(s) scanned.

| file:line | symbol | tier | article | evidence | confidence | source |
|---|---|---|---|---|---|---|
| src/insights.py:12 | summarise_sales | limited | Art. 50(1) | anthropic, chat, messages, dashboard, reply | 0.50 | aicl-deterministic |
| src/insights.py:20 | segment_shoppers | prohibited | Art. 5(1)(g) | face, face_encodings, face_recognition, ethnicity | 0.85 | aicl-deterministic |

## Opencomplai said / aicl said

|  | Opencomplai said | aicl said |
|---|---|---|
| Gate | exit 1 control_fail [CODE_CORROBORATION_GAP] | FAIL |
| Risk signal | scan severity major; categories biometric | code tier prohibited (segment_shoppers Art. 5(1)(g)) |
| Declared vs. code | discrepancies: biometric | declared minimal vs. code prohibited (gap: yes) |
| Art. 5 | unverified (Obligation 'Prohibited AI practices' applies; no automated verification run.) | segment_shoppers Art. 5(1)(g) |
| Decision log | log_entries 7, chain_valid True | local chain ok, count 7 |

## Runtime evidence (agent decision log)

- log: head `sha256:bbaa62077b4108384aa4325d16a29339543eb70dc380539f0295140f195bddd6` count 7
- local chain (aicl, against the anchor): ok
- anchor `.aicl/log-anchor.json`: ok (head `sha256:bbaa62077b4108384aa4325d16a29339543eb70dc380539f0295140f195bddd6` count 7)
- Opencomplai chain (agents verify-log, exit 1 invalid): ok, count 7
- artifact head matches local head

Decision log entries:

| seq | tool | outcome | intent |
|---|---|---|---|
| 1 | Edit | success | Edit: src/insights.py \| aicl:allow:ok |
| 2 | Bash | blocked | Bash: rm (2 args): Delete cached data \| aicl:deny:destructive_shell |
| 3 | Bash | blocked | Bash: curl (3 args): <redacted:anthropic_key> \| aicl:deny:secret_in_input |
| 4 | WebFetch | blocked | WebFetch: example.com \| aicl:deny:tool_prohibited |
| 5 | mcp__github__create_issue | blocked | MCP: github.create_issue \| aicl:deny:mcp_server_not_allowed |
| 6 | Bash | success | [approved by human] Bash: curl (2 args): Fetch competitor pricing page \| aicl:ask:network_egress |
| 7 | Edit | blocked | Edit: .claude/settings.json \| aicl:deny:self_protect |

Out-of-mandate entries (Opencomplai agents verify-log):

| seq | tool | reasons |
|---|---|---|
| 2 | Bash | self_reported |
| 3 | Bash | self_reported |
| 4 | WebFetch | prohibited_action, not_permitted, self_reported |
| 5 | mcp__github__create_issue | tool_not_declared, not_permitted, self_reported |
| 7 | Edit | self_reported |

every out-of-mandate seq was blocked: yes (out_of_mandate ⊆ blocked)

opencomplai agents verify-log exits 1 whenever blocked entries exist; that is the expected signal, not a failure of the log.

Unresolved asks (pending > 10 min): 0

## Article status (5, 6, 12, 14, 15, 26, 50)

| article | status | source | evidence_ref | rationale |
|---|---|---|---|---|
| Art. 5 | unverified | obligation | prohibited | Obligation 'Prohibited AI practices' applies; no automated verification run. |
| Art. 6 | missing | scan | find_sha256:330206d6ad0638537b35604109143d0480eee9c76c655b63edd3a4d6c1faf38f | Scan detected 'biometric' evidence mapping to biometric, not reflected in the declared manifest purpose (1 finding(s)). |
| Art. 12 | partial | artifact | agent-log.jsonl | Found candidate artifact/signal for 'event_log_evidence' (1 path(s), 0 code hint(s)). Heuristic only — not a full obligation assessment. |
| Art. 14 | partial | artifact | docs/human_oversight.md | Found candidate artifact/signal for 'human_oversight_construct' (1 path(s), 0 code hint(s)). Heuristic only — not a full obligation assessment. |
| Art. 15 | partial | manifest | manifest:agent_declarations | Agent inventory declared in the manifest: 1 agent(s), 6 tool(s), 1 requiring approval. Detected but not declared: none. Declared but not detected: agent framew… |
| Art. 26 | missing | artifact | deployer_use_records | No conventional documentation/code probe matched for 'deployer_use_records'. Add the expected file or construct, then re-run gaps. |
| Art. 50 | missing | artifact | transparency_notice_evidence | No conventional documentation/code probe matched for 'transparency_notice_evidence'. Add the expected file or construct, then re-run gaps. |

## Remediation

Manifest patch sets intended_purpose, high_risk_presumption, known_limitations; 1 code action(s). 1 prohibited finding(s) cannot be cured by declaration; the code must change.

Patch keys: intended_purpose, high_risk_presumption, known_limitations

- Remove or disable segment_shoppers (src/insights.py:20): Biometric categorisation inferring sensitive attributes — Art. 5(1)(g).

Files: `aicl-remediation.patch.json`, `aicl-remediation.md`, `system-manifest.proposed.json` (the original manifest is never modified).

Prohibited findings cannot be cured by declaration; the code must change.

## Judge

Judge: skipped (mode=off; deterministic classification only)

## Reproduce

```
/home/user/Ai-Compliance-layer/.venv/bin/opencomplai check -m <demo-workdir>/shopper-insights/system-manifest.json --scan --repo-root <demo-workdir>/shopper-insights --with-gaps --fail-on major --no-emit-evidence --output json
/home/user/Ai-Compliance-layer/.venv/bin/opencomplai agents verify-log <demo-workdir>/shopper-insights/agent-log.jsonl -m <demo-workdir>/shopper-insights/system-manifest.json -o json --expected-head sha256:bbaa62077b4108384aa4325d16a29339543eb70dc380539f0295140f195bddd6 --expected-count 7
```

## Disclaimer

Heuristic evidence, not legal advice.
