# Takeaways for comparing notes with Vidhi

Date: 2026-10-13. Short version of `01-opencomplai-vs-kirin.md` plus what the `aicl` prototype proved.

## The answers

1. **Opencomplai is not like Kirin.** Kirin is runtime security inside the coding agent (hooks, IDE
   extension, endpoint client). Opencomplai is an EU AI Act compliance gate that runs in CI.
   They answer different questions and do not overlap.
2. **Is it strong?** Its regulatory skeleton is strong: gap reports per article, Annex IV dossier
   drafts, signed artifacts, a hash-chained evidence ledger, a clean exit-code contract. Its detection
   is weak by its own benchmark: held-out recall is 33% on the intent path and 8% on the default scan.
   The LinkedIn demo catches `face_recognition` by dictionary lookup.
3. **Can we build a strong wrapper?** Yes, in the gap between the two products. The prototype shows it
   is buildable in one pass and without importing AGPL code.

## What the prototype proved (all offline, `make demo`, about 7 seconds)

- A Claude Code hook can enforce an agent's declared Opencomplai mandate at runtime and log every
  decision in Opencomplai's own decision-log format. `opencomplai agents verify-log` accepts the chain,
  flags exactly the blocked actions as out of mandate, and catches a one-byte tamper.
- That log moves Opencomplai's Art. 12 row from MISSING to PARTIAL. Art. 14 and 15 move to PARTIAL
  through `aicl init`. Caveat: Opencomplai's Art. 12 check only finds the file by path.
  Our own `aicl log verify` is what checks the content.
- A semantic classifier found something Opencomplai's Art. 5 rule did not flag in the declared purpose:
  inferring ethnicity from faces. Opencomplai did classify it high-risk under Art. 6. Calling it
  Art. 5(1)(g) prohibited is our interpretation and needs legal review.

## Things we learned the hard way

- An adversarial review found 34 real defects in the first version. They included regex backtracking that
  made the hook time out and fail open, `rm` flag-order bypasses, secrets missed by the redactor, log
  truncation that went unnoticed, and article mappings that overclaimed. All are fixed with regression
  tests (458 tests in total).
- Shell-command policy by pattern matching is an arms race. Kirin's hardest job is this layer, and it
  is where a funded team has a real edge.
- Never emit `permissionDecision: "allow"` from a Claude Code hook. It bypasses the user's own
  permission prompts.

## Open questions for the conversation

1. Which regime matters to her users first: EU AI Act only, or India DPDP alongside it?
2. Does she see buyers for "runtime evidence for Art. 12/14/15", or is security alone what sells?
3. Would she contribute upstream to Opencomplai (CLA allows them to relicense) or build alongside it?
4. Did she find the same detection weakness in her own use, or did her repos look different?
