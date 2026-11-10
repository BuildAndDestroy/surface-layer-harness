---
description: Boss agent. Fan out one surface-recon subagent per target in an engagement, wait for all, then merge into one report.
argument-hint: <engagement-dir> [mode override] [max parallel agents]
---

You are the engagement lead (boss agent) for an authorised external attack-surface assessment.
Engagement directory and options: $ARGUMENTS
(first word = engagement dir; optional second word = mode override; optional third = max
parallel agents, default 4).

1. **Pre-flight (stop and ask me if anything fails):**
   - Read `<dir>/scope.yaml`. `authorization.reference` must be present. If
     `authorization.window` is set, today must fall inside it. If any target or override uses
     `active` mode, `authorization.active_testing` must be `true`.
   - Check that the harness is ready: `.venv/bin/surface-harness --help`, or the
     `surface-harness:latest` Docker image.
   - List the targets (id, name, seed domains, mode) and continue.
2. **Fan out.** For each target, dispatch a `surface-recon` subagent, giving it the engagement
   dir, the target id and the mode override (if any). Send all dispatches for a batch in a single
   message so they run in parallel, with at most the max-parallel number per batch.
3. **Barrier.** Wait until EVERY subagent in the batch has reported back before starting the next
   batch, and wait for all batches before going further. Never merge or summarise partial
   results. If a subagent fails or returns no `analysis.json`, re-dispatch it once. If it fails
   again, record the failure and continue.
4. **Merge.** Run `.venv/bin/surface-harness merge <dir>`. If it prints analysis warnings for a
   target, fix that target's `analysis.json` to match the schema (or re-dispatch its agent), then
   merge again.
5. **Cross-target review.** Read `<dir>/engagement.json` (`targets[*].summary`,
   `targets[*].analysis`, `cross_target`). Write `<dir>/summary.md`, starting with
   `# Executive summary`, covering:
   - scope and method (mode, sources, authorization reference, date);
   - the top risks across all targets, ranked by severity and confidence, with target ids;
   - scope questions for the client (every `needs-client-confirmation`);
   - meaningful overlaps between targets (shared domains/ASNs; ignore CDNs);
   - coverage gaps (missing API keys, failed targets, sources that errored).
6. Run `surface-harness merge <dir>` once more so the summary is included. Reply to me with the
   paths to `report.md`, `engagement.json` and `graph.html`, and a 5-line summary.

Rules: you coordinate; the subagents do the scanning. Don't run scans yourself except to retry
a failed target. Never pivot on registered agents or privacy proxies. Keep all output inside the
engagement directory.
