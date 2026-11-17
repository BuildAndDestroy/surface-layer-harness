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
   - List the targets (id, name, seed domains, mode).
   - **Tool check (ask me).** Run `.venv/bin/surface-harness doctor <dir> --json`. If
     `coverage_gaps` is not empty, show me a short table (priority, tool, what is lost without
     it, what it needs) and ask me with AskUserQuestion (multiSelect) which gaps to close before
     the run: the highest-priority gaps as options (max 4; mention the rest in the question), plus
     "Proceed with current coverage". Then:
     - API keys: tell me the env var to export in the shell that launches Claude Code (or a
       git-ignored `.env` I source), then restart. Never ask me to paste a key into the chat, and
       never write keys into `scope.yaml` or any file.
     - Binaries: offer `make tools-image` (or the install link); run it only if I say so.
     - Active mode: only I can change `authorization.active_testing`, after the client's written
       authorization. Never edit the `authorization` block yourself.
     - Re-run `doctor` after changes. Gaps I accept go into summary.md's coverage gaps.
2. **Fan out.** First create this run's directory: `.venv/bin/surface-harness new-run <dir>`
   prints it (`<dir>/<YYYYMMDD-HHMMSS>`, called `<run>` below). Every run gets its own, so
   nothing from an earlier run is overwritten; all output of this run goes under `<run>/`.
   For each target, dispatch a `surface-recon` subagent, giving it the engagement dir, `<run>`,
   the target id and the mode override (if any). Send all dispatches for a batch in a single
   message so they run in parallel, with at most the max-parallel number per batch.
3. **Barrier.** Wait until EVERY subagent in the batch has reported back before starting the next
   batch, and wait for all batches before going further. Never merge or summarise partial
   results. If a subagent fails or returns no `analysis.json`, re-dispatch it once. If it fails
   again, record the failure and continue.
   **Kill-switch:** if a target ended with status `killed`, the harness stopped because an
   uncleared (possibly third-party) host was about to be contacted. Never re-dispatch it and
   never edit scope.yaml to get past it. Show me the reason and the "Third-party domains not
   touched" list, and ask me what to do: only I add domains or excludes to scope.yaml.
4. **Merge.** Run `.venv/bin/surface-harness merge <run>`. If it prints analysis warnings for a
   target, fix that target's `analysis.json` to match the schema (or re-dispatch its agent), then
   merge again.
5. **Cross-target review.** Read `<run>/engagement.json` (`targets[*].summary`,
   `targets[*].analysis`, `cross_target`). Write `<run>/summary.md`, starting with
   `# Executive summary`, covering:
   - scope and method (mode, sources, authorization reference, date);
   - the top risks across all targets, ranked by severity and confidence, with target ids;
   - scope questions for the client (every `needs-client-confirmation`), and the third-party
     domains the kill-switch held back (`targets[*].surface.meta.third_party_blocked`);
   - meaningful overlaps between targets (shared domains/ASNs; ignore CDNs);
   - coverage gaps (missing API keys, failed targets, sources that errored);
   - `## Recommended tools`: the high and medium entries of `engagement.json →
     tool_recommendations` (harness coverage gaps first, then complementary tools), one line each:
     tool, which targets, why, and what it needs (key, client access, or authorization). The full
     table is already in report.md, so keep this short.
6. Run `surface-harness merge <run>` once more so the summary is included.
7. **Tool checkpoint (ask me).** Ask me with AskUserQuestion (multiSelect) which recommended
   tools to pursue next: the top recommendations by priority as options (max 4), each labelled
   with what it needs, plus "None for now". Then:
   - Coverage gaps I close (keys, binaries, active mode): offer to re-dispatch the affected
     targets' subagents and re-merge.
   - Complementary tools are outside the harness and outside the subagents' rules of engagement.
     Don't run one unless I explicitly approve it here *and* the authorization covers its traffic
     (nuclei, katana, Burp/ZAP need written authorization for vulnerability/application testing;
     Prowler/ScoutSuite/Maester/ScubaGear need client-issued read-only access). Approved runs keep
     their output in `<run>/tools/<tool>/`.
   - Record what I chose (and declined) under `## Agreed next steps` in summary.md, then merge.
8. Reply to me with the paths to `<run>/report.html` (the work queue: what to do about each
   finding), `report.md`, `engagement.json` and `graph.html`, and a 5-line summary.

Rules: you coordinate; the subagents do the scanning. You are the only one who asks me about
tools: subagents report tool needs to you, and you never install tools or enable keys without me. Don't run scans yourself except to retry
a failed target. Never pivot on registered agents or privacy proxies. Never send anything to a
third party (customers, tenants, vendors): a redirect, shared certificate or link is not
ownership. Keep all output inside this run's directory.
