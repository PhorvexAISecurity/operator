# Phorvex Rev5 agentic workflow handoff

Version 1.0, 13 October 2026. This package defines a portable orchestration protocol for Claude Code, Cursor, Codex, or another harness. It includes the boss's complete Rev5 source package, agent prompts, task and tool contracts, a detailed progress register, and a working local register utility. The experiment adapters and distributed scheduler are implementation contracts, not installed services. A preliminary live diagnostic was recorded on 14 October 2026; no full campaign has been accepted. Read `PILOT-LESSONS.md` for its operational findings and remaining requirements.

The objective is to select reviewed attacker end states applicable to a customer cluster, establish them on an isolated twin, let the unchanged Phorvex brain decide, measure defense and availability, challenge successful defenses, and report the tested scope. Eligible gaps produce actuator specifications for engineering. Customer application source code and application repair are outside the verification loop.

## Begin here

Treat this directory as `PACKAGE_ROOT`. All paths below are relative to it. Move or copy the whole directory to another machine; no historical conversation or private path on the original server is needed.

1. Read `AGENTS.md`, `ARCHITECTURE.md`, `WORKFLOW.md`, `PROGRESS-FORMAT.md`, and `HANDOFF-CONTRACTS.md`, then [PILOT-LESSONS.md](PILOT-LESSONS.md). In Codex, also read `CODEX-ADAPTER.md`; it contains the actual subagent dispatch procedure.
2. Read `source/rev5/HANDOFF-README.md`, the architecture DOCX, and workstreams WS1–WS8. `source/rev5/architecture-docx-extracted.txt` is a reading aid containing paragraphs and tables; retain the DOCX as the source. `SOURCE-MAP.md` records precedence and known ambiguities.
3. Run `python3 tools/check_package.py`. This validates local package structure, source hashes, templates, and examples. It does not contact a cluster.
4. Copy `templates/campaign.json` into a new private run directory, then fill its inputs from the owner's instructions and available connection configuration. Never copy credential values into the manifest. Record missing required inputs rather than guessing a cluster, twin, or authorization.
5. Run `python3 tools/progress.py init --db RUN/progress.sqlite --campaign RUN/campaign.json`. This creates an empty campaign, not fictitious cases. Run `python3 tools/progress.py render --db RUN/progress.sqlite --out RUN/report` to generate the initial report.
6. Assign the current harness session as `ORCHESTRATOR`. Load `prompts/COMMON.md` and `prompts/ORCHESTRATOR.md`. Perform S0 preflight and tool-capability discovery before launching execution tasks. Use `templates/task.json` for every real assignment.
7. Start independent workers only for ready tasks, using their role prompts. Record actual harness session/job IDs, models, and parent task IDs. If subagent execution is unavailable, report the limitation and use sequential independent sessions; never label personas written by one session as independent agents.
8. Continue through the graph. A missing adapter creates a bounded engineering handoff and an explicit blocker, while ready independent work continues. Do not replace a missing adapter with fabricated receipts, an invented attack, or a customer-service repair.

`RUN` above is a path chosen for this new campaign. Commands do not imply a directory named literally `RUN` already exists. Examples in `examples/` are synthetic demonstrations, never initial production data.

## Inputs the harness must bind

| Input | Required meaning |
| --- | --- |
| Owner scope | Scope reference and allowed actions; distinguish documentation, scan, twin execution, and engineering delivery |
| Customer connection | Explicit cluster identity and read-only credential reference; inspect configured contexts without printing secret material |
| Twin connection | Distinct experiment identity, permitted resources, cleanup owner, and isolation limits |
| Phorvex checkout | Repository and immutable revision for inspecting contracts; customer application repositories are not inputs |
| Library admission | Library hash/version, named scope/math review (`library_review_ref`), separate build-time framework refresh (`library_refresh_ref`), and approved fixture-template subset |
| Acceptance profile | Phase 1 or full measurements, availability requirements, hold window, challenge scope, and reproducibility obligations |
| Parallelism, budgets and roster | Primary `case_parallelism` C; supporting maximum active agents N including root, actual harness cap, physical experiments E, provider/token/spend budgets, resource limits, and approved proposer/critic model roster with diversity status |
| Adapters | Real commands/API bindings satisfying `TOOL-CONTRACTS.md`, with identity checks and observed availability |

If these exist in the current session or environment, reuse them after checking identity. Do not repeatedly ask for already supplied authorization. If one is absent, complete independent local planning and request only that missing input. This document grants no new cluster or deployment authority.

## Starting message for another harness

```text
Act as the orchestrator for the Phorvex Rev5 verification workflow in this
directory. Read START-HERE.md and follow its reading and startup sequence.
Use the bundled boss Rev5 sources as authority and the role prompts as your
operating contracts. Apply PILOT-LESSONS.md to tool discovery and blockers.
Preserve the frozen brain, reviewed library, read-only customer scan, isolated
twin, independent reviews, and measured gates.

Discover the available adapters and bind the campaign manifest from my scope
and connection configuration. Start with preflight; do not invent missing
execution tools or treat example records as evidence. Use real subagents for
ready role tasks across at most case_parallelism ACTIVE case workflows, within
max_active_agents and the actual harness cap. Record real job IDs; park blocked
cases only after operation reconciliation and preserve resource reservations.
Update the transactional case register at every transition and meaningful
result. Keep blockers, accepted milestone completion, gates, engineering work,
PR/deployment/retest history, and last substantive evidence visible.

Continue ready work without waiting for routine confirmation. Route genuine
missing scope, tools, or engineering dependencies explicitly. Do not repair
customer applications, author new attacks, alter the brain during the loop,
or claim simulated effects as physical defense. Never add Co-authored-by or
equivalent assistant attribution to commits.
```

The owner should append the campaign scope, connection references, case_parallelism, supporting agent/experiment budgets, and intended total case count. Total case count is the cohort size; it is not the concurrency setting. For documentation-only work, keep `mode` as `PLAN`; do not start a cluster experiment.

## Package navigation

- `ARCHITECTURE.md`: roles, authority, shared state, scalability, and independence.
- `WORKFLOW.md`: stages, admission conditions, outputs, failure routes, and closure.
- `PROGRESS-FORMAT.md`: overview, case detail, milestone arithmetic, evidence, history, and update protocol.
- `TOOL-CONTRACTS.md`: tool I/O, execution restrictions, recovery, and adapter binding.
- `HANDOFF-CONTRACTS.md`: typed task/return envelopes and per-role output requirements.
- `CODEX-ADAPTER.md`: concrete Codex dispatch, identity, capacity, and independent-review procedure.
- `REVIEW.md`: review findings, corrections, local validation, and remaining implementation limits.
- [PILOT-LESSONS.md](PILOT-LESSONS.md): actual pilot blockers, startup remedies, ownership and evidence needed to close them.
- `prompts/`: common contract and nine role-specific prompts.
- `templates/`: campaign, task, case, and milestone templates.
- `schemas/`: machine-readable case, task, and return structure.
- `tools/`: local progress store/renderer and package checker. Python 3.10+ standard library only.
- `examples/`: synthetic reports illustrating progress and failure; not accepted workflow results.
- `source/`: the complete Rev5 source material and checksum manifest.

The local register supports transactional updates from multiple processes on one machine. Hundreds of distributed agents require a shared transactional service and resource gateway as described in the architecture. No scale, physical defense, or isolation claim follows from passing the package checks.
