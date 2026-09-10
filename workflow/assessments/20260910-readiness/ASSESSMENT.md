# Readiness assessment and tiered remediation

- Status: INVESTIGATING_AND_OBSERVING_LIVE; V3 draft assembled, synthesis/tier review and sustained live analysis pending.
- Authorization: user's 2026-09-10 request to reconcile all existing issues against actual code, independently find missing defects, improve the attack catalogue, launch Claude workers automatically, and deliver parallel tiers of reviewed PRs. Stop after each tier's complete PR set; resume after all are merged and deployed and independently verified live.
- Lead: codex-lead, current GPT-6 session; exact Astra variant is not independently exposed. Prior request mentioned Astra; do not mislabel a worker or configured model as Astra.
- Workers: new explicitly assigned Claude CLI sessions; identities, actual model, source, results and review recorded per assignment. Existing M-18/M-21/M-79 sessions retain their assignments.
- Initial source: PhorvexSecurity/operator dbf5fa4321b3 (resolve full SHA in evidence/source.json). Always refresh main before allocating an implementation tier.
- Deployment: earlier observations captured v0.4.108 then v0.4.109. Fresh live decision claims/traces at18:50–18:54 independently identify dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca on0.4.109; observed manager digest sha256:e384b100ddef9bc611971dbea1337ec43a994a36188671aced3b4355aa9470df. No PHORVEX_GIT_SHA/envFrom override in the manager Pod. Main alone is not deployment evidence; per-fix live acceptance still remains separate.
- Scope: shipping Go operator/engines, API/CRD/configuration, all actuators and routed backends, charts/RBAC, dashboard/API, detector/controller integrations, tests, and workflow attack catalogue plus executable scenarios. Audit mathematical correctness and assumptions; defer elective mathematical optimization to later research.
- Environment: local isolated worktrees and tests; read-only dev-cluster observations. DevOps owns deployment. Merge and live mutations are not authorized by this assessment's broad request. Prepare bounded verification experiments before any mutation-dependent work.
- Resource policy: at most three new Claude workers concurrently initially; limit Go compilation concurrency on this 8 GB host. Reassess if memory or subscription limits intervene. Do not disturb existing interactive workers.
- Model policy: user now requires explicit Claude Opus 5 with maximum reasoning on new jobs and resumes; see MODEL-POLICY.md for retained pre-change provenance.
- Architecture plan: refresh the source-derived anatomy as a v3 assessment snapshot and review its issue/contract dependency joins before finalizing tiers; see ANATOMY-V3-PLAN.md. Canonical deployed anatomy remains separately pinned.
- Prior exposure: lead has reviewed historical M-140/M-18/M-21/M-79 context. Fresh investigators must first inspect source/tests without historical issue bodies; preserve and hash that pass before reconciliation.
- Existing deliveries: PR #170 M-21 and #171 M-18 are open and must be reconciled rather than duplicated. M-79 prerequisite claims require fresh source checks. M-140 is merged; live verification remains pending.
- Completion claim: no known unresolved defects within explicitly assessed coverage, backed by source, tests and live evidence. Never assert that software is provably free of all bugs. Unknowns, missing hardware, untested scenarios, and accepted risk remain visible.
- Next action: analyze sustained live campaign2026-09-10-v3-observe (started18:55:42UTC for60 minutes), incorporate live findings, independently review Master Issues V3/Anatomy V3 and finalize tiers. Continue first-tier implementation review. Claude quota reset resumes exact workers at20:00:15UTC; no fallback model.

The owner re-emphasized on2026-09-10 that sustained live observation must help
**discover** issues, in addition to post-deployment fix acceptance. This is a
required assessment phase, not optional follow-up. Read-only collection and
its controls are in LIVE-OBSERVATION-PLAN.md and the linked campaign. V3 cannot
be called final solely from static reconciliation.

## Tier barrier

A tier contains independently implementable fixes after predecessors are verified, with explicit shared-file and semantic compatibility checks. Priority labels alone do not determine concurrency. Every fix has a lead-signed plan, one implementation worker, independent review and meaningful validation. Deliver all reviewed PRs for the tier, record URLs/source heads/CI status/live acceptance plans, then enter WAITING_FOR_DEPLOYMENT. No next-tier implementation starts at that barrier. Upon the user's deployment notice, observe actual image/digest/source and verify all affected fixes. A failed or incomplete verification keeps the barrier closed and creates a repair task in the current tier.

## Durable records

- ASSESSMENT.md: scope, phase and handover.
- COVERAGE.md: every shipping component and catalogue case, test/evidence, reviewer disposition and remaining gap.
- findings/: fresh candidates and independent challenges, frozen before historical reconciliation.
- reconciliation/: every existing M-ID with current-source disposition and references.
- tiers.json: dependency graph, assignments, PRs and live verification barrier (created after validated findings).
- evidence/: source/deployment pins, raw observations and hashes.

Canonical issue/fix states remain governed by existing workflow tools. A worker finishing a CLI turn is a submission, never a passing review or a closed issue.
