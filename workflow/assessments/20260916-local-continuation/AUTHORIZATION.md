# Local continuation authorization — September16

The owner explicitly instructed the lead to continue through the remaining tiers without opening any PRs, pausing only where live verification is critical enough to prevent sound further implementation. This supersedes routine per-tier publication/deployment barriers for this run. It changes scheduling and delivery, not evidence or closure requirements.

Continue from the complete reviewed Tier8 source and current main release configuration. Keep local issue branches, independent lead/worker review and one combined local branch per tier. Run meaningful local API/HTTP/controller and regression controls, then integrate and continue with the next unblocked tier. Do not open new PRs or push these local tiers to remote CI. Existing PR220 is left as published and its deployment remains separately tracked. Publication can resume only on a later user instruction.

Use the assigned GPT5.6 Sol high workers; the lead investigates/signs plans, workers implement and the lead reviews. Never add Co-authored-by or equivalent assistant attribution to commits; relay that rule to workers. Serialize heavy Go/API/full-preflight work on this host.

A live prerequisite blocks dependent source work only when a concrete unanswered deployed/hardware/serving question changes the correct contract, invariant or implementation and cannot be bounded honestly with current source plus local controls. Record the exact missing observation, why local tests cannot establish it, affected dependencies, and the smallest real control needed. Continue independent issues/tiers when such a dependency is isolated; pause the overall run only if no authorized useful independent work remains. Ordinary merge/deploy lag, absent CI administration, historical OPEN labels or missing closure-only L3 do not justify stopping source work.

All unverified behavior remains in the central live backlog. Source-reviewed/local-ready is not deployed, live-verified, closed, risk-accepted or production-approved. Preserve existing source residuals and research questions, including M92. Five-minute read-only deployment monitoring and the combined Tier6–8 live plan remain active. DevOps still owns merge/deployment, runners, RBAC, global brakes and shared infrastructure; no shared mutation is added by this instruction.

The owner also requested unused-directory cleanup. Retire fully integrated, inactive worktrees as the run advances, preserving branches, unique work and evidence; consult CLEANUP.md.

## September17 publication update — current authority

The owner instructed: “keep publishing the PRs. and always set main as target so we don't have to open a separate one. it doesn't matter if the PRs show the diff for all previous unmerged tiers”.

Publish each completed, independently reviewed and composition-tested tier as one PR with base `main`. Push the combined tier branch; cumulative changes from earlier unmerged tiers are explicitly accepted. Do not target another tier branch, create a second delivery PR, or publish individual worker issue branches. The lead owns publication; worker branches remain local until integrated.

This supersedes the earlier no-push/no-PR restriction. Continue independent source work while deployment and closure-only live acceptance lag, as already authorized. Preserve real live-critical dependencies, all evidence requirements and production HOLD. No merge, deployment, shared infrastructure change or evidence waiver is authorized. Never add coauthor or AI attribution to commits.

## September18 owner checkpoint — live verification after Tier14

Latest direct instruction: finish Tier14, then properly verify the previously deployed/unverified tiers before proceeding to Tier15. This supersedes the earlier permission to keep advancing source tiers without an ordinary live checkpoint. Finish/review/publish the combined Tier14 PR to main; then prioritize the accumulated issue-specific live acceptance matrix and actual deployed source/digests. Do not start Tier15 or later implementation during that checkpoint. Preserve per-issue positive, negative, recovery and cleanup evidence; healthy rollout or a quiet observation window cannot stand in for these controls. Missing fixtures/hardware and deployment gaps remain explicitly unverified. Existing DevOps ownership and no shared infrastructure mutation remain unchanged.

## September19 owner update — finish possible live reads, continue remaining tiers

The owner reports DevOps is temporarily unavailable and explicitly instructs: do the remaining live verification possible now, then start the next tiers; write down every unverified live behavior and the required DevOps changes, and resume dependent live controls when the owner reports readiness.

This supersedes the September18 blanket checkpoint barrier before Tier15. Complete the available read-only controls and record their exact limits, then continue independent source investigation, fixes, review and one combined PR per tier targeting main. Reconcile historical tiers against actual current code; do not duplicate already delivered fixes or manufacture a code PR for an empty tier. Preserve local issue branches and assemble each nonempty tier from its complete reviewed predecessor plus current main.

The central LIVE-VERIFICATION-BACKLOG.md and the dated DEVOPS-PENDING.md handoff retain untested issue arms, component deployment/provenance gaps, fixture scope, credentials/hardware, required operations, owner and evidence needed. Later source delivery never upgrades these to live PASS or production approval. A concrete live prerequisite still blocks source work that cannot be designed correctly without it; continue unrelated work. This changes scheduling, not safety or evidence standards.

No merge, deployment, shared cluster mutation, fixture creation, restart, failure injection, credential replay or global brake change is newly authorized. The existing read-only monitor remains active. The lead owns technical compatibility and source investigations; DevOps owns deployment/resource/identity and fixture provisioning. Use existing Sol workers, one heavy local validation at a time, and no coauthor/assistant commit attribution.
