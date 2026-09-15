# Assess and fix a repository in parallel tiers

Use this runbook when the user requests a fresh assessment, reconciliation of the
master register, and multiple parallel fixes through reviewed PR delivery. It
extends ASSESSMENT.md and FIX.md; it does not replace their evidence requirements.

## Assess current reality

Pin freshly fetched main and separately observe the deployed image, digest and
source. Inventory shipping components and executable test/catalogue coverage.
Assign independent fresh investigations before comparing with historical issue
bodies. Reconcile every existing issue against actual code and tests: valid,
already fixed in source but awaiting live verification, verified closed,
superseded/duplicate, contradicted, or unresolved. Keep evidence for each
disposition. An old OPEN label does not prove a defect or a dependency blocker.

Review new findings, register confirmed root causes through the intake/issue
tools, and retain rejected candidates and untested surfaces. Catalogue review
must cover the executable stimulus, oracle, baseline/controls, action attribution,
realism, permissions, capabilities and cleanup; a descriptive scenario name is
not executable coverage. A broken test oracle is a fixable issue, not evidence
that the product defended or failed to defend an attack.

## Form implementation tiers

Build dependencies from current producer/consumer contracts and test evidence.
Separate severity from dependency order. Include shared files, configuration,
schema and deployment compatibility when deciding what can run in parallel.
Record prerequisite fixes already present on main and PRs already in progress.
Never duplicate a colleague's pending fix or infer an unsatisfied dependency
only from the master register.

Each tier's record includes source baseline, member issue/fix IDs, dependencies,
worker identities/worktrees, shared-file conflicts, lead decisions, review and
validation artifacts, PR URL/head, CI state, and a live acceptance experiment.
Refresh source and re-evaluate dependencies before allocating a new tier. Use one
implementation worker per fix and cap concurrency to available resources; a
tier may contain more fixes than can run simultaneously.

The lead investigates and signs each fix plan. The worker implements; the lead
independently reviews and requests corrections until accepted. A worker's final
message is a submission, never self-approval. Automatic worker launch is allowed
only within the user's delegation scope. Never add co-author or AI attribution
to commits; convey this requirement in every worker assignment.

## Campaign delivery packaging

For the current readiness campaign, the user changed packaging on2026-09-13:
Tier2 retains its existing issue PRs; from Tier3 onward publish one PR per tier,
with local issue branches merged into a local tierN branch after all issue fixes
are complete. Commit count is unrestricted; preserve reviewed branch history.
Workers may still implement in parallel, but do not
open individual issue PRs for those later tiers. Independently accept each issue,
assemble its changes into the tier branch and test the complete composition
before publishing. Preserve original evidence/source provenance and verify
consolidation equivalence; never rewrite attestations to invented source pins.
Keep issue-specific live acceptance even though publication uses one shared PR.
See assessments/20260913-tier2/TIER-DELIVERY-POLICY.md for the recorded instruction.

## Stop at the deployment barrier

When every member is independently reviewed and its issue PR or shared tier PR
has required checks passing (or explicitly identified infrastructure blockers),
deliver the complete tier publication and mark the
tier WAITING_FOR_DEPLOYMENT. Open PRs with blocked required checks are not
represented as merge-ready. Do not start the next tier's implementation.
The user and DevOps retain merge/deployment ownership. Do not merge, deploy,
change ArgoCD settings or update shared infrastructure to unblock the process.

CI account, billing, runner and pipeline administration belong to DevOps. Record
missing CI execution honestly and hand the concrete diagnostic to that owner;
continue source review, appropriate local tests and live controls that do not
depend on it. An infrastructure job failure is not a product-test failure and
must not become a blanket reason to stop the agent's independent work. Do not
ask the user to debug CI or represent missing test execution as a pass.

When the user reports deployment, observe the actual deployed identities and
verify every member's acceptance conditions, including relevant regression and
composition tests. Main/merge status and a matching image tag alone do not prove
the fix is live. Reuse existing bounded live-test authorization; otherwise
prepare concrete scope and request only the additional action needed.

Failed verification keeps the current tier open for repair. Missing hardware or
other untested conditions stay explicit; they are not passing evidence. Only
after every member is live-verified may the lead mark the tier VERIFIED and
begin the next tier's fixes.

For this campaign, the owner's September 15 instruction explicitly allows Tier3
implementation while unavailable Tier1/2 live controls remain pending. See
assessments/20260915-tier3/AUTHORIZATION.md. This changes scheduling for Tier3
only; it grants no live evidence waiver or shared deployment authority.

## Durable handover and final evidence

Persist assessment coverage, source/deployment pins, issue reconciliation, the
tier graph and current barrier alongside the normal fix records. Keep worker
runtime/session data in the Git common directory, not tracked evidence. Resume
exact assigned workers rather than guessing the latest session. Worker failures
or permission denials must be visible; do not silently replay ambiguous actions.

Completion means all validated issues in the agreed scope have reviewed fixes
and successful live acceptance evidence, with all coverage gaps and accepted
exceptions stated. Never promise a provably bug-free codebase. Prepare a concise
due-diligence index linking claims to reproducible evidence and residual limits.
