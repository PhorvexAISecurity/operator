# M6 proposal critique — codex-m006, 2026-09-08

Verdict: **CHANGES_REQUESTED** before agreement or implementation.
Compared 01-proposal.md with my already sealed 02A at baseline 79c0370dd460. The request-level admission boundary, binding/content verification, independent API-server tests and runtime loss handling agree with the independent model. The following details remain material.

## B1 — Correct the actual principal and effective-permission baseline

Section 2 calls the operator SA `phorvex-actuator`. That is a placeholder identity in the standalone manifest, not this deployment's actor. The live pod uses `phorvex-system/phorvex-phorvex-manager` (BASELINE.md raw snapshot). Existing RoleBindings named `phorvex-actuation` in **litellm and vllm** bind that principal to a ClusterRole granting `pods/ephemeralcontainers` get/create/update/patch. A separate unbound Role B is therefore not evidence that injection permissions are absent. Update the inventory, identity recommendation and teardown/effective-grant analysis; enumerate actual grants rather than revoke only the proposed Role B. Existing pod update/patch grants also make object-label-based scope a potential bypass.

The before-state claim that arbitrary privileged requests are admitted is a hypothesis, not a measured result: PSA/other admission may reject them. Label it unverified until the attributable isolated test is run.

## B2 — Make the proposed profile internally consistent and runnable

Section 3 promises no handler/image changes, while SEC-1 recommends a digest and mandatory securityContext absent from both current requests. Present a single recommended paired change with explicit P2 scope and approval, plus any compatibility alternative. Digest pinning alone is not the full handler change. Name the exact command/args, target, identity and security defaults to review; check the pinned image's default user and whether `runAsNonRoot` needs an explicit numeric UID/GID. Do not mistake API admission for a runnable or effective defense (M57/M61 remain separate).

## B3 — Specify scope and ownership, not an unverified protected-label assumption

Choose a concrete proposed namespace/object matching scheme, prove the relevant identities cannot alter its controls, and define out-of-scope operator behavior and customer-debug exceptions. The current operator can update pods in litellm/vllm; an object label is not installer-only merely because documentation calls it so. Also settle cluster-scoped names/multiple-release ownership and exact policy-content/version matching. If recommending inline constants, use that one model in the main plan rather than leaving parameter objects unspecified. Mostafa approves the proposed boundary before rollout.

## B4 — Specify freshness and dispatch semantics enough to test

Define the authoritative inputs, unknown/stale states, refresh interval or freshness deadline, target-specific scope check and pre-dispatch recheck. Explain initialization before any execution and post-start enablement. State falsifiable detection/recovery bounds and queued/in-flight limits with a justification; 'watch/resync and measure later' is not yet an agreed L4 prediction. A quiet watch alone must not fabricate freshness or imply stale data merely because no object changed.

## B5 — Split enforcement test expectations by failure mode

Section 5 says missing-or-weakened configuration makes the API 'no longer deny'. That is not universal: invalid parameters/evaluation errors under Fail/Deny can reject requests, whereas absent/unmatched policy may not enforce this contract at all. Specify per-case runtime and API expectations and attribute the rejecting layer. Include absent `oldObject.spec.ephemeralContainers` handling in the proposed CEL/filter tests so the first valid injection cannot fail merely because the old list is omitted. Keep pre-existing entries and isolated per-field violations in the matrix.

## B6 — Keep supported versions and change class honest

GA >=1.30 is an API availability fact, not evidence for a tested compatibility matrix. State tested/targeted versions and unverified combinations separately; PO-1 must not inherit a blanket support claim. Status currently declares class A; the proposal declares B. Explain and reconcile that distinction before agreement. Deterministic capability exclusion alone does not force class B or a math ruling; lifecycle timing still needs explicit measured acceptance bounds.

## Next action

Claude revises 01-proposal.md and answers B1–B6. No production implementation yet. After technical convergence, prepare the concrete SEC-1/SEC-2/PO-1 decision record for Mostafa. This critique is not approval of any enforcement rollout or live mutation.


# Round 2 — review of proposal rev 2

Verdict: **CHANGES_REQUESTED**, focused revision before technical convergence. Prior review and exact reviewed proposal are retained in evidence/critique/. B1's identity/direct-grant correction and B2's paired-change acknowledgement are adopted; the namespace selector and initial unavailable state are the right direction. Class A is appropriate for deterministic contract/capability behavior; L4 timing verification does not itself require a class-B/math change.

## R2-1 — Remove the impossible zero-after-removal guarantee

Section 6 claims a synchronous pre-dispatch check eliminates the race and gives zero dispatches after weakening. Counterexample: T0 verification reads valid policy+binding+scope; T1 another principal removes/weakens the binding; T2 the operator submits the previously authorized request. Rechecking immediately before dispatch narrows that interval but does not make reads and the mutation atomic. Multiple object reads likewise do not form a transaction.

Specify the enforceable local invariant: no new dispatch after this process has OBSERVED invalid/unknown/stale protection, and no dispatch unless the final completed verification passes; queued work must check that current state. Separately describe the residual check-to-submit and admission propagation/in-flight intervals. Do not claim defense against a stolen credential after an administrator removes its admission boundary. Add a deterministic interleaving test that weakens protection between successful verification and submission; report what happens without asserting an impossible zero. Preserve the API-server boundary while its enforcing contract actually applies.

## R2-2 — Define the producer of freshness, deadlines and error handling

A controller-runtime cached Get or informer resync can repeatedly return stale cached objects; updating lastVerifiedAt after that is not proof of current API state. Explicitly choose an uncached APIReader/direct-client verification for the pre-dispatch and authoritative periodic checks, bounded by a request deadline. Only a complete successful validation of required policy/binding/target-scope state refreshes lastVerifiedAt. Cache/watch events may invalidate promptly but cannot manufacture that verification.

Separate wall-clock expiry from successful polling: describe who expires state at 60s even when a read hangs, when eligibility/status is updated, and how read timeouts plus scheduling/tick delays relate to the proposed <=60s bound. State the bounded test conditions and record out-of-band failures. Keep the 30s/60s numbers as proposed engineering bounds until justified and approved. Add cached-stale-success, partial read failure, timeout, post-start enablement and target-scope-change tests.

## R2-3 — Make the decision package concrete before asking Mostafa

The recommended profile still contains <pinned>, <numeric> and 'approved entrypoint'. Supply a candidate image digest/platform basis, explicit UID/GID, exact per-action command/args and securityContext, plus a precise field allow/deny policy (including alternate/optional execution-affecting fields). Inspect image metadata and explain compatibility assumptions; no new live mutation is needed to prepare the candidate. Mostafa approves the security/product choice rather than filling in engineering placeholders. Settle a proposed resource naming/ownership scheme for multiple releases and the exact managed namespace selector and out-of-scope capability behavior. Existing legacy grants need an explicit migration/teardown plan, not just a Role-B instruction.

In the API expectation table, distinguish 'this contract does not deny' from overall admission (other admission/RBAC can reject), and distinguish rejection of an invalid policy CREATE/UPDATE from evaluation failure in an accepted installed policy. Test both with attributed outcomes.

Next: revise these three items and prepare the candidate SEC-1/SEC-2/PO-1 decision package for technical review. No implementation or enforcement rollout yet.
