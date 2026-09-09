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


# Round 3 — review of proposal rev 3 (bus #11)

Verdict: **CHANGES_REQUESTED**. The architecture is converging: paired request/admission profile, uncached verification, independent expiry, and an observed-state dispatch invariant are accepted directions. No implementation or deployment approval is implied. Reviewed bytes are retained in evidence/critique/proposal-rev3-*.md.

## R3-1 — Retire unsupported timing claims throughout the document

Section 6 bounds each gating read by D, then claims the check-to-submit race itself is bounded by D. Those are different intervals: verification can finish, the goroutine can pause, and submission can occur later. Multiple reads also do not automatically share one aggregate D deadline. Define an aggregate verification deadline and a final expiry/generation check before submission; describe residual scheduling, in-flight and admission propagation limits without claiming a proved absolute bound. An invalidation observed during verification must not be overwritten by a late successful verification of older state. Keep the deterministic check/remove/submit interleaving test requested in round 2.

The <=32s reporting prediction needs an explicit refresh/expiry/status-update mechanism and bounded test conditions. It is presently a proposed target, not measured evidence. Section 10 B4 still promises 30s resync/60s staleness/zero stale dispatches; section 9 still says zero stale dispatches. Replace these contradictory summaries with the single section-6 contract and distinguish observed-invalid dispatch from unknown external changes.

## R3-2 — Finish the concrete security package

Section 5a still leaves the image as <DIGEST> and delegates resolution to the installer at SEC-1. The engineering proposal should supply a candidate digest/platform and inspected metadata before requesting approval, as requested in round 2. Specify command and args separately (args are currently not given), exact identity allowlist, and the treatment of other execution-affecting fields such as capabilities.add, envFrom and securityContext additions. The recommended fixed names in 5a conflict with section 5's name-prefix description; choose one reviewed rule.

The new debugger command sleeps for an hour instead of using the previous entrypoint. That is an explicit behavior/lifetime decision for SEC-1/P2, not merely attribution. Present the rationale and compatibility effect.

A shared singleton policy plus namespace selector does not by itself define which release's SA may operate in which namespace. State the identity-to-namespace mapping and out-of-scope behavior of the operator. The authorization snapshot proves only the queried direct permissions at that observation: it does not prove absence of all indirect privilege routes, nor every create/update/delete permission on policy and binding objects. Narrow the 'proven non-bypassable' wording accordingly; retain the concrete known namespace-write denials.

## R3-3 — Keep API outcomes attributable

Section 7 still equates an absent or Warn/Audit-only contract with overall API admission. Say 'this contract does not deny; other admission/authorization may reject'. Separate acceptance/rejection of a policy configuration write from evaluation errors during a workload request. Section 6 likewise cannot conclude the API admits merely because this VAP was removed.

## Three-round escalation / positions

Claude's position (message #11): rev3 addresses R1-R3 and is ready for convergence, followed by Mostafa's SEC-1/SEC-2/PO-1 decision record. My position: the architecture is acceptable, but the concrete profile and above claims remain unfinished; do not sign agreement yet.

The design runbook says: 'After three unresolved rounds, record both positions and seek a human ruling.' Recommended ruling: retain the current security scope and require one focused closure package addressing R3-1 through R3-3, then independent re-review. No broader redesign, weakened guarantee, implementation or live mutation is authorized by that recommendation. Engineering fact collection and preparing the already-required decision package can continue while the ruling is pending.


# Closure review — rev4 / bus #15

Verdict: **CHANGES_REQUESTED**. Architecture remains accepted; the below are concrete contract corrections within the existing scope. Claude reports Mehrdad approved this focused closure package; preserve the exact ruling reference in the decision record rather than treating that report as SEC-1/SEC-2/PO-1 approval. No product implementation is authorized by this review.

## C1 — Default command must still be constrained

Option A says the handler leaves debugger command unset and the VAP 'does not assert a command'. Those are different contracts. With the stated rule an allowed SA could submit name phorvex-debugger, the approved image/securityContext, but an arbitrary command/args. For the recommended behavior-preserving Option A, require BOTH command and args to be absent/empty for that name. For phorvex-custom require the exact paired command/args. Add an isolated negative test that changes only debugger command/args. This closes the existing requested command boundary; it does not change the handler's intended default behavior.

## C2 — Use a local invalidation epoch for overlapping checks and recovery

Section 6 forbids an older-or-equal generation from clearing the latch but then permits generation >= last observed; equality is contradictory. A timeout or TTL expiry can invalidate a perfectly unchanged policy, so requiring a larger Kubernetes object generation would prevent recovery until an administrator edits an otherwise valid object. Delete/recreate also changes object identity; policy, binding and namespace are separate objects, not one common generation clock.

Recommended precise rule: capture a process-local invalidation epoch at verification start. Any relevant invalidation increments it and clears eligibility. Publish success only if a complete authoritative verification passes and the epoch is still equal to the captured value under the same synchronization guard. A fresh verification STARTED AFTER invalidation may validate unchanged API objects; an older in-flight verification may not overwrite the invalidation. Retain UID/resourceVersion per object as evidence, not a cross-kind epoch. Test timeout then recovery without object edits, concurrent invalidation, delete/recreate, and final dispatch checking the current epoch/expiry. Preserve the acknowledged final-check-to-submit residual race.

Current Kubernetes documentation allows resourceVersion ordering for the SAME resource type under its stated version/format conditions; do not use an outdated blanket 'resourceVersions can never be ordered' claim, or order VAP/binding/namespace together. This is distinct from the required local invalidation epoch: https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions .

## C3 — Distinguish nonmatching API policy from operator permission to dispatch

For an unlabeled namespace, it is correct that this VAP does not match. It does NOT follow that Phorvex may dispatch there relying on RBAC alone: the ticket requires code-exec unavailable when its applicable admission contract is unverified. Explicitly make target-specific runtime capability false for an out-of-scope target while leaving unrelated human debug governed by its own controls. Test an allowed operator identity with existing RBAC against an unlabeled namespace: no operator dispatch, independently of whether a direct API dry-run is admitted elsewhere.

The one allowed deployed SA plus a boolean namespace selector is a single-manager contract; it does not distinguish multiple releases. Choose and document either an explicit single-manager installation limit or an actual installer-owned per-release identity/namespace mapping. Do not claim multiple-release isolation from the boolean selector alone. This choice belongs in the already-required PO-1/SEC-2 package.

## Registry evidence supplied / small factual corrections

Captured and verified linux/amd64 manifest digest:
`busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f`.
The image configuration has `Cmd:["sh"]`, with Entrypoint and User omitted. It does not set Entrypoint to sh, and an interactive/long-lived shell is not established with stdin/tty disabled. See evidence/baseline/busybox-1.36-amd64.json for index/config digests and capture method; no execution occurred. Use this concrete candidate in the decision package and keep runnability/efficacy as separate verification.

Kubernetes 1.36.2 is the observed cluster and proposed test target, not an already tested M6 implementation. Use 'targeted; L3 pending' until the new policy actually passes L3. Any additional allowed securityContext fields should be enumerated in the final profile; unspecified fields must not silently broaden it.

Next: proposer incorporates C1-C3 and the supplied registry evidence into the closure/decision package, preserving the existing security scope. This review is not a waiver or an instruction to begin implementation. The human security decisions remain open.
