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
