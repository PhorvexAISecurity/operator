# Role handoffs

Commands are `python3 workflow/tools/workflow.py …`. Run from the issue's own
worktree. Evidence files live in its fix directory; do not paste logs into bus messages.

## Implementer

In the lead/worker loop, implement the lead's signed `03-decision.md` after AGREED.
Report concrete contradictions if found; a separate worker proposal is not required.

Commit code before the final preflight. `preflight <fix>` prints the selected local
checks; add `--run` to execute. Python follows workflow CI (an explicit `--python`
environment or uv); Helm must match CI exactly (`--helm`/`HELM_BIN`); Go follows
go.mod (`GO_BIN`/PATH). Tool absence/version mismatch is unavailable, never skipped.
Shared E2E, image builds and deployment do not run locally or acquire authorization.
A local PASS is not a claim that all remote CI is green.

`submit-review <fix> --file submit.yaml --by <implementer> --expect-revision N`:

```yaml
# Optional: record complete source pins in this same handoff.
source: {branch: fix/example, base_sha: FULL_BASE_SHA, head_sha: FULL_HEAD_SHA}
preflight: evidence/preflight/receipt.json
checks:
  implementation: {artifact: 04-diff.patch, command: "git diff --binary BASE HEAD"}
  l0:
    artifact: evidence/l0.txt
    command: "cd phorvex && go test ./..."
    # Optional COMPLETE dependencies: code, tests, config, schemas, build inputs.
    inputs: [phorvex, build/phoenix-extended]
  l1: {artifact: evidence/l1.txt, command: "EXACT_INVARIANT_COMMAND"}
  l2: {artifact: evidence/l2.txt, command: "EXACT_BEHAVIORAL_COMPARISON"}
  positive_control: {artifact: evidence/control.txt, command: "EXACT_CONTROL_COMMAND"}
```

Already-valid checks at this head, including explicitly authorized waivers, may
be omitted; the batch validates them without changing their signer. It cannot
create a waiver or carry one to a different source implicitly.

Sign `red` once before submission, by whoever executed it (worker or lead; legacy
blind reviewers must seal first). A failure must be the intended baseline assertion, with its
positive control. Merely disabling the new guard at head is not baseline execution.

## Reviewer

`review-delta <fix> --agent <reviewer>` shows changes since the last passing review
and checks eligible for explicit reuse. It does not auto-approve the new delta.

`review-verdict <fix> --result PASS --file review.yaml --by <reviewer> --expect-revision N`:

```yaml
checks:
  incident: {artifact: evidence/incident.md, command: "EXACT_INDEPENDENT_REPRODUCTION"}
  p3: {artifact: evidence/p3/verdict.md, result: PASS, command: "EXACT_REVIEW_AND_COUNTEREXAMPLE_COMMAND"}
# Optional, only after reviewing these checks' complete dependency scopes:
approve_reuse: [l0]
```

For FAIL, supply `p3.result: FAIL` and actionable counter-evidence; no passing incident
is required to reject a patch. The worker fixes the findings and resubmits; repeat
until the lead accepts the implementation. Implementation authors cannot sign their
own reviews or approve reuse scopes. Writing the plan is the lead's responsibility
and does not disqualify the lead from reviewing the worker's implementation.

To reuse an approved, unchanged check, replace its `checks` entry with `reuse: [l0]`
(or `incident` in the reviewer's package). The tool rejects missing scope approval,
changed dependencies, changed evidence or unassigned signers. It retains original
run provenance and never reuses P3, decision, implementation or live checks. Listing
a narrow dependency set is a review responsibility, not an automatic safety proof.

Each batch has one public revision and all-or-nothing state updates. No waiver,
merge, deployment, role reassignment or authorization change is accepted in a batch.
Notifications follow commit; retry `handoff-notify <fix> --by <sender>` if needed.
Successful notifications are deduplicated; an ambiguous transport crash can duplicate
mail, so receivers still drain/ack idempotently. Use `--no-notify` only for an explicit
foreground handoff. If reviewer and coordinator are the same agent, continue directly
with PR delivery instead of sending a message to yourself.
