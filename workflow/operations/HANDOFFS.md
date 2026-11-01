# Role handoffs

Commands are `python3 workflow/tools/workflow.py …`. Run from the issue's own
worktree. Evidence files live in its fix directory; do not paste logs into bus messages.

## Implementer

In the lead/worker loop, implement the lead's signed `03-decision.md` after AGREED.
Report concrete contradictions if found; a separate worker proposal is not required.

Commit code before the final preflight. `preflight <fix>` prints the selected local
checks; add `--run` to execute. Python follows workflow CI (an explicit `--python`
environment or uv); Helm must match CI exactly (`--helm`/`HELM_BIN`). Current Go
unit checks use CI's highest-version file (`build/test-harness/go.mod`), an exact
`GO_BIN`/PATH binary and `GOTOOLCHAIN=local`, including its non-cluster environment.
Tool absence/version mismatch is unavailable, never skipped.
For current CI's pinned Python provisioner, local preflight verifies the full
patch version and attests the provision script hash. If checks need both Python
versions, set `PREFLIGHT_PYTHON_3_11` and `PREFLIGHT_PYTHON_3_12` to the matching
interpreters (with required dependencies installed); these override `--python`
per job. Current chart checks come from `pr-validation.yml` when legacy `ci.yml`
is absent. Historical receipts resolve their authority and provisioner from the
pinned commit, not the current checkout. Recipe version 2 runs all seven current
`go-unit` module commands exactly; its informational affected-services report goes
to the local job log instead of `$GITHUB_STEP_SUMMARY`, and uses the pinned plan
base instead of GitHub's merge-parent `HEAD^1`. Existing extra build/vet
checks remain for changed product modules. Historical version 1 receipts retain
their old module-minimum Go semantics for historical validation only; they cannot
satisfy a current submission. Unsupported CI recipes require an explicit adapter
update rather than silently losing checks.
The separate remote `go-envtest` job (local Kubernetes API binaries), other remote
CI jobs, shared E2E, image builds and deployment are not executed by this preflight.
A local PASS is not a claim that all remote CI is green.
Current chart checks also attest the benchmark wrapper, its pinned Python
dependencies and the exact Go version-file used by the shared-kernel integration
tests. Set `GO_BIN` to the matching local binary for these checks as well. The
wrapper runs bot, worker and stage suites without skipped tests. Historical
chart plans that predate this setup keep their original dependency contract.
Recorded receipts are validated against their attested source and its CI recipes, even
when doctor runs on a newer main or PR merge checkout. Submission additionally requires
the current code worktree to match the pinned implementation; that check is not waived.

`submit-review <fix> --file submit.yaml --by <implementer> --expect-revision N`:

```yaml
# Optional: record complete source pins in this same handoff.
source: {branch: fix/example, base_sha: FULL_BASE_SHA, head_sha: FULL_HEAD_SHA}
preflight: evidence/preflight/receipt.json
checks:
  implementation: {artifact: 04-diff.patch, command: "git diff --binary --full-index BASE HEAD"}
  l0:
    artifact: evidence/l0.txt
    command: "cd phorvex && go test ./..."
    # Optional COMPLETE dependencies: code, tests, config, schemas, build inputs.
    inputs: [phorvex, build/phoenix-extended]
  l1: {artifact: evidence/l1.txt, command: "EXACT_INVARIANT_COMMAND"}
  l2: {artifact: evidence/l2.txt, command: "EXACT_BEHAVIORAL_COMPARISON"}
  positive_control: {artifact: evidence/control.txt, command: "EXACT_CONTROL_COMMAND"}
```

`04-diff.patch` is normally the canonical `git diff --binary --full-index --no-color
--no-ext-diff --no-textconv BASE HEAD`; `submit-review` renders it when absent or
stale and keeps an already-matching artifact byte-for-byte. The gate compares every
byte against the pinned pair; the only tolerance is an `index OLD..NEW` header whose
ids are valid prefixes of the pinned full ids (plain `git diff --binary` abbreviates
them per clone). Never rewrite or re-sign a historical patch to change its bytes.

For a source removal whose patch would retain private bytes, the coordinator may set
`implementation.diff_format: git-diff-digest-v1`. The artifact then contains only its format,
the exact resolved base and head commit IDs, and the SHA256 of the same entire nonempty canonical
diff. Gates regenerate the diff from those objects and compare the strict envelope. Reviewers
inspect ordinary source changes directly and confirm a sensitive deletion through tree and blob
identities without reproducing the deleted bytes. Workers may update source pins during handoff;
they cannot change the selected evidence format.

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
