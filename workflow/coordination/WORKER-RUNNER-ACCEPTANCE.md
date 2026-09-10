# Lead acceptance of the bounded worker supervisor

Reviewer: codex-lead, 2026-09-10. Implementation by the assigned Claude worker,
reviewed through R1 and R2. Accepted for this campaign's supervised worker jobs;
this is not acceptance of any product implementation submitted by those jobs.

Independent validation:

- Complete workflow suite: 193 tests passed under the lead's ordinary shell
  environment, including process-death, malformed output, orphan recovery and
  cancellation tests. Scope includes the two fixture privacy repairs and the
  unique temporary-path fix shared with pending M18/M21 PRs.
- Lead's original R2 probes now pass: an ignored-SIGTERM descendant is killed
  before termination claims success; cancellation after init preserves session
  identity and the following job resumes it.
- Real installed CLI: first queued job completed its allowed file write; a
  separately queued second job resumed the same session and recalled a canary
  that was never written to a worktree file. Both jobs reported Claude Opus5,
  requested max effort, matching init/result sessions and zero tool denials.
  Only Write was exposed. Invocation settings disable commit/PR attribution.

Retained lead evidence lives in the readiness assessment evidence directory:
worker-runner-r2-full-tests.log, worker-runner-r2-lead-retest.json and
worker-runner-real-smoke.json. Raw process/session records remain private in the
Git common directory. No authentication secrets were copied into the repository.

Limits: Linux /proc process identity and cooperative process groups; a process
that deliberately escapes its group is outside the supported worker contract.
Ambiguous or surviving invocations require explicit resolution. Notifications
are at-least-once; status/results remain authoritative. Model output is evidence
for review, never a verdict. The service must use the actual runner worktree path
until this workflow change is merged. A deployment barrier cannot be bypassed by
queueing another job. No merge, DevOps action or live mutation is authorized here.

No co-author or AI attribution is permitted in commit messages.

## Post-acceptance defect and correction, 2026-09-10

The acceptance above stands as recorded; this section adds a limitation found in
live campaign use and its fix. Nothing earlier is withdrawn.

Discovered limitation: the accepted runner mishandled a legitimate CLI event
shape. `system` / `subtype=permission_denied` carries `message` as a plain
**string**, while denial collection read `message` as an object for every event.
Job `claude-v3-m152:implementation-r1` exited `0` with matching init/result
sessions, `is_error: false`, `subtype: success`, Opus 5 on every turn, a
3,853-character final result and no surviving process — a successful, honestly
reported run — yet reconciliation raised
`AttributeError: 'str' object has no attribute 'get'`. The R1 per-job exception
guard then recorded it as `failed (reconcile error: ...)`. The recorded
implementation was never lost, but its execution status was wrong, and any run
that hits a denial would have been misreported the same way.

Correction (this commit): every nested stream read is typed; denials are
collected from all three shapes the CLI uses (`system` event, errored
`tool_result`, final `permission_denials`) with each occurrence kept and labelled
by source; assistant `message`, model ids and final `permission_denials`,
`modelUsage`, `num_turns` and `usage` are type-validated, so a malformed shape is
reported rather than crashing or passing as success. A completed run with denials
is now `done` with `execution_verdict: "succeeded with denials"` and a
`denial_count`, explicitly an execution verdict and not implementation
acceptance. `model_usage_ids` records every model the final event billed
(auxiliary helper models included) while `models_observed` keeps the turn model
ids that decide `model_mismatch`. All original session, model, single-init,
single-result and conservative malformed-result rules are unchanged.

Evidence: replaying the affected job's private stream through the accepted
commit still raises the `AttributeError`; through the fix it yields zero
problems, `session_match` true, `subtype: success`, 192 turns, turn model
`claude-opus-5` only, `model_usage_ids` including a Haiku helper, and 33 denial
records (11 each from the system, `tool_result` and result sources). The raw
stream stays private in the Git common directory; a sanitized fixture with the
same event shapes is committed at
`workflow/tools/tests/fixtures/claude-stream-permission-denied.jsonl`.

Runner suite 90 tests and full workflow suite 203 tests pass on both the pinned
Python 3.11 toolchain and the default interpreter; `sync-index --check` PASS and
`doctor` reports 0 errors with the 17 pre-existing historical warnings.

Not done here and left to the lead: no live runner state, service unit or queued
job was modified; the lead's `resolve` of the affected job stands, so that record
keeps its failed reason and freed slot while `M161` continues. The service must
be restarted by the lead to pick up this code. No push, merge, deployment or
self-approval; this correction is submitted for independent review.

### Independent lead review of 62df1bb

Codex lead, 2026-09-10: accepted the legitimate string-message denial repair
for local campaign operation. Replayed the actual private M152 stream through
`summarize`: zero problems, matching session, 192 turns, 33 denial records,
Opus 5 turn model. Independently ran all 90 runner tests under Python 3.11:
PASS. The first direct process-group-leader invocation was killed by an existing
test cleanup fixture that records its own PID; running unittest as a child of
a waiting Python driver completed. This is a test-isolation limitation to
repair before publishing the runner PR, not a product execution failure.

The helper model listed under modelUsage is retained visibly; it does not mean
the requested implementation turn model was replaced. No historical job result
was rewritten. Restarting the local supervisor is authorized campaign tooling.
Additional malformed final shapes and fixture cleanup ownership remain review
follow-ups before the PR; this acceptance does not claim universal shape safety.

### Independent lead acceptance of fecc213

2026-09-10: all216 workflow tests independently pass under pinned Python3.11, including103 runner cases and the ordinary/process-group-leader cleanup controls. Actual summarize probes retain clean success, reject boolean turn metadata and malformed denial entries, and distinguish the exact synthetic quota sentinel from a real model substitution while keeping quota failures failed. Evidence: lead-runner-r4-tests.log and lead-runner-r4-repaired.json. Original failure probes are preserved.

The source delta keeps one session per worker, bounded permissions, no model fallback, current high default and explicit legacy max support. Test cleanup signals only owned fixture children, never simulated runtime PIDs or the test process group. Unknown event shapes remain conservative failures; no universal shape guarantee or deployment authority is implied.

The lead accepts this source for the local campaign supervisor. With the independent bootstrap job completed, supervisor concurrency may be4 within the existing total4 external-worker cap. Before any future bootstrap job, free/reduce a supervisor slot. Restart uses KillMode=process and the runner's between-pass shutdown; existing wrappers/sessions are adopted rather than relaunched. Historical job receipts are not rewritten. Branch publication is authorized; merge and shared-cluster deployment are not performed.
