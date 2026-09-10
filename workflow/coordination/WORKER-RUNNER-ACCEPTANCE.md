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
