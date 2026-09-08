# Fix or review an issue

Run `doctor` once, then `brief <fix-id> --agent <assigned-id>`.
If an issue has multiple cycles, choose the explicit current fix ID; never
infer ownership from the issue number. If no cycle exists and remediation is
authorized, use `new-fix --issue M-N`; the coordinator assigns participants.

The brief names the stage and minimal reads. Follow `stages/design.md`,
`stages/verify.md`, or `stages/release.md` for your current work. `WORKFLOW.md`
is the reference when a contract is unclear; it is not mandatory preload.

Use `record-check` for signed evidence, `transition --expect-revision` for
state changes, and sync operations for main/deployment/closure. Continue through
steps you own and are authorized to perform. At another owner or a blocker,
record one next action and hand off artifact references.

Done means independent verdict + required verification + synchronization.
PR-ready, merged, and deployed are useful intermediate states, not closure.
