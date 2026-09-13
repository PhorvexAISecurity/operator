# Lead review R2

R1 substantially improves wrapper-death handling, strict success and recovery.
Remaining concrete blockers, independently reproduced on the R1 implementation:

1. `terminate_group` returns success when the group leader exits after SIGTERM,
   while a same-group descendant ignoring SIGTERM is still alive. The lead ran
   a real subprocess parent/child fixture; result was
   `termination_claimed_gone=true, descendant_still_alive=true`. Account for all
   owned group members before claiming timeout/cancellation cleanup; escalate
   while verified members remain, and keep unresolved state otherwise. Do not
   signal an unrelated reused group. Test an actual surviving child and cleanup.
2. Cancel the first job after its init event but before any reconcile pass:
   `stop_job` cancels with `session_started=false`; enqueueing the next job uses
   `--session-id` again, not `--resume`. Preserve init evidence during stop and
   every recovery transition before releasing the worker. Lead used the existing
   fake CLI hang mode, actual stop command, then a successful follow-up invocation.
3. R1 argv lacks the requested explicit `--tools` surface and settings use only
   deprecated `includeCoAuthoredBy:false`. Set current
   `attribution: {commit: "", pr: ""}` per invocation and explicitly expose only
   needed tool names derived from registered rules; do not expose Agent/Monitor.
4. Apply WORKER-RUNNER-MODEL-POLICY.md: persist validated effort, explicit Opus 5 /
   max defaults, include effort on launch and resume, record all observed model IDs
   and mismatch, and test these. No fallback.
5. Test fixtures currently inherit host umask 0002 and create .git mode0775,
   causing registration to fail before tests execute. Make the fixture Git
   common directory private explicitly; do not weaken production checks or rely
   on the worker service's umask. Verify with ordinary shell test execution.

Evidence: lead assessment evidence/worker-runner-review-r2-probes.json. Keep the
scope bounded, run focused and full tests, report residual limits. No commits or
push yet; never add co-author/AI attribution. This is a submission for independent
review, not acceptance.
