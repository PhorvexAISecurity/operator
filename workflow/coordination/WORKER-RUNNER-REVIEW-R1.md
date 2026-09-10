# Lead review R1: corrections required before real use

Reviewer: codex-lead. Reviewed initial implementation while bootstrap job was completing.
Evidence: /home/mehrdad/operator-readiness/workflow/assessments/20260910-readiness/evidence/worker-runner-review-probes.json.
Preserve this review; make one consolidated correction pass with meaningful tests.

1. **Orphaned CLI permits duplicate same-session work.** Independently reproduced:
   launch fake Claude in hang mode, enqueue a second job, SIGKILL only the wrapper,
   run another supervisor pass. First job becomes interrupted; second starts;
   BOTH CLI children are alive. Track actual CLI PID/starttime and session-start
   evidence durably, hold the worker and its concurrency slot while any owned
   process or ambiguous invocation remains, and require explicit resolution before
   subsequent jobs dispatch. Cover wrapper death, spawn-intent ambiguity and
   cancellation without assuming a dead wrapper means all descendants exited.
   The next job must resume the existing session after a resolved interruption,
   not issue a fresh --session-id against a session already created. Test actual
   surviving fake processes, not only a fabricated interrupted state record.

2. **Installed CLI compatibility and noninteractive permissions.** CLI 2.1.267
   accepts acceptEdits/auto/manual/dontAsk/plan/bypassPermissions; `default` is
   rejected. Choose a supported conservative default, keep bypass unavailable,
   and set `--permission-prompts none` so denials cannot wait for an absent host.
   Disable automatic commit/PR attribution in per-invocation settings. Do not
   alter global settings. Expose only necessary tools; do not silently load
   project MCP servers/hooks or unrelated session settings. The actual validated
   bootstrap uses explicit tools, --setting-sources empty, --strict-mcp-config
   with an empty server config, and per-invocation attribution settings. Keep
   authentication via the existing subscription (no --bare). Retain scoped allow
   and deny rules and honest denial reporting; never bypass a denied action.

3. **Success must be explicit.** Current summarize accepts a result with no init,
   no is_error and no success subtype as session_match=true; finalize can call it
   done. Require exact init/result session matches, result.is_error is False,
   successful subtype, zero exit and an actual valid final result. Non-object JSON,
   malformed/partial output, missing flags, or conflicting final results must
   fail visibly per job rather than crashing the supervisor or yielding success.

4. **Corrupt authority cannot become empty state.** load_state uses read_json or
   {}, so malformed/unreadable existing state becomes a new empty registry. Fail
   closed with a retained diagnostic for existing corrupt state. Validate private
   runtime/record paths and ownership, reject symlinks and unsafe existing modes,
   including intermediate directories. chmod-at-creation alone does not validate
   an existing shared runtime. Add corruption and symlink regression tests.

5. **Worker roots and workflow_root must be exact.** compose_prompt and bus notices
   currently name the launcher's own workflow root rather than the assigned
   worker worktree. Use the worker's root and its bus CLI for completion records.
   Parse git's two path output lines with splitlines, not whitespace split (valid
   worktrees may contain spaces). Revalidate registered worktree/common-directory
   identity immediately before dispatch; a removed/replaced worktree must not run.

6. **Role and recovery semantics.** Standing prompt calls every role an implementation
   author even when registered investigator/reviewer. Preserve the assigned role;
   prohibit self-approval only of work the same agent authored. Notification role
   must reflect registration. Document explicit recovery commands for interrupted
   workers and cancellation, process-tree/timeout behavior, and denied jobs. A
   denied but successfully returned turn is still submitted with denials visible,
   never implementation acceptance. A timeout must leave no untracked running
   invocation before another job is dispatched.

7. **Validate input and availability.** Reject non-finite/nonpositive interval and
   timeout values. Status should work before registration. Persist notification
   retries with bounded backoff; one failing bus call must not hold the global
   state lock for every failed job on every 2-second pass. Notification is optional
   and never the only way to retrieve results. Add focused tests for these paths.

8. Fix the test harness's shared `/tmp/workflow-outside-report.md` fixture by
   using a per-test TemporaryDirectory/unique path outside its temporary workflow
   tree. Do not remove the other user's existing file. M-18/M-21 already carry
   the same fixture repair in pending PRs; preserve that behavior and note the
   expected composition overlap. This is authorized harness repair so the full
   suite can pass reliably on this multi-user host.

Keep the runner scoped: no new tier scheduler, no automatic review or merge. Run
the complete focused runner tests after repairs and report all residual limits.
Do not commit or push yet. Never add co-author/assistant attribution.
