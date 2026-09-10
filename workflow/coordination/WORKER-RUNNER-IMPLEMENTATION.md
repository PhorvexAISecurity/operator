# Implementation report: supervised Claude implementation workers

Implementer: claude-worker-runner. Owner/reviewer: codex-lead. Branch
`workflow/claude-workers` in `/home/mehrdad/operator-workers`. **Nothing
committed or pushed**; no real worker was launched, no worktree, permission
setting, credential, live session, cluster or deployment was touched, and no
subagent was used.

- Pass 1: initial implementation of `WORKER-RUNNER-PLAN.md`.
- Pass 2: all eight corrections in `WORKER-RUNNER-REVIEW-R1.md`, plus the
  user-directed `WORKER-RUNNER-MODEL-POLICY.md`.
- Pass 3 (this report): all five corrections in `WORKER-RUNNER-REVIEW-R2.md`,
  with the model policy re-confirmed and extended. R1 behaviour and tests are
  preserved; every review note and the earlier records are retained unchanged.

## Changed paths

| Path | Change |
| --- | --- |
| `workflow/coordination/workers.py` | new, 1439 lines: register / enqueue / run / status / result / stop / resolve plus the `_child` wrapper |
| `workflow/tools/tests/test_workers.py` | new, 1290 lines, **80 tests** driving a fake Claude executable and real process-group fixtures |
| `workflow/coordination/WORKERS.md` | new 253-line runbook: layout and umask rules, model/effort policy, commands, invocation flags, outcome rules, group-aware recovery/cancellation/timeout, service, notices, lead smoke test, stopping point |
| `workflow/coordination/BUS.md` | four-line pointer to `WORKERS.md` in the runner-handoff section |
| `workflow/tools/tests/test_operations.py` | R1 item 8: per-test temp path replaces the shared `/tmp` report fixture |
| `workflow/tools/tests/test_bus.py` | R2 item 5 (same class): the Claude-socket fixture makes its registry file and socket private explicitly |

## R2 corrections, item by item

1. **Group-wide termination, no premature success.** `terminate_group` now
   enumerates the owned members of the target group (`/proc` scan gated by a
   cheap `killpg(pgid, 0)` probe), signals the group *and* each surviving member,
   escalates `SIGTERM` → `SIGKILL`, and re-reads members that appeared while it
   waited; it returns true only when every member is gone. It signals only a
   group whose leader is still verified as ours: a non-empty group pins its id,
   but once the leader has exited the group cannot be re-identified, so
   `terminate_group` refuses to signal and returns false. `process_records` now
   carries a `group` verdict, and `unresolved_processes` reports leftover members
   by PID, keeping the job unresolved. Reproduced and covered with **real**
   processes: a leader plus a `SIGTERM`-ignoring same-group child (escalated to
   gone), a leftover group whose leader was killed (reported, never signalled),
   plus end-to-end cancellation and timeout of a fake CLI that spawns such a
   child, and a leftover-member run that stays unresolved.
2. **Cancellation preserves session evidence.** `stop_job` now takes the state,
   captures `note_session_evidence` both before signalling and after (late
   flushes), and `cmd_resolve` captures it on entry so every recovery transition
   preserves it. The exact reproduction is a test: stop after the init event with
   no reconcile pass in between, then the next job launches with `--resume` and
   the same session id, `resumed: true`.
3. **Explicit tool surface and current attribution keys.** Invocations add
   `--tools` with just the bare names behind the registered allow rules
   (`Bash(git status:*)` → `Bash`), still scoped by `--allowedTools` /
   `--disallowedTools`; `Agent`, `Task` and `Monitor` are refused at
   registration. Per-invocation settings are now
   `{"attribution": {"commit": "", "pr": ""}}`; the deprecated
   `includeCoAuthoredBy` flag is gone. `status` shows `tools_exposed`. No global
   settings are touched.
4. **Model policy re-confirmed.** Persisted validated `--effort`
   (`low|medium|high|max`, default `max`) is sent on every launch **and** resume;
   `--model` defaults to pinned `claude-opus-5` and rejects aliases, `latest` and
   any fallback; every reported model id is kept in `models_observed` (not
   last-event-only) and any id outside the requested family sets
   `model_mismatch`, fails the job and is stated in the notice.
5. **Fixture privacy under a permissive umask.** Reproduced: `git init` under
   umask `0002` creates `.git` at `0775`, so registration failed before the
   tests ran. The runner fixture now chmods its common directory to `0700`, and
   a new test asserts the reproduction, the repair, and that the runtime is still
   created `0700`/`0600` under umask `0002` — i.e. it does not rely on the
   service umask. A second new test asserts a group-writable common directory is
   **still** refused, and the refusal message now names `chmod g-w,o-w`.
   Running the full suite under umask `0002` also exposed two pre-existing
   `test_bus.py` Claude-socket fixtures with the same defect (registry file and
   socket left group-writable); both are repaired in the fixture, not in
   `claude_socket.py`. One production check was corrected rather than the
   fixture: a worker worktree's `bus.py` is a tracked file that legitimately
   inherits a checkout's umask (real files here are `0664`), so it is now
   validated as a real, non-symlinked, own-uid file (`check_owned`) instead of
   requiring `0600`-style privacy; runtime state keeps the strict check.

## R1 corrections, item by item

1. **Orphaned CLI can no longer duplicate same-session work.** The wrapper now
   `Popen`s the CLI in its own session and durably records `cli_pid` +
   `cli_pid_start` in `child.json` *before* waiting. `reconcile` copies that
   identity into state, and a dead wrapper whose CLI is still alive (or whose
   records disagree with a live PID) becomes `interrupted` **and**
   `unresolved: true`. An unresolved job holds its worker *and* one concurrency
   slot, so no later job dispatches for that worker until the new
   `resolve --job <id> [--terminate]` command clears it; plain `resolve` exits
   non-zero while anything owned is alive. Session-start evidence is now
   harvested from the stream itself (`note_session_evidence`), so after a
   resolved interruption the next job uses `--resume`, never a fresh
   `--session-id`. `stop` waits briefly for the wrapper's identity record, then
   ends the CLI group first and the wrapper second. Covered by a test that
   SIGKILLs only the wrapper and asserts the real surviving fake CLI process,
   the held worker, the blocked second job, `--resume` after resolution, plus
   timeout, cancellation and spawn-ambiguity variants.
2. **Installed-CLI compatibility and noninteractive permissions.** Modes are now
   `manual` (default), `auto`, `acceptEdits`, `dontAsk`, `plan`; `default` is
   gone and `bypassPermissions` stays unavailable. Every invocation adds
   `--permission-prompts none`, `--setting-sources ""`, `--strict-mcp-config
   --mcp-config '{"mcpServers":{}}'` and a per-job `--settings` file containing
   `includeCoAuthoredBy: false`. `--allow-tool` is now required, so the tool
   surface is always explicit. No global setting is written, no credential read,
   `--bare` never used.
3. **Success is explicit.** `summarize` requires exactly one `init` and exactly
   one final `result`, both with the assigned session id, `is_error is False`, a
   success subtype and non-empty result text, plus zero exit status and no
   malformed or non-object JSON lines. Every other shape fails visibly with a
   per-job reason; `reconcile` catches per-job exceptions so one broken record
   cannot stop the supervisor.
4. **Corrupt authority cannot become empty state.** `load_state` fails closed on
   unreadable JSON, a non-object top level, an unknown `schema_version` or wrong
   field types, leaves the file untouched and retains a
   `state.corrupt.<ts>.txt` diagnostic. `check_private` validates the Git common
   directory, `phorvex-workflow`, the runtime, `jobs/`, job directories and
   `state.json` on use: symlinks, foreign owners and group/world-writable modes
   are refused, not just set at creation.
5. **Exact roots.** Prompts name the assigned worktree's own workflow root, and
   completion notices run that worktree's `bus.py` with its `workflow_root`; a
   missing bus CLI there is a visible notice error, never rerouted. Git's
   two-line output is parsed with `splitlines`, so worktree paths containing
   spaces work (covered by a test). The registered worktree and common directory
   are revalidated immediately before every dispatch; a removed or replaced
   worktree fails the job with no launch.
6. **Role and recovery semantics.** The standing rules no longer call every
   worker an implementation author: they forbid reviewing or approving work the
   agent authored itself and instruct it to perform its assigned role only. Bus
   notices send the registered role. A denied but successfully returned turn is
   recorded as submitted with denials visible, never acceptance. Timeouts end
   the CLI's whole process group before the receipt is written, and a surviving
   CLI keeps the job unresolved. `WORKERS.md` documents the recovery table,
   `resolve`/`stop` commands, process-tree and timeout behaviour, and denied jobs.
7. **Input validation and availability.** `--timeout` and `--interval` use a
   finite-positive-bounded argparse type (NaN, ±inf, 0, negatives and
   over-range rejected), and concurrency stays 1–8. `status` works before any
   registration and creates nothing. Notices are planned under the lock, sent
   **outside** it, and recorded afterwards, with persisted attempts and bounded
   backoff (60 s → 900 s cap), so one failing bus call cannot hold the global
   lock every pass; a test proves the lock is free during the send. `status` and
   `result` remain the authoritative way to read results.
8. **Harness fixture.** `test_report_file_must_stay_inside_workflow_tree` now
   uses a per-test `TemporaryDirectory` outside the sandboxed workflow tree. The
   other user's existing `/tmp/workflow-outside-report.md` was **not** touched.
   M-18/M-21 carry the same repair in pending PRs, so expect a composition
   overlap on that one test body; the behaviour asserted is identical.

## User-directed model settings (MODEL-POLICY, incorporated in this turn)

`register` now takes `--effort {low,medium,high,max}` (default `max`) and
`--model` (default `claude-opus-5`); both are persisted with the worker and
`--effort` is passed on **every** launch and resume, not only the first. Models
must be explicitly pinned: `opus`, `sonnet`, `haiku`, `default`, `opusplan` and
anything containing `latest` are rejected, and there is no fallback model; a
dated variant such as `claude-opus-5-20260501` is accepted. Each job records
`model_requested`, `effort_requested` and `models_observed` (every model id the
CLI reported). An observed id outside the requested family sets
`model_mismatch: true`, fails the job with `model mismatch: requested ...,
observed ...`, and is stated in the completion notice — a substituted model is
never relabelled as Opus 5. Tests cover argv on launch and resume, status
fields, alias/effort rejection, the dated-variant rule and a substituted-model
run.

## Validation

Run in **both** environments, because R2 item 5 is umask-sensitive: this
session's service umask is `0077`, and the host's ordinary interactive umask is
`0002`.

| Run | umask `0077` (service) | umask `0002` (ordinary shell) |
| --- | --- | --- |
| `python3 -m unittest -b tools.tests.test_workers` | **80 OK** (~27 s) | **80 OK** (~27 s) |
| `python3 -m unittest discover -b -s tools/tests -p 'test_*.py'` | **193 OK** | **193 OK** |

- Focused runner tests also pass under the standard `0022` umask (80 OK).
- `python3 -m compileall -q .`; `tools/workflow.py sync-index --check` (PASS);
  `render-issues --check` (PASS); `doctor` — 0 errors, 17 pre-existing
  historical warnings.
- Real-repo read-only checks: `workers.py status` before any registration prints
  a valid empty report for `/home/mehrdad/operator/.git/phorvex-workflow/workers`
  and creates nothing. The real common directory and `phorvex-workflow` are
  `0755`, owned by this uid, so the strict ancestor check passes there today.
- The temporary umask-runner helper used for the `0002` runs was removed; the
  equivalent invocation is `(umask 0002; python3 -m unittest ...)`.

Focused coverage now includes: session start then `--resume`; role-aware prompt;
`--tools`/`--allowedTools`/attribution settings; forbidden Agent/Task/Monitor;
model+effort argv on launch and resume, alias/effort rejection, dated-variant
rule, substituted-model run; parallel workers vs per-worker serialization;
concurrency cap; unresolved job holding a slot; drain-blocked reporting;
duplicate enqueue; removed worktree; strict-success failures (no init,
missing/duplicate result, absent `is_error`, empty text, non-object line,
session mismatch, nonzero exit, `is_error` true, auth failure, hard crash);
real-process group escalation, unverifiable leftover group, cancellation and
timeout of a CLI with a `SIGTERM`-ignoring child, leftover member keeping a job
unresolved; broken record not stopping the supervisor; adoption after restart;
receipt survival; spawn-window and vanished-tree interruption; orphaned CLI
end-to-end with resolution; cancel-after-init then `--resume`; late-receipt
resolve; stop of the whole tree; PID-reuse refusal; corrupt/symlinked/
shared-mode state; permissive-umask runtime privacy and the still-refused
group-writable common directory; missing state file; traversal and path
constraints; binary discovery; duration validation; status before registration;
privacy of prompts and session ids; notice
role/root/send-once/backoff/lock-freedom/missing-bus.

Earlier correction retained: in pass 1 I claimed the `/tmp` fixture test "fails
identically in isolation"; that isolated run had actually failed to import. The
full-suite `PermissionError` and its cause were as reported.

## Residual limits

- Still **no real Claude CLI invocation** (none was permitted). All execution
  evidence comes from the fake binary and real non-Claude process fixtures. The
  flag set (`--permission-prompts none`, `--setting-sources ""`,
  `--strict-mcp-config`, `--mcp-config`, `--settings`, `--tools`, `--effort`,
  `manual` mode) follows the review's validated bootstrap and the policy note but
  is **unverified against the installed CLI here**; a rejected flag fails the job
  visibly with the CLI's stderr in `stderr_tail`. Run the bounded smoke test in
  `WORKERS.md`.
- `--effort` value names (`low|medium|high|max`) are enforced locally but
  unverified against the CLI; a mismatch fails loudly rather than silently
  running at a lower effort.
- `{"attribution": {"commit": "", "pr": ""}}` is applied per invocation; that it
  suppresses every commit/PR attribution path is unverified without a real run.
- `--tools` names are derived from the allow rules; if the installed CLI expects
  different tool names than the rules use, the derived surface would be wrong in
  the same way the rules are, and the CLI would report it.
- Group cleanup covers process groups, not arbitrary re-parented descendants that
  changed their own group (`setsid`). Such a process is invisible to
  `killpg`/group enumeration; it would be reported only if it were a recorded
  PID. A leftover group whose leader already exited is deliberately reported
  rather than signalled, so it needs a lead decision.
- Notices are at-least-once; a crash between the bus write and the receipt
  update can duplicate one notice. No exactly-once claim.
- Denial detection reads `result.permission_denials` plus a phrase match on
  errored `tool_result` blocks; a CLI wording change could miss one in the
  summary. `stdout.jsonl` stays authoritative.
- Unresolved jobs are deliberately sticky: they block their worker and a slot
  until `resolve`, and re-running one needs a new idempotency key. That is the
  lead's decision, not the runner's.
- `stop`/`resolve` hold the state lock while waiting up to ~5 s for a child
  record or terminating a group, which can briefly delay a concurrent `status`.
- The file grew to 1439 lines for this behaviour, well above the "modest" size of
  pass 1; it is organized in labeled sections of single-purpose functions.
- Group enumeration scans `/proc` when a group probe says the group is non-empty:
  at most two scans per active job per supervisor pass (~ms each at a 2 s
  interval), which is fine here but is not free.
- The strict ancestor-mode check can block a first run if the Git common
  directory or `phorvex-workflow` was created under a permissive umask. The
  runner names the `chmod g-w,o-w` fix rather than proceeding; that is a
  deliberate operator step, not something it repairs itself.
- A model mismatch fails the job. The completed output is still readable with
  `result`, but the runner will not mark work done under a substituted model.
- `resolve` cannot prove that a killed CLI made no repository changes; the lead
  should inspect the worktree of an interrupted job before re-queueing work.

## Commands

```sh
W=workflow/coordination/workers.py
python3 $W register --worker claude-impl-1 --worktree /abs/existing/worktree \
    --role implementer --model claude-opus-5 --effort max \
    --permission-mode manual --allow-tool Read
python3 $W enqueue --worker claude-impl-1 --key t1-m140-impl --prompt-file /path/task.md \
    --scope 'one file and its tests' --timeout 3600 \
    --notify-lead --subject-kind campaign --subject-id claude-workers
python3 $W run --concurrency 3          # or --once / --drain for a bounded pass
python3 $W status --worker claude-impl-1
python3 $W result --job claude-impl-1:t1-m140-impl
python3 $W stop --job claude-impl-1:t1-m140-impl        # or --supervisor
python3 $W resolve --job claude-impl-1:t1-m140-impl --terminate
python3 -m unittest -b tools.tests.test_workers          # from workflow/
(umask 0002; python3 -m unittest -b tools.tests.test_workers)   # ordinary shell umask
python3 -m unittest discover -b -s tools/tests -p 'test_*.py'
```
