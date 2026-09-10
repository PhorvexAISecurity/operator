# Supervised Claude implementation workers

`workers.py` runs bounded jobs on the installed Claude CLI in noninteractive
print mode. A registered worker owns one explicit session: the first job starts
it with `--session-id`, every later job resumes that exact id with `--resume`.
Assignments arrive through this queue, not through native socket wakes, so an
idle or exited shell cannot lose them.

The runner records execution only. Tier readiness, source reconciliation, fix
approval, PR review and live verification stay with the lead and the workflow
records. A finished turn submits work for independent review — including a turn
that hit permission denials, which are recorded and stay visible.

## Layout

Runtime lives once under the Git common directory at
`phorvex-workflow/workers`, mode `0700`: `state.json` (durable state, atomic
writes under `state.lock`), `supervisor.json`, and `jobs/<worker>:<key>/` with
`prompt.txt`, `composed.txt`, `command.json`, `settings.json`, `child.json`,
`stdout.jsonl`, `stderr.log`, `receipt.json`. Prompts, logs and session ids
never enter tracked files, and `status` prints a session fingerprint instead of
the id. Every runtime level is validated on use: symlinks, foreign owners and
group/world-writable modes are refused, and unreadable or unrecognised
`state.json` fails closed with a retained `state.corrupt.<ts>.txt` diagnostic
rather than starting an empty registry.

The runner creates its own directories `0700` and files `0600` regardless of the
caller's umask, and never relaxes those checks to accommodate one. A permissive
umask (for example `0002`) can still leave an **existing** ancestor — the Git
common directory or `phorvex-workflow`, which the bus may have created —
group-writable; the runner then refuses to start and names the fix
(`chmod g-w,o-w <path>`). Tracked repository scripts it executes, such as a
worker worktree's `bus.py`, are only required to be real, non-symlinked files
owned by this user, because checkouts legitimately inherit the caller's umask.

Worker ids, idempotency keys, models and tool specifications must match
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, so no job path can escape `jobs/`.

## Commands

```sh
W=workflow/coordination/workers.py
python3 $W register --worker claude-impl-1 --worktree /absolute/existing/worktree \
    --role implementer --model claude-opus-5 --effort high --permission-mode manual \
    --allow-tool Read --allow-tool 'Bash(git status:*)' --deny-tool WebFetch
python3 $W enqueue --worker claude-impl-1 --key t1-m140-impl --prompt-file /path/task.md \
    --scope 'phorvex/control/tenant_state.py and its tests' --timeout 3600 \
    --notify-lead --subject-kind campaign --subject-id claude-workers
python3 $W run --concurrency 3            # supervisor; --once/--drain for one pass or until idle
python3 $W status --worker claude-impl-1  # JSON, works before any registration
python3 $W result --job claude-impl-1:t1-m140-impl
python3 $W stop --job claude-impl-1:t1-m140-impl      # or --supervisor
python3 $W resolve --job claude-impl-1:t1-m140-impl [--terminate]
```

`register` accepts only an existing worktree **root** whose Git common
directory matches this repository's; it never creates or modifies a worktree,
and the identity is revalidated again immediately before every dispatch, so a
removed or replaced worktree fails the job instead of running. At least one
`--allow-tool` is required: a worker's tool surface is always explicit.
Re-registering with different settings requires `--update` and no job that is
active or unresolved. `enqueue` is idempotent per `(worker, key)`: the same
prompt returns the existing job, a different prompt is rejected. One worker runs
at most one invocation; `--concurrency` (default 3, max 8) bounds all workers
together. Durations must be finite and positive (`--timeout` ≤ 86400,
`--interval` ≤ 60).

## Model and reasoning effort

User-directed for this campaign: pinned `claude-opus-5` at effort `high`, which
are the registration defaults. `--model` accepts only an explicitly pinned id —
`opus`, `sonnet`, `default` and anything containing `latest` are rejected, and
there is no fallback model. `--effort` is one of `low`, `medium`, `high`, `max`,
is persisted with the worker, and is sent on **every** launch and resume;
`--effort max` remains selectable and receipts from earlier `max` runs keep the
effort they recorded.

Each job records the requested model and effort plus `models_observed`, every
model id the CLI reported for a turn. If an observed id is not the requested one
(a dated variant of the same id is accepted), the job records
`model_mismatch: true`, fails with `model mismatch: requested ..., observed ...`,
and the completion notice says so. A substituted model is never relabelled as
Opus 5.

Two model fields are deliberately *not* mismatches. `model_usage_ids` lists
everything the final event billed, which normally includes an auxiliary helper
model. `synthetic_models` lists the CLI's own error placeholder — exactly
`<synthetic>` — which it attributes an error turn to, for example on a quota
error (`is_error: true`, `api_error_status: 429`,
`terminal_reason: "api_error"`, while `subtype` is still `success`). That
placeholder is recorded as a synthetic **error attribution** and always fails the
job, so a quota failure stays a failure; it is never reported as a substituted
model, and no other unknown model string is treated this way.

## Invocation and permissions

Permission modes are `manual` (default), `auto`, `acceptEdits`, `dontAsk` and
`plan` — the values the installed CLI accepts; it rejects `default`.
`bypassPermissions` and `--dangerously-skip-permissions` are deliberately
unavailable, and no flag can change execution or session identity. Each
invocation runs:

```text
claude -p --output-format stream-json --verbose
  --session-id UUID | --resume UUID --model M --effort E --permission-mode MODE
  --permission-prompts none --setting-sources "" --strict-mcp-config
  --mcp-config '{"mcpServers":{}}' --settings <job>/settings.json
  --tools <names derived from the allow rules>
  --allowedTools <rules> [--disallowedTools <rules>]
```

`--permission-prompts none` means an unallowed tool is denied instead of
waiting for a host that is not there; `--setting-sources ""` and the empty
strict MCP config keep user, project and local settings, hooks and MCP servers
out of the run; the per-invocation `settings.json` is
`{"attribution": {"commit": "", "pr": ""}}`, so no commit or pull request
carries assistant attribution (the deprecated `includeCoAuthoredBy` flag is not
used). `--tools` exposes only the bare tool names behind the registered allow
rules — `Bash(git status:*)` exposes `Bash` — and `Agent`, `Task` and `Monitor`
are refused at registration, so a worker cannot start another agent or watch the
bus itself. No global setting is written and no credential is read —
authentication stays with the installed subscription, and `--bare` is never used.

Every composed prompt carries the worker id, its **registered role**, the
assigned worktree, that worktree's workflow root, the scope, and the standing
rules: no `Co-authored-by` or AI attribution, preserve others' work, never
review or approve work you authored yourself, no merge/deploy/live mutation, no
new agents, report blockers honestly, never bypass a denial.

The CLI is found by `--claude`, then `PATH`, then the highest installed VS Code
native binary (`~/.vscode-server/extensions/anthropic.claude-code-*/resources/native-binary/claude`).
The path must be a regular, owner-executable, non-group/world-writable file.

## Outcome rules

Success is explicit. A job is `done` only when the wrapper receipt shows exit
status `0` and the stream contains exactly one `init` event and exactly one
final `result` event, both carrying the assigned session id, with
`is_error: false`, a success subtype and non-empty result text. Anything else —
missing init, missing or duplicated result, absent `is_error`, malformed or
non-object JSON lines, a session mismatch, a nonzero exit — fails visibly with
the reason recorded per job. A broken job record fails that job and never stops
the supervisor. Records keep requested and actual model, timestamps, turns,
permission denials, stderr tail and the log path.

Stream fields are treated as untrusted shapes: the same key can hold a string or
an object depending on the event, so every nested read is typed. A wrong type in
an assistant `message`, a model id, or the final event's `permission_denials`,
`modelUsage`, `num_turns` or `usage` is recorded as a problem and fails the job
visibly — it never crashes reconciliation and never passes as a clean run.

**Denied tool calls are an execution outcome, not an execution failure.** The CLI
reports a denial three ways and all three are kept, each labelled by `source`:
a `system` event with `subtype=permission_denied` (whose `message` is a plain
string, with `tool_name`, `tool_use_id` and `decision_reason*`), an errored
`tool_result` block, and an entry in the final event's `permission_denials`.
Nothing is discarded as a duplicate, since each is separate evidence. Such a run
is `state: done` with `execution_verdict: "succeeded with denials"` and a
`denial_count`; that says the invocation completed and reported honestly, and
says nothing about whether the implementation is acceptable — review stays with
the lead. `models_observed` holds the ids the turns reported and drives
`model_mismatch`; `model_usage_ids` separately lists everything the final event
billed, which normally includes an auxiliary helper model beside the assigned
one and is not by itself a substitution.

## Recovery, cancellation and timeouts

The wrapper records both its own and the Claude CLI's PID and start time in
`child.json` before waiting, and writes `receipt.json` afterwards, so results
and process identity survive supervisor death. A dead wrapper never implies its
CLI exited. Recovery is evidence-based and never silently replays a job:

| Evidence for an in-flight job | Outcome |
| --- | --- |
| Receipt for this invocation | finalized from the receipt |
| Live wrapper with the exact recorded PID and start time | adopted, no second child |
| Wrapper gone, its CLI still running | `interrupted`, **unresolved** |
| Wrapper gone, records disagree with a live PID | `interrupted`, **unresolved**, nothing signalled |
| Leader gone but owned members remain in its process group | `interrupted`, **unresolved**, leftover PIDs listed |
| Wrapper gone with no receipt | `interrupted`, unresolved |
| Nothing, past the spawn grace window | `interrupted`, unresolved; whether a CLI ran is unknown |

An unresolved job holds its worker **and** one concurrency slot: no later job
can reuse that session until the lead clears it. `status` reports `held_slots`,
`unresolved_jobs` and each worker's `blocked_by`; `run --drain` exits with
`WORKERS_DRAIN_BLOCKED` instead of spinning.

```sh
python3 $W resolve --job <id>              # inspect; releases only if nothing owned is alive
python3 $W resolve --job <id> --terminate  # end the verified owned process, then release
```

`resolve` prefers a late receipt over an interruption guess, exits non-zero
while anything owned is still alive, and picks up session-start evidence so the
**next** job resumes the existing session instead of issuing a fresh
`--session-id` against a session that was already created.

`stop --job` cancels a queued job, or ends a running one after waiting briefly
for the wrapper's own identity record — CLI first, then wrapper, each only when
the spawn record, the child's self-report and `/proc` agree on PID, start time
and owner. It also captures session-start evidence, so cancelling a turn that
already opened the session still makes the next job `--resume` it. A mismatch
(including PID reuse) signals nothing and reports the job as unresolved. Only
the runner's own process groups are ever signalled; sessions you opened yourself
and the `bridge.py` adapter are untouched.

Cleanup is judged on the **whole process group**, not the leader alone. A tool
subprocess that ignores `SIGTERM` while its leader exits is not cleanup:
`terminate_group` enumerates the owned members, signals the group and each
surviving member, escalates to `SIGKILL`, and re-checks members that appeared
while it waited. It only signals a group whose leader is still verified as ours;
a non-empty group pins its id, but once the leader has exited the group cannot
be re-identified, so leftovers are listed and the job stays unresolved for the
lead to inspect rather than being signalled blindly.

A `--timeout` expiry ends the CLI's whole process group before the receipt is
written, so a timed-out job leaves no untracked invocation behind; if anything
owned survives, the job stays unresolved and blocks the worker.

## Service supervision

Run the supervisor as a user service so a shell exit cannot discard results:

```ini
# ~/.config/systemd/user/phorvex-workers.service
[Unit]
Description=Phorvex Claude worker supervisor
[Service]
ExecStart=/usr/bin/python3 %h/operator/workflow/coordination/workers.py run --concurrency 3
Restart=on-failure
RestartSec=5
[Install]
WantedBy=default.target
```

```sh
loginctl enable-linger "$USER"
systemctl --user daemon-reload && systemctl --user enable --now phorvex-workers.service
```

`stop --supervisor` sends `SIGTERM`; the loop finishes the current pass and
exits between passes, never inside a spawn window.

## Completion notices

With `--notify-lead`, a terminal job sends one reference-only message through
the **assigned worktree's own** `bus.py`, so the message carries that
worktree's `workflow_root`, with the worker's registered role and the given
`fix`/`campaign` subject. Notices are optional and never the only way to read
results: `status` and `result` are authoritative. Sends happen outside the state
lock, and each failure is persisted with bounded backoff (60 s doubling to a
900 s cap), so one unreachable bus cannot stall other jobs or hold the lock on
every pass. Delivery is at-least-once — a crash between the bus write and the
receipt update can duplicate a notice — and it is not exactly-once. A missing
bus CLI in the assigned worktree is reported as a notice error, never rerouted
through another worktree.

## Bounded real-CLI smoke test (lead)

1. `python3 $W register --worker smoke-1 --worktree "$PWD" --role implementer --model claude-opus-5 --effort high --allow-tool Read`
2. Write `/tmp/smoke.md`: "Print the current branch name and stop. Do not edit files."
3. `python3 $W enqueue --worker smoke-1 --key smoke-a --prompt-file /tmp/smoke.md --timeout 300`
4. `python3 $W run --once --claude /absolute/path/to/claude --no-notices`, then
   `python3 $W status --worker smoke-1` until the job is terminal; check
   `session_started: true`, `state: done`, `models_observed`, `model_mismatch:
   false`, empty `synthetic_models` and `effort_requested: high`. If the CLI
   rejects a flag (`--effort` included), the job fails with the CLI's stderr in
   `stderr_tail`.
5. Enqueue `--key smoke-b` and repeat step 4; confirm `resumed: true` and that
   `result` shows the session kept the earlier context.
6. Try a denied action (for example a prompt needing `Bash` while only `Read` is
   allowed): the turn should still return, with denials listed in `status`.
   Then `stop --job` a `hang`-like job and confirm `status` shows
   `session_started: true` and that the next job reports `resumed: true`.
7. `python3 $W result --job smoke-1:smoke-b`, then `python3 $W stop --supervisor`
   if a long-running supervisor was started.

Treat idle resumption, permission behaviour, flag acceptance and model identity
as unverified until observed in this run. `--bg` cannot be combined with `-p`,
and `--bare` requires API authentication; neither is used here. CLI reference:
<https://code.claude.com/docs/en/headless> (flags checked against 2.1.267).

## Stopping point

The current campaign stops when all current-tier PRs are delivered. Wait for
deployment and live verification before starting next-tier fixes. The runner has
no tier scheduler and cannot approve its own work.
