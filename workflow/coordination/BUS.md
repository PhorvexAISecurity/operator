# Coordination bus

The bus delivers files and prints notifications; it does not start or resume
an agent. The agent runner must surface notifications to an active turn.
Messages request transitions and point to authoritative workflow files; the
bus never owns current state, decisions or evidence.

## Layout

Tools and seed identities live in each branch's `workflow/coordination`. Runtime
inboxes, archives, sequence, active registry and bridge receipts live once under
the Git common directory at `phorvex-workflow/bus`; `bus.py layout` prints both roots.
Register new assigned identities with `bus.py register --agent <id>`. A standalone
non-Git harness uses its local coordination directory. The layout below describes
runtime data; these files are not committed with an issue.

```text
coordination/
  inbox/<agent-id>/
  archive/<year>/
  AGENTS.yaml
  BUS.md
  bus.py
```

## Message schema

```yaml
schema_version: 2
id: 000001
created_at: UTC
from: agent-id
to: agent-id
subject:
  kind: fix
  id: T1-M160
role: skeptic
state_from: IMPLEMENTED
requested_transition: DIFF_REVIEW_PASSED
needs_reply: true
subject_line: one-line summary
refs:
  - fixes/T1-M160/04-diff.patch
  - fixes/T1-M160/05-evidence.md
workflow_root: /path/to/issue-worktree/workflow
```

`subject.kind` is one of `fix`, `intake`, `issue`, `release`, or `campaign`.
The CLI still accepts `--fix` as a compatibility shorthand for
`--subject-kind fix --subject-id ...`; archived schema-v1 messages remain
valid and are not rewritten.

The body contains questions or a concise outcome. Raw logs stay in evidence
artifacts in the owning issue branch. Resolve refs/status using `workflow_root`,
not the recipient's unrelated checkout. Historical messages without that field
retain their original bootstrap-workflow context.

## Safety properties

- Sender and recipient must be registered and differ.
- Sequence allocation is locked.
- Message content is written to a temporary file, fsynced, then atomically
  renamed into the inbox; monitors never see a partial file.
- Reading is non-destructive.
- Archiving requires an explicit acknowledgement and records the reader.
- A message cannot change `STATUS.yaml`; the assignee validates and performs
  the requested transition.
- Monitors notify only on a new filename and survive inbox count decreases.

## Context recovery

After restart:

1. read the assigned subject's authoritative status;
2. list the inbox and handle pending messages, then acknowledge them;
3. perform its `next_action` if owned;
4. read archive history only when a current artifact references a message.

Run `bus.py monitor --agent <id> --existing` through the runner's background
task facility and consume its output while working. `--existing` reports
messages already pending at startup. Starting from the newest filename skips
those messages. A successful send proves delivery to an inbox, not that the
recipient has acted; use acknowledgements, replies and subject status to
establish progress. Do not promise unattended handoffs without a runner that
actually resumes the recipient.

## Runner handoff

`monitor` now includes pending messages by default; `--new-only` is an explicit
opt-out. Use streaming monitors only with a facility that surfaces each line.
For runners that report only command completion, use
`bus.py wait --agent <id> --timeout 45`: it returns on pending mail or timeout,
never acknowledges, and must be reissued while an authorized handoff is pending.
Do not end a turn awaiting a peer and assume a detached shell will resume it.

For an installed Codex CLI supporting `queue --thread`, run the durable adapter:

```sh
python3 workflow/coordination/bridge.py run --agent <id> --thread <existing-thread-uuid> --codex /absolute/path/to/codex
python3 workflow/coordination/bridge.py status --agent <id>
```

Supervise it with the local service manager (`Restart=on-failure`). One process
owns each inbox adapter; its thread binding, heartbeat, retry state and queue
receipts live in the shared bus root's `.runtime/`. Restarting scans all pending
mail, retries failed queues and preserves successful receipts. To rebind a new
conversation, stop the adapter, retain its old runtime JSON, then start with the
explicit new thread ID. Never infer a target from the most recent session.

The adapter batches pending files into one wake and waits for acknowledgement
before queuing another. On wake, drain the WHOLE current inbox, including later
arrivals. Unhandled remainder gets a new wake after the earlier batch is handled.
This reduces redundant turns without deleting messages or auto-acknowledging work.

The adapter queues references to the existing thread; it does not launch a
second agent, copy message bodies into user instructions, acknowledge messages,
or grant permissions. Ambiguous failures can duplicate a notification; handling
must be idempotent. **File delivered → CLI queued → agent handled/acknowledged**
are separate states. A fresh adapter heartbeat is not proof the model is awake.
At setup, test a peer challenge/reply through the runner, including resumption
after a turn ends. Report idle resumption as unverified until actually observed.

The migrated legacy bus and its historical agent-specific instructions are
retained under `archive/coordination-v1/`.
