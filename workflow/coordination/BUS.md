# Coordination bus

The bus wakes participants and requests transitions. It never owns current
state, decisions or evidence; messages point to authoritative fix files.

## Layout

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
schema_version: 1
id: 000001
created_at: UTC
from: agent-id
to: agent-id
fix_id: T1-M160
role: skeptic
state_from: IMPLEMENTED
requested_transition: DIFF_REVIEW_PASSED
needs_reply: true
subject: one subject
refs:
  - fixes/T1-M160/04-diff.patch
  - fixes/T1-M160/05-evidence.md
```

The body contains questions or a concise outcome. Raw logs stay in evidence
artifacts.

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

1. read the assigned fix `STATUS.yaml`;
2. perform its `next_action` if owned;
3. inspect the inbox for additional requests;
4. read archive history only when a current artifact references a message.

The migrated legacy bus and its historical agent-specific instructions are
retained under `archive/coordination-v1/`.
