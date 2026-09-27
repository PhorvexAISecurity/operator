# Voice memory-note revocation hook

This package starts from the installed Voice `/app/bot.py` (original SHA-256
`23b2e6e72912b11a545e06f54af4159789dc3a79f0aaed74cd2ec636cbb371cf`).
The added hook affects the existing Mongo `caller_memory` recall and remember
paths. It does not authenticate caller IDs or undo the first contaminated call.

For the normal Voice Deployment rollout, install these two source files together
at `/app/bot.py` and `/app/voice_memory_policy.py` from an immutable source image
or immutable ConfigMap. The active process freezes
`SHA256(bot.py bytes || NUL || voice_memory_policy.py bytes)` at import. Keep the
existing `/ws` Service and model/provider configuration. The reviewed composite
source SHA-256 is `885915d0a06f4ae4498922873b182c130a46551f27206a59d48db7569d3bf157`.
The memory rule is an
optional ConfigMap named `voice-memory-policy` in namespace `voice`; mount its
directory read-only without `subPath` at `/etc/phorvex/voice-memory-policy`.
The single key `rule.json` is canonical compact sorted UTF-8 JSON and follows
`phorvex/internal/voicememorypolicy/contract.go`. The operator appends up to 32
exact caller/note-digest entries and increases revision. No HTTP rule mutation
exists in the bot.

Mount a Pod-local `emptyDir` at `/var/lib/phorvex-voice-memory`, owned by the bot
UID and mode `0700`, so the fsynced revision ledger survives a container restart
within the Pod. Supply `POD_UID` through the Downward API. The rule is allowed to
be absent before first activation; in that state memory behavior is unchanged and
state readback returns 503. Invalid rule bytes, a replayed revision, or loss after
a valid rule has been seen closes memory reads and writes while ordinary media
continues. Pod replacement gets a fresh ledger and must be provisioned/verified
against the current rule before the actuator claims an effect.

Mount Secret `voice/voice-memory-state-token`, key `token`, read-only at
`/etc/phorvex/voice-memory-state-token/token`. It must contain 32–256 printable
ASCII bytes with no newline. `GET /v1/voice-memory-policy/state` requires that
Bearer token and returns only source/owner/rule identities, revision, operation,
entry count, and readiness. The route cannot reveal caller IDs or note digests.
Missing/invalid token makes readback unavailable. The actuator should reach only
the exact pinned serving Pod and independently join the echoed Deployment and
PhorvexPolicy UIDs to live Kubernetes resources.

After the real `/ws` code loads a caller's notes into its initial system context,
it writes a private digest-only receipt named
`context-<SHA256(call SID)>.json` in the same Pod-local directory. The caller and
note text are absent. The Fire reader must use exact Pod exec authority, bind
the run-owned call SID, and refuse if a receipt is absent; this receipt proves
which stored notes entered that context, not what the model did with them. The
fixed Fire script removes the Pod-local receipt after validating it and retains
a private console copy before emitting a test signal.

Run the source tests with
`python3 -m unittest discover -s build/integrations/voice-memory -p 'test_*.py'`.
