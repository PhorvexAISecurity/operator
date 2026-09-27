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
source SHA-256 is `c378d172483887270514f2ead600f7c4b8e1ad4928cdead9348ca11e46a90010`.
The memory rule is an
optional ConfigMap named `voice-memory-policy` in namespace `voice`; mount its
directory read-only without `subPath` at `/etc/phorvex/voice-memory-policy`.
The single key `rule.json` is canonical compact sorted UTF-8 JSON and follows
`phorvex/internal/voicememorypolicy/contract.go`. The operator appends up to 32
exact caller/note-digest entries and increases revision. No HTTP rule mutation
exists in the bot.

Mount a Pod-local `emptyDir` at `/var/lib/phorvex-voice-memory`, owned by the bot
UID and mode `0700`, so the fsynced revision ledger survives a container restart
within the Pod. Supply `POD_UID` through the Downward API. The default optional
mode allows the rule to be absent before first activation; in that state memory
behavior is unchanged and state readback returns 503. The reviewed rollout sets
`VOICE_MEMORY_POLICY_REQUIRED=true`. A new or replacement Pod then refuses
memory reads/writes and reports `/healthz` 503 until it reads the exact current
rule, even with a fresh ledger. Invalid rule bytes, a replayed revision, or
later rule loss also close memory reads and writes. Pod replacement must be
verified against the current rule before the actuator claims an effect. Other
values for this environment variable refuse startup.

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

`render_activation.py` prepares the normal rollout without contacting Kubernetes.
Give it fresh JSON snapshots of `voice/voice-bot` Deployment and
`voice/voice-defense` PhorvexPolicy, the exact installed bot image reference,
the approved immutable digest of that same running image, and one imageID for
each currently serving bot replica in a private JSON array. The renderer
requires all imageIDs to match that digest and pins the Deployment and init
container to it. The supplied numeric bot UID must be observed from the
installed runtime so the init container can chown the Pod-local ledger volume;
the renderer does not guess it. The event creator must be the actual
admission-stamped console ServiceAccount identity. Its token input is a
private, owned regular file containing 32–256 printable ASCII bytes without a
newline. The output directory must not exist and is created mode `0700`; all
four generated files are mode `0600`. The script never prints the token.

The rendered source ConfigMap is immutable and contains exactly `bot.py` and
`voice_memory_policy.py`; its name includes the reviewed source SHA prefix.
The mutable `voice-memory-policy` ConfigMap has one canonical rev0 `rule.json`
key and an exact Deployment controller owner reference. The token Secret has
the same owner. Create these three objects first, then apply the generated
JSON patch to the same Deployment incarnation. The patch tests Deployment UID,
resourceVersion, bot container name, and prior image before adding only the
new source/rule/token/state mounts, the Downward API UID and required-policy
environment, source/creator annotations, and the state-volume init container.
Existing Voice environment, Service, model, CRM, media, and probe settings are
preserved. If an object already exists or the patch preconditions fail, inspect
the live state and render again from fresh snapshots; do not overwrite a
current policy rule or repeat an ambiguous mutation. Verify every new Pod's
source annotation, `POD_UID`, `/healthz`, and authenticated rule state before
arming Fire. No deployment or policy mutation is performed by the renderer.

Run the source tests with
`python3 -m unittest discover -s build/integrations/voice-memory -p 'test_*.py'`.
