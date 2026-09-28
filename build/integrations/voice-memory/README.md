# Voice memory-note revocation hook

This package starts from the installed Voice `/app/bot.py` (original SHA-256
`23b2e6e72912b11a545e06f54af4159789dc3a79f0aaed74cd2ec636cbb371cf`).
The added hooks affect the existing Mongo `caller_memory` recall/remember path
and the `issue_refund` callback. They do not authenticate caller IDs or undo
the first contaminated call.

The memory/refund feature hashes these two files at `/app/bot.py` and
`/app/voice_memory_policy.py`. The active process freezes
`SHA256(bot.py bytes || NUL || voice_memory_policy.py bytes)` at import. Keep the
existing `/ws` Service and model/provider configuration. The reviewed composite
source SHA-256 is `25fd02b6710f1d687a1c71ba4caf142afcbf57d86c662aef66cf39e7ff370f95`.
The memory rule is an
optional ConfigMap named `voice-memory-policy` in namespace `voice`; mount its
directory read-only without `subPath` at `/etc/phorvex/voice-memory-policy`.
The single key `rule.json` is canonical compact sorted UTF-8 JSON and follows
`phorvex/internal/voicememorypolicy/contract.go`. The operator appends up to 32
exact caller/note-digest entries and increases revision. No HTTP rule mutation
exists in the bot.

The separate `voice-refund-policy` ConfigMap has the same canonical top-level
rule keys and owner/source bindings. Its entries contain exact SHA-256 digests
of the asserted caller and CRM order ID plus operation ID; up to 256 entries
fit within 65,536 bytes. The bot checks the pair before its CRM refund POST.
The denial applies to ordinary and test sessions; other caller/order pairs
remain available. The projected directory is required in the reviewed rollout,
and `VOICE_REFUND_POLICY_REQUIRED=true` makes a missing, corrupt, or replayed
rule fail closed for refund writes and `/healthz`.

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
The same token protects `GET /v1/voice-refund-policy/state`, which returns only
source, owner, rule, revision, operation, entry count, and readiness.

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
five generated files are mode `0600`. The script never prints the token.

The legacy memory-only rendered source ConfigMap is immutable and contains
exactly `bot.py` and `voice_memory_policy.py`. For the combined MCP/output
activation, one immutable ConfigMap contains exactly `bot.py`,
`voice_memory_policy.py`, `voice_output_policy.py`, and `voice_mcp_policy.py`.
Its name binds the four files in that order with NUL separators. Separate
feature digests bind bot+memory, bot+memory+output, and bot+memory+MCP.
The mutable `voice-memory-policy` and `voice-refund-policy` ConfigMaps each have
one canonical rev0 `rule.json` key and an exact Deployment controller owner
reference. The token Secret has the same owner. Create these four objects first,
then apply the generated
JSON patch to the same Deployment incarnation. The patch tests Deployment UID,
resourceVersion, bot container name, and prior image before adding only the
new source/rule/token/state mounts, the Downward API UID and both required-policy
environment, source/creator annotations, and the state-volume init container.
Existing Voice environment, Service, model, CRM, media, and probe settings are
preserved. If an object already exists or the patch preconditions fail, inspect
the live state and render again from fresh snapshots; do not overwrite a
current policy rule or repeat an ambiguous mutation. Verify every new Pod's
source annotation, `POD_UID`, `/healthz`, and authenticated rule state before
arming Fire. No deployment or policy mutation is performed by the renderer.

`--agency-test-enabled` adds stable `VOICE_AGENCY_TEST_ENABLED=true` to the
reviewed rollout. Exact per-run `agencyRunId`, deterministic call SID, and
run-derived synthetic caller A are carried in the direct WebSocket start frame.
Only a run-owned CRM order can pass the test-session refund scope, and the bot
stores private digest-only refund/read callback receipts. This test restriction
does not authenticate the caller and is separate from the refund policy action.

The combined activation requires fresh, explicit memory/refund ConfigMap and
protected journal inventories. An absent ConfigMap is represented by JSON
`null`; an existing nonzero rule or pending journal fails locally because its
source and operation lineage cannot be reset during this rollout. The current
read-only cluster inventory found all four rule ConfigMaps absent. Joint
activation adds a required MCP rule and a two-phase output rule ConfigMap:
create output `rule.json` with an empty `configMapUID` (the app stays unready),
then use `bind_output_uid.py` against the created ConfigMap's fresh UID and
resourceVersion to patch only that UID field. Create separate private test
token Secrets for MCP and output sessions; neither token is an HTTP rule
mutation credential. The bot starts with `python3 -B /app/bot.py`.
The installed `MCP_URL` is fixed to the server's canonical endpoint
`http://mcp-server.mcp.svc.cluster.local:8000/mcp`. Signed clients refuse redirects;
the trailing-slash endpoint returns HTTP 307 and cannot supply reviewed tools.
The legacy `bot.py` default remains unchanged to preserve active source hashes;
the activated Deployment explicitly overrides it with this canonical URL.

For an existing activation, use `render_mcp_endpoint_migration.py` with a fresh
Deployment snapshot and its exact UID/resourceVersion. It emits only guarded
replacement of the existing literal `MCP_URL` environment value. Applying that
patch rolls the Voice pods while preserving Deployment UID, immutable source,
native rules, protected journals, Secrets, and all other template fields. Do not
rerun the full activation renderer to migrate a populated policy epoch.

Run source tests with a Python 3.11 environment containing the installed
Voice probe's `websockets.asyncio.client` dependency:
`python3 -m unittest discover -s build/integrations/voice-memory -p 'test_*.py'`.

For the separate Voice output Live console activation, render the exact
reviewed profile locally after the joint four-file source is frozen. Supply
the intended console's actual `-audit-source-url` and
`-audit-source-server-dns` values; the profile binds their concatenation,
which the console checks against its running audit transport identity. For
example, from this repository root:

```
python3 build/integrations/voice-memory/render_output_profile.py \
  --audit-source-url 'https://phorvex-phorvex-audit-source.phorvex-system.svc:8445' \
  --audit-source-server-dns 'phorvex-phorvex-audit-source.phorvex-system.svc' \
  --output-dir /path/to/private/voice-output-profile
```

The renderer recomputes the output source digest from the exact mounted
`bot.py`, `voice_memory_policy.py`, and `voice_output_policy.py` bytes and
requires it to match the joint activation renderer. It hashes the embedded
console probe and checks both fixed audio clips. It writes canonical
`profile.json`, an immutable `phorvex-system` ConfigMap containing that exact
profile, and an additive `console-values.yaml` fragment with the ConfigMap
name and profile SHA-256. Review the generated values against the installed
audit source and chart, provision the profile ConfigMap, then enable
`phorvex.console.voiceOutputLive` through normal chart delivery. Native
`phorvex.voiceOutput` and the application source/rule/journal/token bundle
must be installed and verified separately. The console route remains disabled
by default; producing these files does not change a workload or prove a
model disclosure, brain selection, or defended result.

Run the local renderer checks from `build/integrations/voice-memory` with
`python3 -m unittest -q test_render_output_profile.py`. The test refuses
source/clip drift and a mismatched audit URL.
