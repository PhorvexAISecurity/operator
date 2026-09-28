# Voice session admission wrapper

This separate entry point wraps the unchanged installed Voice ASGI app. It does
not alter the four `/app` files, existing rule bytes/revisions, journals, model
context, provider routing, processors, or application callbacks. Run exactly
`python3 -B /opt/voice-admission/entry.py`, working directory `/app`.

The new mutable `voice/voice-session-admission-policy` has ten canonical keys:
`version`, `deploymentUID`, `securityPolicyUID`, `wrapperCMUID`,
`admissionSourceSHA256`, `legacyBundleSHA256`, `authProfileSHA256`, `revision`,
`mode`, `operationId`. The only transition is observe/revision 0/empty operation
to require-twilio-signature/revision 1/decision-bound operation SHA. Duplicate,
unknown, noncanonical, oversized, future, stale, foreign-owner or replayed rules
fail closed. Every new handshake and forwarded start reads the authoritative
single ConfigMap; a 250 ms poll drives active cancellation. Runtime RBAC grants
only GET of that named ConfigMap, using verified Kubernetes API TLS. It cannot
write a rule and does not rely on projected-volume propagation.

The immutable wrapper ConfigMap contains exactly `entry.py`, `policy.py`, and
canonical `auth-profile.json`. Code SHA is SHA256(entry bytes + NUL + policy
bytes). The name suffix hashes those two files plus NUL plus profile bytes.
The legacy bundle order is bot.py, voice_memory_policy.py,
voice_output_policy.py, voice_mcp_policy.py, joined by NUL. The seven profile
keys are version, deploymentUID, publicHost, websocketSigningURLs,
webhookSigningURL, twilioSecretName, authTokenSHA256. The wrapper privately
compares the fingerprint with the already-present `TWILIO_AUTH_TOKEN`; no
provider Secret API read, copied credential, signing endpoint or test exemption
exists. Native authority separately verifies the exact existing Secret reference.

The official Twilio 9.8.4 RequestValidator validates the pinned external URLs
`wss://voicebot.phorvex.ai/ws` and `https://voicebot.phorvex.ai/`. Incoming Host
and forwarding headers cannot select signing authority. Raw paths must be
exact, queries are unsupported, and duplicate signature headers fail. Webhook
validation includes all form values, including duplicate/blank fields; the
original body is replayed to the delegated handler without rewriting. These
checks follow [Twilio's validation guidance](https://www.twilio.com/docs/usage/security)
and [Media Streams signature requirement](https://www.twilio.com/docs/voice/media-streams).
Only the reviewed single signing URL is supported. Twilio documents a possible
trailing-slash variation; supporting it requires a separately reviewed profile
and compatibility test. Local controls are owner-generated production-verifier
signatures, not a telephone-leg or stolen-signature replay-protection claim.

Every accepted WebSocket registers a server UUID before delegate accept/reads.
Pending unsigned requests are included in cancellation. Immediately before
forwarding start, the wrapper rereads the rule and gates under the registry
lock. Enforce stops unsigned output, injects websocket.disconnect and awaits
the actual delegated app's completion. It never cancels the outer delegate to
manufacture completion. Network sends race against the session stop event;
network backpressure never holds the shared registry lock. A send already in
flight before activation may finish; settled state requires delegation to end.
Known-authenticated established sessions survive activation and transient policy
read/receipt failures. New setup fails closed while authority is unavailable.

The per-process state endpoint `/v1/voice-session-admission/state` uses the
existing memory-state bearer file. It reports the frozen twenty-field contract,
including exact authority hashes, revision/operation, registry counts, and
settlement. Disconnect-delivered and delegate-completed counters are independent
bounded cumulative counts, not assumed equal. Settlement requires healthy
authoritative enforcement and zero remaining unsigned delegates. It proves local
session termination, not cancellation of already-submitted remote inference.

The passive installed Pipecat BaseObserver is appended through a PipelineTask
subclass. Original observers, pipeline order, parameters and handlers remain
intact. Exact provider-class/final-frame boundaries observe STT transcription,
model text/completion and TTS audio. No prompt, transcript text, audio, signature,
credential or raw caller is persisted. The seventeen-field provider receipt is
joined to the twenty-one-field session receipt using server UUID, run hash,
call-SID hash, Pod/deployment and source hashes. Received audio counts require
nonempty valid media for the admitted stream; sent counts require completed
ASGI delivery. First exposure freezes automatically only while unsigned and
active, all actual provider stages and wire audio are positive, and the locally
observed rule is healthy observe/0. No client request asserts those flags.

Private artifacts are under `/var/lib/phorvex-voice-memory/admission`:
`admission-session-UUID.json`, `admission-provider-UUID.json`, and one atomic
`admission-exposure-UUID.json` containing the immutable pair. Disk work is
coalesced/off-thread. `/v1/voice-session-admission/evidence?sessionID=UUID`
returns that complete frozen pair, or an error until its atomic commit exists.
`/v1/voice-session-admission/session?sessionID=UUID` returns current lifecycle
for exact native pre/post cancellation checks. Both endpoints use the same
state bearer. Current lifecycle preserves the original connected rule SHA/revision.

`X-Phorvex-Admission-Run` and start.customParameters.admissionRunId are bounded
`[a-z0-9]{8,24}` correlation metadata, never authentication; if both are supplied
they must match. Ordinary production sessions retain no persistent fixtures.
Known-enforced unsigned denial is cheap: no UUID, API read, registry entry or
receipt write. Pending sessions cap at 128 with a 240-second first-frame bound;
run evidence groups cap at 256. Completed non-exposure groups are pruned toward
128; active and frozen exposure stay protected. Owned cleanup may delete exact
completed run files after archival/native settlement; the wrapper then reclaims
the corresponding completed in-memory entry. At protected capacity, additional
evidence-bearing setup is refused instead of growing storage.

## Preparation and delivery

The SDK-only overlay starts from the exact current pipecat image digest. It adds
only the hash-pinned official twilio wheel with `--no-deps`, offline; build checks
assert every prior distribution version and every `/app` file hash unchanged.
RequestValidator needs only standard-library imports. The manual main-only
publication workflow uses ECR ImageNotFound structure to prove tag absence,
refuses replacement, verifies published digest and uploads a source-bound receipt.
Root owns dispatch/publication and installation; recipe preparation is local.

`render_activation.py` reads private fresh Deployment, legacy source, security
policy, Ingress and canonical profile inputs. It emits only new source/RBAC
objects first. After root creates and freshly captures the wrapper, it emits a
new observe/0 policy. After root creates and captures that policy UID, it emits
a UID/RV/whole-old-template guarded patch with the reviewed overlay digest.
The patch adds only wrapper authority/env/mounts, command/workingDir/image and
GET-only reader serviceaccount, preserving all inherited legacy fields. The
renderer refuses already activated input; it cannot reset an enforced epoch.
Never rerun the old all-policy activation renderer for this migration.

Root must capture complete before/after legacy source/rules/Secret identities
and hashes, protected journals and stored verdict history; `verify_runtime.py`
checks listed Kubernetes protected bytes privately without printing values.
It does not discover omitted objects or prove stored history/runtime behavior.
Native source attestation and authenticated every-serving-Pod state are separate
requirements. Recheck original memory rev2 exclusion and legitimate signed
context after rollout. This implementation has no live Fire or defense claim.

## Focused checks

Use a local environment with Twilio9.8.4, FastAPI0.115.6 and Pipecat0.0.94:
`python -B -m unittest test_policy test_runtime test_render_activation test_verify_runtime test_pipecat_teardown -v`.
Prepare the pinned wheel before `test_recipe` so its real-wheel test is not skipped.
The real Pipecat teardown test compiles the unchanged legacy disconnect handler,
uses the actual transport/task/runner/serializer, and observes a managed local
producer terminate while a signed producer continues. It makes no remote calls.
Read-only installed module SHAs matched the test transport, task and BaseObserver:
`172f8c83a1ae75dfaaf34f0da96500a78f1450c842c9ecf7d0c63afaceb7fdde`,
`8be344ed20866d739ddef60c61fdf6cc80763bd0284050c0cadbfdffdbe28c75`,
`cfcd7682ef65af1b5996bffaa1985c1f4347aa5576709ee4fc1f14251ae6f136`.
Independent actual provider-class propagation/wrong-origin controls live in the
private campaign evidence bus and must be bound to the final wrapper SHA.
