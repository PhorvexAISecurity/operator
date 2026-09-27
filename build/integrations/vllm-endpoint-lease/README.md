# vLLM endpoint-lease activation package

This offline renderer prepares an **explicit, default-off owner activation** for
the existing vLLM workload. It does not call Kubernetes, ECR, inference, the
manager, or a customer client. Running it never enables endpoint-lease mode.
The old `endpoint-rotate` route effect, current callers, vLLM engine image,
reset/drain operation, and other serving bindings remain separate authorities.
The package cannot establish a defended result; an installed policy, normal
brain selection, native CAS, actual A-401 and B-200 controls are still needed.

The contract is the reviewed `endpoint-security-design-20260927/WIRE-API.md`.
The exact source closure is, in order, `guardrail_proxy.py`, `dual_server.py`,
`endpoint_lease.py`, `drain_v11.py`, `drain_v11_init.py`; its SHA-256 is computed
over the five UTF-8 file byte strings separated by one NUL. The fixed
`vllm/guardrail-proxy` ConfigMap keeps that name for existing guardrail profile
compatibility, has exactly those five keys, and becomes immutable. An already
immutable ConfigMap with different bytes is refused. There is no versioned
source ConfigMap swap in this candidate.

## Inputs and private output

All source and Kubernetes originals are local files supplied with an explicit
SHA-256 argument. JSON duplicate or case-aliased keys are rejected. `provision`
and `prepare` read private owner key and Secret files only when regular and
mode 0600. Every command refuses an existing output directory and writes an
explicit new private directory mode 0700 with files mode 0600; stdout contains
only filenames and SHA-256 hashes, never bearer or seed bytes. The owner must
independently assess key entropy and control distribution; a length/format
check does not prove unpredictability.

The owner key input is private mode 0600 JSON:

```json
{"schema":"endpoint-lease-owner-keys-v1","client-a":"<base64 bearer A>","client-b":"<base64 bearer B>","seed":"<base64 private seed>"}
```

`provision` takes `--owner-input`, `--owner-input-sha256`, and `--out`; it emits
immutable `vllm/phorvex-endpoint-lease-keys` with exact `client-a`, `client-b`,
`seed` keys and immutable `phorvex-system/vllm-endpoint-lease-callers` with only
`client-a`, `client-b`. These two Secret manifests contain raw secret bytes in
base64 and stay in the explicit private output only. The workload owner
provisions them through its normal private Secret path, retains original
one-dispatch create receipts, and reads the installed Secrets privately. No
Secret is committed, placed in a ConfigMap, annotation, profile, or console
response. There is no anonymous or A fallback after opt-in; migration of every
legitimate caller to B is a separate owner gate.

The source manifest is a separately reviewed JSON object with exact fields
`schema=endpoint-lease-source-v1`, `sourceCommit=<full 40-hex commit>`, and
`files={<each of the five exact filenames>:<SHA-256>}`. The renderer checks
every source file byte against it. The image input to `adopt` is the **original**
normal `vllm-lease-proxy-publish-receipt.json` emitted by the reviewed
`build/integrations/vllm-lease-proxy-runtime` publisher, plus the exact local
recipe directory. The renderer checks its source-commit tag, immutable ECR
digest, linux/amd64 platform, dependency-only flags, direct command, fixed
base image, and all 11 recipe-file hashes. The dependency image intentionally
does **not** contain the five executable source files; the immutable source
ConfigMap and its independent five-file digest bind them separately. The
publisher build commit need not equal the earlier reviewed app source commit.
The engine is independently pinned to
`753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:5f80f90be83db84932e1bf70b8fe12ecc3d4f48ffc7b1131003707d8862bdb51`.
`adopt` checks it against the reviewed drain publication join and candidate
`vllm` container, then emits `ADOPTION.engineImage` for manager and console
approved-image configuration. It also requires engine loopback
`127.0.0.1:8001` and the `vllm-control/api-key` SecretKeyRef.
The owner must still verify the real publisher run and platform manifest.
No proxy-image receipt has been invented by this package. A plain `python:3.11-slim` image with
startup `pip install` is not an approved runtime image.

## Two UID-bound phases after provisioning

`prepare` requires the private original installed tenant and console Secret
GETs, each matching the owner key bytes and immutable UID; single-dispatch
create receipts bind both UIDs to the exact private provision manifests. It
also requires the current `vllm/guardrail-proxy` and `vllm/vllm` Service
originals, source manifest and file directory, and fresh (<15 minute)
single-dispatch exact-name 404 evidence for **both**
`vllm/phorvex-endpoint-lease-policy` and
`phorvex-system/phorvex-endpoint-lease-journal` in the same cluster UID.
Absence is not inferred from an empty file, a broad list, or a caller claim.
The absence evidence schema is:

```json
{"schema":"endpoint-lease-absence-v1","clusterUID":"<actual cluster UID>","namespace":"vllm","kind":"ConfigMap","name":"phorvex-endpoint-lease-policy","statusCode":404,"dispatchCount":1,"observedAt":"<UTC ISO-8601>"}
```

Use the corresponding namespace/name for the journal. `prepare` emits a
same-name immutable source ConfigMap **update candidate**, canonical initial
policy `state.json` with actual Service/Secret/source IDs and A/B HMACs, and
canonical protected empty `receipts.json`. The latter two are create-only and
have no invented UID. The owner installs the protected journal **before** the
durable policy, even though product mode remains off. Existing policy or
journal history is never reset or replaced. A lost/ambiguous create result
requires owner reconciliation; this renderer does not retry writes.

`adopt` requires raw installed GETs of those exact objects and the Secrets,
plus owner create receipts for journal and policy proving candidate request
hash, returned UID/RV and journal-before-policy order. It refuses changed
canonical initial state, journal history, source UID/digest, Secret UID,
Service UID/RV, or image/source authority. It also requires a SHA-pinned
six-file reviewed drain base candidate (`deployment.candidate.json`,
`configmap.candidate.json`, `service.candidate.json`, `values.overlay.yaml`,
`secret-contract.json`, `publication-join.json`) and a manifest with schema
`vllm-drain-base-candidate-v1` and the six exact file hashes. The base drain
candidate remains independently reviewed; this package does not modify its
renderer. Pass the exact dependency image recipe directory through
`--proxy-recipe-dir`; no proxy image or source authority is learned from an
event, browser request, or running Pod alone.

The output is an **unapplied** vLLM Deployment candidate, nonsecret
`ADOPTION.json` for the console profile emitter, and named proxy
ServiceAccount/Role/RoleBinding. The Role grants only `get` on the exact
tenant policy ConfigMap and tenant Secret; it grants no list/watch or manager
Secret read. The Pod disables automatic service-account token mounts and
projects token/CA/namespace only into the guardrail container at the standard
Kubernetes service-account path. The engine receives no proxy Secret-get
token mount. The Secret is a nonoptional read-only directory mount; the five
source files are nonoptional read-only `/src/<file>` subPath mounts. The
guardrail and initializer use the reviewed digest image; the guardrail runs
exact `python3 -B /src/dual_server.py` with empty args and no startup shell,
pip, or Python path override. Required lease env and Pod annotations contain
actual source, Service, policy, and Secret UIDs. Because the endpoint lease
changes `guardrail_proxy.py`, the candidate also updates the existing drain
`PHORVEX_PROXY_SOURCE` env and `phorvex.ai/drain-proxy-source` annotation to
that new single-file hash; the lease composite hash is tracked separately.
Both proxy containers run as UID/GID 10001. A Pod fsGroup of 10001 makes the
Pod-scoped drain emptyDir and projected read-only files available to them;
the renderer refuses a shared PVC or other unreviewed volume before adding
fsGroup, so it does not change shared model storage ownership. The engine
retains its own container user/image and receives no proxy token mount.
The existing drain engine
image, secure binding, resource request, and Service selector are preserved.

## Explicit enablement after owner adoption

`ADOPTION.json` is a review handoff, not a live readiness receipt. After a real
proxy-image publication and owner rollout, the manager's independent approved
source, proxy-image, and engine-image values must be set from the exact
installed source digest, published proxy digest, and `ADOPTION.engineImage`.
The native endpoint-lease gate stays off until those authorities and its
fixed policy/journal/Secret checks pass. In the existing `vllm-defense` brain
policy, add `endpoint-lease-revoke` as one ordinary eligible action while
preserving the existing eight actions, triggers, and objective; do not force
selection or replace the policy with an endpoint-only policy. Neither the
renderer nor this repository package edits that live policy.

The console profile emitter consumes `ADOPTION.json` plus fresh installed
policy, journal, source, Service, and Pod authority. Its separate chart switch
is `phorvex.console.endpointLease.enabled` with an immutable profile
ConfigMap and caller-Secret copy. The native chart switch is
`phorvex.endpointLease.enabled`. Both remain false until the owner completes
the reviewed migration and activates them deliberately. An A-401/B-200
comparison and the exact decision→native-operation→public-route evidence are
required for any outcome claim.

## Owner maintenance and outcome limits

This is a one-replica, one-GPU Deployment with zero surge. The owner must
coordinate a serving interruption, preserve exact original ConfigMap,
Deployment, Service and Secret authority, stop the old replica and verify its
endpoint absent before changing the mutable `guardrail-proxy` source; only
then install the immutable five-file source, protected journal, policy,
get-only proxy grant, and candidate Deployment in the order above. Do not
enable mode until the owner has migrated registered legitimate callers to B
and observed B-signed valid completions through the protected public Service.
Fresh Pod/image/source/Secret/policy UID, Service route, private status and
allowed control must be checked after rollout. Failure stays unavailable or
UNKNOWN; there is no automatic unrevocation of A, journal deletion, policy
reset, or claim that the first accepted A request was prevented.

Run the local controls with `python3 -m unittest -v
build/integrations/vllm-endpoint-lease/test_render.py`. These tests use
synthetic credentials and UIDs. No live activation was performed by this
package.
