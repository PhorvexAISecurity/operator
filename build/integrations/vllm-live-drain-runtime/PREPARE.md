# Read-only vLLM drain rollout preparation

`prepare.py` takes an explicit Kubernetes context and the original, reviewed
drain-v11 publication artifact. It performs bounded `kubectl get -o json` reads
only; it cannot create a Secret, patch a workload, run Pod exec, publish an
image, or dispatch a workflow. It refuses an existing output path, creates a
private `0700` directory on success, and writes originals/candidates mode
`0600`. No bearer or Secret bytes are requested or stored.

The currently reviewed publication artifact is
`vllm-drain-v11-publish-receipt.json` from the second drain image publication
attempt. The CLI requires its exact SHA-256
`7061940333a1f3924458125a66721f7729ccdd9671af1d2a865c612f763cc40e`,
source commit `b8cc2e74507b3d26e2c7250269b26c5e040d1873`, recipe hashes,
linux/amd64 platform, and immutable image digest
`sha256:3534dec6b97c1b6e4042b3cb2987c6cf8c4d4e4167a833320e2f1b7f4135d050`.
Changing any of these requires a new reviewed source pin; the CLI does not
silently accept another artifact. The model snapshot revision and `config.json`
hash are the previously reviewed values in `prepare.py`; they still require
post-install verification on the new Pod.

Example, with the actual reviewed context and private artifact path supplied
by the workload owner:

```sh
python3 build/integrations/vllm-live-drain-runtime/prepare.py \
  --context REVIEWED_DEV_CONTEXT \
  --publication /private/vllm-drain-v11-publish-receipt.json \
  --out /private/new-vllm-drain-review
```

The CLI reads `vllm` Namespace; exact `vllm/vllm` Deployment,
`vllm/guardrail-proxy` ConfigMap, `vllm/vllm-defense` PhorvexPolicy and
`vllm/vllm` Service; the Deployment-selected Pod list and exact current Pod;
that Pod's controlling ReplicaSet; and EndpointSlices labeled for the `vllm`
Service. It requires one Ready Pod with an exact Pod→ReplicaSet→Deployment
controller chain and one Ready EndpointSlice target belonging to the same
Service UID. It re-reads the Deployment, source ConfigMap and Service and
refuses UID or resourceVersion drift. For the policy it requires unchanged
UID, generation, spec, labels, annotations, owner references, finalizers and
deletion state; routine status-only resourceVersion ticks are accepted. It
retains private exact policy bytes and hashes from both reads as
`original-policy.json` and `policy-after.json`. It then re-reads the current
Pod and refuses UID or resourceVersion drift there too. An ordinary Service selector that matches
the Deployment template uses the renderer's default route path. Only a
reviewed additional Pod-only `phorvex.ai/route-key` selector supplies the
current Pod/ReplicaSet/EndpointSlice route originals to the renderer; any
other selector mismatch refuses the candidate. A Ready EndpointSlice target
marked terminating or non-serving also refuses. Both route paths require the
current Pod's `vllm` and `guardrail` images and `guardrail-src` ConfigMap
volume to match the Deployment/source originals. The private manifest records each original's exact
bytes, hash, UID and resourceVersion. A failing read or ambiguous route emits
no candidate directory.

The CLI passes these originals and the pinned publication to the reviewed
`render.py`. Its output remains **REVIEW_ONLY**: candidate Deployment,
ConfigMap, Service and operator values; the non-secret Secret contract;
publication join; and original evidence. `secret-contract.json` names the
workload and operator Secret keys but does not contain their values. Review
the generated original/candidate diff and follow the maintenance transition
in [README.md](README.md): arrange distinct private credentials through the
normal owner channel, stop the old single-replica workload before changing
the mutable proxy source, verify the new Pod's image/model/source/ledger and
public/control behavior, and change the Service selector only after that Pod
is Ready. Re-read all UIDs and resourceVersions before any owner-applied
mutation. Keep the old KV journal as an UNKNOWN historical operation.

This preparation is neither an installed-backend receipt nor a defended Live
result. The opt-in console drain producer/profile is a separate step after
the backend and guardrail are installed and independently verified.

The fake-kubectl protocol and refusal tests run without a cluster:

```sh
cd build/integrations/vllm-live-drain-runtime
python3 -m unittest -q test_prepare.py
```
