# Render the existing guardrail effect profile

`render_guardrail_profile.py` is an offline candidate renderer. It reads ten fresh,
one-dispatch Kubernetes **GET receipts**: `cluster` (`kube-system` Namespace),
`pod`, `service`, `endpointslices`, `source` (`vllm/guardrail-proxy` ConfigMap),
`policy` (`vllm/vllm-defense`), `manager` Pod, `console` Pod,
`console_replicaset`, and `console_deployment`. It never reads Secret objects,
calls Kubernetes, sends a Fire request, or changes a workload.

Each receipt is the JSON returned by the reviewed private transport, with
`args`, `rc`, `dispatch_count`, `finished_at`, and `stdout`. Capture the objects
within two minutes, retain their original bytes, and create a manifest of
relative receipt paths and SHA-256 hashes:

```json
{
  "schema": "guardrail-effect-inputs-v1",
  "inputs": {
    "cluster": {"path": "cluster.transport.json", "sha256": "<exact SHA-256>"},
    "pod": {"path": "pod.transport.json", "sha256": "<exact SHA-256>"},
    "service": {"path": "service.transport.json", "sha256": "<exact SHA-256>"},
    "endpointslices": {"path": "endpointslices.transport.json", "sha256": "<exact SHA-256>"},
    "source": {"path": "source.transport.json", "sha256": "<exact SHA-256>"},
    "policy": {"path": "policy.transport.json", "sha256": "<exact SHA-256>"},
    "manager": {"path": "manager.transport.json", "sha256": "<exact SHA-256>"},
    "console": {"path": "console.transport.json", "sha256": "<exact SHA-256>"},
    "console_replicaset": {"path": "console_replicaset.transport.json", "sha256": "<exact SHA-256>"},
    "console_deployment": {"path": "console_deployment.transport.json", "sha256": "<exact SHA-256>"}
  }
}
```

The owner can generate the digest rows mechanically from its retained receipt
files; review the manifest and pass its exact SHA-256 as a separate CLI pin:

```sh
python3 build/integrations/vllm-live-runtime/render_guardrail_profile.py \
  --input-manifest "$PRIVATE_CAPTURE/manifest.json" \
  --input-manifest-sha256 "$REVIEWED_MANIFEST_SHA256" \
  --context 'arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks' \
  --out "$PRIVATE_CAPTURE/guardrail-profile-candidate"
```

The command rejects stale or mixed captures, wrong UID/owner/route, a missing
sole Ready EndpointSlice, inactive policy, missing or altered files from the
reviewed four-file proxy/dual-listener/drain source, absent
Secret-backed `VLLM_API_KEY`, an unreviewed dual-listener command, and source
bytes that differ from the checked-in proxy/dual-listener files or the frozen
drain-source digests (also checked against local files after branch integration).
It derives the actual
runtime image IDs, source hashes, audit TLS route, event creator and native v9
guardrail journal name. It writes an immutable ConfigMap candidate, the exact
profile bytes, a JSON-valid-YAML additive values overlay, and input digests in
a new private directory. The overlay enables only the guardrail-effect child
and its profile source; it must be reviewed and installed through the normal
owner/Helm path. Do not apply the candidate ConfigMap separately if Helm creates
the same object.

The profile uses `captureCurrentJournal: true`, empty `activeVariant` and empty
`guardrailJournalUID`. At Fire, the existing runner re-reads and freezes the
current journal, variant and epoch; an absent journal can start generation one,
while an unresolved journal refuses. It also independently hashes the mounted
runtime source and checks authenticated audit and original guarded replies.
The current stock Pod and disabled console do **not** satisfy these conditions.
No output of this renderer is a Live defense result or an authorization to Fire.
