# vLLM drain-v11 runtime delivery

This package prepares **one review-only** workload rollout. It combines the
reviewed vLLM 0.7.3 drain-v11 derivative (which already contains reset
acknowledgement), the existing dual-listener guardrail proxy, a Pod-scoped
operation ledger, and the current `vllm` Service. Running the renderer does not
publish an image, create credentials, or change a cluster.

## Protected ledger capacity and recovery

The ledger retains at most 64 operations. When all slots contain protected recent
proofs, capability withholds the next generation so native request-drain refuses
before withdrawing routing. An exact authenticated create response with HTTP 503
and `ledger_capacity` can instead be recorded as a request-bound rejection. Native
recovery then checks the same OPEN backend incarnation and unchanged generation,
restores only the owned Pod routing label, and confirms endpoint return. This is
availability recovery; it supplies no abort or defense credit. Existing 24-hour
retention remains unchanged: only OPENED proofs at least 24 hours old are eligible
for eviction when an accepted new operation requires capacity.

Lost responses, generic 404/503 responses, and unacknowledged rejection proofs
remain protected. Pre-fix unresolved receipts cannot be automatically reclassified
as definite rejections; availability recovery needs separately recorded manual
evidence and must preserve their unresolved journal. The journal serializes normal
native operations, but runtime reads and Kubernetes routing writes are not atomic
against an independent privileged backend client. A changed post-restoration
read retains the receipt and reports an unknown outcome without completion credit.

## Current evidence and remaining authority

The 2026-09-27 09:40 UTC read retained in the private campaign runtime shows the
Ready vLLM container still uses official
`docker.io/vllm/vllm-openai@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2`.
The initial `vllm` Service selected `phorvex.ai/role=leader`; it did **not** select
`app=vllm`. Later endpoint work added a Pod-only `phorvex.ai/route-key` to the
selected Pod and Service. Re-read the exact selector before each render. The
derivative is not installed. A separate
read of that exact Pod's local Hugging Face cache found one snapshot revision
`b25037543e9394b818fdfca67ab2a00ecc7dd641` and `config.json` SHA-256
`ec0c1f5f875ad8bc1f78c5140c22dbdde1b55478442ad358e7a4d9ecf947a327`.
These are snapshot/config identity, not a bytewise hash of every model weight.
The candidate pins both `--revision` and `--tokenizer-revision` to that revision.
The renderer derives `PHORVEX_MODEL_DIGEST` from the model name, revision, and
config hash; after rollout, the owner must verify that the new Pod loaded the
same pinned snapshot and config.

An immutable drain-v11 publication receipt now exists; its exact JSON bytes and
image digest must be reviewed against the current source before use. The published reset-only
image `phorvex@sha256:af3e5ce57d156c09533dde6bb7feab8f252ef3dbc3277b77c2baef4bd781897f`
cannot satisfy operation-bound request drain. The normal publisher in
`.github/workflows/publish-vllm-drain-v11.yml` is source-commit keyed,
main-only, refuses an existing tag, builds the exact linux/amd64 derivative,
and emits a digest/recipe receipt. Publication does not prove installed runtime.

The renderer stays strict by default: every existing Service selector field
must match the Deployment template. If the **only** mismatch is the selected
Pod's `phorvex.ai/route-key`, pass all three optional SHA-pinned originals:
that Ready Pod, its owning ReplicaSet, and the complete Service EndpointSlice
list. Exact Pod → ReplicaSet → Deployment owner UIDs, Pod selector labels, and
the sole Ready Service-owned endpoint must agree. The candidate copies only
that route-key into its template; it retains the original Service selector
and adds `phorvex.ai/serving=true`. Other mismatches still refuse.

## Normal workload-owner sequence

1. Publish on reviewed `main` with **Publish vLLM operation-bound drain v11
   image**. Confirm its receipt's source commit, immutable index digest,
   linux/amd64 platform, base digest and all eight recipe-file hashes. Verify
   the resulting platform manifest/image ID separately before admitting the
   running Pod. The publisher does not deploy.
2. Read exact current `vllm/vllm` Deployment, `vllm/guardrail-proxy` ConfigMap,
   `vllm/vllm-defense` policy, and `vllm/vllm` Service originals. If the Service
   selector has a Pod-only route-key, also read the selected Pod, its owning
   ReplicaSet, and all EndpointSlices labeled for that Service. Record each
   original SHA-256. Re-read if any UID, resourceVersion, selector, image,
   source ConfigMap or policy changes. The renderer refuses a changed original
   workload/source/model route or publication recipe.
3. Run `render.py` with those originals, the published JSON receipt and its
   hash, and the two snapshot values above. Supply **names only** for the
   workload Secret `vllm-control`, operator Secret `vllm-serving-admin`, and
   TLS name `vllm-admin.vllm.svc`. For this legacy four-file rollout, execute
   from the reviewed PR365 source checkout
   `440da58d6e965d7f885cd35e44faa510d383cfc8`. Current main has newer
   lease-capable proxy/dual bytes; its renderer deliberately refuses them
   rather than emitting a four-file candidate rejected by the guardrail
   profile. Example arguments:

   ```sh
   python3 build/integrations/vllm-live-drain-runtime/render.py \
     --deployment DEPLOYMENT.json --deployment-sha256 DEPLOYMENT_SHA256 \
     --configmap CONFIGMAP.json --configmap-sha256 CONFIGMAP_SHA256 \
     --policy POLICY.json --policy-sha256 POLICY_SHA256 \
     --service SERVICE.json --service-sha256 SERVICE_SHA256 \
     --publication PUBLISH-RECEIPT.json --publication-sha256 PUBLISH_RECEIPT_SHA256 \
     --workload-secret vllm-control --operator-secret vllm-serving-admin \
     --server-name vllm-admin.vllm.svc \
     --model-revision b25037543e9394b818fdfca67ab2a00ecc7dd641 \
     --model-config-sha256 ec0c1f5f875ad8bc1f78c5140c22dbdde1b55478442ad358e7a4d9ecf947a327 \
     --out PRIVATE_NEW_DIRECTORY
   ```

   For a Pod-only route-key, additionally pass **all six** arguments:

   ```sh
   --current-pod POD.json --current-pod-sha256 POD_SHA256 \
   --current-replicaset REPLICASET.json --current-replicaset-sha256 REPLICASET_SHA256 \
   --current-endpointslices ENDPOINTSLICES.json --current-endpointslices-sha256 ENDPOINTSLICES_SHA256
   ```

   `ENDPOINTSLICES.json` is the complete `kubectl get endpointslices -l
   kubernetes.io/service-name=vllm -o json` list, not one selected slice.

   The result contains candidate Deployment, ConfigMap, Service, additive
   serving-security values, a non-secret Secret contract, and a publication
   join. It emits no credentials. Keep the six candidate files together and
   review the full Deployment/Service diff against the originals.
4. The workload owner must bind two private credentials via its normal Secret
   mechanism, with distinct 32–256 byte `api-key` and `admin-bearer` values;
   `vllm-control` also supplies the TLS certificate/key for
   `vllm-admin.vllm.svc`. The operator binding consumes `bearer` and `ca.crt`
   from `phorvex-system/vllm-serving-admin`. The operator bearer must equal
   the workload admin bearer. Do not put either bearer in ConfigMaps,
   annotations, environment literals, review artifacts, or application logs.
   Merge the additive secure-required binding with any **current** serving
   bindings; do not replace other targets' configuration from this one-target
   overlay.
5. Use an owner-coordinated maintenance transition for the currently observed
   single-replica workload. Its `maxSurge: 0`, `maxUnavailable: 1` strategy does
   not require a second GPU, but replacing it interrupts serving. The current
   source ConfigMap is mutable and directory-mounted: applying new source while
   the old Pod runs creates a mixed-source interval. Stage the image and Secrets,
   stop the old replica, verify its serving endpoint is absent, then install and
   verify the reviewed ConfigMap. Complete and verify the manager's
   secure-binding rollout **before starting the replacement TLS-only Pod**.
   Read back the running manager's mode, exact vLLM policy UID,
   ServiceAccount binding, Secret/CA authority and new manager Pod identity;
   a values change or accepted Deployment update alone does not establish that
   the manager is using the binding. Keep the workload stopped if this
   verification fails. Then start the candidate Deployment at one replica.
   Keep the original ConfigMap and Deployment for rollback during the
   same stopped-workload transition. The PDB's zero allowed evictions does not
   make a Deployment replacement disruption-free. The derivative runs vLLM on
   loopback `8001` with `VLLM_API_KEY`; one guardrail
   process serves public inference on `8000` and private TLS control on `8443`.
   An init container writes `origin.json` and `ledger.json` once into a
   Pod-scoped `emptyDir`, bound to the downward Pod UID. The guardrail uses the
   same volume; `PHORVEX_DRAIN_V11=1` is set in both containers. The proxy and
   engine source annotations match the coordinator's configured source IDs.
   Confirm new Pod Ready, exact platform image ID, model revision/config,
   proxy source hashes, ledger origin, public benign inference, and private
   authenticated capability before changing the Service selector.
6. Only after the new Pod is Ready, apply the candidate Service selector that
   retains all exact original predicates, including a proven route-key, and adds
   `phorvex.ai/serving=true`. Verify a sole owned EndpointSlice target and the
   Service UID/selector. Never apply the Service change first: that would
   remove the old Pod from serving endpoints. Preserve the old protected
   KV journal as an UNKNOWN historical attempt; do not delete or relabel it.
   A new Pod creates a separate Pod-scoped operation ledger. A first request
   drain remains subject to the actuator's fresh capability, policy, route,
   cost and source gates.

The September 27 transition exposed why the manager-first order matters. The
new Pod's private listener was TLS on port 8443 before the secure manager
binding was running. At 13:45:20 UTC the old manager wrote a `dispatching`
KV-reset receipt with `servingLegacy:true`; the secure manager Pod started at
13:46:15. Legacy dispatch constructs an HTTP endpoint even for that Pod's
declared TLS control port. No trustworthy reset acknowledgement or terminal
effect was retained. The later secure manager cannot resume this legacy
receipt under its new binding, and recovery does not replay a `dispatching`
operation. Preserve the receipt as UNKNOWN and use a new Pod UID for a future
attempt. The current recovery log says the target left policy scope after it
discards the legacy binding error; that wording is a diagnostic follow-up,
not evidence that the reset failed or succeeded.

The current vLLM Deployment and proxy ConfigMap have no checked-in GitOps owner
in this repository; prior managed fields show direct workload patches. These
candidate files therefore need adoption by the normal workload owner. This
package deliberately has no apply command or automatic rollout. Root/DevOps can
review and execute the source-pinned normal delivery without editing an
undocumented private file.

## Result limits

The default legacy Live console `request-drain` path creates one synthetic
`DenialOfWallet` SecurityEvent and explicitly records **response-only**. It
launches no bounded in-flight request producer and has no original admission,
abort/quiescence, reopen, or benign-continuity reader. A working drain backend
therefore removes a real actuator prerequisite but cannot by itself turn that
Live row into a behavioral `DEFENDED` or `LANDED` outcome. The opt-in replacement
documented in [REQUEST-DRAIN-LIVE.md](../vllm-live-runtime/REQUEST-DRAIN-LIVE.md)
retains a bounded original inference request and independently reads the v11
operation receipt and that request's outcome. It requires separate reviewed
console profile activation after this runtime is installed. Its positive result
proves request-drain mechanics and continuity, not wallet-exhaustion prevention.
Do not claim a full defense from a Service selector, capability response or
SecurityEvent.

Local controls:

```sh
python3 -m unittest -v build/integrations/vllm-live-drain-runtime/test_integration.py
(cd build/integrations/vllm-0.7.3-drain-v11 && python3 verify_recipe.py && python3 -m unittest -v test_recipe.py)
(cd build/test-harness/guardrail && python3 -m unittest -v test_drain_v11.py)
```

The last suite needs `httpx` and FastAPI in its Python environment. The renderer
suite includes a dependency-free init-container import/ledger proof, source
receipt drift negatives, current selector preservation, private drain route
authorization, and no-Secret output.
