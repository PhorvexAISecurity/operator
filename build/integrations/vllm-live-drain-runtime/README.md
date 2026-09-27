# vLLM drain-v11 runtime delivery

This package prepares **one review-only** workload rollout. It combines the
reviewed vLLM 0.7.3 drain-v11 derivative (which already contains reset
acknowledgement), the existing dual-listener guardrail proxy, a Pod-scoped
operation ledger, and the current `vllm` Service. Running the renderer does not
publish an image, create credentials, or change a cluster.

## Current evidence and remaining authority

The 2026-09-27 09:40 UTC read retained in the private campaign runtime shows the
Ready vLLM container still uses official
`docker.io/vllm/vllm-openai@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2`.
The `vllm` Service selects `phorvex.ai/role=leader`; it does **not** select
`app=vllm` in the observed version. The derivative is not installed. A separate
read of that exact Pod's local Hugging Face cache found one snapshot revision
`b25037543e9394b818fdfca67ab2a00ecc7dd641` and `config.json` SHA-256
`ec0c1f5f875ad8bc1f78c5140c22dbdde1b55478442ad358e7a4d9ecf947a327`.
These are snapshot/config identity, not a bytewise hash of every model weight.
The candidate pins both `--revision` and `--tokenizer-revision` to that revision.
The renderer derives `PHORVEX_MODEL_DIGEST` from the model name, revision, and
config hash; after rollout, the owner must verify that the new Pod loaded the
same pinned snapshot and config.

No immutable drain-v11 publication receipt exists yet. The published reset-only
image `phorvex@sha256:af3e5ce57d156c09533dde6bb7feab8f252ef3dbc3277b77c2baef4bd781897f`
cannot satisfy operation-bound request drain. The normal publisher in
`.github/workflows/publish-vllm-drain-v11.yml` is source-commit keyed,
main-only, refuses an existing tag, builds the exact linux/amd64 derivative,
and emits a digest/recipe receipt. It must run and its original artifact must be
reviewed before rendering a deployable candidate.

## Normal workload-owner sequence

1. Publish on reviewed `main` with **Publish vLLM operation-bound drain v11
   image**. Confirm its receipt's source commit, immutable index digest,
   linux/amd64 platform, base digest and all eight recipe-file hashes. Verify
   the resulting platform manifest/image ID separately before admitting the
   running Pod. The publisher does not deploy.
2. Read exact current `vllm/vllm` Deployment, `vllm/guardrail-proxy` ConfigMap,
   `vllm/vllm-defense` policy, and `vllm/vllm` Service originals. Record each
   original SHA-256. Re-read if any UID, resourceVersion, selector, image,
   source ConfigMap or policy changes. The renderer refuses a changed original
   workload/source/model route or publication recipe.
3. Run `render.py` with those originals, the published JSON receipt and its
   hash, and the two snapshot values above. Supply **names only** for the
   workload Secret `vllm-control`, operator Secret `vllm-serving-admin`, and
   TLS name `vllm-admin.vllm.svc`. Example arguments:

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
5. Install the reviewed source ConfigMap, Secrets, secure operator binding,
   and Deployment through the workload owner's normal deployment path. The
   derivative runs vLLM on loopback `8001` with `VLLM_API_KEY`; one guardrail
   process serves public inference on `8000` and private TLS control on `8443`.
   An init container writes `origin.json` and `ledger.json` once into a
   Pod-scoped `emptyDir`, bound to the downward Pod UID. The guardrail uses the
   same volume; `PHORVEX_DRAIN_V11=1` is set in both containers. The proxy and
   engine source annotations match the coordinator's configured source IDs.
   Confirm new Pod Ready, exact platform image ID, model revision/config,
   proxy source hashes, ledger origin, public benign inference, and private
   authenticated capability before changing the Service selector.
6. Only after the new Pod is Ready, apply the candidate Service selector that
   retains the existing `phorvex.ai/role=leader` predicate and adds
   `phorvex.ai/serving=true`. Verify a sole owned EndpointSlice target and the
   Service UID/selector. Never apply the Service change first: that would
   remove the old Pod from serving endpoints. Preserve the old protected
   KV journal as an UNKNOWN historical attempt; do not delete or relabel it.
   A new Pod creates a separate Pod-scoped operation ledger. A first request
   drain remains subject to the actuator's fresh capability, policy, route,
   cost and source gates.

The current vLLM Deployment and proxy ConfigMap have no checked-in GitOps owner
in this repository; prior managed fields show direct workload patches. These
candidate files therefore need adoption by the normal workload owner. This
package deliberately has no apply command or automatic rollout. Root/DevOps can
review and execute the source-pinned normal delivery without editing an
undocumented private file.

## Result limits

The current Live console `request-drain` path creates one synthetic
`DenialOfWallet` SecurityEvent and explicitly records **response-only**. It
launches no bounded in-flight request producer and has no original admission,
abort/quiescence, reopen, or benign-continuity reader. A working drain backend
therefore removes a real actuator prerequisite but cannot by itself turn that
Live row into a behavioral `DEFENDED` or `LANDED` outcome. The next console
repair must retain a bounded original inference request and independently
read the v11 operation receipt plus the same-request outcome. Do not claim a
full defense from a Service selector, capability response or SecurityEvent.

Local controls:

```sh
python3 -m unittest -v build/integrations/vllm-live-drain-runtime/test_integration.py
(cd build/integrations/vllm-0.7.3-drain-v11 && python3 verify_recipe.py && python3 -m unittest -v test_recipe.py)
(cd build/test-harness/guardrail && python3 -m unittest -v test_drain_v11.py)
```

The last suite needs `httpx` and FastAPI in its Python environment. The renderer
suite includes a dependency-free init-container import/ledger proof, source
receipt drift negatives, current selector preservation, and no-Secret output.
