# LiteLLM gateway runtime reuse

The reviewed LiteLLM gateway is a Python standard-library program. It does not
need a new dependency image. The already published, source-free vLLM lease
proxy runtime supplies Python 3.11 as nonroot UID/GID 10001. The LiteLLM owner
renderer overrides that image's default command with
`python3 -B /opt/phorvex/gateway.py` and mounts the merged gateway source from
an immutable ConfigMap. The image contains neither gateway source nor runtime
credentials. The exact image, source, recipe, and original publication receipt
are pinned in [image-contract.json](image-contract.json).

Run `python3 build/integrations/litellm-gateway-runtime/verify_reuse.py` and
`python3 -m unittest -v build/integrations/litellm-gateway-runtime/test_entrypoint.py`
for source and local protocol checks. The entrypoint test starts the actual
gateway process and a synthetic local upstream. It verifies private status
authentication, baseline admission, a projected policy update that revokes
only client A, and continued client C service without sending A upstream.
Existing gateway tests cover additional request and output behavior.

After this candidate is reviewed and merged to `main`, dispatch the existing
published-image verification path with
`gh workflow run verify-litellm-gateway-runtime.yml --ref main`. The manual
workflow uses the repository's existing ECR read role, pulls the **existing**
image by digest, and reruns the protocol tests with the source mounted
read-only, an unwritable root filesystem, no external network, dropped
capabilities, and UID 10001. Review its uploaded
`litellm-gateway-runtime-reuse-receipt.json` before supplying the pinned image
to the separate owner installation. This workflow does not build or publish an
image, alter the cluster, or inject credentials. If the actual-image check
fails, stop; this contract does not authorize substituting another tag.

## Opt-in gateway metrics candidate (M1a)

The candidate source now includes terminal request counters and latency
histograms on a separate GET-only listener, port 4003. Metrics are disabled by
default; enabling them requires actual namespace/pod name fields from the
Downward API. No extra Python packages or new image are needed. The candidate
source hash in the contract and manual verification workflow move together;
the previously published source-free runtime digest and provenance stay fixed.
This source contract is not an active deployment/source/profile binding.

The new `litellm-gateway-metrics.yml` PR workflow runs the source contract,
localhost enforcement/metrics tests and opt-in renderer tests on Python 3.11.
It also runs the gateway entrypoint in a fresh CI environment with metrics off
and on. The existing manual published-image verification must pass on merged
main before M1b. No workflow is dispatched by source preparation.

Prepare the installed-owner migration with
`build/test-harness/fixtures/litellm-live/render_metrics.py --enable-metrics`.
Its inputs are reviewed nonsecret Deployment/profile/NetworkPolicy snapshots,
verified Prometheus pod labels and a quiescent output policy when applicable.
It generates immutable source/profile candidates and a guarded patch, without
activation. Network policy inventory/enforcement and both gateway replicas'
source/runtime convergence must be proved in the later owner window. See
[coverage and release gates](../../../deploy/monitoring/APP-METRICS-COVERAGE.md).
Never reuse the legacy install/switch path as an upgrade, reset a live output
trial, change active values, or enable this monitor against old gateway source.

The actual-image verification job requires the reserved `phorvex-isolated-aws` executor label; stage 1 does not verify or provision that executor. The owner must provide approved isolated AWS capacity before dispatch. Never register the shared gateway/CI runner with that label. Hosted source/protocol checks remain separate and do not replace the merged-source image receipt.
