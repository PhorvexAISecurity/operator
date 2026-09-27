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
