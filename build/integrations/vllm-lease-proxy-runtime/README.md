# Pinned vLLM endpoint-lease proxy dependency image

This image replaces the guardrail sidecar's startup `pip install` with a complete,
hash-locked Python 3.11 Linux/amd64 CPU wheel closure. It is default-off and is
not an activation manifest. The reviewed workload must mount the immutable
`vllm/guardrail-proxy` ConfigMap's exact five source files read-only at
`/src/guardrail_proxy.py`, `/src/dual_server.py`, `/src/endpoint_lease.py`,
`/src/drain_v11.py`, and `/src/drain_v11_init.py`, then run direct
`["python3","-B","/src/dual_server.py"]` with empty args. The image does not
contain application source, classifier weights, credentials, or mutable policy.

The Python base is the digest observed on the Ready guardrail sidecar. Root
package versions match the 2026-09-27 read-only Pod measurement retained at
`live-workloads-20260926/endpoint-security-design-20260927/PROXY-DEPENDENCY-CACHE-READ.json`.
Torch is the CPU-only PyTorch wheel. The 41-file wheel closure is locked by
version and SHA-256; the publisher downloads exactly those files from PyPI and
the official PyTorch CPU index, verifies all names and bytes, and performs an
offline Docker build with `--network=none`. The build runs `pip check` and
imports the real Torch/Transformers pipeline as both root and nonroot user.
Neither this import nor source-only tests prove that the two classifier models
load or are ready. Model revision pinning and any model-weight caching belong
to the reviewed application source and workload deployment.

The main-only workflow refuses an existing source tag, verifies the remote
digest and emits an `imageByDigest` receipt. Source merge, publication and
deployment are separate reviewed actions. Local verification needs Python 3.11:

```sh
python3 verify_recipe.py
python3 -m unittest -v test_recipe.py
python3 verify_wheelhouse.py requirements.lock wheelhouse.sha256 wheelhouse
```
