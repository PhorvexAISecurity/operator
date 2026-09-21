# vLLM 0.7.3 reset and drain-v11 derivative

This directory contains the complete source delta for the vLLM part of the
operation-bound drain v11 contract. It applies only to official vLLM tag `v0.7.3`,
commit `ed6e9075d31e32c8548b480a47d1ffb77da1f54c`, and the six source hashes in
`manifest.json`. The applier refuses unknown or mixed source trees.

The derivative preserves the acknowledged prefix-cache reset endpoint and adds
an authenticated drain protocol for the V0 frontend-multiprocessing engine.
The supported mode is exactly one virtual engine, pipeline parallel size one,
scheduler steps one, and the stock `vllm.core.scheduler.Scheduler`. Other modes
report an unsupported capability and keep drain admission closed.

Drain messages use the same ordered input stream as generation. Begin closes
admission before snapshotting waiting, running, swapped, and cached work, then
aborts the exact snapshot. Observe returns a fresh queue state with a monotonic
sequence and caller nonce. Reopen requires two distinct zero-queue
observations. A frontend lock orders admission closure with request submission.
The first authenticated begin after an engine boot adopts the proxy ledger's
positive generation. Later begins in that same boot require the exact next
generation. This lets a fresh engine supersede durable history without allowing
generation reuse within one engine incarnation.

The proxy does not trust a cached terminal receipt after an engine restart. A
terminal status is re-bound to the current engine boot, operation identity,
generation, admission generation, admission state, snapshot, and terminal
dispositions. Lost reopen responses are recognized only from the same ordered
engine stream: the same boot and generation must report open admission with no
current operation. Any unavailable, stale, or mismatched state fails closed.

The internal routes `/phorvex/drain/{capability,begin,observe,reopen}` require
`PHORVEX_DRAIN_V11=1` and the normal vLLM API bearer token. Enabling this image
alone is unsupported. The complete deployment also needs the proxy coordinator,
its separately initialized Pod-scoped `emptyDir`, a downward-API Pod UID,
immutable source/model digests, and shared secret-backed credentials. The
legacy guardrail transform does not enable drain v11.

Build from this directory:

```sh
docker build -t REGISTRY/phorvex-vllm:v0.7.3-drain-v11 .
```

The base is the observed Docker v2 `linux/amd64` manifest for official tag
`v0.7.3`, pinned as
`vllm/vllm-openai:v0.7.3@sha256:4f4037303e8c7b69439db1077bb849a0823517c0f785b894dc8e96d58ef3a0c2`.
`base-image-receipt.json` retains the registry manifest and config body hashes;
`verify_recipe.py` binds those hashes and the config platform to the Dockerfile
`FROM`, OCI base labels, and `manifest.json`. It can also verify the compact
receipt against retained raw registry responses with `--registry-manifest` and
`--registry-config`.

Only Python modules are replaced, leaving the base image's compiled CUDA and
extension ABI intact. The build verifies the recipe binding, installed
distribution version, pre-patch hashes, patch digest, post-patch hashes, Python
syntax, and focused contract controls. It writes the actual installed hashes
and Python cache tag to
`/opt/phorvex-vllm-drain-v11/runtime-receipt.json`.

For a checked-out upstream source tree, apply and test with:

```sh
python3 apply_patch.py --source-root /path/to/vllm
python3 test_contract.py --source-root /path/to/vllm
python3 test_drain_contract.py --source-root /path/to/vllm
python3 verify_recipe.py
python3 -m unittest -v test_recipe.py
```

The retained reset producer control demonstrates the original and corrected
reset acknowledgement:

```sh
python3 producer_control.py --source-root /path/to/unmodified/vllm
python3 producer_control.py --source-root /path/to/patched/vllm
```

The CPU controls execute patched producer methods with substituted transport and
scheduler objects. They prove ordering, parsing, replay identity, and
supported-mode refusal. They do not prove GPU cancellation, allocator release,
or deployed multi-container lifecycle behavior; those require live controls
against the exact built image and Pod incarnation.
