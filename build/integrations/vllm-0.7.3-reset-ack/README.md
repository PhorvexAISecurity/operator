# vLLM 0.7.3 reset acknowledgement derivative

This directory contains the complete source delta for the vLLM part of the
prefix-cache reset contract. It applies only to official vLLM tag `v0.7.3`,
commit `ed6e9075d31e32c8548b480a47d1ffb77da1f54c`, and the six source hashes in
`manifest.json`. The applier refuses unknown or mixed source trees.

The patch carries the allocator's existing boolean through both supported V0
frontends: the in-process wrapper and a correlated request/reply in the default
multiprocess frontend. Every multiprocess waiter is removed on success, false,
exception, timeout, or cancellation. The method's own `VLLM_RPC_TIMEOUT`
deadline covers both a stalled send and a lost reply; a late reply is dropped
after waiter cleanup. Existing multi-scheduler aggregation
retains false. The HTTP endpoint returns exactly `{"success": <bool>}`.

V1 is rejected during API-server startup because this scoped patch does not
alter V1 internals. The reset route is covered by the normal API bearer token,
and developer endpoints cannot start without `VLLM_API_KEY` or `--api-key`.
`VLLM_SERVER_DEV_MODE=1` remains required to expose the endpoint. The guardrail
transform requires `VLLM_API_KEY_SECRET_NAME` and optionally
`VLLM_API_KEY_SECRET_KEY` (default `api-key`), then mounts the same Secret key as
`VLLM_API_KEY` in the vLLM and proxy containers. The operator serving endpoint
must use that bearer token when it calls `/v1/kv/invalidate`.

Build from this directory:

```sh
docker build -t REGISTRY/phorvex-vllm:v0.7.3-reset-ack .
```

The base image is pinned by digest. Only Python modules are replaced, leaving
the base image's compiled CUDA and extension ABI intact. The build verifies the
installed distribution version, pre-patch hashes, patch digest, post-patch
hashes, Python syntax, and focused contract controls. It writes the actual
installed hashes and Python cache tag to
`/opt/phorvex-vllm-reset-ack/runtime-receipt.json`.

For a checked-out upstream source tree, apply and test with:

```sh
python3 apply_patch.py --source-root /path/to/vllm
python3 test_contract.py --source-root /path/to/vllm
```

The same producer control demonstrates the original and corrected result:

```sh
python3 producer_control.py --source-root /path/to/unmodified/vllm
python3 producer_control.py --source-root /path/to/patched/vllm
```

The reset acknowledgement confirms that vLLM's allocator accepted and
completed its synchronous reset call. It does not claim physical memory
erasure, GPU-wide sanitization, or scheduler quiescence.
