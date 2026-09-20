# Report

## Claim

The deployed reset path can report local prefix-cache invalidation without an
allocator-confirmed completion result.

## Expected behavior

The exact boolean returned by the vLLM allocator must reach the vLLM HTTP
response, proxy response, and operator. Only an explicit, bounded,
unambiguous `success:true` may receive completion credit. Authentication and
the exact patched source must be verifiable before deployment.

## Observed behavior

Official vLLM 0.7.3 has a real boolean result at `LLMEngine.reset_prefix_cache`,
but `AsyncLLMEngine`, the V0 multiprocess engine/client, and the API endpoint
discard it. The API responds with an empty HTTP 200. The guardrail proxy then
turns any upstream HTTP 200 into `invalidated:true`, and
`httpKVTransfer.InvalidateLocal` accepts status alone, including HTTP 204.

The unchanged producer control records allocator `false` followed by the
original empty HTTP 200. This is a source-level completion gap; deploying the
unchanged image cannot close it.

## Reproduction and scope

- Operator base: `3d691f5fe15f706ae7cb962d6bdd3293be3196be`.
- vLLM tag/commit: `v0.7.3` / `ed6e9075d31e32c8548b480a47d1ffb77da1f54c`.
- Observed image: `vllm/vllm-openai:v0.7.3` at digest
  `sha256:4f4039589120397ce64231883a1b8a78e7bc83b2a8999c5951af0bd72f6eea79`.
- Scope: prefix-cache reset acknowledgement only. This does not establish
  physical erasure, GPU-wide sanitization, or scheduler quiescence.
- No cluster mutation was used for reproduction.

## Initial evidence

- `evidence/source-pins.txt`
- `evidence/producer-control.txt`
- `evidence/vllm-contract.txt`
- `evidence/proxy-parser.txt`
- `build/integrations/vllm-0.7.3-reset-ack/manifest.json`
