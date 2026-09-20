# Root-cause deduplication

## Search terms and anatomy locus

Searched `reset_prefix_cache`, `InvalidateLocal`, `success`, HTTP 200/204, and
the ACTUATION issue register. The path starts at the vLLM allocator result and
ends at Phorvex reset completion credit.

## Candidate comparison

M-178 is the same invariant and mechanism: vLLM prefix-cache reset receives
completion credit without an explicit backend acknowledgement. T14-M178 made
the direct operator client strict, while this follow-up closes the upstream
vLLM producer and the deployment-specific proxy/operator invalidation branch.
No other issue owns this allocator acknowledgement.

## Determination

`DUPLICATE`.

- Existing issue: M-178.
- Human ruling reference: not required.
- Rationale: same allocator operation, same lost boolean, and same prohibited
  completion credit; this is a remaining branch of the existing correction.
