# Verification

## Pre-registered test

- Claim: allocator `false` is lost before the current HTTP and proxy/operator
  completion decisions.
- Falsifier: the unchanged vLLM API emits explicit JSON false, or either local
  consumer rejects its empty/status-only response.
- Baseline: official vLLM commit and operator main pinned in `REPORT.md`.
- Positive control: run the same API producer with a patched wrapper returning
  false; require `{"success":false}` and no strict success confirmation.
- Source/deployment pins: `evidence/source-pins.txt`.
- Safety boundary: source and local controls only; no cluster or GPU mutation.

## Execution

- Ran the same `producer_control.py` against an archive of the exact upstream
  commit and a hash-verified patched archive.
- Ran five dependency-free contract tests against the exact patched method
  bodies, including true/false, engine exception/death, malformed/lost reply,
  timeout, cancellation, concurrent generation/reset routing, queue cleanup,
  in-process aggregation, API JSON, V1 startup rejection, and route auth.
- Ran the proxy acknowledgement parser against true, false, empty, duplicate,
  case-alias, trailing, non-object, wrong-type, and oversized responses.
- No ambient service or mutation was involved.

## Result

`PASS`. The baseline returned empty HTTP 200 after allocator false. The patched
positive control returned explicit JSON false. All focused vLLM and proxy
controls passed. Retained artifacts: `evidence/producer-control.txt`,
`evidence/vllm-contract.txt`, and `evidence/proxy-parser.txt`.
