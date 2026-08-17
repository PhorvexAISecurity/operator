# PHORVEXSEC-93 — kv-reset TTFT penalty measurement and cost-model integration

Date: 2026-08-17  
Branch: `measure/phvx-9d-kv-reset-ttft`  
Base: `v0.4.30` (`7d2be46275c3f19e0d6e8df48b486b0a8865b61f`)

## Outcome

`kv-reset` has a reproducible live-AWS time-to-first-token measurement and no longer
inherits the unvalidated generic serving-state prior.

| Metric | Result |
|---|---:|
| Paired samples | 20 |
| Cached TTFT, median | 325.196 ms |
| Cached TTFT, p95 | 327.853 ms |
| First post-reset TTFT, median | 1811.871 ms |
| First post-reset TTFT, p95 | 1828.527 ms |
| Paired reset penalty, median | **1486.686 ms** |
| Paired reset penalty, p95 | **1503.838 ms** |
| Median-penalty bootstrap 95% CI | **1484.418–1494.930 ms** |
| Positive paired penalties | **20/20** |
| Median TTFT multiplier | **5.572×** |

The measured dimensionless `C_flow` is `0.820526`: the paired median penalty divided
by the median first-post-reset TTFT. This expresses the fraction of post-reset latency
attributable to the reset penalty without mixing raw milliseconds into the existing
dimensionless objective.

## Environment

- AWS node instance type: `g4dn.xlarge`
- Serving pod: `vllm/vllm-65b5489974-ntw6p`, both containers Ready, zero restarts
- vLLM image and runtime version: `vllm/vllm-openai:v0.7.3` / `0.7.3`
- Model: `Qwen/Qwen2.5-7B-Instruct-AWQ`
- Model length: 4096; prefix caching enabled
- Phorvex policy: `vllm-defense`, active, `kv-reset` enabled, 90-second
  anti-over-rotation window

The benchmark used a direct localhost port-forward to vLLM port 8001. That isolates
the prefix-cache reset penalty from guardrail classification and proxy overhead.

## Method and interference controls

Each sample used the same 13,600-character benign prompt:

1. issue one request to populate the prefix cache;
2. measure a second cached streaming request to its first generated token;
3. call `/reset_prefix_cache`;
4. measure the first post-reset streaming request to its first generated token.

Before the accepted run, vLLM reported zero running and zero waiting requests. The
benchmark recorded the pod's `phorvex.ai/kv-reset-epoch` before and after; it remained
`45198878`, proving that no background Phorvex reset overlapped the accepted window.

An earlier exploratory 30-pair run was deliberately rejected because this epoch
changed during its measurement window. Its numbers were not used in the model or in
the table above.

Raw accepted evidence:

- `phorvex/benchmarks/kv-reset-ttft/aws-vllm-20260817.json`
- SHA-256: `28df12a50a6f479932da61543917ce239b799f18ef356433104d1788c123c1c3`
- Measurement start: `2026-08-17T10:05:35.779Z`
- Prompt SHA-256: `097b79b815f8d580bff0333b66298eb6d60a1fb16196b8a70ac0c4a35a866089`

## Implementation

### Reproducible benchmark

`phorvex/benchmarks/kv-reset-ttft/kv_reset_ttft.py` is a standard-library-only
runner that:

- requires explicit `--confirm-reset` acknowledgement;
- discovers the model or accepts an explicit one;
- reads the first non-empty generated SSE token, not response headers;
- preserves every paired sample in JSON;
- computes median, nearest-rank p95, and a deterministic 10,000-resample bootstrap
  interval for the paired median.

Its local fake-vLLM tests pin the warm/control/reset/cold call order, model discovery,
paired arithmetic, p95, and confidence-interval behavior.

### Cost model

`internal/cost/action_flow.go` now routes `kv-reset` to its own measured family.
`kv-migrate-invalidate`, `adapter-rotate`, and `guardrail-rotate` remain in the
explicitly unvalidated serving-state family; no evidence from this measurement is
silently transferred to them. The measured idle value is intentionally constant:
the code does not invent a load-response curve that this run did not measure.

The older `internal/console/perActionSeconds = 0.534` is unchanged. It prices measured
actuation compute in the ROI view; it is not a TTFT measurement and is not substituted
for this user-visible latency result.

## Verification

```text
python3 -m unittest discover -s phorvex/benchmarks/kv-reset-ttft -p 'test_*.py'  PASS (2 tests)
python3 -m py_compile phorvex/benchmarks/kv-reset-ttft/kv_reset_ttft.py          PASS
go test ./internal/cost                                                           PASS
go test ./...                                                                      PASS
git diff --check                                                                   PASS
```

## Honest scope

This is a causal paired measurement for one model, prompt shape, vLLM version, AWS
instance type, and idle serving condition. It is not a universal TTFT constant for
all models or hardware, and it does not characterize loaded-queue behavior. The raw
runner makes those future strata reproducible instead of extrapolating them now.
