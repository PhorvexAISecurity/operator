# kv-reset TTFT benchmark

This benchmark measures the user-visible time-to-first-token (TTFT) penalty caused by
vLLM's `/reset_prefix_cache`, which is the serving-state operation behind Phorvex
`kv-reset`.

Each paired sample uses one stable long prompt:

1. issue a warm-up request to populate the prefix cache;
2. measure a second, cached request;
3. reset the prefix cache;
4. measure the first post-reset request.

The output includes raw pairs, median and p95 TTFTs, the paired penalty, and a
deterministic bootstrap 95% confidence interval for the median paired penalty.

Run the test harness:

```sh
python3 -m unittest discover -s phorvex/benchmarks/kv-reset-ttft -p 'test_*.py'
```

Run against a deliberately selected vLLM endpoint (for example, a local port-forward):

```sh
python3 phorvex/benchmarks/kv-reset-ttft/kv_reset_ttft.py \
  --base-url http://127.0.0.1:29183 \
  --samples 30 \
  --output result.json \
  --confirm-reset
```

`--confirm-reset` is mandatory because this benchmark intentionally clears live
serving state. Use the direct vLLM port to isolate the cache-reset cost from guardrail
classification and proxy overhead, and run only when the selected endpoint has no
active requests.
