# Guardrail observation and calibration

`GUARDRAIL_MODE=enforce` is the compatibility default. `observe` runs the same
classifier and threshold decision for real chat/completion requests, records a
prompt-free `guardrail_verdict`, and admits each request to the normal upstream
proxy path exactly once. `admitted_observe` and `admitted_enforce` describe only
that guardrail decision; they do not claim an upstream connection or completed
response. An observe-mode admission is not a claim that the prompt is safe.

Effective settings are startup configuration:

- `GUARDRAIL_INITIAL_VARIANT=pgv1|pgv2` (default `pgv2`)
- `GUARDRAIL_MODE=enforce|observe` (default `enforce`)
- `GUARDRAIL_THRESHOLD_PGV1` and `GUARDRAIL_THRESHOLD_PGV2`, finite values in
  `[0,1]` (default `0.5`)

The proxy rejects invalid settings before serving. `/v1/guardrail/state` reports
the effective mode, thresholds, requested model IDs, resolved model revisions when
Transformers provides them, and runtime package versions. Unknown revisions stay
`unknown`; they must not be inferred from a model name.

The deployment currently installs Python packages and downloads models at startup.
A reproducible calibration record therefore needs the exact source SHA, rendered
environment, model cache revision/digest, Python/package lock, hardware/runtime,
effective `/state`, labelled corpus, raw per-variant scores, and collection time.
Pin those artifacts before using measurements to change a threshold.

The included corpus is deliberately small and synthetic. It exercises the two
historical false-positive prompts and ordinary/malicious controls, split into
calibration and held-out sets. It is an interface and counterexample corpus, not a
representative production distribution.

Collect scores through the non-forwarding debug endpoint:

```sh
python3 collect_calibration.py \
  --base-url http://127.0.0.1:8000 \
  --corpus calibration_corpus.json \
  --source-sha "$(git rev-parse HEAD)" \
  --output observations.json
```

Evaluate the retained scores at the retained effective thresholds:

```sh
python3 evaluate_calibration.py \
  --corpus calibration_corpus.json \
  --observations observations.json \
  --output report.json
```

The collector binds observations to a canonical SHA256 over the complete parsed
corpus, including labels and text. The evaluator refuses a corpus-hash mismatch or
an incomplete per-variant matrix, so reusing a corpus ID cannot silently relabel old
scores. Original collection timestamps and model/runtime provenance remain intact.

The evaluator reports confusion counts, FPR/FNR, score ranges, and whether any
threshold can separate the retained labels. It never selects or promotes a new
threshold. A production threshold still requires an approved representative corpus,
held-out evidence, and deployment verification.
