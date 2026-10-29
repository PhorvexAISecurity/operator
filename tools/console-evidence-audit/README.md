# Console evidence audit

`audit.py` is an independent, fail-closed verifier for the 192-case Console
catalogue campaign. It reads JSON and may issue authenticated HTTP `GET`
requests, but it has no Kubernetes client, mutation verb, case launcher, or
deployment path.

The verifier accepts the strict contract in [CONTRACT.md](CONTRACT.md). It also
recognizes the durable `phorvex.attack-catalogue-run.v1` record, standalone
`phorvex.attack-catalogue-result.v1`, the Console evidence API wrapper, native
`phorvex.prometheus-run-evidence.v1`, and `phvx-attack` evidence shapes. Those
native/legacy adapters never infer missing correlation or promote cleanup,
emitted dispatches, summary booleans, parsed metrics, or screenshots into proof.
Consequently, a native runtime export remains `BLOCKED` or `INVALID` until an
audit-ready producer adds the required fields.

## Run

For a campaign bundle whose `expected_runs` contains all 192 exact ID/run
pairs:

```sh
python3 tools/console-evidence-audit/audit.py \
  exported-console-evidence.json \
  exported-prometheus-evidence.json \
  --output audit-output \
  --expected-count 192
```

Use `--as-of 2026-10-29T12:10:00Z` to make an offline replay byte-stable apart
from absolute input paths in provenance. The default signal freshness ceiling
is 300 seconds and can be tightened with `--max-signal-age-seconds`.

Optional API input is read-only and uses `GET` only:

```sh
PHORVEX_AUDIT_TOKEN='...' \
python3 tools/console-evidence-audit/audit.py \
  campaign-manifest.json \
  --console-api 'https://console.example/api/exported-run-evidence' \
  --prometheus-api 'https://console.example/api/exported-prometheus-evidence' \
  --bearer-token-env PHORVEX_AUDIT_TOKEN \
  --output audit-output \
  --expected-count 192
```

Credentials in URLs are rejected. Query strings are omitted from output
provenance. Each source is capped at 64 MiB. The output directory must be empty,
which prevents results from an older campaign being silently retained.

Exit status is `0` only when the campaign verdict is `PASS`, `1` when evidence
was evaluated but any ID or campaign check is non-PASS, and `2` for malformed
input or invocation errors.

## Output

- `verdicts/<catalogue-id>--<hash>.json`: one verdict per expected catalogue ID,
  with check-level reasons, canonical evidence hash, source hashes, and
  retrieval/export timestamps.
- `matrix.md` and `matrix.csv`: concise campaign matrices.
- `summary.json`: counts, campaign cardinality check, source provenance, and
  output locations.
- `screenshot-bindings.json`: deterministic Console/Grafana attachment slots.
  They bind to the exact catalogue ID, run ID, and evidence hash but are marked
  `source_of_truth=false` and never participate in a verdict.

Overall severity is `INVALID > FAIL > BLOCKED > PASS`:

- `INVALID`: untrustworthy structure or attribution, including mismatched IDs,
  stale/out-of-window observations, metadata-only proof, hash conflicts, or
  contradictory sources.
- `FAIL`: well-attributed evidence proves a required control was false, such as
  `selected=false`, a rejected receipt, or `postflight.clean=false`.
- `BLOCKED`: a required fact is absent or unknown.
- `PASS`: every strict check passed. Unknown values are never coerced to PASS.

## Tests

```sh
python3 -m unittest discover -s tools/console-evidence-audit/tests -v
```

The suite is hermetic and uses only the Python standard library. The strict
positive fixture is `fixtures/strict-valid.json`; negative cases mutate it one
proof boundary at a time. `fixtures/persisted-runtime-incomplete.json` pins the
actual durable runtime shape and proves it is consumed without being upgraded to
PASS when audit-only evidence is absent.
