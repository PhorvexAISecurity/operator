# Console catalogue QA driver

`console_catalog_qa.py` is an operator-side, fail-closed driver for validating the
review-pinned 192-entry attack catalogue after a Console/attacks deployment. It
does not deploy anything and it never launches an implicit “all” selection.

The driver reads the repository catalogue and authenticated `GET /api/catalog`,
then refuses to continue unless both contain the same ordered set of exactly 192
unique IDs. Only IDs named with `--id` or `--ids-file` are considered, and every
selected row must advertise both `available=true` and
`reactiveCompatible=true` before any launch is sent.

## Credential and transport boundary

Use exactly one credential source; there is deliberately no token argument:

- `PHORVEX_CONSOLE_TOKEN` — the established CI-secret environment variable;
- `PHORVEX_CONSOLE_TOKEN_FILE` — a current-user-owned `0600` regular file; or
- `PHORVEX_CONSOLE_TOKEN_FD` — the number of an already-open descriptor.

The token is kept out of argv, state, reports, errors, and logs. HTTPS uses the
platform trust store (or `PHORVEX_CONSOLE_CA_FILE`). Plain HTTP is accepted only
for a literal loopback address. Redirects are not followed. A server response
that reflects the exact bearer value is redacted before persistence.

Example with a descriptor:

```sh
exec 9<~/.phorvex/console-token
PHORVEX_CONSOLE_TOKEN_FD=9 \
PHORVEX_CONSOLE_BASE=https://console.staging.example \
python3 tools/console-catalog-qa/console_catalog_qa.py \
  --output /var/tmp/phorvex-console-catalog-qa \
  --id AML.T0012 \
  --concurrency 2 \
  --timeout-seconds 600
```

`--ids-file FILE` accepts one exact ID per line; blank lines and lines beginning
with `#` are ignored. `--dry-run` still authenticates, checks repository/API
parity, availability, and reactive compatibility, but sends no mutation requests.

## Resume, retry, and cancellation

The output directory is single-writer locked. `attempts.jsonl` is append-only and
each record is flushed with `fsync`; it retains catalogue, launch, status,
evidence, cancellation, error, and final observations. `state.json` is an atomic
materialized view used for resume. `summary.json` and `report.md` describe the
latest result without deleting earlier attempts.

Re-running the same command and output directory:

- skips a strict PASS;
- resumes an unfinished attempt by polling its retained run ID;
- retries a terminal non-PASS in catalogue order only when retained cleanup says
  retry is safe; and
- blocks replay after an ambiguous launch, exact-ID mismatch, or unverified
  cleanup.

The per-ID deadline starts at the original retained launch time, so restarting
the driver cannot reset it. On timeout, SIGINT, or SIGTERM, the driver posts the
known run ID to `/api/runs/stop`, polls for a bounded cleanup window, and records
what the API actually returned. A stop response is not treated as cleanup proof.

## Strict local PASS

HTTP success, event creation, `dispatchOutcome=emitted`, or even a Console
`DEFENDED` string is insufficient. PASS requires one `done`
`catalogue-validation` run whose status and typed evidence bind all of:

- the exact catalogue and run IDs;
- trigger mode `reactive` and execution mode `active` as separate persisted
  fields;
- the exact observed signal, selected feasible Console decision, and actuator
  receipt for the expected action;
- a validated physical oracle;
- verified cleanup with no unsafe-to-retry flag; and
- complete, error-free Prometheus evidence for the same IDs and modes, including
  positive trusted-event, active selected-action, and accepted-actuation deltas.

The Console's raw verdict is retained unchanged. The driver adds a separate
`localVerdict` and a list of failed bindings.

## Runtime API contract

The driver sends only the exact ID in the launch body:

```json
{"id":"AML.T0012"}
```

Trigger and execution modes are server-owned values resolved by adapter preflight,
so callers cannot select or override them. The launch response binds only the new
run ID and exact catalogue ID. The driver then requires separate `triggerMode` and
`executionMode` fields in terminal status, the typed catalogue result, and
Prometheus evidence. Missing, conflated, or inconsistent modes fail closed.

## Tests

All tests use loopback fake HTTP servers and synthetic 192-entry repository
catalogues; they never contact staging:

```sh
python3 -m unittest -v tools/console-catalog-qa/test_console_catalog_qa.py
```
