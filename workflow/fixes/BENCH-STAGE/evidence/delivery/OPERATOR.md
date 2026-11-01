# Read-only report collection

Run from the issue worktree; credentials remain in the existing private SSH askpass helper. Never read or package that helper. The collector sends a read-only Python program over SSH; it does not upload files, write remote state, dispatch work, or restart a service.

```bash
SSH_ASKPASS=/home/node/.ssh/jh/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
python3 workflow/fixes/BENCH-STAGE/evidence/delivery/collect-bot-delivery.py \
  --output /workspace/.phorvex-test-tmp/stage-delivery-YYYYMMDD-HHMMSS
```

Default selection includes parameter batch `8ffcfca38357`, V2-A batch `474cff3249df`, and its known child `4b8171ea3c83`. Completed batches expand to their child IDs. For later endpoint batches, repeat `--job` for **all** wanted batches/children; explicit options replace the defaults. A pending selection still produces a clearly labelled partial bundle and exit 2; `--allow-pending` changes only that exit code. Existing bundle paths are never overwritten. Final root delivery must check `COLLECTION.json`, job result states, omissions, and archive SHA256 independently.

The bundle includes the exact local acceptance requests `stage-endpoint-custom.json` and `stage-endpoint-600.json`, the reusable 600-second template, and the original 30-day pending template. Actual receipt directories are read independently and labelled `receipts/bot-acceptance/`, `receipts/endpoint-bot-acceptance/`, and `receipts/code-bot-retry/`; selection is filtered to the requested job IDs and their completed batch children. Sources and phase states remain separate. Retry receipt top-level fields `previous_failed_batch` and `retry_policy` are retained verbatim; a later success never overwrites the first failure.

Final selection, once the bounded retry is terminal: repeat `--job` for `8ffcfca38357`, `474cff3249df`, `180d1e5b1ee9`, `74240aadda51`, `84fcf64f961b`, and `5fc1c1b0f192`. The last batch expands to retry child `c963f138052b`. Do not run the final collection while that attempt is still running.

The collector retains byte-for-byte allowed result JSON/HTML/CSV, metric and candidate traces, bounded normalized endpoint traces, tests summary and candidate diff. It generates allowlisted provenance receipts instead of exporting personal hypotheses/request records. Original evidence ZIPs can contain raw snapshots, input policy data, inspection records and execution logs; these are deliberately replaced by the collection ZIP. The user-facing `README-fa.txt` explains how to use the included requests and the remaining limits. File receipts identify original paths and hashes; derived receipts are explicitly marked.

When retained by the lead, `candidate.git.bundle` and `candidate-source-retention.json` are explicitly included. The retry bundle retains the exact candidate commit after normal clone cleanup; it is an incremental Git bundle with the recorded `ef94...` source prerequisite, not a full source clone or configuration archive. Lead verified the 2,517-byte retry bundle (`885ca6eedb0b757bd0a5610161d527f35585117a6e41571841add34898caecda`) before collection. The collector checks transport/file hashes; that does not replace Git object/source review or test acceptance. First failed attempt has its exact diff and base provenance, but no retained bundle or built candidate binary. Never infer those absent artifacts exist.

## Parsing actual results and future endpoint runs

- Remote root: `/home/hami/phorvex-benchmark`.
- Terminal job authority: `bot/history.jsonl`, keyed by `id`; `state` retains DONE/PARTIAL/BLOCKED/FAILED and `batch_id` links children. Do not use acceptance-status's QUEUED field alone: it is updated only after the synchronous call returns.
- Batch expansion: `bot/jobs/<batch>/BATCH.json` → `results[].job`, `results[].state`, `state`.
- Parameter report: `bot/jobs/<child>/report.html` and `metrics.csv`. Exact underlying experiment: find one `stage-data/mathlab/experiments/<uuid>/request.json` with title starting `Telegram <child>: `; then read that directory's `result.json`, `experiment_manifest.json` and tables. Do not export the request.
- Code report: `bot/jobs/<child>/experiment/result.json`; top-level `report.html`, `metrics.csv`, `TESTS.json`, `brain.diff`. Successful V2-A helper arithmetic does not mean the helper was invoked by active replay.
- Endpoint report after a later refresh/dispatch: `bot/jobs/<child>/endpoint/result.json`, `report.html`, `metrics.csv`, `study-settings.json`, `dataset-manifest.json`. Read top-level `state`, `mode`, `comparable_ticks`, `baseline_exact_count`, `runner` identities and `missing_reasons`; nested acting-admission BLOCKED is a separate offline actuation refusal.
- Periodic refresh status: `stage-data/mathlab/endpoint-refresh/phorvex-staging-demo/stage-bench-defense.status.json`. A successful installed generation is selected by `stage-data/mathlab/endpoint-traces/phorvex-staging-demo/stage-bench-defense.manifest.json`; read its `trace_file` pointer, never infer readiness from a trace filename alone.
- Operator acceptance receipts: `stage-data/live/{bot-acceptance,endpoint-bot-acceptance,code-bot-retry}/acceptance-status.json`; Telegram document receipts: each directory's sibling `telegram-delivery.jsonl`. These prove operator-submitted actual queue work and Telegram delivery, not an incoming Telegram upload. Future jobs are collected by explicit IDs even if absent from those receipts.

There is no new HTTP endpoint in this helper and no legacy dashboard API should be used for the stage run. The actual bot Python boundary is `file_requests.parse(...)` → `Job('batch',...)` → `BenchBot.queue`/`run_next()`; **dispatch remains lead-owned and is outside this collector**. Root may copy the resulting private ZIP to the final download location after independent verification.
