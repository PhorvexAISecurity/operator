# Report

## Claim

Console catalogue and per-run evidence discard benign-control and validity meaning. Actual retained round57 benign success is counted as a security trial and the history UI expression labels it attack landed. Actual valid round69 benign success is reduced to skipped. Actual invalid GPU v11 is also shown only as skipped, losing its specific invalid reason.

## Expected behavior

Preserve source metadata and validity. Separate functional outcomes from security outcomes; retain invalid/inconclusive/unsupported explanations. Exclude benign and unscorable rows from security aggregates. Only supported security evidence may label an attack result.

## Observed behavior

The real RunEvidence reader reproduced all three mappings locally against unchanged retained metric values. A separate valid adversarial positive control reached the same reader. The initial v11 false-defended hypothesis was disproved: skipped=true already excludes that specific row. No installed browser behavior is claimed from this local reproduction.

## Scope

Catalogue list parsing, per-run and streaming aggregation, typed API responses and dashboard rendering. Existing catalogue entries stay available; this correction alone does not implement actual Voice service scenarios or finish console v1 delivery. No new NATS execution or rejected proposals.

## Evidence

See VERIFICATION.md and evidence/reproduction-result.json. Source: main3f4e2cc0c9415ce93ec525a957bfd96029f8dc0a; modified branch source4cb736e1 has identical affected console/UI files.
