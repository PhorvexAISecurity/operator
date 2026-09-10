# Verification — observation confirmed, classification pending

This record consolidates already performed read-only observation and local
mechanism replay, not a retroactive pre-registration claim.

Observed dev policies configured5s produce roughly10s median decision intervals;
10s policies roughly17-18s. Same-policy tick counters corroborate reduced cadence.
Live manager base-interval is10s. Source manager.Start uses one global ticker;
tick selects a policy only when now-lastTick >= EffectiveTickInterval.

Actual Manager.Start -> tick -> CollectSnapshot -> PodMetrics replay uses a fake
Kubernetes client and compressed100ms policy duration. Over2.1s each:
200msbase produced10calls;100msbase13calls with many200ms gaps;20msbase control
19calls. Evidence: ../../assessments/20260910-readiness/evidence/
lead_live_cadence_test.go, lead-live-cadence-overlay.json, lead-live-cadence.log.
The test asserts a distinguishing faster-base control, not a fabricated live SLA.

Falsifier: actual source producer does not exhibit base quantization/boundary
skips under a clean distinguishing replay, or the contract explicitly defines
this only as a minimum interval with a separately documented base scheduling
resolution. Evaluate configuration guidance and intended TickInterval semantics.
Do not infer CPU saturation, exact production latency, or high-load guarantees.
No live mutation. Independent contract review and comparison with M5/M128/M137
are pending before classifying a new BUG or choosing a configuration remedy.

## Independent review completed

Independent R3 section2.3 observes the live CRD description: TickInterval is the decision cadence. Empty defaults to20s in code. Live base interval10s cannot honor configured5s. Lead real Start/tick/CollectSnapshot/PodMetrics replay gives10,13,19 observations over2.1s for200ms,100ms,20ms bases against100ms policy. This is a contract/implementation discrepancy, not a general throughput or real-time SLA claim.

Lead accepted this bounded finding; see ../../assessments/20260910-readiness/fresh-integration/LEAD-REVIEW-R3.md and sealed r3/REPORT-R3.md with SHA256SUMS-R3. Positive control PASS. The source/deployment pins in STATUS.yaml are unchanged.
