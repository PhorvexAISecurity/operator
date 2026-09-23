# Root-cause deduplication

## Determination: DUPLICATE (M-161 follow-up)

M-161 requires all consumers to preserve validity and exclude unobserved/invalid comparisons from security/ROI. Earlier M-161 commits corrected console metrics.go to use shared metricvalidity, but separate runevidence.go and runstream.go still decode partial independent rows and bypass that contract. This is a missed consumer of the same measurement-validity invariant. Benign functional semantics are included in the bounded correction so a successful functional oracle cannot become an attack outcome.

M-168 concerns the separate three-arm live runner, its authenticated stimulus and durable mode restoration; none is mutated here. M-170 concerns falsely advertised technique stimuli, not the per-run consumer that loses already-present meaning. M-18 loses Phoenix dispatch identifiers in the manager audit, a different producer and path. Ranked textual candidates M-144/M-2 share words only; lambda optimization and API enums are unaffected.

Create follow-up fix POST25-CONSOLE-V1-VERDICTS against M-161; retain original issue and do not assert it live-closed.
