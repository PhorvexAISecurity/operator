# Lead verification

Affected source at assessment dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca is unchanged at 418cf2005a45c80c15b93f86d5548f73836bc7d7.

Real ShadowViews -> DecideShadowChecked -> DecideChecked with default refresh cadence and Running pods resets production stage dwell from1200s to0 and changes coverage0.284667 to0.200667; AssembleSet also increments production exclusion counters during shadow work.

Positive control: Same-stage shadow and omitted-shadow controls retain identical production dwell/hazard/coverage; actual default-cadence ObserveSnapshot and platform producers cause divergence. R2 tests cover owner/pruning boundaries.

Raw output: evidence/lead-decision-stale-shadow.log. Review: ../../assessments/20260910-readiness/fresh-decision/LEAD-REVIEW-R2.md.

Defect verification only, not repaired behavior or a live frequency claim.
