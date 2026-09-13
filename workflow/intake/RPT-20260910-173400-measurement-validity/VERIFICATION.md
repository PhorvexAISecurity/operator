# Lead verification

Affected source at assessment dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca is unchanged at 418cf2005a45c80c15b93f86d5548f73836bc7d7.

runOneTrial scores oracle/Execute errors as full disruption, invents a successful missing baseline for adaptive trials, and hides cleanup failures/unrun controls/partial invalid trials in aggregate validity.

Positive control: Working oracle, genuine defense comparison, setup-invalid control, actual adaptive no-defense arm, and report partial-skip/unrun-control comparisons.

Raw output: evidence/lead-catalogue-r2-reproduction.log. Review: ../../assessments/20260910-readiness/fresh-catalogue/LEAD-REVIEW-R2.md.

Defect verification only, not repaired behavior or a live frequency claim.
