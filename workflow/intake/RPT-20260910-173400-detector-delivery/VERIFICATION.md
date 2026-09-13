# Lead verification

Affected source at assessment dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca is unchanged at 418cf2005a45c80c15b93f86d5548f73836bc7d7.

Actual Falco webhook handler returns HTTP200 when its real custom REST client receives Forbidden on SecurityEvent Create; Prometheus handler has the same swallowed-error branch inside its alert loop.

Positive control: Actual FalcoHandler/custom REST client with local API403 and201 control both return200. No live detector/API contacted. Batch behavior needs its own implementation regression.

Raw output: evidence/falco-delivery-errors.log. Review: ../../assessments/20260910-readiness/findings/lead-fresh-integration.md.

Defect verification only, not repaired behavior or a live frequency claim.
