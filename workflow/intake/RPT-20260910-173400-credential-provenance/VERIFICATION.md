# Lead verification

Affected source at assessment dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca is unchanged at 418cf2005a45c80c15b93f86d5548f73836bc7d7.

c1-credtheft-rbac discards the stolen prefix and ignores exec failure; its oracle mints and replays a new unbound TokenRequest credential. Failed theft can report success and the original pod-bound token's survival is unmeasurable.

Positive control: Real replay HTTP API observes minted dummy token instead of captured bytes; denied-token control, failed-theft case and TokenRequest bound-object assertions. No live credential used.

Raw output: evidence/lead-catalogue-r2-reproduction.log. Review: ../../assessments/20260910-readiness/fresh-catalogue/LEAD-REVIEW-R2.md.

Defect verification only, not repaired behavior or a live frequency claim.
