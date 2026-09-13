# Lead verification — PASS (defect reproduced)

By codex-lead; audited product dbf5fa4, main418cf20 differs only in release image tags.

Real C1 lateral oracle scores an absent target as disruption and C3 IMDS observation timeout is indistinguishable from eviction. Source census identifies11 related target/oracle paths; two producer cases and a marker-present control reproduced. A lost observation or never-established target cannot prove defender-caused attack failure.

Positive control and limits: TestR2AbsentPodScoresAsDisruptionC1Lateral, TestR2ObservationTimeoutIsIndistinguishableFromEvictionC3IMDS and TestR2ControlMarkerPresentScoresAttackAchieved independently rerun.

Source review: /home/mehrdad/operator-readiness/workflow/assessments/20260910-readiness/fresh-catalogue/REVISION-2.md
Evidence: evidence/lead-catalogue-r2-reproduction.log
SHA256: 5cda14f6b2a778dc425b9aac7f95a8e36f1967211b35d5f1e92e428567a15930

No live frequency or current deployment claim. This verification does not approve an implementation.
