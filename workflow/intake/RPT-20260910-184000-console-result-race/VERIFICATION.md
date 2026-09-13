# Lead verification — PASS (defect reproduced)

By codex-lead; audited product dbf5fa4, main418cf20 differs only in release image tags.

The attack watcher mutates result fields outside the lock while HTTP readers/persistence marshal shared pointers; the real watcher/result read fixture triggers the Go race detector. Locking only writes or map lookup cannot protect references after unlock.

Positive control and limits: Lead reran real TestFreshAttackResultRaceUnderRaceDetector with expected race failure; non-race handler/control suite passes.

Source review: /home/mehrdad/operator-readiness/workflow/assessments/20260910-readiness/fresh-console/LEAD-REVIEW-R1.md
Evidence: evidence/lead-console-race.log
SHA256: ed7ccd06bee0a905b5759dcbbb98464585268ce34aa1161ec0b741bb83af56b6

No live frequency or current deployment claim. This verification does not approve an implementation.
