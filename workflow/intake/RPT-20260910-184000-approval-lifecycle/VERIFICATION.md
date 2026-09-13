# Lead verification — PASS (defect reproduced)

By codex-lead; audited product dbf5fa4, main418cf20 differs only in release image tags.

The real submit/gate/Approve HTTP path permits two concurrent approvers to enter the external Apply callback for the same pending request. Pending records are keyed only by caller-provided ID and can overwrite another tenant request; nil applier can still return applied. The shipped nil applier limits current cluster-write impact, but duplicate execution occurs with the supported real callback.

Positive control and limits: Actual same-principal approval and sequential replay refuse; concurrent real route calls enter external callback twice. Worker ID-collision source/HTTP fixture also reproduced.

Source review: /home/mehrdad/operator-readiness/workflow/assessments/20260910-readiness/fresh-console/LEAD-REVIEW-R1.md
Evidence: evidence/console-approval-race.log
SHA256: 2fd53a4815c54ddf0e467bcd5054c09f9ab0eb29d4c5e34b75d57513683d9972

No live frequency or current deployment claim. This verification does not approve an implementation.
