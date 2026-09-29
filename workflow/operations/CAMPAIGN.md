# Run a full-system live campaign

For workload-derived red-team design, Console Live promotion, and the original
22-item continuation map, start with [LIVE-CATALOGUE.md](LIVE-CATALOGUE.md).
It explains the case/evidence contract; this runbook still governs campaign state.

A request to test Phorvex or the dev cluster authorizes campaign planning and
read-only preflight; the user need not use the word “campaign.” A broad live
attack phase still requires its explicit bounded scope. It is
not implied by fix-level L3, a release, or the number of recently closed
issues.

1. Create it with `new-campaign`, recording the owner's approval reference,
   question, release/fix set, environment, duration/cost ceiling, and initial
   permission level.
2. Pre-register hypotheses, falsifiers, sample requirements, positive
   controls, stop conditions, and evidence retention before `APPROVED`.
3. Confirm image tag/digest/embedded SHA and baseline instrumentation before
   `BASELINED`.
4. Reuse existing authorization for its covered mutating/fault/attack phases;
   request only missing scope. Record every mutation and cleanup action.
5. Run rounds through `campaign-transition`; preserve observations separately
   from analysis and independent review.
6. Send every discovered claim through `intake/`. A campaign never writes an
   issue directly.
7. Close only with a reviewed verdict, evidence manifest, complete cleanup,
   and an empty unresolved-safety list.

Normal states are `DRAFT -> APPROVED -> BASELINED -> RUNNING -> ANALYZING ->
REVIEWED -> CLOSED`. `PAUSED` and `ABORTED` are explicit safe exits. A paused
campaign must re-enter `BASELINED` with current image, digest, and source pins
before it may run again.

Select reusable cases with `workflow.py attacks list/show/plan`; read only
`attacks/README.md` and the chosen procedures. Plans/results belong to each round.
`attacks report` distinguishes test PASS from attack mitigation. A reviewed
negative result may close a campaign; unfinished cases or cleanup may not.
