# Design: TRIAGED → AGREED

Read status, target issue, its reviewed anatomy locus, and source at the pinned
baseline. Unreviewed joins are search hints. Expand context only for actual
readers/writers of the touched state.

Each derivation traces the incident's real inputs through their producers to
the decisive condition and outcome. Inspect every arm of a compound predicate,
including defaults, missing/stale inputs and upstream dependencies. A field's
name or ticket description is not its semantics. Predict both the failing
case and legitimate behavior that must survive; scale the trace to the change.

| Owner | Work | Output |
|---|---|---|
| coordinator | assign actual participants, capabilities, baseline, dependencies, scope/approval | `00-intake.md`, status |
| proposer | explain root cause, minimal change, blast radius, exact delta/bands and tests | `01-proposal.md` |
| skeptic | independently derive cause, expected fix, predictions and adversarial cases | `02A-blind-derivation.md` |
| skeptic | seal 02A **before** reading proposal; compare models and attack assumptions | `02B-critique.md`, `critique` check |
| skeptic with proposer | settle attacks with evidence; record chosen scope and criteria | `03-decision.md`, `decision` check |

Seal: `workflow.py seal <fix> --by <skeptic> --expect-revision N`. A seal detects later changes;
it cannot prove what the participant previously read. If exposed prematurely,
record that fact and assign an unexposed reviewer; never claim blind derivation.

Declare `change_class: A|B`, `verification.required` (at least L0–L2),
`live_required` and `soak_required` before implementation. L3 is required for a
live finding, deployment/actuation, external actor or timing contract. L4 is
required for evolving belief, cost, clocks or retry state. Waivers require a
human ruling, not an omitted level. Detailed layer meanings: `verification/LEVELS.md`.

Every critique item is answered or adopted. After three unresolved rounds,
record both positions and seek a human ruling. Do not weaken a prediction to
fit results. Freeze the agreed document through its hash-indexed decision check;
amendments reference authorization and retain original predictions.

Handoff to implementer: agreed artifact/check, baseline, exact scope and tests.
