# PHORVEXSEC-219 / M-16

DEV Milad, independent reviewer/verification requested Hami. Baseline ea5d5cad4990365f55e61eddb3da2c6bfc2009a1 / v0.4.96. No MATH, DEVOPS or product decision is required for this scoped label correction. Independent DEV/QA approval remains pending.

## Source correction and implementation

The historical false selected claim is already absent at this SHA. Current fallback says `<action> not selected by the current greedy/budget result (...)`. Align it with the card's requested `<action>: considered (...)` vocabulary, without implying a specific exclusion cause. Only the fallback format prefix in internal/decision/coverage.go:coverageReason changes. The genuine selected branches retain their existing strict-gain wording and Selected=true, rather than inventing a new selected sentence. No-candidate remains noop.

The current fallback seed is math.Inf(-1), already changed by earlier work, not the historical -1.0 in the source report. It is untouched here. The current empty-cover exclusion and positive-control regression already exist in actionset/generator.go and generator_test.go. No candidate generation, ranking, cost, tie, budget or actuation change.

Consumers use structured Selected/Actuated for owner inclusion/dispatch; no directly affected consumer of the old exact fallback phrase was found. Original audit files and schema are unchanged.

## Predicted and actual evidence

Before running: a three-view, one-move fixture should create one selected record and two feasible unselected named candidates, serialized through actual audit.Logger.Record. New prefix assertion should fail on current baseline wording and pass after the one-line change. Empty action set should serialize noop without considered/selected claims.

Actual: baseline overlay fails only fallback prefix expectations. After correction TestM016SerializedFallbackAndSelection passes with one selected + two fallbacks. TestM016NoCandidateDoesNotInventAction passes. JSONL serialization preserves structured identity/selection/actuation/feasibility and the existing four-decimal numerical projection. Raw decision cost/net/coverage and serialized fields are byte-identical between before/after signature files. The first draft test incorrectly compared raw floats to the audit's rounded values; corrected the test to the existing rounding contract before retaining the meaningful negative control.

Focused decision/actionset/audit package regression output retained separately. Synthetic deterministic fixture, not historical live replay. Independent review must reproduce these checks before closure. No deployment migration required. Rollback reverts to the baseline's truthful but nonstandard not-selected wording, **not** to the older false-selected defect.
