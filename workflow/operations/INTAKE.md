# Report and verify a finding

Intake is the non-canonical holding area for a `BUG`, `INCIDENT`,
`OBSERVATION`, `RISK`, or `ENHANCEMENT`. It prevents an unverified claim from
silently becoming an M-issue.

## Flow

1. Create a record with `new-intake` or the `report-bug` alias. Capture the
   reporter, exact claim, environment, source/deployment pins, and approval
   reference carried by the request.
2. Triage scope and safety. Bugs and incidents normally enter `VERIFYING`;
   enhancements may move directly to `DEDUP_REVIEW` after scope review.
3. Pre-register reproduction criteria, falsifier, evidence retention, and a
   positive control before any live mutation.
4. Record `VERIFIED`, `REJECTED`, or `UNAVAILABLE`; “could not reproduce” is
   not evidence that the bug is absent.
5. Run `dedup-intake`. Its ranked candidates are search aids, not a verdict.
   Write a root-cause comparison against plausible candidates.
6. If overlap is ambiguous, transition to `NEEDS_DEDUP_RULING` and stop for
   the human owner. If it is the same root cause, link it as `DUPLICATE`.
7. If it is new and filing is approved, use `promote-intake`. Add
   `--start-fix` only when the owner also requested remediation.

Terminal states are `DUPLICATE`, `FILED`, `REJECTED`, and `UNAVAILABLE`.
Evidence remains attributable to the intake after promotion.
