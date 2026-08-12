# PHORVEXSEC-58 — ThreatPosture targeting decision

**Decision: Option B — document the scalar as audit-only in P1.**

`ctxprov.ThreatPosture` is a derived, age-decayed summary of the same
`SecurityEvent` stream consumed by `killchain.Assess`. The default P1 coverage
engine already uses event severity in `eventAlpha`, which changes P(hold), stage
urgency, and therefore recon-fact weights and greedy selection. Applying the
derived posture scalar to P1 gain would count one event twice and introduce a new,
uncalibrated coefficient into the consequence-weighted coverage objective.

The boundary is therefore:

- raw event type, target, and severity drive P1 through kill-chain assessment;
- `ctxprov.ThreatPosture` is retained in decision/audit records for explanation;
- the legacy P0 `Engine` still has its historical risk blend, but it is not the
  default `p1-coverage` engine.

`TestEventSeverityDrivesP1WithoutThreatPostureScalar` proves that a critical event
on the second of two otherwise tied assets wins a one-move budget even while both
posture scalars are forced to zero. `TestThreatPostureScalarIsAuditOnlyInP1`
records the inverse boundary: changing only the derived scalar does not reweight
P1 targeting.
