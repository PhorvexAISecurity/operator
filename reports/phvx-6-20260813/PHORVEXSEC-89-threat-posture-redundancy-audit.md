# PHORVEXSEC-89 (PHVX-6) — ThreatPosture redundancy audit

Date: 2026-08-13
Branch: `audit/phvx-6-threat-posture-redundancy`
PR: #43
Stacked on: PR #34 (`fix/phvx-58-threat-posture-claim`)

## Verdict

`ThreatPosture` is **runtime-inert in P1, but not informationally redundant**.

- Runtime-inert: P1 records the scalar for audit, but does not use it in gain or selection.
- Not informationally redundant: there are event histories with identical kill-chain output,
  P1 fact weights, and provenance, but different `ThreatPosture`.

Development decision: keep `ThreatPosture` dormant/audit-only. Do not add it to gain, and do not
remove it yet. This audit changes no production decision formula.

## Mapping comparison

| Input from `view.Events` | `ThreatPosture` | `Killchain.Assess` and downstream P1 |
|---|---|---|
| Severity | Normalized rank (`info=0` through `critical=1`), then max-aggregated. Unknown levels map to medium. | Direct alerts add `1 + 2*severity` to `eventAlpha`; high/critical can also advance stage. Neighbor severity sets maximum lateral pressure. The unknown-level severity component is currently clamped to 0 here. |
| Recency (`e.Age`) | Linearly decays to zero over `ProactiveFloor`. | Not read. Stage, hazard, P(hold), fact weights, and provenance do not change when only event age changes. |
| Count | Uses a maximum; an identical duplicate does not change posture. | Direct alerts are summed into `eventAlpha`, so repeats change P(hold) and fact weights. Neighbor alerts use a maximum, so identical neighbor repeats do not accumulate. |
| Event type | Ignored. | Direct `TypePanic`/`TypeDrift` → Persist; `TypePolicyViolation`/`TypeDisable` → Exploit; other high/critical → Exploit; other info/low/medium → Recon. AI workloads can further map persist/exploit evidence into their AI stages. |
| Direct vs neighbor | Direct weight is 1.0; neighbor weight is 0.4. | Direct alerts affect stage and `eventAlpha`; neighbor alerts affect lateral pressure/next-stage direction, not direct stage or `eventAlpha`. |
| Aggregation over `view.Events` | Maximum of severity × recency × directness. | Maximum stage, sum of direct evidence, maximum neighbor pressure, plus boolean `HasEvidence`. |

Downstream, `eventAlpha` changes P(hold), and P(hold)/StageUrgency change recon-fact weights.
`prov` is 1 for any evidenced asset; otherwise it is the exposure ramp. Therefore the raw event
stream carries information through both paths, but the two summaries are not equivalent.

## Requested cases

| # | Case | Result |
|---|---|---|
| 1 | Same stage, different severity | A fresh generic low and medium alert both stay at Recon with identical StageUrgency. `ThreatPosture` differs; P(hold) and fact weights also differ through `eventAlpha`. |
| 2 | Repeated alerts, same stage | Duplicating the same low alert leaves `ThreatPosture`, stage, and StageUrgency unchanged. P(hold) and fact weights increase because direct evidence is summed. |
| 3 | Same stage, different recency | Changing only `Age` leaves all kill-chain/P1 values identical, but changes age-decayed `ThreatPosture`. This is the decisive counterexample. |
| 4 | Severity rises without stage advancement | Low → medium on a generic direct alert keeps Recon/StageUrgency unchanged. Both posture and the P(hold)/fact-weight path retain the severity rise differently. |
| 5 | `view.Events` | Both paths read the same list, but one computes a recency-aware maximum while the other computes max stage + direct sum + neighbor maximum. |
| 6 | Find `K(E1)=K(E2)` with different posture | Found and pinned by test; exact values are below. |

## Exact counterexample

Policy: `ProactiveFloor=60m`; pod exposure: `10m`; one direct generic medium alert.

| Value | E1: age 0m | E2: age 30m |
|---|---:|---:|
| Stage | Recon | Recon |
| P(hold) | 0.523810 | 0.523810 |
| StageUrgency | 0.068403 | 0.068403 |
| P1 fact-weight entries | 5, identical | 5, identical |
| prov | 1.000 | 1.000 |
| **ThreatPosture** | **0.500** | **0.250** |

Thus `K(E1)=K(E2)` while `ThreatPosture(E1) != ThreatPosture(E2)`. Informational redundancy is
disproved by one canonical, in-vocabulary counterexample; no unknown severity is needed.

## Reproducible proof

`threat_posture_redundancy_test.go` pins three behaviors:

1. event recency yields the exact equal-K/different-posture counterexample;
2. low → medium severity stays in the same stage but is retained differently by both paths;
3. duplicate direct alerts are max-ignored by posture but counted by kill-chain evidence.

Focused validation:

```text
go test -count=1 -v ./internal/decision -run 'TestThreatPosture(IsNotInformationallyRedundantWithP1|AndKillchainAggregateSeverityAndCountDifferently)'  PASS
```

Repository validation:

```text
go test -count=1 ./...   PASS in phorvex and all 11 additional Go modules
go vet ./...             PASS in phorvex
go build ./...           PASS in phorvex
```

## Final decision

- Keep `ThreatPosture` in decision/audit output.
- Keep it out of P1 gain and selection.
- Do not delete it while it still retains recency information absent from `K`.
- Revisit removal only if the kill-chain contract is extended to preserve that information and a
  new equivalence audit finds no counterexample.
