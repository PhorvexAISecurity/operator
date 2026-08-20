# PHORVEXSEC-141 (PHVX-60a) — SLO disruption bound and Phorvex disruption ledger — report

Updated: 2026-08-20 · Branch `feat/phvx-60a-slo-bound-ledger` · PR #54

Implementation commits: `f02cd20`, `9a2e225`

## Headline

Part one of the SLO cost model: the two halves that need no SLO history, so they can land while the
monitoring stack the remaining-budget gate depends on does not yet exist.

**Nothing here gates a move.** `go list -deps` reports zero dependency on `internal/slo` from
`decision`, `feasibility`, `actionset`, `recon` and `cost`.

## 1. Policy fields

`SLOSpec` gains `window`, `availabilityBudget`, `latencyBudget`, `disruptionBudgetReplicaSeconds`
and `reserveFraction`, with `BudgetsConfigured()` as the per-service switch.

**No code defaults were added.** Lambda and the cost weights have a documented baseline that
reproduces the PRD example, so falling back to it is harmless. A budget has no such baseline:
inventing one would put a denominator under the SLO cost model that nobody measured, and every ratio
computed from it would look meaningful while being arbitrary.

`BudgetsConfigured()` returns **false for every existing policy**, so current behaviour is
unchanged. The inverse reading — "no budget configured means the budget is exhausted" — would block
every action on every service and silently switch Phorvex off.

`UsableBudget` implements the math owner's formula exactly:

```
usable remaining = (1 - reserveFraction) × total budget - consumed
```

A dedicated test fails if anyone re-derives it as reserve-off-the-*remainder*, which is the natural
mistake and gives a different number.

## 2. `internal/slo/bound.go` — the per-action deterministic bound

`max unavailable replicas × max unavailable duration`, per the ruling. Max load is deliberately
**not** multiplied in; it belongs to a differently-dimensioned question and lives in
`LostRequestBound`. Folding load into a replica-seconds figure would add quantities with different
units and produce a number that means nothing.

**Most actions need no measurement at all.** The replica count is derived from
`feasibility.RemovesReadyReplica` — the *same* predicate the availability floor gates on, not a
second list. An action that removes no Ready replica is therefore bounded at **exactly zero**, and
that follows from what the action does rather than from any observation. So `kv-reset`, `warm-swap`
and every identity/path/endpoint rotate are fully bounded today.

A test pins the two predicates together: if a new action is added to one and not the other, the
bound would silently start reporting zero disruption for an action that removes a replica — a hard
gate that is not one.

**`quarantine` is blocked, and that is correct.** It removes a replica but nobody has measured how
long it holds one out, so it is unbounded and blocked. No default was invented, because a fabricated
bound is worse than a blocked action: it is a hard gate that is silently not hard.

`rotate` is bounded because there is a real measurement behind it — **117 seconds**, the worst
observed vLLM replacement on the fleet.

⚠️ **Review attention.** The registry therefore contains exactly one measured duration. Opening the
others means firing and observing those actions somewhere. This is a deliberate stopping point, not
an oversight.

## 3. `internal/slo/ledger.go` — the disruption Phorvex caused

Per the ruling, **two** ledgers rather than one. The SLO itself is indifferent to cause: a replica
that was out is out, so the *total* budget must count every outage of the service. But Phorvex's own
contribution is tracked separately with a cause, so the question "how much of this budget did we
spend" stays answerable.

The ledger is fed from the recovery path `observeReadyRotations` already measures. Each entry now
stores both the disruption start and the known end of the interval. Rolling-window reads count only
the overlap with the requested window; a 20-second outage crossing the boundary by 10 seconds
therefore consumes 10 in-window replica-seconds.

Right-censored recovery is not frozen at the RLS model's 800-second observation ceiling. The RLS
outcome is emitted once at that ceiling, while the ledger upserts the same disruption ID on later
snapshots. If recovery is eventually observed, the measured endpoint replaces the censored floor.
This keeps match-rate metrics stable while preventing a long outage from remaining permanently
undercounted. Retention is one month — the longest SLO window anyone has proposed.

The ledger observes only. Nothing reads it to gate a move.

## 4. Scope

The full remaining-budget gate is **not** implemented and is not implementable yet: it needs SLO
history the cluster does not record. That was the math owner's own conclusion — *"we can implement
the upper bound per action and the Phorvex-consumption ledger, but the full remaining-budget gate
must stay uncalibrated until the metric, retention and policy fields are ready"*.

## Verification

`go build ./...`, `go vet ./...`, full `go test ./...`, and the combined PR #52–#59 race suite are
green. The targeted runner/SLO integration tests also pass, including the one-time right-censor,
continued-ledger-accrual, later-recovery, and no-double-count behavior. CRD copies are byte-identical;
Helm 3.17.3 lint/template checks and the vendored-chart comparison pass locally, including the EKS
values render. `git diff --check` passes and this PR does not modify `.github/workflows/`.

The GitHub Actions jobs triggered on 2026-08-20 did not start because GitHub reported an
organization billing/spending-limit problem. That infrastructure failure is not represented here
as a code or chart failure.
