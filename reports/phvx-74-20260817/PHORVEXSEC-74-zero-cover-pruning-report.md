# PHORVEXSEC-74 — Zero-cover candidate pruning report

Date: 2026-08-17  
Branch: `fix/phvx-74-empty-cover`  
Base: `origin/main` at `7d2be46` (`v0.4.30`)

## Problem

The dynamic action-set generator appended every enabled action that passed feasibility and the conformal cost gate, even when the recon profile supplied an empty `CoverByAction[action]` set.

Such a move has zero marginal security gain by construction. It cannot improve the coverage objective, but it still inflates candidate, demand, exclusion, and audit accounting. PHORVEXSEC-74 recorded the live symptom: all 2,880 observed `adapter-rotate` candidates had guaranteed-empty cover because the selected pods had no flagged `SuspectAdapter` fact.

Adding false cover to make those candidates useful would be unsound. `adapter-rotate` may cover `adapterIntegrity` only while a detector has identified an unauthorized adapter.

## Fix

The generator now applies a structural recon-relevance gate before feasibility and cost evaluation:

```text
enabled action
  -> empty cover: Excluded (recon-cover reason)
  -> non-empty cover: feasibility -> conformal cost -> Candidate
```

The gate is deliberately general. It prevents every enabled action with no fact-invalidating effect for that asset from entering the optimizer, including current conditional cases such as:

- `adapter-rotate` without `SuspectAdapter`;
- `mig-rebind` without a MIG-backed contention cover;
- actions whose mechanism intentionally has no honest binary cover.

Each pruned move remains visible in `ActionSet.Excluded` with the stable reason:

```text
recon-cover: action invalidates no facts for this asset
```

This preserves auditability and allows `CoverageEngine.DecideChecked` to surface the reason through its existing infeasibility mapping.

## Regression coverage

The tests now prove that:

- an AI pod with no suspected adapter emits zero `adapter-rotate` candidates and records the structural exclusion;
- the same pod with `SuspectAdapter="evil-adapter"` emits one candidate with non-empty adapter-integrity cover;
- every candidate returned when all mutating actions are enabled has a non-empty cover set.

Existing dynamic feasibility and exclusion tests continue to pass.

## Validation

```text
go test ./internal/actionset -count=1
PASS

go test ./...
PASS

go test -race ./internal/actionset
PASS

go vet ./...
PASS

git diff --check
PASS
```

## Operational note

The change does not mutate production and does not grant any new security claim. It narrows optimizer input to moves with honest positive coverage. Post-merge CI and read-only production candidate telemetry are the remaining release checks.
