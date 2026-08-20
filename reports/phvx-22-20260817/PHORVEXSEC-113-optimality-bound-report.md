# PHORVEXSEC-113 — false optimality-bound claim correction

Date: 2026-08-17  
Branch: `fix/phvx-22-optimality-claims`  
Base: `v0.4.30` (`7d2be46275c3f19e0d6e8df48b486b0a8865b61f`)

## Outcome

The shipped UI and methodology documents no longer claim a generic `1−1/e`
approximation guarantee for the implemented selector.

The mathematically correct statement is now consistent across all affected surfaces:

- weighted coverage `g(S)` is monotone submodular;
- the implemented objective `g(S) − λ·C(S)` is generally **non-monotone** because of
  the cost penalty;
- the feasible sets form a truncated partition matroid, not merely a cardinality
  constraint;
- therefore the classic monotone/cardinality guarantee does **not** apply;
- the shipped asset-keyed profiles have a separate exactness proof because block
  ownership makes their objective modular;
- future overlapping profiles require a new algorithm-specific proof or exact
  measurement; no replacement constant is asserted.

## Root cause

PHVX-76 corrected the false comment in `internal/recon/ucw.go`, but its regression
test scanned only three Go files: `ucw.go`, `profile.go`, and `facts.go`. The same
claim remained in customer-visible UI copy and six methodology/report documents, so
the source correction did not protect the shipped product narrative.

## Changes

False or misleading claims were corrected in:

- `dashboard-web/components/subsystems/panels.tsx`
- `phorvex/METHOD-DECISION.md`
- `phorvex/P-DASHBOARD-REPORT.md`
- `phorvex/P-OPTIMIZE-RATIO-DECISION.md`
- `phorvex/P-PHYSICS-DECISION.md`
- `phorvex/P-REDTEAM-DECISION.md`
- `phorvex/P5-FINAL-REPORT.md`

The live ablation badge now says what the panel actually demonstrates:
`deterministic greedy · empirical ratio shown`.

`TestNoSourceClaimsTheOneMinusOneOverEBound` now scans all of those shipped surfaces,
the original recon source files, and the benchmark optimality UI. Explicit
disclaimers remain allowed; assertive claims fail CI with the reason the bound does
not apply.

Historical point-in-time evidence under `reports/` is deliberately not scanned as a
current product claim. The test targets the source and documents shipped by the
product.

## Verification

```text
go test ./internal/recon                       PASS
go test ./...                                  PASS
npm ci --include=dev                           PASS
npm run build                                  PASS
  - optimized production build compiled
  - lint and TypeScript checks passed
  - 4/4 static pages generated
git diff --check                               PASS
```

The initial `npm ci` inherited `NODE_ENV=production` and omitted dev dependencies;
the authoritative build was rerun with `--include=dev` and passed. npm also reported
three pre-existing dependency advisories (two high, one critical). This PR does not
change the lockfile or dependency graph; those advisories are outside this claim-only
fix and are not hidden by the successful build result.

## Runtime impact

This change corrects UI text, methodology documents, and its regression guard. It
does not alter the selection algorithm, candidate set, objective values, or
actuation behavior.
