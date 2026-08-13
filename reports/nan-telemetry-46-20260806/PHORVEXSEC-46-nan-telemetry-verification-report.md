# PHORVEXSEC-46 — NaN telemetry corrupts the cost model — re-verification report

Date: 2026-08-06
Tree audited: `origin/main` @ `c0553ed`
Severity as filed: **Critical**
Outcome: **already fixed in code — one residual test gap closed by PR #10**

---

## 1. Executive summary

The ticket states:

> *"the prior audit report by Hami claimed this was fixed. It is **not** verified against the live
> tree today. **None of the guards exist; the tests were never created.**"*

That statement is **no longer true**. Re-verified against the current tree:

- **All six guards the ticket names exist**, each with a comment explaining the NaN trap.
- **Both demanded test files exist** — and they are *meaningful*, not merely green: neutralising the
  cost clamps makes them fail.
- The ticket's closing note (`ObserveRotation` still unwired, headers overclaiming
  "self-calibrating") is also **stale** — it is wired at `runner/manager.go:391`.

**One real gap remained:** the **ingest-layer** guards — the first line of defence — had **no test
at all**. Removing the Prometheus `NaN/Inf` guard left the entire suite green, so nothing prevented
it being dropped again. That is closed by **PR #10** (tests only, no production code touched).

---

## 2. Why this bug matters (restated from the ticket, confirmed)

`strconv.ParseFloat("NaN")` returns `NaN` **with `err == nil`**, and Prometheus genuinely serves the
literal `NaN` (a `0/0` expression, a stale/absent series). So the ubiquitous
`if err != nil { continue }` idiom is **not** a validity check.

If a `NaN` is admitted it flows into `C_flow` → `ECost`. Because **every comparison against NaN is
false**, the optimizer's `gain > best` is always false: the engine does **not** error — it silently
stops selecting and usually emits `noop` when it should act. Safety is unaffected (the hard laws run
before cost); **effectiveness fails silently**, which is the dangerous kind.

---

## 3. Guard verification — every location the ticket named

| # | ticket location | present | evidence |
|---|---|---|---|
| 1 | `cost/switching.go` — `sat()` | ✅ | `switching.go:107` `if math.IsNaN(x) { return 0 }` |
| 2 | `cost/rls.go` — `satRLS()` | ✅ | `rls.go:140` |
| 3 | `cost/rls.go` — `RLS.Predict()` clamp | ✅ | `rls.go:81` (NaN reads as the **neutral low end**, so a poisoned signal cannot inflate cost either) |
| 4 | `ingest/prometheus.go` parse site | ✅ | `prometheus.go:217` drops the sample (honest-absent) |
| 5 | `ingest/events.go` parse site | ✅ | `events.go:43` keeps the score honest-absent (`-1`) |
| 6 | `console/metrics.go` parse site | ✅ | `metrics.go:167` (`clamp01`) and `:184` (`atof`) |

Additional guards found beyond the ticket's list: `decision/engine.go:256`,
`physics/littleslaw.go:87`, `cost/conformal.go:40`.

---

## 4. Test verification — and why "green" was not accepted as proof

Both files the ticket demanded exist:

- `cost/costaudit_test.go` — incl. `TestInvariants_GarbageTelemetryDoesNotPoisonCost`,
  `TestInvariants_NonNegativeFiniteDeterministic`
- `decision/nan_property_test.go` — `TestDecideNeverEmitsNonFiniteCost`,
  `TestDecideStaysSelectableUnderPoisonedTelemetry` (the property test at the `Decide()` boundary the
  ticket asked for)

A passing test proves nothing unless it fails when the defect returns. So the guards were
**neutralised** (the `IsNaN` check swapped for an `IsInf` check, keeping `math` used so the package
still builds) and the suite re-run:

```
--- FAIL: TestInvariants_GarbageTelemetryDoesNotPoisonCost
--- FAIL: TestDecideNeverEmitsNonFiniteCost
```

Restoring the guards returns both to green. **The cost-layer tests are real.**

---

## 5. The residual gap — ingest had guards but no tests

Same experiment at the ingest layer. The Prometheus guard was removed:

```go
- if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
+ if err != nil {
```

and the **whole repository** test suite was run. Result: **everything stayed green** (the only
failure was the pre-existing, unrelated `TestScenariosExport`, which fails on `main` too because it
writes to a `bin/` directory that does not exist).

So the first line of defence was unprotected. This is exactly the failure mode that let this
Critical bug be marked "done" once before: the code was right at that moment, and nothing held it
right afterwards.

### Closed by PR #10 (tests only — no production code changed)

| test | what it pins |
|---|---|
| `TestInstantQueryDropsNonFiniteSamples` | raw `NaN`, `nan`, `+Inf`, `-Inf`, `Inf` sample strings driven through the **real** parse path must each be dropped |
| `TestInstantQueryKeepsFiniteSamples` | the guard must not discard good data (`0.37` survives) |
| `TestPodMetricsNeverYieldsNonFiniteTelemetry` | end-to-end property: whatever Prometheus serves, **none** of the 10 `Telemetry` fields leaving ingest is non-finite |
| `TestParseFloatAcceptsNaN` | documents *why* the guard exists, so it is not "cleaned up" later |

**Regression-verified:** with the Prometheus guard removed **6 of these fail**; with it present all
pass. `go build ./...` clean · `go vet ./internal/ingest/` clean.

---

## 6. Stale sub-claim in the ticket

> *"Out of scope but noted: `ObserveRotation` is still unwired, so `C_flow(rotate)` is a frozen
> prior, yet `p1cost.go:11` / `rls.go:9` headers still call it 'self-calibrating.' Correct the
> comments; don't let it get marked 'done' again."*

Also **stale**: `ObserveRotation` is wired — `runner/manager.go:391` →
`decision/coverage.go:61` → `cost/p1cost.go:96` (landed in `cb7514d`, PHORVEXSEC-54, Done). The
headers no longer make a false "self-calibrating" claim.

---

## 7. Verdict and recommendation

| ticket claim | verdict |
|---|---|
| "None of the guards exist" | ❌ **false today** — all 6 present |
| "The tests were never created" | ❌ **false today** — both exist and are proven meaningful |
| "`ObserveRotation` still unwired" | ❌ **stale** — wired at `manager.go:391` |
| *(unstated)* ingest guards untested | ✅ **true and now closed** — PR #10 |

**Recommendation: close PHORVEXSEC-46 once PR #10 merges**, recording that the Critical defect was
already fixed in code and what was actually missing was the ingest-layer test that keeps it fixed.

**Process note worth keeping:** this ticket was reopened because a previous report claimed a fix
without evidence that could be re-checked. The guard against repeating that is not a longer report —
it is a test that **fails when the defect returns**. That is why every claim above was verified by
breaking the code and watching the test go red.

## 8. Artifacts

- **PR #10** — `test/ingest-nan-guards`
- Tests added: `phorvex/internal/ingest/nan_guard_test.go`
- Pre-existing coverage confirmed: `phorvex/internal/cost/costaudit_test.go`,
  `phorvex/internal/decision/nan_property_test.go`
