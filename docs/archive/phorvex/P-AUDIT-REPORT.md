# P-AUDIT — systematic code-quality + correctness audit (the bug-class siblings)

**Trigger.** A real measurement bug (`armRotates` gated on `MeanRotationIntervalSeconds>0`, excluding
emergent-rate PX) + 7 affected AI scenarios + a pre-existing metadata-test failure. This stage finds the
**siblings of that bug class** and other correctness issues **systematically**, not by guessing — and fixes the
real ones (harness-side; **brain untouched**), proving each by running.

**Premortem (what would we miss?).** (a) Runtime-only bugs invisible to static reading → mitigated by re-running
before/after. (b) Helpers reached indirectly → grepped *all* callers of the root field/helper. (c) Over-fixing
that breaks genuine ceilings → guarded with controls + ceiling checks (ceilings must stay 0). (d) Assuming "K8s
is fine" without reading every oracle → inventoried all 24. (e) The metadata failure having one obvious cause →
it had **two** (regex + a junk data row); kept going until the suite was green.

---

## Complete findings table

| # | Area | Issue | Severity | Status | Before → After (proven by running / test) |
|---|---|---|---|---|---|
| 1 | **K8s oracles (24)** | Same bug class? (fixed-interval / fixed-pod / arm assumption / cross-arm inconsistency) | — | **NOT A BUG (correct as-is)** | All 24 use robust **by-`app`-label** helpers (`backdoorAlive`/`measureSurvival`/`runningPodByApp`); **zero `armRotates`, zero fixed-pod-name captures**; `.oldUID` cases compare the current by-label pod (rotation-robust). |
| 2 | Assumption root | `armRotates` gated on `MeanRotationIntervalSeconds>0` → excluded emergent-rate PX | **High** | **FIXED (prior oracle-fix §9.15)** | 7 AI scenarios 0.00→1.00 (BOUNDS-ONLY); re-confirmed here. |
| 3 | **Assumption: `neutralized`** | `neutralized := armIsFullPhoenix(env) && X` — arm-gated: **over-credited** d-fullphoenix (NEUTRALIZES even with `inReq=true`) and **under-credited** PX | **Medium** | **FIXED** — fix-once in `aiOracle.result()`: `neutralized = persistenceDisrupted && !inRequestAchieved` (outcome-derived, arm-neutral) | d-fullphoenix `NEUTRALIZES → BOUNDS-ONLY` on the 3 scenarios where the in-request leg fired (agent-injection, malicious-artifact, rogue-tool); correctly **keeps** NEUTRALIZES where there is no in-request leg (data-model-poisoning, poisoned-registry). PX disruption unchanged (driven by `achieved`), nothing over-credited. |
| 4 | **Assumption: Schwartau** | `ComputeSchwartau(dmeta.MeanRotationIntervalSeconds, …)` → PX `interval=0` ⇒ `ProtectionTimeSeconds=0` ⇒ classified a **static arm** ("the target never moves") | **Medium** | **FIXED** (runner metric) — for an emergent-rate arm that actually acted, use the **observed** time-to-first-rotation | PX `ProtectionTimeSeconds`: **0 → 5 / 9 / 5s** on the scenarios where PX acted; correctly **stays 0** where PX took no action (data-plane ceilings). |
| 5 | **Metadata test (regex)** | `attackIDRe` ATT&CK-only (`^T\d{4}…`) — rejected **ATLAS** IDs (`AML.T*`) that AI scenarios legitimately carry | **Medium** | **FIXED** — regex now accepts ATT&CK **and** ATLAS | the AI `-apt`/`-agent` scenarios FAIL → PASS. |
| 6 | **Metadata test (data)** | junk placeholder id `"T1induce-not-real-removed"` in `c3-cryptomining-apt`'s TTPs (data-extraction artifact) | Low | **FIXED** — removed | `c3-cryptomining-apt` FAIL → PASS; **`TestScenarioMetadataComplete` now green**. |
| 7 | **Shared helpers (K8s)** | `backdoorAlive`/`measureSurvival`/`runningPodByApp` robust to rotation + emergent-rate? | — | **NOT A BUG (correct)** | All resolve **by `app` label** and skip terminating/non-Running pods — a rotation that replaces the pod correctly reads the foothold as gone. |
| 8 | Shared helpers (AI) | fixed-pod-name marker check | High | **FIXED (prior §9.15)** | `markerFilePresent(PodName)` → `markerPresentByApp` (by-label). |
| 9 | **Test coverage** | the by-label robustness of `backdoorAlive`/`measureSurvival` was **unpinned** (0 tests); the arm-credit + Schwartau emergent-rate paths were uncovered (the bugs existed undetected) | **Medium** | **PARTIALLY ADDRESSED** — added 3 regression tests pinning the fixes; remaining gaps flagged below | 0 → 3 green tests (`TestNeutralizedDerivedFromOutcomeNotArm`, `TestArmRotatesCreditsEmergentRate`, `TestAttackIDReAcceptsAtlas`). |

---

## Detail by audit area

### 1. The K8s oracles (highest priority — never got the AI sweep) — CLEAN
Inventoried all 24 K8s scenario oracles. The disruption signal is driven by the robust by-label helpers
(`backdoorAlive`/`measureSurvival`/`dwellCheck`) or by an attack-objective check; **none** use `armRotates`
(AI-only) and **none** capture a fixed pod name. The `.oldUID` oracles (`c2-persistence-evict`,
`c2-stateful-training`) compare the captured UID against the **current** by-label pod, so a rotation (new
UID/NotFound) reads as evicted. **The two AI bug classes do not exist on the K8s side** — the K8s helpers were
written rotation-robust from the start. (Per the standing rule: where it is correct as-is, we say so.)

### 2. Assumption audit (the root-cause class) — 3 siblings, all fixed
Every place the code encoded an assumption true for one arm/config but false for another:
- **`armRotates`** (fixed prior) — fixed-interval ⇒ excluded emergent-rate PX.
- **`neutralized := armIsFullPhoenix(env) && X`** (Finding 3) — arm-identity gate. Fixed **once** in
  `result()` so all 7 callers are corrected; the per-scenario `o.neutralized` field is now informational
  (a vestigial assignment — a clean follow-up could delete it).
- **Schwartau `MeanRotationIntervalSeconds`** (Finding 4) — fixed-interval ⇒ PX mis-classified static.
- (**Metadata `attackIDRe`**, Finding 5, is the same class: an ATT&CK-only assumption false for AI/ATLAS.)

### 3. The metadata-completeness test failure — root-caused, fixed (2 causes)
`TestScenarioMetadataComplete` validates every `AttackTechniqueIDs` entry against `attackIDRe`. **Two** root
causes: (a) the regex was ATT&CK-only and the AI scenarios carry ATLAS IDs; (b) one junk row. Both fixed; the
test is green. (This was previously flagged as a "separate known issue" — now resolved.)

### 4. Test-coverage gaps — flagged + partially closed
Added 3 regression tests that pin the fixes so the class cannot silently recur. **Remaining flagged gaps**
(documented, not yet closed): (a) **no unit test** asserts `backdoorAlive`/`measureSurvival` by-label
rotation-robustness — a future "optimization" to a fixed-pod check would pass CI; recommend a fake-client test.
(b) The **live `d-phorvex` decide→emit→actuate path** is exercised only by integration runs, not a unit test
(inherent — it needs a live operator). (c) The Schwartau emergent-rate branch is now exercised by the audit run
but has no isolated unit test.

### 5. Shared-helper correctness — verified
K8s helpers (`backdoorAlive`/`measureSurvival`/`runningPodByApp`/`teardownByApp`): **robust by-label, correct.**
AI helpers (`markerPresentByApp`, fixed prior): **robust by-label.** `aiOracle.result()` now derives
`neutralized` arm-neutrally (Finding 3). One bug in a shared helper would affect everything — each is verified.

---

## Proven by running (before/after)

- **Schwartau (Finding 4):** d-phorvex `ProtectionTimeSeconds` **0 → 5/9/5s** where PX acted; **0** where it
  took no action (honest). `out-oraclefix` (before) vs `out-audit` (after).
- **neutralized (Finding 3):** d-fullphoenix `NEUTRALIZES → BOUNDS-ONLY` on the 3 in-request scenarios;
  retained `NEUTRALIZES` only where no in-request leg exists; d-phorvex disruption + ceilings unchanged
  (data-plane stays `CANNOT-HELP` 0.00, foothold-eviction `BOUNDS-ONLY` 1.00) — **nothing over-credited.**
  `out-audit` (6 scenarios × {d-nomtd, d-phorvex, d-fullphoenix}).
- **Controls clean (both runs):** negative-control max `falseDefensiveActions = 0`; positive control d-nomtd
  achieves the oracle (6/6 in the audit run, 21/27 with 6 GPU-skip in the oracle-fix run).
- **Metadata test + 3 new regression tests + full harness suite: green.** Brain gates green
  (`TestAblationP1BeatsRandomPerDollar` / zero-day / stateful) — **brain unchanged.**

---

## Scope + boundary

This audit changed **harness files only**: `scenarios/ai_common.go` (neutralized fix-once),
`scenarios/scenarios_test.go` (ATLAS regex), `scenarios/apt_campaigns.go` (junk-id removal),
`internal/core/runner.go` (Schwartau emergent-rate metric), `scenarios/audit_regression_test.go` (new tests).
**No brain change** — `phorvex/internal/{decision,cost}` untouched (the prior gated `coverage.go`/`dual.go`
fixes are not re-touched); **1.62× / P3 / lead-demo preserved**. The runner metric change is harness-core (not
the optimizer/actuator/brain). GPU/AI magnitudes remain `[SP-0-PENDING-P4]`. **STOP for review.**
