# Phoenix AMTD — Phase 0 Report (Contract + Relaxed Matcher)

**Date:** 2026-05-30
**Tree under test:** `c:\Users\moh87733\Phorvex\build\phoenix-extended` (extensions to phoenix-main)
**Toolchain:** `go version go1.26.3 windows/amd64`; controller-gen `v0.17.2`
**Verdict:** **PASS** (all Phase 0 requirements met; verified by real build/vet/test + live kind cluster).

---

## Scope & non-goals

**Phase 0 delivers** (and only these):

1. **The API contract** — new `AMTDAction` union members (`Rotate`, `WarmSwap`, `Regenerate`, `NodeRotate`) with their argument/overlay types; the `MatcherMode` switch (default `Exact`); scored-clause fields (`Rule.Match`, `Rule.ScoreThreshold`); populated `AdaptiveMovingTargetDefenseStatus` / `SecurityEventStatus`; and the `SecurityEvent` drift/score fields (`AnomalyScore`, `Metrics`, `Evidence`).
2. **A relaxed matcher** — `MatchStrategy` with an exact fast-path that is **outcome-identical to the previous `reflect.DeepEqual`**, plus an **opt-in scored path** that is gated by `MatcherMode` (default `Exact` ⇒ zero behavior change).
3. **NIM timer-gate dissolution** — the hard-coded NIM self-action on a timed event is demoted to pass-through; a timed rotation now flows `time-based-trigger → SecurityEvent → matcher matches {type:'timed',source:'TimeBasedTrigger'} → Rotate branch (cold reschedule)`. The annotate-then-delete primitive is shared, so the observable restart is preserved exactly (30s grace).

**Explicitly deferred to later phases (NOT in Phase 0):**

- **WarmSwap / Regenerate / NodeRotate execution** — these are **type-only, no-op-with-log stubs** in Phase 0 (recognized by the dispatch, log "Phase 4/5/6 … not yet implemented; no-op", no faked effects).
- **MutationApplier / mutation-overlay interpretation** — `RotateAction.Overrides` / `RotateAction.PolicyRef` are recognized but **not interpreted**; Rotate in Phase 0 is a **cold reschedule only** (the branch logs a notice if overrides/policyRef are set).
- **Warm-pool / LeaderWorkerSet**, **GPU/memory resource handling**, **drift-signing**, **node drain/cordon/taint**, and **scoring/telemetry math** (smoothing, backoff, interval computation) — all later phases.

The original repo at `c:\Users\moh87733\Phorvex\repos\phoenix-main\phoenix-main\` was **not touched** at any stage.

---

## Output location

All work landed in **`c:\Users\moh87733\Phorvex\build\phoenix-extended`** (a copy/extension of phoenix-main). The pristine upstream tree (`repos\phoenix-main\phoenix-main\`, nested one level) was used read-only for diffing and remained unmodified.

---

## Requirement-by-requirement

| # | Requirement | Status | Evidence (file:line + test/command output) |
|---|-------------|--------|---------------------------------------------|
| R1 | New `AMTDAction` union members, **MaxProperties=1 preserved**, struct stays comparable | ✅ PASS | `api/v1beta1/adaptivemovingtargetdefense_types.go:270` keeps `// +kubebuilder:validation:MaxProperties=1`; existing 5 members `Disable/Delete/Quarantine/Debugger/CustomAction` (L272-276) are **byte-identical** to pristine (diffed). New all-pointer members `Rotate`(L284)/`WarmSwap`(L289)/`Regenerate`(L294)/`NodeRotate`(L299) with §2.1 arg types (`RotateAction` L361, `WarmSwapAction` L374, `RegenerateAction` L385, `NodeRotateAction` L395). All-pointer ⇒ comparable ⇒ the `action != (amtdv1beta1.AMTDAction{})` sentinel still compiles. **Live cluster: CR4 with 2 keys REJECTED** — `spec.strategy[0].action: Too many: 2: must have at most 1 item`. |
| R2 | `MatchStrategy` exact fast-path == previous `reflect.DeepEqual` (byte-compat) | ✅ PASS | `api/v1beta1/matcher.go:52`: `if rule.Match==nil && rule.ScoreThreshold==nil { return rule.Type==ev.Rule.Type && rule.ThreatLevel==ev.Rule.ThreatLevel && rule.Source==ev.Rule.Source }` (3-string projection). **Proven exhaustively:** controller-package `TestMatchStrategy_LegacyEqualsDeepEqual` asserts `MatchStrategy == reflect.DeepEqual` over **262144 (rule,event) pairs** (log: "verified MatchStrategy == reflect.DeepEqual over 262144 legacy (rule,event) pairs"); api-package `TestMatchStrategy_ByteCompatWithDeepEqual` independently over a 7^6 sweep. Both **PASS**. |
| R3 | Opt-in **scored** path, gated by `MatcherMode` (default `Exact`) ⇒ zero behavior change | ✅ PASS | `api/v1beta1/matcher.go:95` `MatchStrategyForMode`: `Scored` ⇒ full `MatchStrategy`; otherwise **strips to the bare 3-string projection** (Match/ScoreThreshold never consulted). Default `Exact` via `+kubebuilder:default=Exact` on `Spec.MatcherMode` (types L43). `TestMatchStrategyForMode_ExactInertScoredHonored` **PASS** — incl. the discriminating case where an event with an extra non-empty field FAILS in Exact mode (proves the scored clause is truly ignored). A numeric/score clause vs nil/absent value ⇒ **FALSE** (`evalExpression` L129-133, `projectField` L167-172); `TestMatchStrategy_ScoreClauseVsNilScoreIsFalse` (4 subtests) **PASS**. **Live cluster:** CR3 (`matcherMode: Scored` + scored clause) accepted and round-tripped. |
| R4 | Dissolve NIM timer gate into the `{type:'timed'} → rotate` rule; **no double-action** | ✅ PASS | Pristine `nim_controller.go:121-132` did `FindTimedEvent → processPodWithNIM (annotate+delete) → RequeueAfter:10s`. Extended `nim_controller.go:136-141` is **pass-through**: on a timed event it only logs "NIM pass-through: timed rotation is now owned by the matcher Rotate path; not self-acting" — **no annotate/delete/requeue**. Shared primitive `rescheduleByAnnotateThenDelete` (`nim_controller.go:161`) is reused **verbatim** by the SecurityEvent Rotate branch (`securityevent_controller.go:416`, grace `defaultRotateGracePeriodSeconds=30` at L53). **Only the Rotate branch deletes** ⇒ no double-delete. Test `TestNIMReconciler_Reconcile_ValidTimedEvent_PassThrough` **PASS** (NIM no longer deletes/requeues); `TestSecurityEventReconciler_Rotate_TimedReschedule` **PASS** (the `{timed→rotate}` path deletes end-to-end). |
| R5 | **Existing exact-match rules still work** (backward compatibility) | ✅ PASS | `securityevent_controller.go:162` replaces the old L139 `reflect.DeepEqual(...)` with `MatchStrategyForMode(strategy.Rule, securityEvent.Spec, AMTD.Spec.MatcherMode)`. First-match-wins loop (L156-167) + zero-value sentinel (L169) preserved; existing Delete/Quarantine/Debugger/CustomAction dispatch bodies **`Compare-Object` IDENTICAL** to pristine. `TestSecurityEventReconciler_ExactMatch_DeleteStillWorks` **PASS** (legacy `{timed,info,TimeBasedTrigger}→delete` still deletes). **Live cluster:** CR1 legacy exact-match AMTD (quarantine+disable) **ACCEPTED**, server applied default `matcherMode: Exact`. |
| R6 | Populate `Status` (§2.3) + `SecurityEvent` drift/score contract + `MatcherModeWarning` | ✅ PASS | `AdaptiveMovingTargetDefenseStatus` populated (types L472-547, `Conditions` with `+listType=map +listMapKey=type`); `SecurityEventStatus` populated (`securityevent_types.go:76-90`). `SecurityEventSpec` gains `AnomalyScore *string`(L49)/`Metrics map[string]string`(L55)/`Evidence *DriftEvidence`(L59). `MatcherModeWarning` set best-effort via `setMatcherModeWarning` (`securityevent_controller.go:467`); `TestSecurityEventReconciler_ExactMode_ScoredClauseInert` **PASS** (asserts the condition is set; reconcile never fails). **Live cluster:** SecurityEvent CR with `anomalyScore/metrics/evidence` **ACCEPTED** and round-tripped. |

Legend: ✅ PASS · ⚠️ partial · ❌ fail. **No requirement is ⚠️ or ❌.**

---

## Files changed

**API (`api/v1beta1/`):**
- `adaptivemovingtargetdefense_types.go` — 4 new `AMTDAction` pointer members + arg/overlay/helper types (`RotateAction`, `WarmSwapAction`, `RegenerateAction`, `NodeRotateAction`, `LocalRef`, `LocalPolicyRef`, `InferenceRotationOverlay`, `DrainPolicy`); `Rule.Match` + `Rule.ScoreThreshold`; `MatchExpression`; `MatcherMode` type + `Spec.MatcherMode` (`+kubebuilder:default=Exact`) + consts; fully populated Status with sub-types.
- `securityevent_types.go` — `SecurityEventSpec.AnomalyScore/Metrics/Evidence` + `DriftEvidence`; populated `SecurityEventStatus`.
- `matcher.go` (NEW) — the single-source-of-truth predicate: `MatchStrategy`, `MatchStrategyForMode`, `RuleHasScoredClause` + unexported helpers (`evalExpression`, `projectField`, `inList`).
- `matcher_test.go` (NEW) — proves byte-compat over a 7^6 sweep + scored/nil-score/guard/mode cases.
- `zz_generated.deepcopy.go` — regenerated (DeepCopy for all new types; no hand-writing).

**Controller (`internal/controller/`):**
- `matcher.go` (NEW) — controller-side entry points (`MatchStrategy`/`MatchStrategyForMode`/`RuleHasScoredClause`) that **delegate** to the api-package implementation (no duplicated logic). This is the L139-replacement call site named by the Stage 3 brief.
- `matcher_test.go` (NEW) — the core Phase-0 proof (262144-pair DeepEqual equivalence + scored operators + mode gating + guards).
- `securityevent_controller.go` — loop now calls `MatchStrategyForMode(...)`; `reflect` import removed; new `else if action.Rotate/WarmSwap/Regenerate/NodeRotate` branches (Rotate = cold reschedule; the other three are no-op-with-log); `setMatcherModeWarning`; new const `defaultRotateGracePeriodSeconds=30`; new RBAC markers for `adaptivemovingtargetdefenses` + `/status`.
- `securityevent_controller_test.go` (NEW) — fake-client tests: Rotate timed reschedule, legacy exact delete, scored-inert-under-Exact + warning, scored-panic-selects-Rotate.
- `nim_controller.go` — Reconcile demoted to pass-through; `rescheduleByAnnotateThenDelete` + `determinePodStartupStateFor` extracted to package level; dead `processPodWithNIM` removed; `FindTimedEvent` kept (detection-only).
- `nim_controller_test.go` — conscious inversion: `..._ValidTimedEvent_UpdateAndDelete` → `..._PassThrough` (NIM no longer deletes/requeues on a timed event); all other NIM tests preserved.

**Manifests / generated config:**
- `deploy/manifests/time-based-trigger-demo-amtd.yaml` — timed rule action `delete: {}` → `rotate: {}`.
- `config/samples/amtd_v1beta1_adaptivemovingtargetdefense.yaml` — fixed the pre-existing stray `actions` typo; `{timed,info,TimeBasedTrigger}→rotate`.
- `config/crd/bases/*.yaml` + `config/rbac/role.yaml` — regenerated (matcherMode enum+default, rotate/warmSwap/regenerate/nodeRotate under action with `maxProperties:1` preserved, scoreThreshold/match on rule, populated status, SecurityEvent drift fields; `adaptivemovingtargetdefenses` + `/status` grants).

---

## Backward-compatibility evidence

**The argument.** The exact fast-path triggers exactly when `rule.Match == nil && rule.ScoreThreshold == nil`, and then returns equality of the 3-string projection `{Type, ThreatLevel, Source}` of `rule` vs `ev.Spec.Rule`. Legacy CRs and every verified emitter carry `nil` Match/ScoreThreshold on the event Rule, so the **old** whole-struct `reflect.DeepEqual(strategy.Rule, ev.Spec.Rule)` already reduced to equality of exactly those three strings. The two are therefore **outcome-identical** on all legacy inputs.

**The proof.** `TestMatchStrategy_LegacyEqualsDeepEqual` asserts `MatchStrategy(rule, ev) == reflect.DeepEqual(rule, evRule)` over an 8^6 matrix of (strategy.Rule, event.Rule) values → **262144 pairs, all equal** (real log line: "verified MatchStrategy == reflect.DeepEqual over 262144 legacy (rule,event) pairs"). The api-package `matcher_test.go` independently proves the same theorem over a 7^6 sweep. Both **PASS**.

**The live confirmation.** On `kind-amtd-test`, the legacy exact-match AMTD **CR1** (quarantine + disable strategies, no matcherMode) was **ACCEPTED** and the server applied the default `matcherMode: Exact` — proving existing manifests deploy unchanged and run the exact path.

---

## Build result (REAL)

```
go build -C "c:\Users\moh87733\Phorvex\build\phoenix-extended" ./...   → BUILD_EXIT=0   (logs: build\logs\review-build.txt)
go vet   -C "c:\Users\moh87733\Phorvex\build\phoenix-extended" ./...   → VET_EXIT=0     (logs: build\logs\review-vet.txt)
gofmt -l (api + internal touched files)                                → clean (no files need formatting)
```

controller-gen, run from the repo root (leaf-package invocation — `paths="./..."` is a known v0.17.2 path-resolution quirk, NOT the EphemeralContainer bug):

```
controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./api/v1beta1"                                  → DEEPCOPY_EXIT=0  (review-deepcopy.txt)
controller-gen rbac:roleName=manager-role crd webhook paths="./api/v1beta1" paths="./internal/controller" \
               paths="./cmd" output:crd:artifacts:config=config/crd/bases                                          → CRDGEN_EXIT=0    (review-crdgen.txt)
```

The EphemeralContainer `allOf` CRD-gen bug did **not** manifest (sidestepped by the existing CustomAction/CustomContainerPort workaround). Post-gen `go build` re-verified **EXIT=0** (no drift).

---

## Test result (REAL)

**Working command / harness (the regression yardstick):**

```powershell
$env:KUBEBUILDER_ASSETS = "C:\Users\moh87733\AppData\Local\kubebuilder-envtest\k8s\1.30.3-windows-amd64"
go test -C "c:\Users\moh87733\Phorvex\build\phoenix-extended" ./... -count=1
```

**Which path ran:** the **local envtest control plane** (assets `1.30.3-windows-amd64`). `USE_EXISTING_CLUSTER` was **not** needed. The result is **identical with `KUBEBUILDER_ASSETS` unset**, because `suite_test.go` still contains **zero Ginkgo Describe/It specs** (Ginkgo reports "Ran 0 of 0 Specs … SUCCESS", BeforeSuite/AfterSuite never fire, no control plane starts). The **meaningful coverage** is therefore the fake-client controller tests + the matcher table tests. (envtest **1.30.4 does not exist for windows/amd64** — the remote index jumps 1.30.0 → 1.30.2 → 1.30.3 → 1.31.0; **1.30.3 is the correct nearest patch**, established in baseline. Any script hardcoding 1.30.4 must be updated.)

**Per-package, baseline vs after** (`TEST_EXIT=0` throughout):

| Package | Baseline (Stage 1) | After (Stage 4 re-run) |
|---|---|---|
| `api/v1beta1` | [no test files] | **ok** (~1.1s) — matcher byte-compat + scored table tests |
| `internal/controller` | **ok** (0.3s), 12 funcs/subtests, all pass | **ok** (~0.4s), all pass (matcher + reconciler + NIM dissolution) |
| `cmd` | [no test files] | [no test files] |
| `pkg/controllers` | [no test files] | [no test files] |
| **Overall** | **TEST_EXIT=0** | **TEST_EXIT=0** |

**Matcher unit tests (verbose, all PASS** — logs `review-controller-verbose.txt` / `review-api-verbose.txt`):
- `TestMatchStrategy_LegacyEqualsDeepEqual` (262144 pairs == `reflect.DeepEqual`)
- `TestMatchStrategy_LegacySpotChecks` (8 subtests)
- `TestMatchStrategy_ScoredOperators` (22 subtests: Gte/Gt/Lte/Lt/In/NotIn/Eq/NotEq/Exists/metrics + boundaries)
- `TestMatchStrategy_ScoreThresholdEqualsGte` (sweeps thr×score; `ScoreThreshold X ≡ Match{anomalyScore,Gte,X}`)
- `TestMatchStrategy_ScoreClauseVsNilScoreIsFalse` (4 subtests — Phase-0 inertness, never panics)
- `TestMatchStrategyForMode_ExactInertScoredHonored`
- `TestMatchStrategy_GuardBlocksUnrelatedEvent` (3 subtests — Source/Type guard each block a 0.99 score)

**Reconciler + NIM (fake-client, all PASS):**
- `TestSecurityEventReconciler_Rotate_TimedReschedule` — `{timed→rotate}` deletes the pod end-to-end via the CRD.
- `TestSecurityEventReconciler_ExactMatch_DeleteStillWorks` — legacy exact delete still deletes (back-compat).
- `TestSecurityEventReconciler_ExactMode_ScoredClauseInert` — pod survives **and** `MatcherModeWarning` condition is set.
- `TestSecurityEventReconciler_ScoredMode_PanicSelectsRotate` — `0.90 ≥ 0.85` under Scored selects Rotate.
- `TestNIMReconciler_Reconcile_ValidTimedEvent_PassThrough` — NIM does **not** delete/requeue on a timed event.
- `TestNIMReconciler_Reconcile_NoTimedEvent`, `TestFindTimedEvent`, `TestNIMReconciler_DeterminePodStartupState` — preserved, pass.

**Failures shown verbatim:** **none.** No failures, no skips, no flakes at any stage. (The only non-zero exit ever observed was a cosmetic `git status` → 128 because the build tree is not a git repo — not a code/test failure.)

Saved logs (`c:\Users\moh87733\Phorvex\build\logs\`): `baseline-test.txt`, `stage3-build.txt`, `stage3-matcher-unit.txt`, `stage3-full-test.txt`, `stage3-controller-verbose.txt`, `stage3-deepcopy.txt`, `review-build.txt`, `review-vet.txt`, `review-full-test.txt`, `review-controller-verbose.txt`, `review-api-verbose.txt`, `review-deepcopy.txt`, `review-crdgen.txt`.

---

## Kind-cluster validation (REAL)

Context `kind-amtd-test`, node `amtd-test-control-plane` Ready, apiserver `v1.35.0`. CRDs applied from `config/crd/bases` (both **created**, **Established**, no schema error — log `review-kubectl-crd-apply.txt`).

| Case | Manifest | Outcome |
|---|---|---|
| CR1 | LEGACY exact-match AMTD (quarantine + disable) | **ACCEPTED** — back-compat proven; server applied default `matcherMode: Exact`. |
| CR2 | `{type:timed,source:TimeBasedTrigger} → rotate:{}` | **ACCEPTED** — new action + dissolved gate are schema-valid; round-tripped `rotate:{}` + the timed rule. |
| CR3 | `matcherMode: Scored` + `Rule.Match` (`anomalyScore Gte 0.85`, `threatLevel In high,critical`) + `scoreThreshold:"0.85"` + `rotate.overrides{gpuResource:"0", envPatch:[RUNTIME_MODE=SECURE]}` | **ACCEPTED** — full round-trip; every field preserved (scored contract proven). |
| CR4 | `AMTDAction` with TWO keys (`rotate:{}` + `delete:{}`) | **REJECTED** — `spec.strategy[0].action: Too many: 2: must have at most 1 item` (**MaxProperties=1 enforced server-side**; kubectl exit 1 is the intended rejection). |
| BONUS | SecurityEvent CR with `anomalyScore:"0.92"` + `metrics{...}` + `evidence{...}` | **ACCEPTED** and round-tripped — the new SecurityEvent spec fields the matcher reads are schema-valid. |

Cleanup: all 4 test CRs + the SecurityEvent deleted ("No resources found"). The two CRDs remain installed on the cluster (they hold no CRs). Logs: `review-kubectl-cr-apply.txt`, `review-kubectl-se-apply.txt`.

---

## Deviations / honest gaps / what the reviewer flagged

1. **envtest 1.30.4 unavailable for windows/amd64** — used **1.30.3** (the correct nearest patch). Moot for results since the Ginkgo suite runs 0 specs and tests pass with assets unset; only a deviation from the brief's literal "1.30.4", not from architecture. Update any script/doc hardcoding 1.30.4.
2. **`suite_test.go` has ZERO Describe/It specs** — envtest's control plane is never actually started by `go test`, and `config/crd/bases` is never loaded by the suite. The real envtest exercise was instead done via the **live kind cluster apply** above (stronger evidence). Unchanged from baseline; not a Phase-0 requirement. If a future stage adds real envtest specs (or sets `ErrorIfCRDPathMissing` against freshly generated CRDs), the known controller-gen CRD-gen breakage could surface there.
3. **No CRD `shortNames`** — `kubectl get amtd` fails; must use the full `adaptivemovingtargetdefenses.amtd.r6security.com`. Cosmetic, pre-existing, out of scope.
4. **Downstream mirrored CRD copies** (`charts/phoenix/templates/crds/*`, `deploy/manifests/deploy-phoenix/crds.yaml`) were **not** hand-synced (packaging artifacts). The authoritative regenerated CRDs in `config/crd/bases` are what envtest references and what was applied live. Flagged for a later packaging step.
5. **NIM double-delete guard for the future** — the NIM timer gate is dissolved and NIM no longer self-acts. If a later stage re-introduces a NIM cold fallback, it must guard against double-delete with the Rotate branch (e.g. an in-progress annotation, per architecture D2/§3).
6. **Phase-scope honesty** — `RotateAction.Overrides`/`PolicyRef` exist but are **not interpreted** (logged-and-cold-rescheduled only); `WarmSwap`/`Regenerate`/`NodeRotate` are **type-only no-op-with-log stubs**. No fabricated effects anywhere.

---

## Verdict

**Phase 0: PASS.**

The contract + relaxed matcher + NIM-gate dissolution are faithful to architecture.md §2/§3/§6, **build and test green for real** (`BUILD_EXIT=0`, `VET_EXIT=0`, `TEST_EXIT=0`), the **byte-compat theorem is proven exhaustively** (262144 controller-package pairs + a 7^6 api-package sweep, both `== reflect.DeepEqual`), and the **live apiserver** accepts the legacy / rotate+timed / scored CRs while **enforcing MaxProperties=1** (2-key action rejected). Scored evaluation is opt-in and fully inert under the default `Exact` mode ⇒ existing exact-match rules behave exactly as before. WarmSwap/Regenerate/NodeRotate are honest no-op stubs, and Rotate is a cold reschedule only — consistent with the declared Phase 0 scope.

**Next: Phase 1 (not started).**
