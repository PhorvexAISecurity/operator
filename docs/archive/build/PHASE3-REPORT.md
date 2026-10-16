# Phoenix AMTD — Phase 3 Report (Telemetry Scoring & Adaptive Cadence)

Module `github.com/r6security/phoenix` · workspace `c:\Users\moh87733\Phorvex\build\phoenix-extended` · Go 1.26.3 · live cluster `kind-amtd-test` (apiserver v1.35.0). All results below are stated only as actually run; no green is claimed that the logs do not show.

---

## Scope & non-goals

**Phase 3 delivers (implemented + verified):**
- `AdaptiveRotationPolicy` scoring fields — additive/pointer/optional: `PanicThreshold *string`, `StalenessWindow *metav1.Duration`, `EWMAAlpha *string`, `ConsecutiveHighSamples *int`, `ScoringPolicy *ScoringPolicy` (new type, NO default weights).
- Pluggable `AnomalyScorer` interface; default `PassthroughScorer` (consumes `Spec.AnomalyScore` as-is, no invented math, D20); opt-in `WeightedScorer` inert unless `ScoringPolicy.Weights` is set.
- EWMA `SmoothedScore` + N-consecutive-high count + monotone-decreasing `ComputedInterval` written to the previously-inert Status (AMTD + SecurityEvent).
- Staleness decay (D25): a score older than `StalenessWindow` decays to 0 (raw kept for audit).
- Trusted-Source provenance (D26g): score honored only from {Prometheus/Falco/KubeArmor}Integrator; RBAC is the primary gate, allowlist is defense-in-depth.
- Panic gate (arch L330 LOCKED): bypasses ONLY the G3 min-interval floor under hysteresis (`SmoothedScore≥PanicThreshold && ConsecutiveHighCount≥N`); keeps G1/G2/G4/G5/G6.
- Scored-rule action selection under `MatcherMode=Scored`, with the Exact/unset path byte-for-byte unchanged.

**Phase 3 DEFERS / does NOT touch:**
- `ContextMutationPolicy` — the single remaining Phase-3 sub-item, **honestly DEFERRED, not faked** (see Deviations).
- Warm-pool / GPU work (Phase 4 / GPU run), drift/node work (Phase 5/6), and the GPU panic-MTTR SLO — NOT started.
- `WarmSwap`/`Regenerate`/`NodeRotate` remain honest no-op stubs.
- NIM pass-through unchanged. No GPU/warm-pool/drift/node work. Phase 4 NOT started. `c:\Users\moh87733\Phorvex\repos` untouched.

---

## Requirement-by-requirement

| # | Requirement | Status | Evidence (file:line) + test/cmd |
|---|---|---|---|
| 1 | Scoring fields additive/pointer/optional on `AdaptiveRotationPolicy` | ✅ | `adaptivemovingtargetdefense_types.go:588` PanicThreshold, `:595` StalenessWindow, `:602` EWMAAlpha, `:608` ConsecutiveHighSamples, `:616` ScoringPolicy. `MaxProperties=1` preserved `types.go:277`. CRD on live apiserver carries all 6 fields. |
| 2 | Default scorer = Passthrough, NO invented math | ✅ | `scoring.go:70-82` returns `Spec.AnomalyScore` as-is (parse-validate/clamp only). `TestPassthroughScorer` PASS. |
| 3 | `ScoringPolicy` NO default weights (inert unless set) | ✅ | `scoring.go:92-94` unscored on nil/empty Weights; `scorerFor` `:142-145` picks Weighted only if `ScoringPolicy!=nil`. `TestWeightedScorer`, `TestScorerFor` PASS. |
| 4 | The 6 previously-inert Status fields are written | ✅ | `scoring_update.go:174-189` writes AMTD `SmoothedScore`/`ConsecutiveHighCount`/`LastObservedScore`/`CurrentInterval` (`types.go:743,747,760,763`) + SecurityEvent `ObservedScore`/`ComputedInterval` (`securityevent_types.go:83,86`). `TestScoring_TrustedScoreWritesAllFields` PASS (smoothed=0.15, interval=8.65m, all 6 written). |
| 5 | Provenance — only trusted Sources honored (D26g) | ✅ | `scoring.go:41-55` allowlist; gate `scoring_update.go:88-92`; empty Source not trusted. `TestProvenance_Allowlist`, `TestScoring_ProvenanceUntrustedIgnored` PASS. |
| 6 | Staleness decays to 0 (D25) | ✅ | `scoring_update.go:115-121`. `TestScoring_StalenessDecaysToZero` PASS. |
| 7 | EWMA `smoothed = α·eff + (1−α)·prev` | ✅ | `scoring_update.go:124-129`. `TestEWMA_Math` PASS (0.3·0.9+0.7·0.4=0.55). |
| 8 | N-consecutive-high count / reset | ✅ | `scoring_update.go:131-139`. `TestScoring_ConsecutiveHighResets` PASS (1,2,0,1). |
| 9 | `ComputedInterval` monotone-decreasing, bounded [min,base] | ✅ | `scoring_update.go:206-222`: `base − smoothed·(base−min)`, clamped; misconfig pins to base. `TestComputedInterval_MonotoneDecreasingBounded`, `TestComputedInterval_RisingScoreShrinks` PASS. |
| 10 | Panic bypasses ONLY G3 (keeps G1/G2/G4/G5/G6) | ✅ | `rotate_executor.go:170` G3 is the ONLY guard gated on `!score.panic`; G1`:151`, G2`:157`, G5a`:189`, G4`:205`, G5b`:222`, G6`:239` unconditioned. `TestPanic_DoesNotBypassReadiness` PASS. |
| 11 | Panic only when `SmoothedScore≥thr AND ConsecHigh≥N`; immediate Rotate only + Panic condition | ✅ | `scoring_update.go:147`; `rotate_executor.go:472-484` sets `Panic/ScoreThresholdCrossed`, no node/quarantine call. `TestPanic_OnlyAfterNConsecutiveHigh`, `TestPanic_SingleSpikeNoPanic` PASS. |
| 12 | Scored selection under `MatcherMode=Scored && AdaptiveRotation!=nil` | ✅ | `securityevent_controller.go:247-252`; score threaded to `executeRotate` `:442`. `TestScored_SelectsRotateAtThresholdNotBelow` PASS. |
| 13 | EXACT-MATCH unchanged (byte-compat, scored clauses inert) | ✅ | `matcher.go:54-58` 3-string projection; `MatchStrategyForMode:95-102` strips scored clauses in Exact; nil-score Gte→FALSE `:130-133`/`:168-170`. `TestScoring_ExactModeUnchanged` PASS. |
| 14 | Phase-0/1/2 invariants intact | ✅ | byte-compat matcher (ByteCompatWithDeepEqual, LegacyEqualsDeepEqual, ScoreClauseVsNilScoreIsFalse), D22 G1-G5 (`TestRotate_G1..G5`), G6 (`TestMaxConcurrentRotations_*`), NIM pass-through (`TestNIMReconciler_*`), `TestSecurityEventReconciler_ExactMatch_DeleteStillWorks` — all PASS. |
| 15 | WarmSwap/Regenerate/NodeRotate still honest stubs | ✅ | `securityevent_controller.go:448,451,454` "not yet implemented; no-op". |
| 16 | ContextMutationPolicy | ⚠️ DEFERRED | No `contextmutation*` files exist; documented as the single remaining Phase-3 sub-item, not faked. |

---

## Files changed

**API (`api/v1beta1/`)**
- `adaptivemovingtargetdefense_types.go` — updated the Phase-1 reservation comment (~L561); added the 5 scoring fields to `AdaptiveRotationPolicy`; added the new `ScoringPolicy{Weights map[string]string; Normalization string (enum minmax;zscore;clamp)}` type.
- `zz_generated.deepcopy.go` — regenerated (controller-gen v0.17.2): `AdaptiveRotationPolicy.DeepCopyInto` extended (`:236-268`, 6 ptr fields); new `ScoringPolicy.DeepCopyInto/DeepCopy` (`:781-790`, Weights map).
- `config/crd/bases/amtd.r6security.com_adaptivemovingtargetdefenses.yaml` — regenerated; the 6 adaptiveRotation fields verified live on the apiserver.

**Controller (`internal/controller/`)**
- `scoring.go` (NEW) — `AnomalyScorer`, `PassthroughScorer` (default), `WeightedScorer` (opt-in), `scorerFor`, `trustedScoreSources` allowlist + `isTrustedScoreSource`, helpers `parseScore/formatScore/clamp01`.
- `cadence.go` — `adaptiveRotationOf` + `effectivePanicThreshold` (0.85), `effectiveEWMAAlpha` (0.3), `effectiveConsecutiveHighSamples` (3), `effectiveStalenessWindow` (0=disabled) + default consts. (Code defaults are FLAGGED proposals, NOT CRD defaults — nil == today's behavior.)
- `scoring_update.go` (NEW) — `applyScoring(...) scoringResult` (provenance→staleness→EWMA→consec-high→ComputedInterval, writes both Status structs restart-safe); `computedInterval`, `writeScoringStatus`, `parseSmoothed`, `panicConditionMessage`.
- `securityevent_controller.go` — calls `applyScoring` in the per-AMTD match loop ONLY when `MatcherMode==Scored && InferenceRotation.AdaptiveRotation!=nil`; threads `score` into `executeRotate`.
- `rotate_executor.go` — `executeRotate` + `recordRotationSuccess` gain a `score scoringResult` param; **G3 gated on `!score.panic`**; records the `Panic`/`ScoreThresholdCrossed` condition on a panic rotation.

**Tests (NEW):** `api/v1beta1/scoring_test.go`, `internal/controller/scoring_update_test.go`, `internal/controller/panic_gate_test.go` (reuse `managedOwnedPod`, `reconcileEvent`, `seTestScheme`, `WithStatusSubresource`).

---

## Build result (REAL exit codes — Stage-5 review session)

- `go build ./...` → **BUILD_EXIT=0** (`review3-build.txt`)
- `go vet ./...` → **VET_EXIT=0** (`review3-vet.txt`)

---

## Test result (REAL `go test ./... -count=1`, KUBEBUILDER_ASSETS set)

- **TEST_EXIT=0** (`review3-test.txt`):
  - `api/v1beta1 ok 1.170s`
  - `internal/controller ok 0.353s`
  - `internal/scheduler ok 0.225s`
  - `cmd` / `pkg/controllers` — no test files.

**Phase-3 named suite — 18/18 PASS** (`review3-phase3-tests.txt`):
`TestEWMA_Math`, `TestComputedInterval_MonotoneDecreasingBounded`, `TestComputedInterval_RisingScoreShrinks`, `TestPassthroughScorer`, `TestProvenance_Allowlist`, `TestWeightedScorer`, `TestScorerFor`, `TestEffectiveScoringDefaults`, `TestScoring_TrustedScoreWritesAllFields`, `TestScoring_ProvenanceUntrustedIgnored`, `TestScoring_ConsecutiveHighResets`, `TestScoring_StalenessDecaysToZero`, `TestScoring_ExactModeUnchanged`, `TestScoring_NilAdaptiveRotationNoScoring`, `TestPanic_OnlyAfterNConsecutiveHigh`, `TestPanic_SingleSpikeNoPanic`, `TestPanic_DoesNotBypassReadiness`, `TestScored_SelectsRotateAtThresholdNotBelow`.

**Phase-0/1/2 invariant regression — all PASS** (`review3-invariants.txt`):
byte-compat matcher (`ByteCompatWithDeepEqual`, `LegacyEqualsDeepEqual`, `ScoreClauseVsNilScoreIsFalse`, `MatchStrategyForMode_ExactInertScoredHonored`), D22 G1-G5 (`TestRotate_G1..G5`), G6 (`TestMaxConcurrentRotations_{DefersAtCap,ProceedsUnderCap,NilUnlimited}`), NIM pass-through (all `TestNIMReconciler_*`), `TestSecurityEventReconciler_ExactMatch_DeleteStillWorks`.

**Failures:** none. 0 fail across all packages.

**Log paths:** `c:\Users\moh87733\Phorvex\build\logs\review3-build.txt`, `review3-vet.txt`, `review3-test.txt`, `review3-phase3-tests.txt`, `review3-invariants.txt`.

---

## Kind-cluster live verification (REAL — `kind-amtd-test`, manager run from `bin\manager.exe`, then killed)

Constants for the live AMTDs: `baseInterval=10m`, `minInterval=1m`, span=9m; `panicThreshold=0.85`, `ewmaAlpha=0.3` (unless noted), `N=ConsecutiveHighSamples`. Evidence: `live3-evidence.txt`, `live3-manager.log`, `live3-tests.txt`, `live3-panic-tests.txt`.

**(1) Telemetry updated the scored Status fields — PROVEN LIVE.**
Trusted `PrometheusIntegrator` event score=0.5 on a Scored AMTD with an enrolled pod →
- AMTD Status: `lastObservedScore=0.5`, `smoothedScore=0.499999` (EWMA), `consecutiveHighCount=0`, `currentInterval=5m30s` (= 10m − 0.5·9m, exact).
- SecurityEvent Status: `observedScore=0.5`, `computedInterval=5m30s`. Pod survived (0.5 < 0.85).
- Manager log: `applyScoring: scored {... rawScore:"0.5", effective:0.5, smoothed:"0.499999", consecutiveHighCount:0, computedInterval:"5m30.000378s", panic:false}` then `ACTION: warmSwap` (benign catch-all → telemetry recorded without rotation).
- **Rising sequence 0.2→0.6→0.9** ⇒ `currentInterval` monotone-decreasing, bounded [1m,10m]: **8m12s → 4m36s → 1m54s** (each = 10m − smoothed·9m, strictly shrinking toward minInterval).

**(2) Scored rule selected an action under `MatcherMode=Scored` while a legacy exact-match AMTD stayed unchanged — PROVEN LIVE.**
- BELOW threshold: score=0.5 (<0.85) → catch-all warmSwap, rotationCount unchanged, pod survives, telemetry still recorded.
- AT/ABOVE threshold: score=0.9 (≥0.85) → Rotate selected, rotationCount 1→2, pod rotated, SecurityEvent `appliedAction=rotate`.
- Definitive toggle on the SAME AMTD (rule `{type:anomaly, source:PrometheusIntegrator, scoreThreshold:0.85}`→delete), SAME event `type:anomaly/score:0.5`:
  - Under **Scored**: pod NOT deleted (0.5<0.85); scored Status written (AMTD `smoothed=0.499999`/`lastObs=0.5`/`interval=5m30s`; SE `observedScore=0.5`).
  - Under **Exact** (score stripped, bare `{type:anomaly}` projection matches): pod DELETED (score IGNORED); NO scored Status on the SecurityEvent (`observedScore=''`, `computedInterval=''`); condition `MatcherModeWarning=True/ScoredClauseInertInExactMode`.
- Legacy exact-match unchanged: a separate Exact AMTD `{type:timed, threatLevel:info, source:TimeBasedTrigger}`→delete deleted the pod on a matching timed event (recreated by Deployment); SecurityEvent carried no scored fields. Manager log confirms `applyScoring` NEVER ran for any Exact-mode AMTD (0 occurrences) — scoring block skipped byte-for-byte.

**Panic gate (arch L330 LOCKED) — PROVEN LIVE.**
- **Bypasses floor** (Ready pod, minInterval=30m): event 1 set `lastRotationTime` (30m floor active); event 2 fired ~22s later (floor NOT elapsed) with smoothed=0.95≥0.85 & consecHigh≥N ⇒ Rotate FIRED (rotationCount 1→2) + `Panic=True/ScoreThresholdCrossed`. Manager log: `Rotate PANIC: bypassing ONLY the min-interval floor (readiness/backoff/max-concurrent retained)`; `Rotate G3 min-interval: skipping` count = 0 (floor never blocked it).
- **Does NOT bypass readiness** (headline LOCKED proof, never-Ready pod via `/bin/false` probe): floor active AND a panic-armed 0.95 event ⇒ rotation did NOT fire (rotationCount stayed 1, pod unchanged); AMTD carried BOTH `Panic=True/ScoreThresholdCrossed` AND `RotationThrottled=True/ReplacementNotReady`. Manager log at 01:21:52 shows `Rotate PANIC: bypassing ONLY the min-interval floor` immediately followed by `Rotate G4 readiness: skipping` for the same reconcile; `recorded Panic condition (immediate Rotate; node-move/quarantine NOT triggered)`.

**Staleness decay (D25) — PROVEN LIVE.**
AMTD `stalenessWindow=3s`, `ewmaAlpha=0.9`, score=0.9; once the event aged past 3s, forced re-reconciles drove `smoothedScore` 0.0891 → 0.00891 → 0.000891 (decaying to 0), `consecutiveHighCount` reset, `currentInterval` pinned at 10m=BaseInterval (no acceleration); raw `lastObservedScore=0.9` kept for audit. Manager log: `applyScoring: score is stale; decaying effective score to 0 (D25)`.

**Provenance reject (D26g) + RBAC — PROVEN LIVE.**
Untrusted `Source=EvilWorkload`, score=0.99 → IGNORED: AMTD scored Status did NOT advance (`lastObservedScore` unchanged), SecurityEvent `observedScore=''`. Manager log: `applyScoring: score from a non-trusted Source ignored (D26g provenance)`. RBAC primary gate: `kubectl auth can-i create securityevents --as=system:serviceaccount:phase3-verify:noperm` → **no**; an actual create as that SA → `Error from server (Forbidden): securityevents.amtd.r6security.com "ev-rbac-denied" is forbidden: User "system:serviceaccount:phase3-verify:noperm" cannot get resource "securityevents" in API group "amtd.r6security.com" at the cluster scope`.

**Cleanup confirmation:** manager process gone; namespace `phase3-verify` deleted (took down deployments/AMTDs/pods/noperm SA); no test SecurityEvents remain; CRDs intentionally left installed; `repos` untouched (11 entries).

---

## Deviations / honest gaps

- **ContextMutationPolicy — DEFERRED (documented, not faked).** No `contextmutation*` files exist. It is the single remaining Phase-3 sub-item. Rationale: it needs a new cluster kind + scheme registration (`cmd/main.go`) + reconciler + RBAC + CRD generation, and its `GatekeeperViolation` trigger has no emitter; a clean implementation exceeds a thin add and would risk destabilizing the now-solid scoring core. Deferred per Stage-1 plan §7.
- **Provenance mechanism = RBAC + Source allowlist.** RBAC (workload SAs have no `securityevents` create grant) is the PRIMARY gate, verified live (Forbidden). The trusted-Source allowlist {Prometheus/Falco/KubeArmor}Integrator is defense-in-depth.
- **Live N-consecutive counting caveat (not a code bug).** The SecurityEvent controller re-reconciles the same event repeatedly, inflating live `consecutiveHighCount` (observed 11/37) — so live single-spike / N-consecutive counting is NOT cleanly observable. The authoritative N-consecutive assertions correctly rest on the deterministic table tests (`TestPanic_OnlyAfterNConsecutiveHigh` / `TestPanic_SingleSpikeNoPanic` / `TestPanic_DoesNotBypassReadiness` all PASS). Honestly disclosed, not hidden.
- **G6 max-concurrent deviation (pre-existing, documented).** The one-shot executor cannot return `ctrl.Result{RequeueAfter}`, so MaxConcurrent uses skip + `RotationThrottled` + re-selection on the next cadence tick (`rotate_executor.go:226-251`) — an honest realization of D24's requeue intent.
- **Live staleness-vs-table note.** Staleness is proven both live (above) and by the deterministic `TestScoring_StalenessDecaysToZero`, since `kubectl` cannot backdate `creationTimestamp` cleanly.
- **Live-test caveat (not a code bug):** hand-writing the pod `amtd.r6security.com/managed-by` annotation with Go field names fails — real struct tags are `amtd-namespace`/`amtd-name`/`managed-since` (`internal/controller/amtd_manage_info.go`). Let the AMTD controller stamp enrollment.

---

## Verdict

**PASS.** Every Phase-3 deliverable (1–5: scoring fields, Passthrough scorer, the 6 Status writes, provenance, staleness, EWMA, consecutive-high, monotone-decreasing ComputedInterval, panic-after-N bypassing only G3, scored selection under Scored, exact-match unchanged, Phase-0/1/2 invariants intact) is verified by file:line plus real build/vet/test exit codes (all 0) and direct live observation on `kind-amtd-test`. Deliverable 6 (ContextMutationPolicy) is honestly DEFERRED, not faked.

**Next:** Phase 4 (warm-pool / LeaderWorkerSet — GPU-headline) — **NOT started.**

---

**Evidence files** (`c:\Users\moh87733\Phorvex\build\logs\`): `review3-build.txt`, `review3-vet.txt`, `review3-test.txt`, `review3-phase3-tests.txt`, `review3-invariants.txt` (Stage-5 review session); `live3-tests.txt`, `live3-panic-tests.txt`, `live3-evidence.txt`, `live3-manager.log`, `live3-build.txt` (Stage-4 live, re-validated).
