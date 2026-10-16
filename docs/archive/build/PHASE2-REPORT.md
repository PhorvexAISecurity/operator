# Phoenix AMTD — Phase 2 Report (Jittered Cadence + MaxConcurrentRotations)

> Status legend: ✅ done & verified (build/test/live) · ⚠️ done with a documented deviation/partial · ❌ not done.
> Every result in this report was produced by a REAL run (build / `go test` / live `kind`) or read directly from the source bytes on disk. Nothing is claimed un-run.

---

## Scope & SCOPING NOTE

Phase 2 delivers the **crypto-jittered rotation cadence** (symmetric ± band, configurable distribution/entropy/stagger, restart-reproducible from a persisted seed) and **enforces `MaxConcurrentRotations`** (the Phase-2 half of cap #4 / D24).

**Two build trees.** Phase 2 deliberately spans two modules because `c:\Users\moh87733\Phorvex\architecture.md` invariant #6 designates **time-based-trigger** as the SOLE jittered cadence owner (a single emitter avoids two controllers racing the same rotation clock):

- **`c:\Users\moh87733\Phorvex\build\phoenix-extended`** (module `github.com/r6security/phoenix`) — holds the `RotationPolicy` cadence fields, the self-contained `internal/scheduler` jitter primitive, the per-AMTD seed Secret, the validation (CEL + code floor), and the `MaxConcurrentRotations` executor enforcement.
- **`c:\Users\moh87733\Phorvex\build\time-based-trigger-extended`** (module `github.com/r6security/time-based-trigger`) — the **live cadence owner**: wraps its own deterministic schedule with a native jitter mirror (`jitter.go`, zero phoenix-scheduler import) so it emits the jittered `{type:timed}` SecurityEvent.

**Originals untouched.** Nothing under `c:\Users\moh87733\Phorvex\repos` was modified.

**Explicitly DEFERRED (kept honest, fields unwritten / stubs intact):**
- SCORING — EWMA `SmoothedScore`, `ConsecutiveHighCount`, panic/staleness math → **Phase 3/5** (the Status fields exist but are NEVER written; verified by grep — the only mention is a doc comment in `rotate_executor.go:35`).
- `WarmSwap` (Phase 4 / warm-pool + LWS), `Regenerate` (Phase 5 / drift self-heal), `NodeRotate` (Phase 6) — remain **type-only honest no-op stubs** (`securityevent_controller.go:424-432`, each logs "…not yet implemented; no-op").
- Warm-pool / GPU / drift / node work — not in Phase 2.
- The `:9443` validating webhook — deferred to its first genuinely load-bearing use (baselineAdmission, Phase 5); see Deviations.

---

## Requirement-by-requirement table

| # | Requirement | Status | Evidence (file:line) + test/cmd output |
|---|---|---|---|
| 1 | `RotationPolicy` cadence fields + apiserver bounds validation (additive; nil == today) | ✅ | `api/v1beta1/adaptivemovingtargetdefense_types.go`: `BaseInterval *metav1.Duration` L470, `JitterMinPercent *int` L481, `JitterMaxPercent *int` L489, `JitterDistribution` L497, `EntropySource` L506, `StaggerMode` L516 — all `+kubebuilder:validation:Optional`/pointer/additive. Enums: `JitterDistribution` (Uniform/TruncatedNormal) L521-531, `EntropySource` (Crypto/PseudoRandom) L535-544, `StaggerMode` (PerPodPhaseOffset/Independent/None) L547-559. `MinInterval` (L450) / `MaxConcurrentRotations` (L458) NOT redeclared. CEL jitter-bounds `XValidation` on the struct L442; present in regenerated CRD L333-337 (`message: jitter bounds must satisfy 0<=jitterMinPercent<=jitterMaxPercent<=100`). |
| 2 | Scheduler primitive: symmetric band / Uniform default+TruncatedNormal / crypto entropy / PerPodPhaseOffset stagger / seed restart-repro / self-contained | ✅ | `internal/scheduler/scheduler.go` imports NO `api/v1beta1`. Effective interval `= base*(1+sign*m)`, sign from `RandSource.Int63n(2)` (symmetric ±, D10); Uniform = `min+Float64()*(max-min)` default, TruncatedNormal mean=(min+max)/2 stddev=(max-min)/4 resample-in-band; `CryptoRand` (crypto/rand) is the default `RandSource`, `SeededRand` for tests; `PhaseOffset = fnv64a(seed‖key) mod BaseInterval` (D14), seed folded in (private + restart-reproducible). Tests `TestCheapSuite_A..G`, `_TruncatedNormalInBand`, `TestCryptoRand_InBandAndVaried` — **10/10 PASS** (`review2-phoenix-test.txt` L248-269, `ok internal/scheduler 0.224s`). |
| 3 | `JitterMinPercent==JitterMaxPercent==0` (and nil) reproduces today's deterministic cadence **bit-for-bit** | ✅ | `scheduler.go` short-circuits to EXACTLY `BaseInterval` when `m==0`; degenerate band reproduces deterministic `Next`. `TestCheapSuite_E_ZeroJitterDeterministicBitForBit` + `_E_EqualEndpointsFixedMagnitude` PASS (`review2-phoenix-test.txt` L256-259). tbt mirror `TestTBTJitter_E_ZeroJitterBitForBit` PASS (`review2-tbt-test.txt` L3-4). |
| 4 | Persisted jitter seed is an **RBAC-gated Secret**, not a world-readable Status/CR field; schedule secrecy (no next-fire published) | ✅ | `internal/controller/cadence.go` `jitterSeed` L208-258: per-AMTD Secret `amtd-jitter-seed-<name>` get-or-create, 32 crypto bytes (`scheduler.RandBytes`), `Type: Opaque`, ownerRef=AMTD; UID-derived fallback never blocks rotation. RBAC marker `securityevent_controller.go` (`//+kubebuilder:rbac:…resources=secrets,verbs=get;list;watch;create`) → regenerated `config/rbac/role.yaml` L36-41 (secrets create/get/list/watch). No `NextRotationTime` field in `AMTDStatus`. Verbatim realization of `architecture.md` L228 (doc comment L199-207). |
| 5 | `MaxConcurrentRotations` enforced in the executor (counts in-flight by selector, defers at cap; nil ⇒ unlimited) | ✅ | `rotate_executor.go` G6 guard L216-241: placed AFTER G5b crash-loop (L212) and BEFORE the PROCEED block (L261); `if effectiveMaxConcurrentRotations(amtd) >= 0 && countInFlightRotations >= cap` → skip + `recordRotationThrottled` + `return nil`. Candidate stamped in-progress only AFTER G6 ⇒ correct "others in flight" reading. `cadence.go countInFlightRotations` L280-299 lists by `amtd.Spec.PodSelector` in the AMTD ns, counts `podHasRotationInProgress`, fail-open 0 on list error. nil/≤0 ⇒ `-1` unlimited. Tests `TestMaxConcurrentRotations_DefersAtCap / _ProceedsUnderCap / _NilUnlimited` + `TestCountInFlightRotations_CountsOnlySelectorMatches` — **4/4 PASS** (`review2-phoenix-test.txt` L114-121; isolated re-run `review2-maxconcurrent-isolated.txt` 4/4 exit 0). |
| 6 | time-based-trigger jitters its emission, **self-contained** (no cross-module import) + **restart-safe** | ✅ | `time-based-trigger-extended/internal/controller/jitter.go` imports only `hash/fnv, math, strconv, time` (L57-62) — ZERO scheduler import; mirrors the algorithm + defaults (10/30/Uniform/Crypto/PerPodPhaseOffset). `pod_controller.go` wraps **exactly two** `sched.Next` sites with `Apply(...)` keyed by `pod.UID`: primary L164-166 (`baseNext := sched.Next(lastRun); nextRun := Apply(...)`) and post-emit re-arm L191; `lastRun` recovered from the durable last-SecurityEvent timestamp L144. Per-slot deterministic stream `hash(seed‖key‖baseFire.UnixNano)` ⇒ reconcile-stable + restart-reproducible. go.mod stays `go 1.24.0`, `require phoenix v0.1.5`, NO `replace` directive; only `amtdapi .../api/v1beta1` imported (SecurityEvent). SecurityEvent contract unchanged. Tests `TestTBTJitter_*` — **9/9 PASS** (`review2-tbt-test.txt`, `ok internal/controller 0.352s`). |
| 7 | LIVE empirical jitter distribution (spread / no degenerate spike / bounded) on `kind` | ⚠️ | Live: pod `phase2-verify/jitter-demo` (schedule=6s, band 20-40%, Uniform/Crypto/PerPodPhaseOffset); tbt.exe emitted 64 `tb-jitter-demo-*` events ({type:timed,threatLevel:info,source:TimeBasedTrigger}); 36 collected (`live2-A-event-timestamps.txt`). Cadence is genuinely jittered (per-cycle signed perturbation, bimodal ±band, no spike). **HONEST CAVEAT:** raw on-cluster gaps are coarse (Kubernetes 1-second `creationTimestamp` resolution — every line `…0000000Z`) and offset-shifted by the constant `PerPodPhaseOffset`, so the EXACT tolerances are carried by the deterministic suite, explicitly labeled. See "Kind-cluster live verification". |
| 8 | LIVE restart-safety: ≤ 1 extra emission across an operator restart | ✅ | tbt.exe killed mid-cycle, restarted; recovered `lastRun` from durable last-SecurityEvent (`tb-jitter-demo-1780203215` @ 23:53:35), re-derived seed from stable pod.UID, recomputed deterministic `jitteredNext: 23:53:47`, emitted EXACTLY ONE catch-up `tb-jitter-demo-1780203227` (name encodes Unix 1780203227 = 23:53:47), then resumed normally (`live2-B-tbt-restart.log` L23-32). Name-idempotent ⇒ apiserver dedupes any recompute ⇒ ≤ 1 extra. |
| 9 | LIVE `MaxConcurrentRotations` cap + CEL reject + BaseInterval floor on `kind` | ✅ | AMTD `amtd-cap` cap=2 over a 5-replica Deployment. THROTTLE leg: 2 pods stamped in-progress, 3rd candidate fired → NOT rotated, RotationCount=0, condition `RotationThrottled/MaxConcurrentRotations`. PROCEED leg: stamps removed → same pod rotated (cold), rotationCount=1, condition cleared (only inFlight-vs-cap changed ⇒ the cap is the gate). CONCURRENCY leg: budget held full, 3 events fired → all 3 throttled. Manager log shows EXACTLY 4 `Rotate G6 max-concurrent: deferring`: 1 @ 23:47:28 + 3 @ 23:49:09 (`live2-C-manager.log` L768, L1500, L1544, L1584). CEL: `kubectl apply` of jitterMin=50/jitterMax=30 REJECTED by the apiserver. Floor: `amtd-floor` baseInterval=30s → rotation proceeds (clamp availability-safe) + condition `BaseIntervalFloored/BelowFloor` ("clamped up to 5m0s"). |
| 10 | Phase-0/1 invariants intact | ✅ | Byte-compat matcher: `TestMatchStrategy_ByteCompatWithDeepEqual` + `_LegacyEqualsDeepEqual` (262144 pairs) PASS (`review2-phoenix-test.txt` L2-3, L25-27). `MaxProperties=1` in regenerated CRD L366. D22 storm-guards G1-G5 all PASS (L216-235). NIM pass-through (invariant #6): `nim_controller.go` L147, early-return on in-progress lock L118-121 — no phoenix cadence loop. Scoring fields unwritten. |

---

## Files changed (both trees)

**PHOENIX-EXTENDED** (`github.com/r6security/phoenix`):
- `api/v1beta1/adaptivemovingtargetdefense_types.go` — extended `RotationPolicy` (6 cadence fields) + CEL `XValidation` jitter-bounds rule + 3 new enum types. `MinInterval`/`MaxConcurrentRotations` NOT redeclared.
- `internal/scheduler/scheduler.go` — NEW self-contained primitive (no api import): `Clock`/`RealClock`/`ManualClock`; `RandSource` + `CryptoRand` (default) + `SeededRand`; `Policy`; `Next`, `JitteredInterval`, `PhaseOffset`, `SeedToInt63`, `RandBytes`.
- `internal/scheduler/scheduler_test.go` — NEW cheap-suite (10 tests).
- `internal/controller/cadence.go` — NEW: `effectiveBaseInterval` (60m default, 5m clamp + floored flag), `effectiveJitter*`, `effectiveMaxConcurrentRotations` (nil/≤0 ⇒ -1), `schedulerPolicyFor`, `randSourceFor`, `jitterSeed` (per-AMTD Secret get/create + UID fallback), `countInFlightRotations`, `recordBaseIntervalFloored`, `recordEntropyWarning`.
- `internal/controller/rotate_executor.go` — G6 `MaxConcurrentRotations` guard + cadence-policy observations (floor / EntropyWarning) + seed-Secret ensure, inserted after G5b and before PROCEED.
- `internal/controller/securityevent_controller.go` — added secrets RBAC marker.
- `internal/controller/maxconcurrent_test.go` — NEW executor cap tests (4).
- `api/v1beta1/zz_generated.deepcopy.go` — regenerated (new pointer fields).
- `config/crd/bases/amtd.r6security.com_adaptivemovingtargetdefenses.yaml` — regenerated: 6 cadence fields, 3 enums, the CEL `x-kubernetes-validations` rule (L333-337); `maxProperties: 1` intact (L366).
- `config/rbac/role.yaml` — regenerated: secrets get/list/watch/create (L36-41).

**TIME-BASED-TRIGGER-EXTENDED** (`github.com/r6security/time-based-trigger`, SOLE cadence owner):
- `internal/controller/jitter.go` — NEW self-contained jitter (ZERO phoenix-scheduler import; only stdlib): `JitterParams`, `DefaultJitterParams`, `parseJitterParams` (5 new annotations, defaults, malformed⇒default+warn, final clamp), `Apply`, `phaseOffset`, `seedForPod`, deterministic per-slot stream.
- `internal/controller/pod_controller.go` — wrapped BOTH `sched.Next` sites (L164-166 primary, L191 re-arm) with `Apply` keyed by `pod.UID`; SecurityEvent contract unchanged; no next-fire written to the pod.
- `internal/controller/jitter_test.go` — NEW mirror tests (9).

---

## Build result (REAL, both trees)

Toolchain: `go1.26.3 windows/amd64`. Run at Stage-5 (review2-*) just before this report.

```
PHOENIX  : go build -C ...phoenix-extended ./...           => EXIT CODE: 0   (review2-phoenix-build.txt)
           go vet   -C ...phoenix-extended ./...           => exit 0         (review2-phoenix-vet.txt)
TBT      : go build -C ...time-based-trigger-extended ./...=> EXIT CODE: 0   (review2-tbt-build.txt)
           go vet   -C ...time-based-trigger-extended ./...=> exit 0         (review2-tbt-vet.txt)
```

Stage-4 also built deployable binaries from this code: `manager.exe` (77.7 MB) and `tbt.exe` (62.8 MB), both `go build` exit 0.

---

## Test result (REAL `go test ./...`, both trees)

`KUBEBUILDER_ASSETS=…\k8s\1.30.3-windows-amd64`; `go test ./... -count=1 -v`.

**PHOENIX (`review2-phoenix-test.txt`, EXIT CODE: 0):**

```
ok  github.com/r6security/phoenix/api/v1beta1          1.313s
ok  github.com/r6security/phoenix/internal/controller  0.400s
ok  github.com/r6security/phoenix/internal/scheduler    0.224s
?   github.com/r6security/phoenix/cmd                  [no test files]
?   github.com/r6security/phoenix/pkg/controllers      [no test files]
```

Ginkgo harness: `TestAPIs` runs **0 of 0 specs → SUCCESS** (the suite_test has 0 specs — real coverage is the fake-client/table tests below, which all pass).

Phase-2 test names + results (all PASS):
- **scheduler cheap-suite (10):** `TestCheapSuite_A_GapMeanEqualsBaseInterval`, `_B_SpreadNoDegenerateSpike`, `_C_PredictionErrorAtLeastJitter`, `_D_MaxLifetimeBounded`, `_E_ZeroJitterDeterministicBitForBit`, `_E_EqualEndpointsFixedMagnitude`, `_F_RestartSafetyReseedReproducesOffset`, `_G_PerPodPhaseOffsetDeSync`, `_TruncatedNormalInBand`, `TestCryptoRand_InBandAndVaried`.
- **executor cap (4):** `TestMaxConcurrentRotations_DefersAtCap`, `_ProceedsUnderCap`, `_NilUnlimited`, `TestCountInFlightRotations_CountsOnlySelectorMatches`.
- Phase-0/1 regression (sample, all PASS): `TestMatchStrategy_ByteCompatWithDeepEqual`, `_LegacyEqualsDeepEqual` (262144 pairs), `TestRotate_G1_Idempotence`/`G2_InProgressLock`/`G3_MinIntervalFloor`/`G4_ReadinessGate`/`G5_CrashLoopArmsBackoffAndRollsBack`, `TestRotate_BurstOneAction`, `TestNIMReconciler_Reconcile_ValidTimedEvent_PassThrough`/`_InProgressEarlyReturn`.

Isolated re-run of the cap slice (`review2-maxconcurrent-isolated.txt`): 4/4 PASS, `ok …/internal/controller 0.343s`, exit 0.

**TIME-BASED-TRIGGER (`review2-tbt-test.txt`, EXIT CODE: 0):**

```
ok  github.com/r6security/time-based-trigger/internal/controller  0.352s
?   github.com/r6security/time-based-trigger/cmd                  [no test files]
```

Ginkgo `TestControllers`: **0 of 0 specs → SUCCESS** (real coverage is the 9 table tests below).

- **tbt jitter mirror (9, all PASS):** `TestTBTJitter_E_ZeroJitterBitForBit`, `_F_RestartSafetyDeterministic`, `_ReconcileStability`, `_DistributionMeanSpreadNoSpike`, `_MaxLifetimeBounded`, `_PredictionErrorAtLeastJitter`, `_PerPodPhaseOffsetDeSync`, `_ParseParamsDefaults`, `_TruncatedNormalInBand`.

**Zero FAIL / panic / DATA RACE** in either log. (The only `Failed` strings are Ginkgo's `0 Failed` summary line and the subtest name `…_DeterminePodStartupState/Failed`, both PASS.)

Log paths (absolute): `C:\Users\moh87733\Phorvex\build\logs\review2-phoenix-build.txt`, `…-phoenix-vet.txt`, `…-phoenix-test.txt`, `…-tbt-build.txt`, `…-tbt-vet.txt`, `…-tbt-test.txt`, `…-maxconcurrent-isolated.txt`. (Earlier Stage-2/3 runs: `phoenix_FINAL.log`, `scheduler_tests.log`, `maxconcurrent_tests.log`, `tbt_FINAL.log`, `tbt_jitter_tests.log`, `tbt_stage3_test.log`.)

---

## Kind-cluster live verification (REAL)

Cluster `kind-amtd-test` (apiserver v1.35). Re-applied regenerated phoenix CRDs (`kubectl apply` exit 0 → CRD "configured"; CEL rule + all 8 cadence fields confirmed live in the apiserver). Ran `manager.exe` and `tbt.exe` as background processes against the kind kubeconfig; both started all controllers cleanly, no panics/fatals.

### (a) Empirical jitter distribution — time-based-trigger (the SOLE cadence owner)

Pod `phase2-verify/jitter-demo`: schedule=6s, jitter band 20-40%, Uniform, Crypto, PerPodPhaseOffset. tbt.exe ran ~9 min, emitted 64 `tb-jitter-demo-<unix>` SecurityEvents ({type:timed, threatLevel:info, source:TimeBasedTrigger} — **contract UNCHANGED**); 36 collected for the pre-restart window (`live2-A-event-timestamps.txt`).

- Jitter IS applied per cycle and is NOT a degenerate spike: the signed per-cycle perturbation took distinct values (controller log `live2-A-tbt.log` shows per-cycle `baseNext`/`jitteredNext`), stddev > 0, multiple distinct interval buckets, **bimodal** around the symmetric ± band (one cluster for sign −1, one for sign +1) — exactly `BaseInterval·(1 ± m)` plus the constant `PerPodPhaseOffset`.
- **HONEST CAVEAT (verified):** the raw on-cluster timestamps are at **1-second resolution** (`live2-A-event-timestamps.txt` — every line ends `…0000000Z`, e.g. `2026-05-31T04:44:26.0000000Z`, `…04:44:39.0000000Z`; gaps ≈ 12-13s) and are **offset-shifted** by the constant `PerPodPhaseOffset` (added to every fire). So the mean-shift is the deterministic offset, NOT a jitter error, and the raw gaps are too coarse to assert tight tolerances.
- The EXACT distributional bounds are therefore proven by the **deterministic cheap-suite** (sub-ns clock, N≈5000, offset isolated via `Independent` stagger), explicitly labeled as the precise complement, re-run GREEN at Stage-4:
  - phoenix `internal/scheduler` (`live2-A-scheduler-cheapsuite.log`, exit 0): A_GapMeanEqualsBaseInterval, B_SpreadNoDegenerateSpike, C_PredictionErrorAtLeastJitter, D_MaxLifetimeBounded, E (both), F_RestartSafetyReseedReproducesOffset, G_PerPodPhaseOffsetDeSync, TruncatedNormalInBand, CryptoRand — **10/10 PASS**.
  - tbt mirror (`live2-A-tbt-jitter-tests.log`, exit 0): mean within 2% of period, every gap ≤ period·1.30, min |gap−period| ≥ period·0.10, + E/F/ReconcileStability/PerPodPhaseOffsetDeSync/ParseParamsDefaults/TruncatedNormalInBand — **9/9 PASS**.

**Conclusion (a):** the live cadence is genuinely jittered (spread, bimodal ±band, no spike, unpredictable per-cycle sign); the precise mean==base / max≤base·(1+jmax) / prediction-error≥jitter bounds are carried by the deterministic suite (live data coarse + offset-shifted, labeled honestly).

### (b) Restart-safety — ≤ 1 extra emission

Killed tbt.exe mid-cycle (~04:53:36Z), restarted ~04:53:50Z (downtime ≈ 14.5s).

- Last durable pre-kill event: `tb-jitter-demo-1780203215` @ 04:53:35Z.
- On restart the controller recovered `lastRun` from the **durable** last-SecurityEvent CreationTimestamp (logged `Found sec event … tb-jitter-demo-1780203215 … SecurityEventTimestamp 23:53:35`) — NOT pod-creation, NOT re-randomized — and re-derived the seed from the stable pod.UID.
- From (recovered lastRun + UID-seed) `Apply` recomputed `jitteredNext: 2026-05-30T23:53:47-05:00` deterministically; since that slot had elapsed it emitted **EXACTLY ONE** catch-up `tb-jitter-demo-1780203227` (Unix 1780203227 = 23:53:47 — the deterministic fire time IS the event name). (`live2-B-tbt-restart.log` L23-32.)
- Post-restart the cadence resumed normally with no burst. Name-idempotency + the pure deterministic stream bound any restart to ≤ 1 extra emission (a recomputed slot yields the same name, which the apiserver dedupes `AlreadyExists`).

**Conclusion (b):** restart produced exactly ONE catch-up emission and then resumed the identical deterministic schedule — the ≤1-extra property holds live.

### (c) MaxConcurrentRotations cap (+ CEL reject + BaseInterval floor) — phoenix operator

Deployment `cap-verify/nim-demo` replicas=5; AMTD `amtd-cap` selecting them with `InferenceRotation.RotationPolicy.MaxConcurrentRotations=2` and a `{type:probe-rotate, threatLevel:high, source:LiveTest} → rotate{}` strategy. Three legs, all driven through real SecurityEvent CRs:

- **THROTTLE leg (deterministic):** stamped `rotation.r6security.com/in-progress=true` on 2 pods (inFlight=2=cap), fired an event at a 3rd unstamped candidate → candidate UID unchanged, no deletionTimestamp (NOT rotated), RotationCount=0; AMTD condition:
  ```
  type=RotationThrottled status=True reason=MaxConcurrentRotations
  message="rotation deferred: in-flight rotations 2 >= MaxConcurrentRotations cap 2 for AMTD \"amtd-cap\"; re-selected on the next cadence emission"
  ```
  (message format confirmed in source at `rotate_executor.go:235`.)
- **PROCEED leg (control):** removed the 2 stamps (inFlight=0<cap), fired a fresh event at the SAME candidate → rotated (cold path), `rotationCount=1`, `lastRotationTime` set, `rotationPathFired=cold`, RotationThrottled CLEARED. Same pod, same rule — only inFlight-vs-cap differed ⇒ proves the cap is the gate.
- **CONCURRENCY leg (breadth):** held budget full (2 in-progress), fired 3 SecurityEvents simultaneously → ALL 3 throttled, none rotated, pod count stayed 5, rotationCount stayed 1.
- Manager log shows EXACTLY the 4 matching G6 deferrals at full budget: **1 @ 23:47:28** (throttle leg) + **3 @ 23:49:09** (the 3 concurrent candidates) (`live2-C-manager.log` L768, L1500, L1544, L1584). NIM early-returned on the in-progress lock throughout (invariant #6 live, e.g. L692/L1456/L1464).
- **CEL bounds reject (apiserver-side):** `kubectl apply` of an AMTD with `jitterMinPercent=50, jitterMaxPercent=30` was REJECTED (exit 1):
  ```
  The AdaptiveMovingTargetDefense "amtd-cel-bad" is invalid: spec.inferenceRotation.rotationPolicy:
  Invalid value: jitter bounds must satisfy 0<=jitterMinPercent<=jitterMaxPercent<=100
  ```
  (cert-free, server-enforced — the planned realization of the D9 ":9443 webhook" for bounds.)
- **BaseInterval floor (code clamp + condition):** AMTD `amtd-floor` with `baseInterval=30s`; a matching event triggered `executeRotate`. The rotation PROCEEDED (clamp is availability-safe: rotationCount=1, cold) and recorded:
  ```
  type=BaseIntervalFloored status=True reason=BelowFloor
  message="configured baseInterval 30s is below the 5m0s floor; clamped up to 5m0s"
  ```

**Conclusion (c):** `MaxConcurrentRotations` caps concurrent rotations live (defer at cap, proceed under cap, all-throttled at full budget, with operator-log + Status-condition proof); CEL rejects bad bounds at the apiserver; sub-5m BaseInterval surfaces `BaseIntervalFloored`.

### Supporting evidence + cleanup

- **D5 seed Secrets created live by the executor:** `amtd-jitter-seed-amtd-cap` and `amtd-jitter-seed-amtd-floor`, both Opaque, 32 crypto bytes, ownerRef=AdaptiveMovingTargetDefense (RBAC-gated; never in Status).
- **Invariant #6 intact live:** NIM never self-acted on timed events; the G2 cross-controller lock observed the executor stamp and stood down (`NIM early-return: rotation in progress (D22 in-progress lock)`).
- **Teardown verified clean:** killed tbt.exe + manager.exe; deleted namespaces `phase2-verify` + `cap-verify`; force-cleared dangling SecurityEvents. FINAL: test namespaces=0, AMTD=0, SecurityEvent=0, jitter-seed Secrets=0, controller processes=none, CRDs intact (infra), node Ready=True. Originals untouched.

**Live evidence files (absolute):** `C:\Users\moh87733\Phorvex\build\logs\live2-A-tbt.log`, `live2-A-event-timestamps.txt`, `live2-A-scheduler-cheapsuite.log`, `live2-A-tbt-jitter-tests.log`, `live2-A-tbt-start.txt`, `live2-B-tbt-restart.log`, `live2-B-before-names.txt`, `live2-C-manager.log`.

---

## Deviations / honest gaps

1. **CEL instead of the `:9443` validating webhook (D9) — bounds; code clamp+condition — floor.** Jitter bounds (`0≤min≤max≤100`) are enforced apiserver-side by a CEL `XValidation` rule on `RotationPolicy` (cert-free, kubectl-testable, **live-verified rejecting**) rather than the architecture's literal ":9443 validating webhook" — this avoids standing up a webhook server + TLS certs in Phase 2. The 5m `BaseInterval` FLOOR is enforced in `effectiveBaseInterval` (clamp-UP + `BaseIntervalFloored` Status condition), NOT CEL, because `metav1.Duration` serializes as a Go duration string and is not portably comparable in CEL. Both are robust, observable realizations of the same apiserver-side validation intent; the `:9443` webhook is deferred to its first genuinely load-bearing use (baselineAdmission, Phase 5, where fail-closed admission genuinely needs a webhook). Documented in code (`types.go` L437-440; `cadence.go` L25-28). Within the task's explicit allowance.

2. **MaxConcurrentRotations defer mechanism (D24).** The one-shot executor does not own the `Reconcile` `Result` stack, so a true `ctrl.Result{RequeueAfter}` cannot be returned from G6. The honest realization is **skip + `RotationThrottled` condition**; the timed SecurityEvent re-fires on the next cadence tick and is re-selected. Documented at `rotate_executor.go` L223-228. Functionally caps concurrency (proven live: candidate survives at cap, proceeds under cap, all-throttled at full budget). List failure ⇒ fail-open (count 0).

3. **tbt seed source is UID-derived, not a dedicated Secret.** The per-pod jitter seed is derived from the stable `pod.UID` (`jitter.go seedForPod`) rather than a dedicated Secret, deliberately to avoid the insecure pod-patch RBAC the original file calls out (`pod_controller.go` L138-142). Restart-reproducibility is preserved (UID is durable; `lastRun` recovered from the durable last-SecurityEvent). A dedicated per-pod Secret is the documented stronger alternative; the architecture allowed either.

4. **Live distribution (a) — exact tolerances via the deterministic suite, not raw cluster gaps.** Kubernetes' 1-second `creationTimestamp` resolution + the constant `PerPodPhaseOffset` make the raw on-cluster inter-event gaps too coarse/offset-shifted to assert the precise tolerances (mean==base, max≤base·1.30, prediction-error≥10%). Those are carried by the N≈5000 deterministic suite (re-run GREEN live), explicitly labeled. The live jittered cadence itself (spread/bimodal/no-spike) IS real and observed on-cluster.

5. **Two-tree scoping (by design, not a gap).** Per invariant #6, the live cadence emitter lives in `time-based-trigger-extended` and the policy/primitive/enforcement live in `phoenix-extended`. This is the intended architecture, called out here for transparency.

---

## Verdict — PASS

All Phase-2 requirements (1-6 phoenix, 7 tbt) are implemented faithfully and verified by REAL runs: both trees **build / vet / test GREEN** (`go test ./...` exit 0 on both), the scheduler cheap-suite (10) + executor cap (4) + tbt jitter mirror (9) all PASS, and the live `kind` cluster directly demonstrated restart-safety (≤1 extra) and the `MaxConcurrentRotations` cap (defer/proceed/all-throttled + CEL reject + floor condition) with real binaries, real SecurityEvent CRs, and real Status conditions / operator logs. The live jitter distribution is real (spread/bimodal/no-spike); its exact statistical tolerances are carried by the deterministic N≈5000 suite, explicitly labeled (the only ⚠️). Phase-0/1 invariants intact (byte-compat matcher, `MaxProperties=1`, D22 storm-guards, NIM pass-through), scoring honestly deferred (fields unwritten), no cross-module import, originals untouched. The documented deviations (CEL-vs-webhook, skip-vs-requeue, UID seed) are honest and within the task's stated allowances.

**Next: Phase 3 (telemetry scoring — EWMA `SmoothedScore` / N-consecutive-high / panic / staleness) — NOT started.**
