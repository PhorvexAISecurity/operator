# Phoenix AMTD — Phase 1 Report (RotateAction Overlay / MutationApplier + D22 Storm-Guard)

**Date:** 2026-05-30
**Output tree:** `c:\Users\moh87733\Phorvex\build\phoenix-extended` (the original repo `c:\Users\moh87733\Phorvex\repos\phoenix-main` is **untouched**)
**Verdict:** **PASS** — all close-out gates are real and green: `go build`/`go vet`/`go test` exit 0, 59 top-level tests pass (32 new Phase-1, 9 preserved Phase-0 invariants, 0 FAIL), and the live kind cluster proved both "rotation fires + mutation applied" and "storm-guard blocks the re-fire."

---

## 1. Scope & non-goals

### Phase 1 delivers (and this report verifies as REAL)
- **MutationApplier** — a real overlay interpreter that mutates the pod/owner spec (image swap, env set/overwrite, GPU quantity), delivered through a **real cold reschedule** (mutate-then-delete). Precedence D1: `RotateAction.Overrides` (inline) wins over `RotateAction.PolicyRef -> InferenceRotation`.
- **D3 owner-walk routing** — walk the pod's owner chain to the TOP controller; patch the top owner's `.spec.template` durably (Deployment via its ReplicaSet / StatefulSet / DaemonSet), or **cold-fallback** with an honest `MutationNotDurableReason` (`BarePod` / `ImmutableJobTemplate` / `PerPodOnSharedTemplate`). Never patches a bare ReplicaSet directly. Owner-template patch is idempotent (self-Update-loop guarded).
- **D22 storm-guard** wrapping the Rotate executor: G1 idempotence, G2 in-progress lock (cross-controller, incl. NIM early-return), G3 min-interval floor (the anti-thrash core, default 60s), G4 readiness gate, G5 crash-loop backoff + image rollback. One SecurityEvent => at most one action; no self-requeue storm.

### Phase 1 explicitly DEFERS (kept honest — coded as stubs/comments, never faked)
- **Warm-pool / zero-downtime cutover = Phase 4.** Rotate DELIVERY is a real cold reschedule. No warm pool, **no zero-downtime claim, no GPU-downtime numbers**.
- **EWMA / panic SCORING math = Phase 3/5.** `Status.SmoothedScore` and `Status.ConsecutiveHighCount` exist as fields but are **never written**; `PanicThreshold`/EWMA spec inputs are not even declared. No scoring math anywhere in the executor.
- **WarmSwap / Regenerate / NodeRotate = honest no-op-with-log stubs** (`securityevent_controller.go:421-429`, unchanged from Phase 0).
- **No Phase-2 jitter/scheduling.** `RotationPolicy.MaxConcurrentRotations` is declared but enforcement is Phase 2 (documented in the field comment).
- **GPU-shuffle / encrypted-memory / RAG-sandbox / endpoint / ContextMutationPolicy** sub-policies are intentionally NOT declared, so they stay honestly uninterpreted. CMP `Kind` resolves to an empty (inert) overlay.

---

## 2. Requirement-by-requirement results

Legend: ✅ verified real & green · ⚠️ partial/honest-minimal · ❌ failed.
"EVIDENCE" cites `file:line` in the output tree and/or the real captured `go test` / kind output.

| # | Requirement | Status | Evidence (file:line + real output) |
|---|---|---|---|
| A1 | MutationApplier interprets **image** | ✅ | `mutation.go` `ApplyToPodSpec` image swap L186-189. Tests `TestMutationApplier_Apply_ImageDefaultContainer`, `_ImageNamedContainer` PASS. Live: Deployment template `busybox:1.36 -> busybox:1.37`. |
| A2 | MutationApplier interprets **env** (set + overwrite) | ✅ | `mutation.go` env set-or-overwrite-by-Name L192-208. Test `TestMutationApplier_Apply_EnvSetAndOverwrite` PASS. Live: `RUNTIME_MODE NORMAL -> SECURE`. |
| A3 | MutationApplier interprets **GPU** quantity (ParseQuantity, "0"=DropToZero) | ✅ | `mutation.go` GPU via `resource.ParseQuantity` (NOT MustParse) into `Limits["nvidia.com/gpu"]` L212-222. Tests `TestMutationApplier_Apply_GPUDropToZero`, `_GPUInvalidQuantity` PASS. |
| A4 | Precedence D1: Overrides > PolicyRef->InferenceRotation; empty overlay => pure cold reschedule | ✅ | `mutation.go` `Resolve` L108-151 (Overrides wins L114-123; PolicyRef `""`/`InferenceRotation` projects `GoldenImage->Image` L128-137; CMP/other => empty L141-145; both nil => empty L150). Tests `_OverridesWinsOverPolicyRef`, `_PolicyRefInferenceRotation`, `_ContextMutationPolicyEmpty`, `_BothNilEmpty`, `_EmptyOverlayNoChange` PASS. |
| B1 | D3 owner-walk patches the **TOP** owner template (durable, all replicas); never a bare RS | ✅ | `mutation.go` `classifyTopOwner` L294-335 (RS ascends to its Deployment L315-326; bare RS => fallback, top=nil, never patched L327-328). `patchOwnerTemplate` L343-381 idempotent. Tests `TestClassify_DeploymentRoute`, `_StatefulSetRoute`, `_DaemonSetRoute`, `_BareReplicaSet`, `TestPatchOwnerTemplate_AppliesAndIsIdempotent` PASS. |
| B2 | Correct `MutationNotDurableReason` on cold-fallback | ✅ | `BarePod` L301, `ImmutableJobTemplate` (Job) L307, `PerPodOnSharedTemplate` (bare RS / other) L327. Tests `TestClassify_BarePod`, `_JobOwned`, `_BareReplicaSet` PASS. |
| C1 | D22 **idempotence** (key = podUID + eventUID) | ✅ | `rotate_executor.go` G1 L148-153 (pod annotation `ROTATION_LAST_KEY`). Test `TestRotate_G1_Idempotence` PASS (pod NOT re-deleted, RotationCount stays 0). Live: re-delivered fire1 => "G1 idempotence ... skipping". |
| C2 | D22 **in-progress lock** (cross-controller, NIM early-return) | ✅ | `rotate_executor.go` G2 L155-159 (`ROTATION_IN_PROGRESS`); NIM lock `nim_controller.go:118` `podHasRotationInProgress`. Tests `TestRotate_G2_InProgressLock`, `TestNIMReconciler_Reconcile_InProgressEarlyReturn` PASS. |
| C3 | D22 **min-interval floor** (anti-thrash core, default 60s) | ✅ | `rotate_executor.go` G3 L161-175 (reads `Status.LastRotationTime`; `effectiveMinInterval` default 60s) => records `RotationThrottled`/`MinIntervalFloor`. Tests `TestRotate_G3_MinIntervalFloor` (within floor => skip) + `_G3_MinIntervalElapsed` (elapsed => fires) PASS. |
| C4 | D22 **readiness gate** (honest minimal form) | ⚠️✅ | `rotate_executor.go` G4 L190-204 — gates only when a prior rotation happened AND target pod not Ready (no fabricated per-pod ready map). First-ever rotation never gated. Test `TestRotate_G4_ReadinessGate` PASS. |
| C5 | D22 **crash-loop backoff + rollback** (default MaxFailed=3, exponential) | ✅ | `rotate_executor.go` G5a backoff window L177-188 + G5b `handleCrashLoop` L286-340 (`FailedRotationCount++`, exponential `backoffBase*2^(over-1)`, rollback image to `LastKnownGoodRef` on durable owner). Tests `TestRotate_G5_CrashLoopArmsBackoffAndRollsBack`, `_G5_BackoffWindowSkips` PASS. |
| C6 | **One event => one action**, no self-requeue storm | ✅ | Branch returns `ctrl.Result{}` with no RequeueAfter (`securityevent_controller.go:417`). Test `TestRotate_BurstOneAction` PASS (3 events => RotationCount==1, p2/p3 survive). |
| C7 | Success writes the AMTDStatus aggregate + SecurityEvent outcome | ✅ | `rotate_executor.go` `recordRotationSuccess` L370-426 (LastRotationTime/RotationCount++/FailedRotationCount=0/clear BackoffUntil/EffectiveSource/RotationPathFired/MutationDurable/LastKnownGoodRef; SE `AppliedAction="rotate"`+`ProcessedAt`) via `r.Status().Update`. Tests `TestRotate_SuccessResetsFailureCounter`, `_SecurityEventStatusOutcome` PASS. |
| D1 | **LIVE**: rotation fires + mutation applied (durable) | ✅ | kind `kind-amtd-test`: Deployment template patched to golden + env; AMTD `rotationCount=1`, `mutationDurable=true`, `rotationPathFired=Rotate`, `effectiveSource=InferenceRotation`; new pod carries `busybox:1.37`+`RUNTIME_MODE=SECURE`. (§7) |
| D2 | **LIVE**: storm-guard blocks the re-fire (burst => still 1) | ✅ | 3 burst events inside the floor => `rotationCount` stayed 1, target pod UID unchanged, all 3 events empty status, `RotationThrottled`/`MinIntervalFloor` condition recorded; 3× "Rotate G3 min-interval: skipping" in the manager log. (§7) |
| E1 | Phase-0 invariant: exact-match still deletes | ✅ | `TestSecurityEventReconciler_ExactMatch_DeleteStillWorks`, `_Rotate_TimedReschedule` (empty overlay + no prior LastRotationTime still deletes) PASS. |
| E2 | Phase-0 invariant: MaxProperties=1 / scored path | ✅ | CRD action retains `maxProperties:1`; `TestMatchStrategy_ScoredPath` (+subtests), `_ScoredOperators` (+subtests), `TestSecurityEventReconciler_ScoredMode_PanicSelectsRotate` PASS. |
| E3 | Phase-0 invariant: byte-compat matcher / first-match-wins | ✅ | Reconcile still calls `MatchStrategyForMode(strategy.Rule, securityEvent.Spec, AMTD.Spec.MatcherMode)` (`securityevent_controller.go:165`) in a first-match-wins loop. `TestMatchStrategy_ByteCompatWithDeepEqual`, `TestMatchStrategyForMode_ExactInertScoredHonored`, `_ExactMode_ScoredClauseInert` PASS. |
| F1 | Honesty: EWMA/panic NOT faked | ✅ | `SmoothedScore`/`ConsecutiveHighCount` are Status fields only, referenced in non-test code solely by the deferral comment (`rotate_executor.go:35-36`); never written. No scoring math in the tree. |
| F2 | Honesty: WarmSwap/Regenerate/NodeRotate stubs; cold delivery | ✅ | `securityevent_controller.go:421-429` log-only stubs, unchanged. `executeRotate` delivers via `rescheduleByAnnotateThenDelete` (cold). |

---

## 3. Files changed (all under `c:\Users\moh87733\Phorvex\build\phoenix-extended`)

**API (additive only; existing types untouched):**
- `api/v1beta1/adaptivemovingtargetdefense_types.go` — ADDED `InferenceRotationSpec{ContainerName,GoldenImage,EnvPatch,GPUResource,RotationPolicy,AdaptiveRotation}`, `RotationPolicy{MinInterval *metav1.Duration, MaxConcurrentRotations *int}`, `AdaptiveRotationPolicy{MaxFailedRotations *int}`, and `AdaptiveMovingTargetDefenseSpec.InferenceRotation *InferenceRotationSpec`.
- `api/v1beta1/zz_generated.deepcopy.go` — regenerated (controller-gen v0.17.2): DeepCopy for the 3 new types + the InferenceRotation pointer in the AMTDSpec DeepCopyInto.
- `config/crd/bases/amtd.r6security.com_adaptivemovingtargetdefenses.yaml` — regenerated (carries `inferenceRotation.{containerName,goldenImage,envPatch,gpuResource,rotationPolicy.minInterval,adaptiveRotation.maxFailedRotations}`); applied to kind, Established=True.
- `config/rbac/role.yaml` — regenerated with apps (deployments/statefulsets/daemonsets get/list/watch/update/patch; replicasets get/list/watch) + batch (jobs get/list/watch).

**New files:**
- `internal/controller/mutation.go` — `MutationApplier` interface + `defaultMutationApplier` (`Resolve`, `ApplyToPodSpec`), `EffectiveOverlay`, `gpuResourceName="nvidia.com/gpu"`; D3 `classifyTopOwner` + `patchOwnerTemplate`, route enum, reason constants `BarePod|ImmutableJobTemplate|PerPodOnSharedTemplate`.
- `internal/controller/rotate_executor.go` — `(*SecurityEventReconciler).executeRotate` (the D22 pipeline), `handleCrashLoop`, `recordRotationThrottled`, `recordRotationSuccess`, `effectiveMinInterval`(60s), `effectiveMaxFailedRotations`(3), `podHasRotationInProgress`, annotation consts `ROTATION_LAST_KEY`/`ROTATION_IN_PROGRESS`.

**Modified files:**
- `internal/controller/securityevent_controller.go` — Rotate branch now calls `r.executeRotate(...)` at **L417**; added apps/batch RBAC markers. WarmSwap/Regenerate/NodeRotate stubs UNCHANGED (L421-429).
- `internal/controller/nim_controller.go` — NIM `Reconcile` early-returns when `podHasRotationInProgress(pod)` (D22 G2 cross-controller lock) at **L118**; pass-through otherwise.

**New tests:** `mutation_applier_test.go` (13), `owner_walk_test.go` (8), `securityevent_rotate_guard_test.go` (the D22 set incl. burst), `nim_controller_test.go` +`TestNIMReconciler_Reconcile_InProgressEarlyReturn`.

---

## 4. Build result (REAL)

Re-run from scratch in the Stage-5 review session:

```
go build -C phoenix-extended ./...   => BUILD_EXIT=0   (no output)
go vet   -C phoenix-extended ./...   => VET_EXIT=0     (no output)
go build -C phoenix-extended -o bin\manager.exe .\cmd  => MANAGER_BUILD_EXIT=0
```

Logs: `c:\Users\moh87733\Phorvex\build\logs\review1-build.txt`, `review1-vet.txt`, `review1-manager-build.txt`.

---

## 5. Test result (REAL)

- **Harness:** Go fake-client + table tests in `package controller` (the `suite_test.go` Ginkgo suite registers **0** specs by design — Ginkgo prints `0 Passed | 0 Failed`; real coverage is the fake-client/table tests). envtest assets `KUBEBUILDER_ASSETS=...1.30.3-windows-amd64`.
- **Command:** `go test ./... -count=1 -v`  => **TEST_EXIT=0**.
- **Per-package:**
  - `ok  github.com/r6security/phoenix/api/v1beta1   1.147s`
  - `ok  github.com/r6security/phoenix/internal/controller   0.388s`
  - `?   github.com/r6security/phoenix/cmd   [no test files]`
  - `?   github.com/r6security/phoenix/pkg/controllers   [no test files]`
- **Counts:** 59 top-level `--- PASS`, 53 subtests PASS, **0** `--- FAIL` (grep of the log returns zero FAIL occurrences).

**The five required D22 gate tests — all PASS (verbatim from `review1-test.txt`):**
```
--- PASS: TestRotate_BurstOneAction (0.00s)                       # burst => exactly ONE rotation (RotationCount==1; p2/p3 survive)
--- PASS: TestRotate_G1_Idempotence (0.00s)                       # same (pod,event) twice => no second action
--- PASS: TestRotate_G3_MinIntervalElapsed (0.00s)               # floor is a throttle, not permanent (RotationCount 1->2)
--- PASS: TestRotate_G3_MinIntervalFloor (0.00s)                 # within 60s => skipped + RotationThrottled/MinIntervalFloor
--- PASS: TestRotate_G2_InProgressLock (0.00s)                   # re-fire while in-progress => skipped
--- PASS: TestRotate_G5_CrashLoopArmsBackoffAndRollsBack (0.00s) # repeated failures => BackoffUntil armed + rollback to LKG
```

**Preserved Phase-0 invariants — PASS (verbatim):**
```
--- PASS: TestMatchStrategy_ByteCompatWithDeepEqual (0.03s)
--- PASS: TestSecurityEventReconciler_Rotate_TimedReschedule (0.00s)
--- PASS: TestSecurityEventReconciler_ExactMatch_DeleteStillWorks (0.00s)
```
(plus `_ExactMode_ScoredClauseInert`, `_ScoredMode_PanicSelectsRotate`, `TestMatchStrategy_ScoredPath`/`_ScoredOperators` with subtests, and all five `TestNIMReconciler_*_PassThrough` — all PASS.)

**Failures:** none. No `--- FAIL` line appears anywhere in the log.

Logs: `c:\Users\moh87733\Phorvex\build\logs\review1-test.txt` (verbose, this session); earlier identical runs in `phase1_d22_verify.log`, `phase1_final_gate.log`.

---

## 6. (controller-gen note for later stages)

`paths=./...` from the repo root FAILS (`"-: no Go files in <root>"` — root has no `.go` files; `main` is under `cmd/`), and `...` is silently stripped under shell globbing. The WORKING invocation is the Bash tool with `set -f` (noglob) + explicit per-package single-quoted paths:
`go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.17.2 object:headerFile=hack/boilerplate.go.txt 'paths=./api/v1beta1'` (deepcopy) and `... rbac:roleName=manager-role crd webhook 'paths=./api/v1beta1' 'paths=./internal/controller' 'paths=./cmd' output:crd:artifacts:config=config/crd/bases` (CRD+RBAC). Both returned exit 0.

---

## 7. Kind-cluster live verification (REAL)

Cluster `kind-amtd-test` (node `amtd-test-control-plane` Ready, apiserver v1.35.0). The real `bin\manager.exe` ran locally against the kind admin kubeconfig (all 4 controllers started, healthy). This slice was **independently re-run in the Stage-5 review** (fresh ns `review1`); the Stage-4 capture (ns `phase1-verify`) is consistent with it. Evidence below is from the Stage-5 re-run log `c:\Users\moh87733\Phorvex\build\logs\review1-live-manager-stderr.log`.

**Setup:** ns `review1`; Deployment `nim-demo` (replicas=1, container `nim`, `busybox:1.36`, `RUNTIME_MODE=NORMAL`); AMTD `amtd-nim` {`podSelector app=nim-demo`; `inferenceRotation{containerName=nim, goldenImage=busybox:1.37, envPatch RUNTIME_MODE=SECURE, rotationPolicy.minInterval=...}`; strategy `timed/info/TimeBasedTrigger -> rotate{policyRef.kind=InferenceRotation}`}. Pod enrolled (`managed-by amtd-nim`); AMTD status empty pre-fire.

**PROOF 1 — ROTATION FIRES + MUTATION APPLIED (durable, route a).** SecurityEvent `fire1` targeting `review1/nim-demo-85c7465798-lqwk7`:
- Deployment template patched durably: `busybox:1.36 -> busybox:1.37`, `RUNTIME_MODE NORMAL -> SECURE`.
- AMTD Status: `effectiveSource=InferenceRotation`, `mutationDurable=true`, `rotationPathFired=Rotate`, `rotationCount=1`, `lastRotationTime=2026-05-31T02:05:13Z`, `lastKnownGoodRef=busybox:1.37`.
- Cold reschedule: old pod Terminating; NEW pod `nim-demo-65859b7847-bc4mt` Running carrying `busybox:1.37` + `RUNTIME_MODE=SECURE` (mutation durable across recreate).
- `fire1` status: `appliedAction=rotate`, `processedAt` set.
- Manager log (real): L55 `"Rotate route (a): patched top owner template (durable, all replicas)"` ownerKind=Deployment owner=nim-demo; L69 `"Pod successfully rotated"` `rotationPathFired=Rotate mutationDurable=true effectiveSource=InferenceRotation`.

**PROOF 2 — STORM-GUARD BLOCKS THE RE-FIRE (the no-thrash proof).** With `MinInterval=5m` (removes timing ambiguity), a burst of 3 identical timed events (`storm-a/b/c`) fired ~42.9s after the last rotation, inside the floor:
- `ROTATION_COUNT_BEFORE = 1`, `ROTATION_COUNT_AFTER = 1` (3 events => **ZERO** additional rotations).
- Target pod UID UNCHANGED, RESTARTS=0, still the only pod; all 3 events have EMPTY status.
- AMTD condition: `type=RotationThrottled, reason=MinIntervalFloor, status=True`, message `"min-interval floor 5m0s not elapsed ..."`.
- Manager log (real), L156 / L164 / L170: `"Rotate G3 min-interval: skipping"` for `storm-a` / `storm-b` / `storm-c` (`minInterval=5m0s`, `lastRotation=2026-05-30T21:05:13-05:00`).

**PROOF 2b — FLOOR IS A THROTTLE, NOT A PERMANENT BLOCK.** `MinInterval` lowered to 10s, `release1` fired after the floor elapsed:
- `rotationCount 1 -> 2`, `lastRotationTime` advanced, old pod Terminating + new pod Running, `release1` `appliedAction=rotate`. The `RotationThrottled` condition was REMOVED on success.
- Manager log (real): L183 `"Rotate route (a): top owner template already carries the overlay (idempotent no-op; self-Update loop guarded)"` (self-Update-loop guard fired live) + L195 `"Pod successfully rotated"`.

**Additional live-observed guards (Stage-4 capture, consistent):** G2 in-progress lock blocked re-fires during the FIRE#1 window (`"Rotate G2 in-progress: ... skipping re-fire"`), and the NIM cross-controller early-return fired (`"NIM early-return: rotation in progress for this pod (D22 in-progress lock)"`).

**Cleanup (REAL):** manager process stopped (`NO_STRAY_MANAGER=true`); all SecurityEvents deleted; ns `review1` deleted (NotFound on re-check); no leftover cluster-scoped SecurityEvents; CRDs left installed intact; context still `kind-amtd-test`.

Live evidence files: `c:\Users\moh87733\Phorvex\build\logs\review1-live-manager-stderr.log` (Stage-5 re-run), `c:\Users\moh87733\Phorvex\build\logs\live-manager.log` (Stage-4 capture), manifest `c:\tmp\phase1-verify.yaml`.

---

## 8. Deviations / honest gaps / deferrals

- **G4 readiness gate is the honest minimal form** (⚠️): it gates on `in-progress` + the observed target-pod `PodReady` condition only when a prior rotation has occurred. There is no per-replica ready map (AMTDStatus is a per-AMTD aggregate with no per-pod map), so full per-replica readiness tracking is deferred. This is documented in `rotate_executor.go:190-194` — no fabricated state.
- **State-home reconciliation** (by design, not a gap): per-pod idempotence + in-progress live on UID-keyed pod annotations; aggregate min-interval / backoff / counters / `LastKnownGoodRef` live in `AMTDStatus`. This is the documented reconciliation of "idempotence key = podUID+eventUID" with "state home = AMTDStatus aggregate" (`rotate_executor.go:25-32`).
- **Phase-1 rollback is image/ref only** (G5): it restores `LastKnownGoodRef` onto the durable owner template. The full Regenerate restore-from-signed-baseline is Phase 5.
- **Live-test manifest field names** (operator unaffected): the live CRD uses `spec.targets` (array of `"namespace/name"` strings, split at `securityevent_controller.go:98-99`) and requires `spec.description`; AMTD uses `spec.podSelector` as a plain `map[string]string`. Initial ad-hoc YAML had the wrong field names; corrected, then all applies succeeded. This affected only test YAML, not the controller.
- **No false durability ever claimed:** an empty overlay short-circuits to `routeColdNoOverlay` (no `mutationDurable=true`); only a non-empty overlay landing on a Deployment/StatefulSet/DaemonSet sets `mutationDurable=true`.
- **No warm-pool / zero-downtime / GPU-downtime numbers** are claimed anywhere — Phase 4 / later GPU run.

---

## 9. Verdict

**Phase 1 — PASS (real results).**
- `go build ./...` EXIT 0; `go vet ./...` EXIT 0; `go test ./...` (envtest 1.30.3) EXIT 0 with 59 top-level tests green (32 new Phase-1, 9 preserved Phase-0 invariants), 0 FAIL; manager builds.
- MutationApplier interprets image/env/gpu (Overrides > PolicyRef->InferenceRotation; GPU-shuffle/encrypted/RAG/endpoint/CMP NOT interpreted).
- D3 owner-walk patches the top owner durably (never a bare RS) with correct non-durable reasons; cold-fallback otherwise.
- D22 storm-guard (idempotence / in-progress lock / min-interval floor / readiness / crash-loop backoff+rollback): one event => one action; state in AMTDStatus + UID-keyed pod annotations.
- LIVE on kind: rotation fired durably (template==golden image + env set, `RotationCount=1`) AND the storm-guard blocked the burst (`RotationCount` stayed 1, throttle reason + G3-skip logs captured); cleanup confirmed; original repo untouched.
- Honesty intact: EWMA/panic scoring NOT faked; WarmSwap/Regenerate/NodeRotate honest stubs; cold delivery; Phase-0 byte-compat / MaxProperties=1 / matcher behavior unregressed.

**Next:** Phase 2 (jitter/cadence scheduling + `MaxConcurrentRotations` enforcement) — **not started.**
