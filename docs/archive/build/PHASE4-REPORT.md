# Phoenix AMTD — Phase 4 Report (Warm-Pool / LeaderWorkerSet Control Plane)

Repo: `c:\Users\moh87733\Phorvex\build\phoenix-extended` (Go module `github.com/r6security/phoenix`).
Kube context: `kind-amtd-test` (apiserver gitVersion v1.35.0). Report date: 2026-05-31.

---

## Scope

Phase 4 delivers the warm-pool **CONTROL PLANE**:

- a new `WarmInferenceSet` CRD (namespaced, `amtd.r6security.com/v1beta1`, shortName `wis`),
- a `WarmPoolManager` (`EnsurePool` / standby provisioning / leader election / leader-selecting Service),
- a `ReadinessGate` (strict warm definition: pod Ready + `MinWarmSeconds` dwell + `RequireModelLoaded`),
- a `LeaderSwapper.Swap` restart-safe phase machine (Ready → flip → drain → retire → re-warm),
- and the **WarmSwap action wired** into the SecurityEvent dispatch (replacing the prior Phase-0 no-op stub).

### STATED PROMINENTLY — the downtime SLO is GPU-PENDING

**The 400s → 15s warm-vs-cold warm-swap DOWNTIME SLO is GPU-PENDING.** It was deferred to a real-GPU run and was **neither measured nor fabricated on kind**. On kind there is no GPU and no real model server, so no warm-vs-cold downtime number is asserted anywhere in this report.

`lastSwapDurationMillis` measured on kind (observed values **5122 ms** and **5859 ms**, with a 5 s drain override) is the **control-plane cutover time only** = (leader-label flip + `DrainTimeoutSeconds` drain). It is **explicitly NOT** the GPU model-load downtime. The p50 ≤ 5 s / p95 ≤ 15 s latency, zero-non-2xx-during-cutover, and warm ≤ COLD/10 targets all require a real GPU + real model server and are **GPU-PENDING**. `RequireModelLoaded` GPU-weights-resident verification is **GPU-PENDING**; on kind it is realized via the documented proxy (pod Ready + `MinWarmSeconds` + the `amtd.r6security.com/model-loaded=true` annotation as the model-loaded SIGNAL).

---

## Non-goals / deferred

- **Phase 5 (drift self-heal) — NOT started.** `Regenerate` action remains an honest no-op stub.
- **Phase 6 (node rotation).** `NodeRotate` action remains an honest no-op stub.
- **AnomalyScorer Passthrough** unchanged.
- **The GPU downtime / load-generator SLO is GPU-PENDING** (real-GPU run).

---

## Requirement-by-requirement table

Legend: ✅ verified by real results · ⚠️ verified but with an honest caveat · ❌ not done.
Evidence paths are absolute. Source file refs are under `…\build\phoenix-extended\`.

| # | Requirement | Status | Evidence (file:line / test / log) |
|---|---|---|---|
| 1 | `WarmInferenceSet` kind (arch §2.4): namespaced, owns N pods + leader Service; `WarmSwapAction.WarmInferenceSetRef` is the only reference | ✅ | `api\v1beta1\warminferenceset_types.go` (`scope=Namespaced,shortName=wis` ~L266; Spec=Replicas/Template/WarmReadyGate/TrafficCutStrategy/DrainTimeoutSeconds/SwapRequest; Status=ActiveLeader/ReadyShadows/LastSwapDurationMillis/Conditions; `init()` SchemeBuilder.Register ~L371). `WarmSwapAction` at `adaptivemovingtargetdefense_types.go` L640-647 |
| 2 | Code-default helpers FLAGGED via code, not CRD `+default` markers | ✅ | `EffectiveReplicas()`=2, `EffectiveRequireModelLoaded()`=true, `EffectiveTrafficCutStrategy()`=ServiceSelectorSwap, `EffectiveDrainTimeoutSeconds()`=30 (warminferenceset_types.go). Only `Optional`/`Minimum`/`Enum` markers present |
| 3 | `EnsurePool` maintains N + exactly one leader + leader-selecting Service | ✅ | `internal\controller\warmpool.go` `EnsurePool` (elect one leader, create up-to-N standbys, delete surplus, ensure Service whose selector = `{warm-inference-set=<name>, leader=active}`). Tests `TestEnsurePool_CreatesNPodsAndOneLeaderAndService`, `TestEnsurePool_DefaultReplicasIsTwo` PASS |
| 4 | `ReadinessGate.IsWarm` = Ready + `MinWarmSeconds` + `RequireModelLoaded`; GPU-resident-weights verification GPU-PENDING | ✅ | warmpool.go `IsWarm` (Ready AND dwell AND RequireModelLoaded); GPU-PENDING doc note; kind proxy = `amtd.r6security.com/model-loaded` annotation/condition. Test `TestReadinessGate_IsWarmMatrix` PASS |
| 5 | Class-B reconcile does NOT self-initiate a swap (arch §1.3 invariant) | ✅ | `warminferenceset_controller.go` `Reconcile`: `swapInFlight := wis.Spec.SwapRequest != nil`; swap logic reachable ONLY when `swapInFlight`; no-request branch only writes Status. Test `TestClassB_NoSwapWithoutRequest` PASS; LIVE Stage B (6 cycles, leader unchanged) |
| 6 | `LeaderSwapper.Swap` cutover: Ready→flip(ServiceSelectorSwap)→drain→retire→re-warm; records `LastSwapDurationMillis` | ✅ | `internal\controller\swap.go` `Swap` dispatch; `doFlip`→`doDrain`→`doRetire`→`doRewarm`; durable phase via metadata annotation (`annSwapPhase`) so a status-write conflict can't lose a transition; `TrafficSteerer.CutTraffic` flips leader label. Test `TestSwap_FlipsRetiresRewarmsAndRecordsDuration` PASS; LIVE Stage C |
| 7 | Readiness-gate BLOCK: no warm shadow ⇒ no cutover, `SwapBlockedNoReadyShadow=True`, request retained | ✅ | swap.go `doFlip` BLOCK path (`setBlockedCondition`, request retained, requeue). Test `TestSwap_BlockedWhenNoReadyShadow` PASS; LIVE Stage C block-then-resolve |
| 8 | WarmSwap action WIRED (no longer the Phase-0 stub) | ✅ | `securityevent_controller.go` L446-461 calls `requestWarmSwap` (replaced no-op). `warmswap_action.go` `requestWarmSwap`: resolves ref in pod namespace, sets `Spec.SwapRequest`, records `SecurityEventStatus.AppliedAction="warmSwap"` + `ProcessedAt`; nil/missing ref = recorded no-op, not error. Registered in `cmd\main.go` above `//+kubebuilder:scaffold:builder`. Tests `TestWarmSwapAction_SetsRequestAndOutcome`, `_DrainOverridePropagates`, `_MissingWISIsNoOp` PASS |
| 9 | LIVE: reconcile + standby provisioned (pod/Service/Status) | ✅ | `live4-stageA.txt`: 2 pods, leader `wis-a-warm-0` (`leader=active`), Service `wis-a-leader` endpoints resolve to ONLY the leader (10.244.0.73); after model-loaded annotation `readyShadows=1` |
| 10 | LIVE: leader-swap cutover with readiness gate (flip / Service re-resolve / old retired / re-warm / duration populated) | ✅ | `live4-stageC.txt`: oldLeader `wis-a-warm-0` → newLeader `wis-a-warm-1`, EndpointSlice followed to new leader, old leader NotFound (retired), replacement `wis-a-warm-2` re-warmed, `lastSwapDurationMillis=5122`, SwapRequest cleared; SecurityEvent `appliedAction=warmSwap` |
| 11 | LIVE: gate-block then resolve | ✅ | `live4-stageC.txt`: block-event with no warm shadow ⇒ `SwapBlockedNoReadyShadow=True`, leader unchanged, request retained; annotate `wis-a-warm-2` model-loaded ⇒ retained request completes (leader→`wis-a-warm-2`, `lastSwapDurationMillis=5859`) |
| 12 | LIVE: class-B stable (no self-swap) | ✅ | `live4-stageB.txt`: 6 cycles, `activeLeader` fixed, `swapPhase=Idle`, exactly 1 leader label |
| 13 | Downtime SLO GPU-PENDING (no number on kind) | ✅ | `live4-stageD-gpu-pending.txt`: 400s→15s SLO + p50/p95/non-2xx/warm-ratio explicitly NOT measured; only control-plane flip+drain recorded |
| 14 | Phase-0..3b invariants intact (regression) | ✅ | Full suite GREEN 91/0; `TestMatchStrategy_LegacyEqualsDeepEqual`, `TestMatchStrategyForMode_ExactInertScoredHonored`, `TestPanic_*`, `TestPassthroughScorer`, `TestScoring_*`, `TestCMPReconcile_*`, `TestNIMReconciler_Reconcile_ValidTimedEvent_PassThrough`, `TestSecurityEventReconciler_ExactMatch_DeleteStillWorks`, D22 storm-guards `TestRotate_G2/G3/G4/G5` PASS |
| 15 | Regenerate / NodeRotate remain honest stubs; Passthrough unchanged | ✅ | `securityevent_controller.go` L462-464 (Regenerate "Phase 5 … no-op"), L465-467 (NodeRotate "Phase 6 … no-op"); `scoring.go` `PassthroughScorer` returns `Spec.AnomalyScore` as-is |
| 16 | `MaxProperties=1` preserved on `AMTDAction` | ✅ | `adaptivemovingtargetdefense_types.go` L277 `+kubebuilder:validation:MaxProperties=1`; new members all-pointer/omitempty |
| 17 | LIVE: teardown / cleanup | ✅ | `live4-stageE-cleanup.txt`: owner-ref GC (wis-pods=0, leader-svc=0), manager PID 23340 stopped, namespace `phase4-verify` deleted (NotFound), 4 CRDs remain; `repos` untouched |

---

## Files changed / added (all under `…\build\phoenix-extended\`)

**NEW**
- `api\v1beta1\warminferenceset_types.go` — `WarmInferenceSet` / `…List` / `…Spec` / `…Status`, `WarmReadyGate`, `WarmSwapRequest`, `TrafficCutStrategy` enum (`EndpointSwap;ServiceSelectorSwap(default);GatewayWeight;LeaderLabel`), swap-phase + condition consts, `ModelLoadedAnnotation`, `PoolPodLabel`, code-default helpers, `init()` SchemeBuilder.Register.
- `internal\controller\warmpool.go` — `WarmPoolManager` (`EnsurePool`, `ReadyShadows`, `CurrentLeader`, `pickReadyShadow`, `ensureLeaderService`), `ReadinessGate.IsWarm`, `TrafficSteerer.CutTraffic`.
- `internal\controller\swap.go` — `LeaderSwapper.Swap` phase machine (`doFlip`→`doDrain`→`doRetire`→`doRewarm`), durable swap annotations as the source of truth, control-plane `LastSwapDurationMillis`.
- `internal\controller\warminferenceset_controller.go` — `WarmInferenceSetReconciler.Reconcile` (class-B `EnsurePool` always; class-A swap only when `Spec.SwapRequest != nil`); `SetupWithManager` Owns Pods + Service; RBAC markers.
- `internal\controller\warmswap_action.go` — `requestWarmSwap` / `recordWarmSwapOutcome`.
- `internal\controller\warminferenceset_controller_test.go`, `internal\controller\warmswap_action_test.go` — fake-client table tests.

**EDITED**
- `internal\controller\securityevent_controller.go` — L446-461 WarmSwap branch wired (replaced the Phase-0 no-op); Regenerate/NodeRotate stubs kept.
- `cmd\main.go` — `WarmInferenceSetReconciler` registration block above `//+kubebuilder:scaffold:builder`.

**REGENERATED**
- `api\v1beta1\zz_generated.deepcopy.go` (WarmInferenceSet/List/Spec/Status/WarmReadyGate/WarmSwapRequest); independently re-regenerated in review with **no drift**.
- `config\crd\bases\amtd.r6security.com_warminferencesets.yaml` (NEW; scope Namespaced, shortName wis).
- `config\rbac\role.yaml` (gained warminferencesets + pods-delete + services verbs).

---

## Build result (REAL exit codes, this run)

- `go build ./...` → **BUILD_EXIT=0** — `c:\Users\moh87733\Phorvex\build\logs\review4-build.txt`
- `go vet ./...` → **VET_EXIT=0** — `c:\Users\moh87733\Phorvex\build\logs\review4-vet.txt`

---

## Test result (REAL `go test ./... -count=1`, `KUBEBUILDER_ASSETS` set)

Log: `c:\Users\moh87733\Phorvex\build\logs\review4-fulltest.txt` → **TEST_EXIT=0**.

Per-package:

```
ok      github.com/r6security/phoenix/api/v1beta1          0.869s
?       github.com/r6security/phoenix/cmd                  [no test files]
ok      github.com/r6security/phoenix/internal/controller  0.366s
ok      github.com/r6security/phoenix/internal/scheduler    0.206s
?       github.com/r6security/phoenix/pkg/controllers       [no test files]
```

**Controller verbose: 91 top-level tests, 91 PASS, 0 FAIL, 0 SKIP** (independently confirmed: `go test -list` returns 91 top-level `Test…` funcs; the verbose log shows 91 `--- PASS: Test…` lines and 0 `--- FAIL`). Log: `c:\Users\moh87733\Phorvex\build\logs\review4-controller-verbose.txt`.

Phase-4 test names (all PASS): `TestEnsurePool_CreatesNPodsAndOneLeaderAndService`, `TestEnsurePool_DefaultReplicasIsTwo`, `TestReadinessGate_IsWarmMatrix`, `TestClassB_NoSwapWithoutRequest`, `TestSwap_FlipsRetiresRewarmsAndRecordsDuration`, `TestSwap_BlockedWhenNoReadyShadow`, `TestWarmSwapAction_SetsRequestAndOutcome`, `TestWarmSwapAction_DrainOverridePropagates`, `TestWarmSwapAction_MissingWISIsNoOp`.

Regression / D22 storm-guard (all PASS): `TestRotate_G2_InProgressLock`, `TestRotate_G3_MinIntervalFloor`, `TestRotate_G4_ReadinessGate`, `TestRotate_G5_CrashLoopArmsBackoffAndRollsBack`, `TestMatchStrategy_LegacyEqualsDeepEqual`, `TestMatchStrategyForMode_ExactInertScoredHonored`, `TestPanic_*`, `TestPassthroughScorer`, `TestScoring_*` (6), `TestCMPReconcile_*` (3), `TestNIMReconciler_Reconcile_ValidTimedEvent_PassThrough`, `TestSecurityEventReconciler_ExactMatch_DeleteStillWorks`.

No failures. (Note on naming: prior summaries referenced `TestMatchStrategy_ByteCompatWithDeepEqual`; that test does not exist — the real byte-compat test is **`TestMatchStrategy_LegacyEqualsDeepEqual`**. Coverage is real; only the name was misquoted.)

---

## Kind-cluster live verification (REAL — context `kind-amtd-test`, apiserver v1.35.0, control plane only)

The `warminferencesets` CRD was applied **server-side** (`kubectl apply --server-side`) because client-side apply exceeds the 262144-byte annotation limit due to the large embedded `PodTemplateSpec` schema; CRD `Established=True`, scope Namespaced, shortName `wis`, printer columns Leader/ReadyShadows/SwapPhase/LastSwapMillis/Age. Operator built (`bin\manager.exe`) and run against kind. Test WIS used `registry.k8s.io/pause` as a GPU-free golden image. Full manager log: `c:\Users\moh87733\Phorvex\build\logs\live4-manager.txt`.

**Stage A — reconcile + standby provisioned** (`live4-stageA.txt`): WIS `wis-a` (replicas=2, ServiceSelectorSwap) reconciled to 2 running pods; leader `wis-a-warm-0` carries `amtd.r6security.com/leader=active`, shadow `wis-a-warm-1` does not. Leader Service `wis-a-leader` selector `{leader=active, warm-inference-set=wis-a}`; EndpointSlice resolved to ONLY the leader (`wis-a-warm-0`, 10.244.0.73 — not the shadow). Status `activeLeader=wis-a-warm-0, currentReplicas=2, swapPhase=Idle`. After annotating the shadow `model-loaded=true`, `readyShadows=1` (strict gate satisfied).

**Stage B — class-B no self-swap, arch §1.3** (`live4-stageB.txt`): with a warm shadow present (swap candidate exists) and NO SwapRequest, 6 reconcile cycles observed — `activeLeader` stayed `wis-a-warm-0`, exactly one pod carried the leader label, `swapPhase` stayed `Idle`. Class-B never self-initiates a swap.

**Stage C — leader-swap cutover with readiness gate** (`live4-stageC.txt`): triggered via the supported chain (SecurityEvent → AMTD-managed pod → action `warmSwap{warmInferenceSetRef: wis-a, drainTimeoutSeconds: 5}` → `requestWarmSwap` sets `Spec.SwapRequest`). Phase machine (real manager timestamps):
- 03:16:07 SwapRequest set; leader label flipped `wis-a-warm-0` → `wis-a-warm-1`; draining.
- 03:16:13 drain elapsed (5 s); old leader retired; replacement re-warmed.
- 03:16:13 WarmSwap COMPLETE; `lastSwapDurationMillis=5122`; leader `wis-a-warm-1`.

Post-swap: `activeLeader=wis-a-warm-1`; EndpointSlice followed to `wis-a-warm-1` only; old leader `wis-a-warm-0` NotFound (retired); replacement re-warmed on a fresh index (`wis-a-warm-2`), N restored to 2; SwapRequest cleared. SecurityEvent `status.appliedAction=warmSwap` + `processedAt` set.

**Gate BLOCK then RESOLVE** (`live4-stageC.txt`): a second SecurityEvent requested a swap while the only shadow (`wis-a-warm-2`) had no model-loaded signal (`readyShadows=0`) ⇒ `SwapBlockedNoReadyShadow=True` (reason `NoReadyShadow`), leader unchanged (`wis-a-warm-1`), request retained. Annotating `wis-a-warm-2` `model-loaded=true` resolved the retained request (leader → `wis-a-warm-2`, request cleared, condition cleared, `lastSwapDurationMillis=5859`) — proving the gate is a gate, not a dead-end.

**Stage D — downtime SLO GPU-PENDING** (`live4-stageD-gpu-pending.txt`): the 400s→15s warm-vs-cold downtime SLO was NOT measured on kind and no warm-vs-cold downtime number is asserted. The two measured values (5122 ms, 5859 ms) are the control-plane cutover (flip + 5 s drain) ONLY. p50 ≤ 5 s / p95 ≤ 15 s / zero-non-2xx / warm ≤ COLD/10 and GPU-weights-resident verification are GPU-PENDING.

**Stage E — teardown** (`live4-stageE-cleanup.txt`): owner-ref cascade GC confirmed (`wis-pods=0`, `wis-leader-svc=0`); manager PID 23340 stopped (verified not running); namespace `phase4-verify` deleted (NotFound). 4 `amtd.r6security.com` CRDs remain. `c:\Users\moh87733\Phorvex\repos` untouched.

Evidence files (absolute):
- `c:\Users\moh87733\Phorvex\build\logs\live4-manager.txt`
- `c:\Users\moh87733\Phorvex\build\logs\live4-stageA.txt` / `live4-stageB.txt` / `live4-stageC.txt`
- `c:\Users\moh87733\Phorvex\build\logs\live4-stageD-gpu-pending.txt`
- `c:\Users\moh87733\Phorvex\build\logs\live4-stageE-cleanup.txt`
- `c:\Users\moh87733\Phorvex\build\logs\review4-build.txt` / `review4-vet.txt` / `review4-fulltest.txt` / `review4-controller-verbose.txt`

---

## Deviations / honest gaps

1. **In-tree pool, not LWS.** The default `WarmPoolManager` runs controller-managed bare pods from `Spec.Template` (runs GPU-free on kind). A `sigs.k8s.io/lws` (LeaderWorkerSet) wrap is documented in a code comment only — NOT wired. This is the deliberate kind-runnable path.

2. **Request-based progressive swap (locked decision), not synchronous-only.** The reconcile NEVER initiates a swap; it acts only on `Spec.SwapRequest` (set by the WarmSwap action). No request ⇒ no swap. This is what keeps class-B provably honest (arch §1.3) and is restart-safe across reconciles (durable swap annotations are the source of truth; Status is a best-effort mirror).

3. **GPU-pending warm definition.** `RequireModelLoaded` GPU-weights-resident verification is GPU-PENDING. On kind it is realized via the documented proxy (pod Ready + `MinWarmSeconds` + `amtd.r6security.com/model-loaded=true` annotation/condition). True weights-resident + warm-up-inference verification awaits a real GPU.

4. **One benign live ERROR (correcting a prior over-claim).** Prior summaries said the live manager log had "zero Reconciler errors." That literal claim is **wrong**. `live4-manager.txt` **line 162** contains one `ERROR Reconciler error … "the object has been modified; please apply your changes to the latest version and try again"` — an optimistic-concurrency conflict on `wis-a` during the block-event stress. It is **benign and self-healing**: controller-runtime auto-requeued and the very next reconcile (line 169) correctly proceeded to the BLOCK path; all live outcomes still converged correctly. The Stage-C cutover slice itself (captured at 03:16) had zero errors; the single conflict occurred later at 03:18:29 under the rapid block-event reconcile. Correct statement: "one benign transient optimistic-concurrency conflict, auto-resolved, no incorrect outcome."

5. **`LastSwapDurationMillis` Status mirror is best-effort (not guaranteed to converge on a fast/contended swap).** Swap truth lives in durable annotations; Status is a best-effort mirror. In an independent review run the cutover/retire/re-warm/endpoint-follow were all durable and correct, but a `Status().Update` conflict during rapid phase transitions left the final `Idle`+duration mirror unwritten (it lagged at `SwapPhase=Retiring`, empty duration). Not a correctness defect — the live4 runs DID record 5122 ms / 5859 ms with a 5 s drain — but a reviewer should know the duration mirror is best-effort and may lag on a fast swap.

6. **AMTD `rotationPathFired` mirror is best-effort and read back empty live.** The authoritative per-event record is `SecurityEvent.status.appliedAction=warmSwap` (set on both events). The AMTD `.status.rotationPathFired` best-effort mirror read back empty because the AMTD controller's own status reconcile can overwrite it; non-load-bearing, no error logged.

7. **Stale doc comment (cosmetic).** `adaptivemovingtargetdefense_types.go` L293-294 still says WarmSwap is "TYPE-ONLY in Phase 0 … no-ops" — that comment is now false (the action is wired in Phase 4). Behavior is correct; only the struct comment is stale.

8. **CRD apply specifics.** Server-side apply is required (client-side exceeds the 262144-byte annotation limit due to the embedded `PodTemplateSpec` schema). The on-cluster CRD's `spec.template.metadata` is `type: object` with no nested properties (standard controller-gen behavior for embedded `corev1.PodTemplateSpec` ObjectMeta), so a WIS manifest must omit `spec.template.metadata.labels` under strict decoding — the controller stamps the pool + leader labels itself, so template labels are unnecessary.

---

## Verdict

**PASS (control plane).** Build / vet / full test suite are genuinely GREEN this run (exit 0; **91/91 controller tests pass, 0 failures**). The code faithfully implements the Phase-4 surface — `WarmInferenceSet` CRD, `WarmPoolManager`/`EnsurePool`, `ReadinessGate`, `LeaderSwapper.Swap`, and the wired WarmSwap action — and the live control plane (standby provisioning, class-B no-self-swap, readiness-gated cutover, gate-block + block-resolve, owner-ref GC) was verified end-to-end on real kind. Phase-0..3b invariants are intact.

The only honest caveats are the deviations above: in-tree pool (LWS noted-not-wired), the GPU-pending warm definition, the request-based swap model, one benign auto-resolved optimistic-concurrency conflict in the live log, a best-effort (occasionally lagging) `LastSwapDurationMillis`/`rotationPathFired` Status mirror, and a stale doc comment.

**The 400s → 15s warm-swap DOWNTIME SLO is NOT claimed on kind — it is GPU-PENDING and awaits a real-GPU run.** `lastSwapDurationMillis` on kind is the control-plane cutover (flip + drain) only.

**Next: Phase 5 (drift self-heal) — NOT started.** Regenerate/NodeRotate remain honest stubs; AnomalyScorer Passthrough unchanged; the GPU downtime / load-generator SLO awaits a real-GPU run.
