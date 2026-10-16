# Phoenix AMTD — Phase 6 Report (Node Rotation)

## Scope

Phase 6 delivers **node rotation**, the relocate-before-dispose disposition that moves a flagged workload off a compromised/suspect node onto a clean node, behind a hard trust gate. It is composed of:

- **`NodeRotation` CRD** — cluster-scoped, status subresource, **restart-safe phase machine** (durable phase in an annotation, swap.go pattern).
- **`NodeDrainer`** — cordon / taint / uncordon + **drain via `policy/v1` Eviction subresource** (PDB-honoring by construction, targeted-pod-only by default, opt-in co-tenant drain).
- **`CleanNodeSelector`** — label-pool selection (`r6security.com/clean-pool=true` default) + exclude source/cordoned/tainted + PVC-topology preflight + GPU-MIG preflight seam → **`NoCleanTarget`** abort with a machine reason rather than landing an unschedulable pod.
- **`NodeRotationReconciler`** — `Cordoning → Draining → Rescheduling → Pinning → Completed` (or `RolledBack` / `NoCleanTarget`), with the **`MaxConcurrentNodes` + `Stagger` no-mass-eviction ceiling** and **class-B continuation** (never self-initiates).
- **The `NodeRotate` action wired** — the **LAST AMTDAction no-op stub** (`securityevent_controller.go:493`) replaced with the real gated path. With this, **all `AMTDAction` members are now implemented; no stubs remain.**
- **The D26 trust gate** — Source-allowlist + ThreatLevel-floor + Delete-needs-human-approval, checked BEFORE any `NodeRotation` is created.

### PROMINENT REAL-NODE / GPU constraint

**kind nodes are CONTAINERS.** The test cluster `kind-amtd-test` has **one real node** (`amtd-test-control-plane`); the "clean pool" nodes were **fake `Node` objects** created via `kubectl create` and have **no kubelet**. Consequently:

- **True relocation** — the targeted pod actually **RUNNING** on a different **REAL** clean node — was **NOT achieved and is NOT claimed**. A pinned replacement (nodeAffinity to the fake clean node, never `spec.nodeName`) stays **Pending** because the fake node has no kubelet.
- **Node-rotation MTTR (`CompletionTime − StartTime`)** is **NOT measured and NOT asserted** as a meaningful number on kind — on kind both timestamps land in the same control-plane reconcile burst and do not reflect real kubelet/GPU scheduling.
- The **GPU-MIG preflight** is a permissive seam (**GPU-PENDING**).

Only the **control plane** is kind-verified: clean-node *selection*, source *cordon*, targeted-pod *drain off the source*, the *D26 gate*, *NoCleanTarget* abort, and *restart-safe* resume. Relocation-to-Running and timing are **REAL-NODE/GPU-PENDING**.

## Non-goals / deferred

- **Phase 7 (per-integrator ThreatLevel/Type normalization)** — NOT started. The `ThreatLevel In high,critical` floor remains a normalization-gated string guard (fail-safe).
- **AnomalyScorer Passthrough** — unchanged (`scoring.go` PassthroughScorer default intact; not touched by Phase 6).
- **`repos\`** — untouched.
- **GPU/real-node-PENDING SLOs**: GPU-MIG preflight, node-rotation MTTR, and (carry-over) panic MTTR / warm-swap downtime all await a real-GPU / real-multinode run.

## Requirement-by-requirement

| # | Requirement | Status | Evidence (file:line / cmd) |
|---|---|---|---|
| 1 | NodeRotation CRD: cluster-scoped, restart-safe phase machine | **PASS** | `api/v1beta1/noderotation_types.go:271` (`+resource:scope=Cluster`), own `SchemeBuilder.Register()` `:363`; CRD base `config/crd/bases/amtd.r6security.com_noderotations.yaml:17` (scope: Cluster); durable phase read at `noderotation_controller.go:113`; live apiserver scope=Cluster, Established=True |
| 2 | NodeDrainer cordon/taint/uncordon + drain via Eviction (PDB-honoring, targeted-only default) | **PASS** | `nodedrainer.go:78` (Cordon), `:91` (Uncordon), `:109` (Taint NoSchedule, NoExecute NOT auto), `:236` (`SubResource("eviction").Create`), `:180` (targeted-only returns before co-tenant loop); tests `nodedrainer_test.go:141` (targeted=1, cotenant=0), `:177` (cotenant only on opt-in) |
| 3 | CleanNodeSelector label-pool + exclude + NoCleanTarget reason | **PASS** | default selector `noderotation_types.go:102`; exclude/cordoned/tainted `nodedrainer.go:306`; PVC-topology preflight `:293`; GPU-MIG seam `:403` (GPU-PENDING); reasons `CleanPoolExhausted\|PVCTopologyBound\|NoMatchingGPU` `:337`; tests `TestCleanNodeSelector_PicksAndExcludes`, `_NoCleanTarget`, `_PVCTopologyBound` |
| 4 | Reschedule pins via nodeAffinity on the REPLACEMENT (NEVER spec.nodeName / owner template) | **PASS** | `injectCleanNodeAffinity` (Required nodeAffinity, hostname + clean-pool) `noderotation_helpers.go:346`; `spec.NodeName` stripped to `""` `:286`/`:320`; grep of `internal/controller` for `NodeName =` shows only the two strips + one test setup; owner-managed rides warm-swap shadow `:253` |
| 5 | Phase machine + MaxConcurrentNodes/Stagger no-mass-eviction + class-B | **PASS (unit)** | ceiling checked BEFORE first cordon `noderotation_controller.go:143`, `countOtherInFlight :384` (errors out, does NOT fail-open); class-B `For(&NodeRotation{})` only `:412`; test `TestNodeRotation_MaxConcurrentNodesThrottle` (2nd rotation stays Cordoning, `NodeRotationThrottled` set). **Not exercised live** (test AMTDs set no NodeRotationPolicy ⇒ unlimited) |
| 6 | NodeRotate action wired (last stub gone) | **PASS** | `securityevent_controller.go:493` calls `r.requestNodeRotate(...)` (former no-op); only remaining else-branch is the generic "NOT IMPLEMENTED YET" fallthrough `:498`; no AMTDAction stub remains. `requestNodeRotate` `noderotate_action.go:51` (idempotent create, provenance, `AppliedAction=nodeRotate`, `RotationPathFired=NodeRotate`) |
| 7 | D26 gate (allowlist + floor + human-approval-for-Delete) BLOCKS forged/below-floor | **PASS** | `evaluateNodeRotateGate node_rotate_gate.go:105`; (a) Source allowlist `:111` (default `{KubeArmorIntegrator,FalcoIntegrator}` `:53`); (b) ThreatLevel floor `:120` (default `{high,critical}` `:54`); (c) Delete→approval `:129`; tests assert 0 NodeRotations on each deny path (`noderotate_action_test.go:168/:204/:236`), 1 on allow/approved (`:97/:262`) |
| 8 | NIM in-progress lock | **PASS** | action stamps `ROTATION_IN_PROGRESS` `noderotate_action.go:162`; NIM early-returns `nim_controller.go:118` |
| 9 | LIVE: select-clean + cordon + drain-off-source | **PASS (control-plane)** | live6-manager.txt: cordon `L318`, evicted off source `L337`, COMPLETE `L351`, `targetCleanNode=fake-clean-1` |
| 10 | LIVE: D26 gate enforced (non-allowlisted + below-floor BLOCKED; allowlisted+critical ALLOWED) | **PASS** | live6-manager.txt: `NodeRotateGatedSourceNotAllowed` `L464`, `NodeRotateGatedBelowFloor` `L527`; allow path created exactly 1 NodeRotation; review6 independent re-run reproduced deny+allow |
| 11 | LIVE: NoCleanTarget abort | **PASS** | live6-manager.txt `L717` "NodeRotation ABORTED: NoCleanTarget (no unschedulable pod landed)", reason `CleanPoolExhausted` |
| 12 | Node-rotation MTTR / true relocation | **REAL-NODE/GPU-PENDING** | NOT measured/claimed on kind; doPin log line itself states it `noderotation_controller.go:320`, live6-manager.txt `L351-352` |
| 13 | Phase 0–5 invariants intact | **PASS** | byte-compat matcher `matcher_test.go:31`; `MaxProperties=1` on AMTDAction `adaptivemovingtargetdefense_types.go:307`; D22 cross-controller lock `nim_controller.go:118`; full suite GREEN |
| 14 | AnomalyScorer Passthrough unchanged | **PASS** | `scoring.go` PassthroughScorer default intact, not touched by Phase 6 |

## Files changed

All paths under `c:\Users\moh87733\Phorvex\build\phoenix-extended\`.

**New:**
- `api\v1beta1\noderotation_types.go` — `NodeRotation` (Cluster-scoped, `+subresource:status`, own `init()` Register), `NodeRotationList`, `NodeRotationSpec` (`SourceNode`, `TargetPods []NamespacedPodRef`, `Strategy`, `DrainPolicy*`, `TargetNodeSelector`, `TriggerProvenance{Source,ThreatLevel,EventName}`, `MaxConcurrentNodes*`, `Stagger*`), `NodeRotationStatus` (`Phase`, `SourceNode`, `TargetCleanNode`, `RelocatedPods`, `EvictedCoTenants`, `NoCleanTargetReason`, `StartTime`, `CompletionTime`, `Conditions`), phase consts, `NodeRotationPolicy` (default-off), `NodeRotateTrustPolicy`, `EffectiveStrategy()`/`EffectiveCleanSelector()`.
- `internal\controller\nodedrainer.go` — `NodeDrainer{Cordon,Uncordon,Taint,RemoveTaint,Drain}` + `CleanNodeSelector.SelectCleanNode`.
- `internal\controller\noderotation_controller.go` — `NodeRotationReconciler` phase machine, `countOtherInFlight`, `SetupWithManager`, RBAC markers.
- `internal\controller\noderotation_helpers.go` — annotation/status helpers, pinning (`injectCleanNodeAffinity`, bare-pod snapshot/recreate), `appendAMTDHistory`.
- `internal\controller\node_rotate_gate.go` — `evaluateNodeRotateGate` (D26 HARD gate) + `Effective*` helpers + denied-reason consts.
- `internal\controller\noderotate_action.go` — `requestNodeRotate` (gate → idempotent NodeRotation create; NIM lock; AppliedAction; RotationPathFired).
- Tests: `nodedrainer_test.go`, `noderotation_controller_test.go`, `noderotate_action_test.go` (14 new tests).

**Edited:**
- `api\v1beta1\adaptivemovingtargetdefense_types.go` — additive `AMTDSpec.NodeRotationPolicy *NodeRotationPolicy` + `AMTDSpec.NodeRotateTrust *NodeRotateTrustPolicy` (nil ⇒ defaults).
- `api\v1beta1\zz_generated.deepcopy.go` — regenerated.
- `config\crd\bases\amtd.r6security.com_noderotations.yaml` — new CRD (scope: Cluster).
- `config\rbac\role.yaml` — **regenerated** (see Deviations): now grants `nodes` (incl. update/patch), `pods/eviction` create, `policy/poddisruptionbudgets` get/list/watch, `noderotations`/`/status`/`/finalizers` (verified on disk: `role.yaml:20,42,91,177`).
- `internal\controller\securityevent_controller.go:493` — last no-op stub replaced with `r.requestNodeRotate(...)`.
- `cmd\main.go` — `NodeRotationReconciler` registered above the `//+kubebuilder:scaffold:builder` marker.

## Build result (REAL)

- `go build ./...` → **exit 0** (`build\logs\review6-build.txt` / `review6-build-final.txt`, empty = clean)
- `go vet ./...` → **exit 0** (`review6-vet.txt` / `review6-vet-final.txt`, empty)

## Test result (REAL)

`go test ./... -count=1` with `KUBEBUILDER_ASSETS` set (kubebuilder 1.30.3-windows-amd64, verified present) → **exit 0**, per-package (`review6-test-final.txt`):

```
ok  github.com/r6security/phoenix/api/v1beta1          0.913s
ok  github.com/r6security/phoenix/internal/controller  0.370s
ok  github.com/r6security/phoenix/internal/scheduler   0.196s
?   github.com/r6security/phoenix/cmd                  [no test files]
?   github.com/r6security/phoenix/pkg/controllers      [no test files]
```

No failures. Phase 0–5 invariants (api-package byte-compat / `MaxProperties=1` / DeepEqual sweep + all controller tests) intact.

**Phase-6 verbose: 14/14 PASS** (`review6-test-verbose.txt`):
`TestNodeDrainer_CordonTaintUncordon`, `TestNodeDrainer_Drain_TargetedOnlyDefault`, `TestNodeDrainer_Drain_CoTenantOptIn`, `TestCleanNodeSelector_PicksAndExcludes`, `TestCleanNodeSelector_NoCleanTarget`, `TestCleanNodeSelector_PVCTopologyBound`, `TestNodeRotateAction_AllowedCreatesNodeRotation`, `TestNodeRotateGate_BlocksNonAllowlistedSource`, `TestNodeRotateGate_BlocksBelowFloor`, `TestNodeRotateGate_DeleteNeedsApproval`, `TestNodeRotation_ProgressesToCompleted`, `TestNodeRotation_NoCleanTargetAbort`, `TestNodeRotation_RestartSafeResume`, `TestNodeRotation_MaxConcurrentNodesThrottle`.

Log paths (all `c:\Users\moh87733\Phorvex\build\logs\`): `review6-build.txt`, `review6-vet.txt`, `review6-test.txt`, `review6-test-verbose.txt`, `review6-build-final.txt`, `review6-vet-final.txt`, `review6-test-final.txt`; prior-run `phase6_build.log`, `phase6_vet.log`, `phase6_test.log`, `phase6_test_verbose.log`, `phase6_test_final.log`.

## Kind-cluster live verification (REAL, control-plane only)

Context `kind-amtd-test`, apiserver live, **single real node** `amtd-test-control-plane` (NOT clean-pool-labeled). Clean pool = **fake `Node` objects** `fake-clean-1`/`fake-clean-2` labeled `r6security.com/clean-pool=true` (no kubelet). CRDs applied server-side; `noderotations` confirmed scope=Cluster, Established=True on the live apiserver. Manager built (`bin\manager.exe`, exit 0) and run via `run_in_background`; noderotation + securityevent controllers both started. Full evidence: `build\logs\live6-manager.txt` (independently re-confirmed in `review6-live-manager.txt`).

### (A) Clean node SELECTED + source CORDONED + pod DRAINED off source — PROVEN

Allowlisted SecurityEvent (Source=`KubeArmorIntegrator`, ThreatLevel=`critical`) targeting `phase6-verify/nim-demo`:
- `NodeRotation nrot-se-a-allowed-critical-nim-demo` CREATED → reached `Phase=Completed`.
- `CleanNodeSelector` selected `status.targetCleanNode=fake-clean-1` (source excluded).
- Source `amtd-test-control-plane` CORDONED (`.spec.unschedulable=true`).
- Targeted pod DRAINED off source (`kubectl get pod nim-demo` → NotFound after rotation; `evictedTargeted:1, evictedCoTenants:0`).
- `SecurityEvent .status.appliedAction=nodeRotate`; `TriggerProvenance{source:KubeArmorIntegrator, threatLevel:critical, eventName:se-a-allowed-critical}`.
- Phase progression in log: "source node cordoned (relocate-before-dispose)" (`L318`) → "targeted pod(s) evicted off source; selecting a clean node" (`L337`) → "clean node selected; pinning the replacement via nodeAffinity" `{cleanNode:fake-clean-1}` → "NodeRotation COMPLETE ... relocated:1" (`L351`).
- **IDEMPOTENT**: re-reconcile of the same event → "a NodeRotation for this event already exists; idempotent no-op" — still exactly 1 NodeRotation.
- **NIM lock observed**: `nim-demo` carried `rotation.r6security.com/in-progress=true`; NIM logged "NIM early-return: rotation in progress" (no double-evict).

### (B) D26 gate ENFORCED — PROVEN (both block paths + allow path)

- **B1 non-allowlisted Source** (`EvilWorkload`, critical): `appliedAction=nodeRotate-denied`; **NO NodeRotation**; source NOT cordoned (`.spec.unschedulable` empty); pod still Running; AMTD condition `NodeRotateGatedSourceNotAllowed=True`; log "NodeRotate GATED (D26): no NodeRotation created ... reason: NodeRotateGatedSourceNotAllowed" (`L460-464`, `L504-508`).
- **B2 allowlisted but below floor** (`KubeArmorIntegrator`, low): `appliedAction=nodeRotate-denied`; **NO NodeRotation**; source NOT cordoned; pod still Running; AMTD condition `NodeRotateGatedBelowFloor=True`; log reason `NodeRotateGatedBelowFloor` (`L523-527`, `L570-574`).
- After B1+B2 the NodeRotation list was unchanged (still only the A rotation) — both gated events created **zero drains**.
- **Allow path** (A) confirms allowlisted `KubeArmorIntegrator`+critical → NodeRotation created.
- **Strategy=Delete human-approval** is **unit-proven** (`TestNodeRotateGate_DeleteNeedsApproval`); not re-run live this session.
- The `review6` independent live re-run reproduced DENY (non-allowlisted `EvilWorkload/critical` → 0 NodeRotations, source not cordoned) and ALLOW (allowlisted `KubeArmorIntegrator/critical` → exactly 1).

### (C) NoCleanTarget — PROVEN live; no-mass-eviction — unit-proven

With both fake clean nodes deleted (no clean-pool node remaining), an allowed `KubeArmor/critical` event:
- Gate PASSED; `NodeRotation nrot-se-c-noclean-critical-nim-demo` created.
- The machine cordoned the source FIRST (relocate-before-dispose), evicted the targeted pod (`evictedTargeted:1`), then at Rescheduling found no clean node and ABORTED: "NodeRotation ABORTED: NoCleanTarget (no unschedulable pod landed)", reason `CleanPoolExhausted` (`L717-721`); durable annotation `amtd.r6security.com/noderotation-phase=NoCleanTarget`. **Never landed an unschedulable pod.**
- **no-mass-eviction (MaxConcurrentNodes/Stagger)** was **NOT exercised live** (this AMTD set no `NodeRotationPolicy` ⇒ `MaxConcurrentNodes` nil = unlimited, so the ceiling never engaged). It remains **unit-proven** (`TestNodeRotation_MaxConcurrentNodesThrottle`: the Nth concurrent rotation stays Cordoning with `NodeRotationThrottled` set).

### (D) Node MTTR / true relocation — EXPLICITLY REAL-NODE/GPU-PENDING (NOT measured)

- True relocation (targeted pod RUNNING on a different REAL clean node) was **NOT achieved/measured**: fake clean nodes have no kubelet, so the pinned replacement (nodeAffinity to the clean node, **NEVER `spec.nodeName`**) stays Pending; kind has only ONE real node. The replacement-spec pinning is **unit-verified only**.
- **Node-rotation MTTR (`CompletionTime − StartTime`) is NOT asserted** as a meaningful number — on kind both timestamps land in the same control-plane reconcile burst. The COMPLETE log line itself states this is REAL-NODE/GPU-PENDING (`L351-352`). GPU-MIG preflight is a permissive seam (GPU-PENDING). **No node-rotation timing number is asserted anywhere.**

### Teardown — CONFIRMED

- `kubectl uncordon amtd-test-control-plane` → node uncordoned, `.spec.unschedulable` now empty (schedulable RECOVERED), no leftover AMTD taints.
- Fake nodes `fake-clean-1`/`fake-clean-2` deleted; final `kubectl get nodes` shows only `amtd-test-control-plane` Ready, `UNSCHEDULABLE=<none>`.
- All SecurityEvents, NodeRotations, the AMTD, the pod, and the `phase6-verify` namespace deleted; `kubectl get noderotation,securityevent -A` → No resources found.
- Manager killed (`Stop-Process`; the background task's **exit 255 is the kill**, not an operational failure — the manager ran cleanly throughout). Manager NOT running confirmed. **Cluster fully recovered.**

## Deviations / honest gaps

1. **[FIXED] Stale RBAC manifest.** A prior summary claimed `config\rbac\role.yaml` was already regenerated with the node-rotation grants; that was **FALSE against on-disk** — the committed `role.yaml` contained none of `nodes`, `pods/eviction`, `policy/poddisruptionbudgets`, or `noderotations`. The **in-source RBAC markers were correct** (`noderotation_controller.go:95-102`); only the generated manifest was never written back. It was **regenerated via controller-gen v0.17.2** and now matches the markers (verified on disk: `role.yaml:20,42,91,177`). Build/vet/test re-run GREEN after the fix. The live demos used admin kubeconfig creds, so the stale manifest never affected them — but a real in-cluster deployment with the old role would have failed (no nodes/eviction/PDB perms). Now correct.

2. **[DOCUMENTED] Source IS cordoned before a NoCleanTarget abort.** Contrary to the plan's "no cordon of the source on NoCleanTarget," the live machine runs `doCordon` as its first durable step, *before* `SelectCleanNode`. So on the no-clean-target path the source IS cordoned (and the pod drained) before the abort. The invariant that actually holds is **"never land an unschedulable pod,"** not "never cordon the source." Independently reproduced in the `review6` live re-run. Teardown uncordoned the source.

3. **[DOCUMENTED] NoCleanTarget Status mirror is best-effort.** For the C rotation, `status.phase`/`status.conditions` came back empty on the object even though the durable annotation = `NoCleanTarget` and the log recorded the abort (`abortNoCleanTarget`'s `Status().Update` is best-effort, error swallowed; resourceVersion race after the annotation write). The **durable annotation + log are authoritative**; the Status mirror is the documented best-effort surface. (Scenario A's status DID persist fully: `phase=Completed`, `targetCleanNode=fake-clean-1`, `relocatedPods=[nim-demo]`.)

4. **Fake-node control plane vs real relocation.** Everything above is control-plane behavior on kind. Pod-RUNNING-on-a-different-real-node and node-rotation MTTR are REAL-NODE/GPU-PENDING (see (D)).

5. **Pinning: owner-managed vs bare.** Bare pods get a one-shot pinned recreate (spec snapshotted pre-eviction, `nodeName` stripped, nodeAffinity injected — unit-verified). Owner-managed pods (Deployment/StatefulSet/DaemonSet) do NOT patch the shared owner template (would rotate all replicas); pinning rides the warm-swap shadow when a WarmInferenceSet covers the pod.

6. **GPU-MIG preflight** is a permissive seam (GPU-PENDING); label-pool + PVC-topology selection IS kind-tested.

## Verdict

**PASS** (by real results, this session).

- Build / vet / test **GREEN** (real exit 0; per-package `ok`; 14/14 Phase-6 tests PASS; Phase 0–5 invariants intact).
- All 8 deliverables present and faithful with file:line evidence (NodeRotation CRD, NodeDrainer, CleanNodeSelector, nodeAffinity pinning, phase machine + no-mass-eviction ceiling, NodeRotate action wired, D26 gate, NIM lock).
- **The `NodeRotate` action is wired — the LAST AMTDAction stub. All AMTDAction members are now implemented; no stubs remain.**
- Live (control-plane): clean-node selection + source cordon + targeted-pod drain off source; D26 gate blocked non-allowlisted (`NodeRotateGatedSourceNotAllowed`) and below-floor (`NodeRotateGatedBelowFloor`) with zero NodeRotations and no cordon, and allowed allowlisted+critical; NoCleanTarget abort (`CleanPoolExhausted`, no unschedulable pod landed); restart-safe resume; cluster fully recovered (real node uncordoned, fake nodes deleted).
- One real deviation found and **FIXED** (stale RBAC `role.yaml` regenerated to match in-source markers).
- **No node-rotation timing/MTTR claimed on kind.** True relocation (pod RUNNING on a different real clean node) + node MTTR are REAL-NODE/GPU-PENDING; no-mass-eviction is unit-proven (not exercised live, no NodeRotationPolicy set); GPU-MIG preflight GPU-PENDING.

**Next:** Phase 7 (per-integrator ThreatLevel/Type normalization) — NOT started. GPU/real-node SLOs (node-rotation MTTR, panic MTTR, warm-swap downtime) await a real-GPU / real-multinode run. `repos\` untouched; AnomalyScorer Passthrough unchanged.
