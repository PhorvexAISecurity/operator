# Phoenix AMTD — Phase 3 Closure Report (ContextMutationPolicy + GatekeeperViolation Receiver)

Date: 2026-05-31
Module: `c:\Users\moh87733\Phorvex\build\phoenix-extended`
Verdict (real results): **PASS** — Phase 3 is now fully closed.

---

## Scope

This report closes the single deferred Phase-3 sub-item: the **ContextMutationPolicy (CMP)** kind + thin reconciler + CMP resolution inside the `MutationApplier`, plus the **GatekeeperViolation RECEIVER** path.

**State up-front and prominently:**
> **GatekeeperViolation has NO native emitter in any of the 5 repos. It is paper-only (ADA Listing 1, D7g). We built the RECEIVER; we did NOT fabricate an emitter.** In both live verifications the GatekeeperViolation `SecurityEvent` was **INJECTED MANUALLY** to stand in for the absent OPA-Gatekeeper-audit emitter. This is disclosed in the SecurityEvent's own `description`, in the CMP advisory condition, in code comments, and in the evidence files.

The CMP kind is a real operator kind on the **`amtd.r6security.com/v1beta1`** group (D7g), NOT the paper literal `ADA.security.r6.dev/v1` (which appears only in a rejection comment). It mirrors ADA Listing 1 (selector / triggers.telemetrySources / mutations) verbatim in shape.

---

## Non-goals / deferred

- **Phase 4** (warm-pool / GPU / LWS headline) — NOT started.
- Drift / node-level rotation — deferred.
- `WarmSwap` / `Regenerate` / `NodeRotate` — remain honest type-only "not yet implemented; no-op" stubs (`securityevent_controller.go:446-454`), UNCHANGED.
- `AnomalyScorer` Passthrough default — UNCHANGED (`scoring.go:65-82`, `scorerFor` returns `PassthroughScorer{}` when no ScoringPolicy, `:145`).
- `c:\Users\moh87733\Phorvex\repos` — NOT touched (newest file dated 5/30, pre-dating this session).

---

## Requirement-by-requirement table

| # | Requirement | Status | Evidence (file:line) | Test / Cmd |
|---|-------------|:------:|----------------------|------------|
| 1 | CMP is a real kind on `amtd.r6security.com/v1beta1` (NOT the paper literal) | ✅ | `api/v1beta1/groupversion_info.go:30`; `contextmutationpolicy_types.go:218` (`SchemeBuilder.Register`); CRD `config/crd/bases/amtd.r6security.com_contextmutationpolicies.yaml:7,9,17` (group/`Namespaced`/short `cmp`); literal `ADA.security.r6.dev/v1` only in rejection comment `:29` | `go build ./...` EXIT 0 |
| 2 | Faithful to ADA Listing 1 (selector / triggers / mutations) | ✅ | `contextmutationpolicy_types.go`: Selector `:157`; Triggers.TelemetrySources `:94-117` (enum `:61`); Mutations `:126-150` (enum `:77`); Status `:171-191`. CRD schema `yaml:56,233,304-305,313,365,390` | type/build |
| 3 | Reconciler is THIN (status only, does NOT rotate) + surfaces no-emitter advisory | ✅ | `contextmutationpolicy_controller.go:21` ("DOES NOT ROTATE"); only `r.Status().Update` `:114`, no workload Delete/patch; advisory `GatekeeperViolationUnsupported`/`NoNativeEmitter` `:102-112` | `TestCMPReconcile_StatusAndAdvisory`, `TestCMPReconcile_NoGatekeeperTrigger_NoAdvisory`, `TestCMPReconcile_NilSelectorSelectsNothing` |
| 4 | MutationApplier.Resolve FETCHES CMP, projects Mutations[]→overlay; `EffectiveSource="ContextMutationPolicy"`; reuses ApplyToPodSpec + D3 + D22 | ✅ | `mutation.go`: signature `:100,124`; fetch in `amtd.Namespace` `:157-180`; `projectCMPMutations` (image/gpu/env) `:210-238`; same `ApplyToPodSpec` `:278` + D3 `classifyTopOwner`/`patchOwnerTemplate` `:414,463`. Call site `rotate_executor.go:279-283` | `TestMutationApplier_Resolve_ContextMutationPolicy`, `..._ContextMutationPolicyNotFound`, `..._OverridesWinsOverPolicyRef`, `..._PolicyRefInferenceRotation`, `..._BothNilEmpty` |
| 5 | GatekeeperViolation receiver exists with NO fabricated emitter | ✅ | `gatekeeper_receiver.go:84-99` (convention constants); header `:20-22` (no emitter in any of 5 repos); `NewGatekeeperViolationEvent` "NOT an emitter" `:103-106`; matcher needs no change — `matcher.go:120-121` (Eq) → `projectField` `metrics.` prefix `:173-177` | `TestGatekeeperReceiver_RoutesToRotateCMP` |
| 6 | LIVE: CMP reconciles (Status values written) | ✅ | `live3b-evidence-20260531-021909.txt`; independently re-run `review3b-live-evidence.txt` | kind `kind-amtd-test` |
| 7 | LIVE: injected GatekeeperViolation → CMP-mutation durable rotation | ✅ | same evidence files (template image/env/gpu mutated, new pod, `effectiveSource=ContextMutationPolicy`) | kind `kind-amtd-test` |
| 8 | Phase-0/1/2/3 invariants intact | ✅ | byte-compat `matcher.go:54`; MaxProperties=1 `adaptivemovingtargetdefense_types.go:277`; D22 + scoring/panic + NIM pass-through | `TestMatchStrategy_ByteCompatWithDeepEqual`, `_LegacyEqualsDeepEqual`, `_ScoredPath/*`, `TestRotate_DurableRoute_MutatesOwnerTemplate`, `TestMaxConcurrentRotations_*`, `TestNIMReconciler_*`, `TestPanic_*` |
| 9 | Passthrough / stub honesty | ✅ | `scoring.go:65-82,145`; `securityevent_controller.go:446-454` | `TestPassthroughScorer`, `TestEWMA_Math`, `TestSecurityEventReconciler_ScoredMode_PanicSelectsRotate` |

Legend: ✅ pass · ⚠️ documented deviation · ❌ fail. No ❌ rows. The one documented deviation (cpu/memory ResourceAdjustment requests) is in **Deviations** below.

---

## Files changed

**Created**
- `build/phoenix-extended/api/v1beta1/contextmutationpolicy_types.go` — the NEW CMP kind.
- `build/phoenix-extended/internal/controller/contextmutationpolicy_controller.go` — thin status reconciler.
- `build/phoenix-extended/internal/controller/gatekeeper_receiver.go` — receiver convention (no emitter).
- `build/phoenix-extended/internal/controller/contextmutationpolicy_controller_test.go`
- `build/phoenix-extended/internal/controller/gatekeeper_receiver_test.go`
- `build/phoenix-extended/config/crd/bases/amtd.r6security.com_contextmutationpolicies.yaml` (generated)

**Modified**
- `internal/controller/mutation.go` — `Resolve` signature (`ctx, reader client.Reader` added; `error` return added) + CMP fetch/projection + `projectCMPMutations` / `summarizeOverlay`.
- `internal/controller/rotate_executor.go` — L274/279 call site: `overlay, effectiveSource, err := applier.Resolve(ctx, r.Client, action, amtd)` + fatal err handling.
- `internal/controller/mutation_applier_test.go` — 4 `Resolve` call sites updated; CMP-empty test replaced with resolve-projection + not-found tests.
- `cmd/main.go` — registered `ContextMutationPolicyReconciler` above `//+kubebuilder:scaffold:builder` (scheme already covered by `amtdv1beta1.AddToScheme`, same group/SchemeBuilder).
- `api/v1beta1/zz_generated.deepcopy.go` — regenerated (CMP / CMPMutation / CMPTriggers / TelemetrySource / Spec / Status + List).
- `config/rbac/role.yaml` — regenerated (`contextmutationpolicies` + `/status` + `/finalizers` + `core/pods`).

---

## Build result (REAL exit codes)

Re-run verbatim in Stage-4 review:
- `go build ./...` → **EXITCODE = 0**. Log: `build/logs/review3b-build-20260531-022113.txt`
- `go vet ./...` → **EXITCODE = 0**. Log: `build/logs/review3b-vet-20260531-022121.txt`

---

## Test result (REAL `go test ./...`)

`go test ./... -count=1` (KUBEBUILDER_ASSETS set) → **EXITCODE = 0**.

Per-package:
- `ok api/v1beta1 0.928s`
- `ok internal/controller 0.365s`
- `ok internal/scheduler 0.202s`
- `cmd` and `pkg/controllers` — no test files.

Verbose tally: **149 `--- PASS`, 0 `--- FAIL`, 0 `^FAIL` package lines, 3 `^ok`.**
- Log (summary): `build/logs/review3b-test-20260531-022133.txt`
- Log (verbose): `build/logs/review3b-test-verbose-20260531-022148.txt`

> Honest count note: an earlier Stage-2 pass reported "96 `--- PASS`"; the Stage-4 verbose re-run enumerated 149 (more subtests surfaced) with **0 failures** — a counting-granularity difference, NOT a regression.

**Phase-3b test names — all PASS:**
`TestCMPReconcile_StatusAndAdvisory`, `TestCMPReconcile_NoGatekeeperTrigger_NoAdvisory`, `TestCMPReconcile_NilSelectorSelectsNothing`, `TestGatekeeperReceiver_RoutesToRotateCMP`, `TestMutationApplier_Resolve_ContextMutationPolicy`, `TestMutationApplier_Resolve_ContextMutationPolicyNotFound`, plus adapted `TestMutationApplier_Resolve_OverridesWinsOverPolicyRef` / `_PolicyRefInferenceRotation` / `_BothNilEmpty`.

**Invariant test names — all PASS:**
`TestMatchStrategy_ByteCompatWithDeepEqual`, `TestMatchStrategy_LegacyEqualsDeepEqual`, `TestMatchStrategy_ScoredPath/*` (7 subtests), `TestMaxConcurrentRotations_*`, `TestNIMReconciler_*` (pass-through), `TestPanic_*`, `TestEWMA_Math`, `TestPassthroughScorer`, `TestSecurityEventReconciler_ScoredMode_PanicSelectsRotate`, `TestRotate_DurableRoute_MutatesOwnerTemplate`.

No failures to report verbatim (0 `--- FAIL`).

---

## Kind-cluster live verification (REAL)

Cluster `kind-amtd-test` (apiserver v1.35), real manager `bin\manager.exe` run in background, real evidence captured, torn down after. **Both asks were verified twice** on a real cluster: once in Stage-3 (namespace `phase3b-verify`, manager PID 180) and again, independently, in the Stage-4 adversarial review on fresh objects (namespace `review3b-verify`, Stage-4 rebuild `bin\manager.exe` = 77,897,216 bytes, PID 18304).

Manager startup confirmed CMP controller up: `Starting workers {"controller": "contextmutationpolicy", ... "worker count": 1}`.

### (1) ContextMutationPolicy RECONCILES — PROVEN

Applied CMP `nim-risk-based-mutation` (selector `app=nim-demo`; mutations: ContainerImageUpdate→`busybox:1.37`, ResourceAdjustment gpu `"0"` + cpu/mem requests, EnvPatch `RUNTIME_MODE=SECURE`; triggers include GatekeeperViolation constraint `disallowed-hostpath`) + Deployment `nim-demo` (container `nim`, 1 Running pod). Thin reconciler wrote CMP `.status`:
- `observedGeneration = 1`
- `selectedPodCount = 1` (matched the running pod by matchLabels)
- `resolvedMutationSummary = "image=busybox:1.37; gpu=0; env=RUNTIME_MODE; container=nim (cpu/mem requests recognized, not applied)"`
- advisory condition `GatekeeperViolationUnsupported` Status=`True` Reason=`NoNativeEmitter` (message: OPA-Gatekeeper emitter is receiver-only future-work).
- Manager log: `ContextMutationPolicy reconciled (thin status; no rotation performed) ... "selectedPods": 1, "mutations": "image=busybox:1.37; gpu=0; env=RUNTIME_MODE; container=nim (cpu/mem requests recognized, not applied)", "gatekeeperAdvisory": true`.

Stage-4 independent re-run reproduced identical Status values on `review3b-verify`.

### (2) INJECTED GatekeeperViolation → CMP-mutation rotation FIRES — PROVEN

Applied AMTD `nim-demo-amtd` (`matcherMode=Scored`) with rule `metrics.gatekeeper.constraint Eq disallowed-hostpath` → `action.rotate.policyRef{kind: ContextMutationPolicy, name: nim-risk-based-mutation}`. Then **MANUALLY INJECTED** a cluster-scoped SecurityEvent `injected-gatekeeper-violation` (Source=`GatekeeperIntegrator`, Type=`gatekeeper-violation`, Metrics[`gatekeeper.constraint`]=`disallowed-hostpath`, Targets=`[phase3b-verify/<pod>]`).

Result — rotation fired and the CMP mutation was applied durably to the **Deployment template**:
- Template BEFORE: `image=busybox:1.35`, `env RUNTIME_MODE=PERMISSIVE`, no gpu limit.
- Template AFTER: `image=busybox:1.37`, `env RUNTIME_MODE=SECURE`, `limits={"nvidia.com/gpu":"0"}`.
- New pod rotated in (`nim-demo-5c8bc944c8-65zgg`, new RS hash) Running with the mutated spec; old pod `nim-demo-7c947f9755-wkstq` gone.
- AMTD `.status`: `rotationCount=1`, `effectiveSource=ContextMutationPolicy`, `rotationPathFired=Rotate`, `mutationDurable=true`.
- SecurityEvent `.status`: `appliedAction=rotate`, `processedAt` set.
- Manager log: `Rotate route (a): patched top owner template (durable, all replicas) ... "ownerKind": "Deployment", "owner": "nim-demo"` and `Pod successfully rotated ... "rotationPathFired": "Rotate", "mutationDurable": true, "effectiveSource": "ContextMutationPolicy"`.

Stage-4 independent re-run reproduced the same outcome on `review3b-verify`: template `busybox:1.35`→`busybox:1.37`, `RUNTIME_MODE=PERMISSIVE`→`SECURE`, `nvidia.com/gpu:"0"`; new pod `review-demo-7574bff76f-g84z5` Running, old `...-d6cmj` Terminating; AMTD `rotationCount=1, effectiveSource=ContextMutationPolicy, rotationPathFired=Rotate, mutationDurable=true`; SE `appliedAction=rotate`.

> **EXPLICIT — manual injection (no emitter):** the GatekeeperViolation SecurityEvent was injected by hand because NO native OPA-Gatekeeper-audit→SecurityEvent emitter exists in any of the 5 repos. The injection stands in for the absent emitter and is documented paper-only/future-work (D7g). The mutation being verified is that the CMP overlay reaches the **Deployment template** — NOT that any NVIDIA image runs (placeholder kind-pullable `busybox` images were used precisely because `nvcr.io/nim/secure-nim` will not pull on kind).

### Honest live artifact (benign)
The AMTD (NIM-style) controller logged a few `Operation cannot be fulfilled on pods ... the object has been modified` conflict ERRORs during rotation churn — optimistic-concurrency retries that self-resolved (followed by "successfully updated" lines). They are NOT on the rotation path and did not affect the durable template patch or any status field above.

### Cleanup confirmation
Both runs torn down: SecurityEvent, AMTD, CMP, Deployment, and the test namespace deleted (`NAMESPACE_GONE` / `NotFound`); managers killed (Stage-3 PID 180; Stage-4 PID 18304 `PROCESS_ABSENT`, no stray `manager.exe`). The 3 CRDs were intentionally left installed (per the stated procedure, which scopes teardown to test objects + namespace + manager). `c:\Users\moh87733\Phorvex\repos` untouched.

**Evidence files:**
- Stage-3: `build/logs/live3b-evidence-20260531-021909.txt`, `build/logs/live3b-manager-20260531-021515.txt` (+ `.out`)
- Stage-4: `build/logs/review3b-live-evidence.txt`, `build/logs/review3b-live-manager-20260531-022438.txt` (+ `.out`)
- Build/vet/test: `build/logs/review3b-build-20260531-022113.txt`, `review3b-vet-20260531-022121.txt`, `review3b-test-20260531-022133.txt`, `review3b-test-verbose-20260531-022148.txt`, `review3b-manager-build-20260531-022406.txt`

---

## Deviations / honest gaps

1. **cpu/memory `ResourceAdjustment` requests are NOT projected** into the `EffectiveOverlay` (the Phase-1 overlay is image/env/gpu only). This is the documented (**document, not extend**) decision permitted by the stage scope — and it is **not a silent drop**: `summarizeOverlay` appends `(cpu/mem requests recognized, not applied)` to the summary (visible in the live `resolvedMutationSummary`), and code comments mark the overlay extension as deferred (`mutation.go:228-229, 267-268`). Extending `EffectiveOverlay` with `CPURequest/MemRequest` remains an available future option.
2. **GatekeeperViolation is paper-only / receiver-only.** No native emitter exists in any of the 5 repos and none was fabricated. The live receiver test therefore required a MANUAL injection of the SecurityEvent (disclosed in the SE description, the CMP advisory, code comments, and the evidence files). This is the intended scope (D7g, arch §7 prereq #1).
3. **PrometheusAlert leg is reused, not newly built** — the CMP `TelemetrySources[PrometheusAlert]` rides the existing matcher/metrics path (`metrics.` prefix projection), consistent with the existing AMTD strategy matching; no new emitter or matcher surface was added.
4. **Benign teardown scripting error (Stage-4):** an early teardown attempt reused the read-only automatic `$PID` variable in PowerShell; objects + namespace were still deleted and the manager was correctly killed by saved PID via a renamed variable (`PROCESS_ABSENT` verified). No functional impact.

---

## Verdict

**PASS** by real results: build EXIT 0, vet EXIT 0, full test suite EXIT 0 (149 `--- PASS`, 0 `--- FAIL`), and both live asks verified TWICE on a real `kind-amtd-test` cluster (Stage-3 and an independent Stage-4 adversarial re-run on fresh objects), then cleaned up.

**Phase 3 is now fully closed** — the deferred ContextMutationPolicy + GatekeeperViolation-receiver sub-item is delivered: the CMP kind faithful to ADA Listing 1 on the operator group, a thin status-only reconciler with the no-emitter advisory, CMP resolution in the MutationApplier reusing the same `ApplyToPodSpec`/D3/D22 path, and the GatekeeperViolation receiver with NO fabricated emitter. Phase-0..3 invariants intact.

**Next: Phase 4 (warm-pool / LWS — GPU headline) — NOT started.**
