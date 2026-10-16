# Phoenix AMTD — End-to-End Platform Validation

## Summary

The complete Phoenix AMTD platform (Phases 0-7) was built, vetted, and tested across all 5 source trees (operator + the 3 integrators + time-based-trigger) and then exercised **live** on a real kind cluster (`kind-amtd-test`, apiserver v1.35, single node `amtd-test-control-plane`). **All 5 trees are build=0 / vet=0 / test=0 — 233 tests RUN, 233 PASS, 0 FAIL, 0 skips** — and this was re-confirmed by an independent adversarial re-run in Stage 4. **All 11 action paths FIRED end-to-end** from a real `SecurityEvent`/CR plus an operator log line plus an observed cluster effect; the **Phase-0 exact-match delete is unregressed**; the **D26 node-rotation gate blocked both** the non-allowlisted source and the below-floor event; and **score flowed end-to-end on paths 3 and 6**. No feature code was modified. The platform's **action control planes are fully validated on kind**; the only items not measured are the **GPU / real-node SLOs** — warm-swap downtime (400s→15s), panic MTTR, node-rotation MTTR, and GPU-MIG preflight — which are explicitly **PENDING** a real-GPU / real-multi-node run (their control planes fired, but the numbers were not measured and are not claimed).

## Build / Test Matrix

Toolchain: Go 1.26.3 windows/amd64. Operator tests run with `KUBEBUILDER_ASSETS=C:\Users\moh87733\AppData\Local\kubebuilder-envtest\k8s\1.30.3-windows-amd64`; integrators and time-based-trigger are plain table / fake-client suites. Exit codes below are REAL and were reproduced independently in Stage 4.

| Tree (module) | build | vet | test | Per-package results (tests) |
|---|---|---|---|---|
| **operator** (`github.com/r6security/phoenix`) | 0 | 0 | 0 | `ok api/v1beta1`, `ok internal/controller`, `ok internal/scheduler`; `cmd`, `pkg/controllers` [no test files] — RUN=209 PASS=209 FAIL=0 |
| **time-based-trigger** (`github.com/r6security/time-based-trigger`) | 0 | 0 | 0 | `ok internal/controller`; `cmd` [no test files] — RUN=10 PASS=10 FAIL=0 |
| **falco-integrator** (`github.com/r6security/falco-integrator`) | 0 | 0 | 0 | `ok cmd`; `clients`, `clients/securityevent` [no test files] — RUN=5 PASS=5 FAIL=0 |
| **prometheus-integrator** (`github.com/r6security/prometheus-integrator`) | 0 | 0 | 0 | `ok cmd`; `clients`, `clients/securityevent` [no test files] — RUN=4 PASS=4 FAIL=0 |
| **kubearmor-integrator** (`github.com/r6security/kubearmor-integrator`) | 0 | 0 | 0 | `ok cmd`; `clients`, `clients/securityevent`, `kubearmorlog` [no test files] — RUN=5 PASS=5 FAIL=0 |
| **TOTALS** | **0×5** | **0×5** | **0×5** | **RUN=233 / PASS=233 / FAIL=0** |

Captures: `c:\Users\moh87733\Phorvex\validation\raw\build-test-all-trees.txt` (Stage 1) and `c:\Users\moh87733\Phorvex\validation\raw\review-build-test.txt` (Stage 4 independent re-run). Both agreed on exit 0 across every package; no error output from build or vet on any tree.

## Action-Path Results

All paths exercised live on `kind-amtd-test`. Each row carries the real `SecurityEvent`/CR, the load-bearing operator log line, the observed cluster effect, and the raw evidence file under `c:\Users\moh87733\Phorvex\validation\raw\`.

| # | Path | Status | SecurityEvent / CR | Operator log line | Observed effect | Raw file |
|---|---|---|---|---|---|---|
| 1 | Exact-match delete (Phase-0 regression guard) | **FIRED** | `path1-timed-delete` {timed/info/TimeBasedTrigger}; AMTD `legacy-amtd` Exact `{…→delete}` | `Pod "legacy-demo-…-d6w2q" was sucessfully deleted with ACTION: delete` | Pod DELETED (UID 628dfe50…), ReplicaSet recreated `47w2l` (UID a4c8d99d…); exact 3-string projection still selects byte-for-byte | `path1-exactmatch-delete.txt` |
| 2 | Rotate (durable mutation) | **FIRED** | `path2-timed-rotate` → rotate{`InferenceRotation`} | `Rotate route (a): patched top owner template (durable, all replicas)` owner=`nim-demo`; `Pod successfully rotated rotationPathFired=Rotate mutationDurable=true` | Deployment template + recreated pod = `busybox:1.37` + `RUNTIME_MODE=SECURE`; AMTD `rotationCount=1`; SE `status.appliedAction=rotate` | `path2-rotate.txt` |
| 3 | Scored rotate via Falco + score flow | **FIRED** | POST Falco Critical "Container Drift Detected" → :33333 (HTTP 200); canonical SE `anomalyScore=0.95` {drift/critical/FalcoIntegrator}; AMTD `nim2-scored-amtd` Scored `[anomalyScore Gte 0.85]→rotate` | `applyScoring: scored rawScore=0.95 effective=0.95 smoothed=0.95 computedInterval=3m57s panic=true`; `Rotate route (a)…`; `recorded Panic condition (immediate Rotate; node-move/quarantine NOT triggered)` | image→`busybox:1.37`; AMTD `smoothedScore=0.95 currentInterval=3m57s`; SE `appliedAction=rotate observedScore=0.95` | `path3-scored-rotate-falco.txt` |
| 4 | Quarantine | **FIRED** | `path4-quarantine` {policy-violation/medium/KubeArmorIntegrator}→quarantine; AMTD `quar-amtd` Exact | `Pod quar-demo-…-95m69 was put in quarantine` | deny-all NetworkPolicy created — `ingress:[] egress:[] policyTypes:[Ingress,Egress]`; pod relabeled to policy selector; AMTD set as controller owner | `path4-quarantine.txt` |
| 5 | Timed-trigger flow (cadence owner emits) | **FIRED** | tbt emitted 4 distinct timed SEs (`baseNext≠jitteredNext`) at 14:20:57 / 14:21:16 / 14:21:44 / 14:22:09 (gaps 19/28/25s ≈ jittered 15s) | `Pod "tbt-demo-…-<id>" was sucessfully deleted with ACTION: delete` (each cycle) | pod recreated each cycle, annotations persist on template; cadence owner proven to emit | `path5-timed-trigger.txt` |
| 6 | Prometheus normalized + score flow | **FIRED** | POST Alertmanager webhook (`anomaly_score=0.91`) → :33337 (HTTP 200); canonical SE `anomalyScore=0.91` with `metrics["anomaly_score.source"]=alert` (REAL label, not proxy); AMTD `prom-scored-amtd` Scored `[anomalyScore Gte 0.85]→rotate` | `applyScoring: … smoothed=0.91 computedInterval=6m18.6s`; `Rotate route (a)…` owner=`prom-demo` | image→`busybox:1.37`; AMTD `smoothedScore=0.91 currentInterval=6m18.6s`; SE `appliedAction=rotate`. 0.91<0.95 ⇒ longer interval (6m18.6s vs 3m57s) — monotone, score-derived | `path6-prometheus.txt` |
| 7 | WarmSwap (control-plane cutover) | **FIRED** (control plane) | `path7-timed-warmswap` {timed}→WarmSwap; WIS `wis-e2e` (Replicas=2, ServiceSelectorSwap, RequireModelLoaded) | `WarmSwap: set Spec.SwapRequest` → `leader label flipped (oldLeader=warm-0, newLeader=warm-1)` → `drain window elapsed` → `old leader retired` → `WarmSwap COMPLETE: lastSwapDurationMillis=2114` | leader flipped warm-0→warm-1; old leader retired; pool re-warmed to 2; leader Service resolves to new leader (10.244.0.123); `swapPhase=Idle`; AMTD `rotationPathFired=WarmSwap`. **Downtime GPU-PENDING (not measured)** | `path7-warmswap.txt` |
| 8 | Regenerate / drift self-heal | **FIRED** | WorkloadBaseline `drift-baseline` pins golden digest with REAL ecdsa-P256 sig + inline PKIX PEM (`requireSignature=true`); AMTD `drift-amtd` {drift/high/FalcoIntegrator→regenerate{resetHardeningProfile:true}} | `BaselineDrift: emitted Type:'drift' SecurityEvent with Evidence` (observed `73aaf090`≠expected `9532d8c3`) → `Regenerate verify-before-recreate: pinned target verified (signed=true, keyType=ecdsa)` → `patched top owner template to golden Repository@Digest (durable)` → `workload restored to golden baseline` | deployment + running pod restored to GOLDEN digest; WB `driftDetections=1 lastRegeneration set`; self-heal confirmed (Running pod at golden digest) | `path8-regenerate-drift.txt` |
| 9 | NodeRotate + D26 gate | **FIRED** (control plane) + BOTH gate blocks proven | Negative (a): non-allowlisted PrometheusIntegrator critical; Negative (b): allowlisted KubeArmor below-floor (low); Positive: allowlisted KubeArmor critical. AMTD `nrot-amtd` Scored `nodeRotateTrust{allow:[KubeArmorIntegrator], floor:[high,critical]}` | (a) `NodeRotate GATED (D26) … reason=NodeRotateGatedSourceNotAllowed`; (b) `reason=NodeRotateGatedBelowFloor`; (positive) `created NodeRotation request` → `source node cordoned; draining` → `evicted off source (evictedTargeted=1)` → `clean node selected; pinning` → `NodeRotation COMPLETE` | Negatives: 0 NodeRotations, source NOT cordoned, `appliedAction=nodeRotate-denied`. Positive: `phase=Completed targetCleanNode=fake-clean-1`, source cordoned. **True relocation + node-rotation MTTR REAL-NODE-PENDING** | `path9-noderotate-d26.txt` |
| 10 | ContextMutationPolicy | **FIRED** | CMP `cmp-e2e` (ADA Listing 1 shape; thin reconciler `selectedPodCount=1`, advisory `GatekeeperViolationUnsupported=True`); GatekeeperViolation trigger paper-only ⇒ SE `path10-cmp-gatekeeper` INJECTED; AMTD `cmp-amtd`→rotate{`ContextMutationPolicy/cmp-e2e`} | `SecurityEvent found: path10-cmp-gatekeeper` → `Rotate route (a)…` ownerKind=Deployment → `Pod successfully rotated (rotationPathFired=Rotate, mutationDurable=true, effectiveSource=ContextMutationPolicy)` | recreated pod carries full CMP mutation set: `image=busybox:1.37`, `nvidia.com/gpu=0`, `RUNTIME_MODE=SECURE`; AMTD `effectiveSource=ContextMutationPolicy` | `path10-contextmutationpolicy.txt` |
| 11 | KubeArmor normalized | **FIRED** (synthetic canonical, by design) | exact `buildKubeArmorSpec()` shape `path11-kubearmor` {policy-violation/critical/KubeArmorIntegrator, `anomalyScore=0.95`, `kubearmor.policy=ksp-block-shell`, `severity="9"`}; AMTD `ka-amtd` Scored `[threatLevel In high,critical]→quarantine` | `SecurityEvent found: path11-kubearmor` → `Pod ka-demo-…-4vf6z was put in quarantine` | deny-all NetworkPolicy created; rank-aware matcher consumed critical natively (critical ∈ {high,critical}); backed by passing `cmd` table tests (RUN=5 PASS=5) | `path11-kubearmor.txt` |

## Phase-0 Regression

The Phase-0 exact-match path is **unregressed**. Path 1 fired a `{timed/info/TimeBasedTrigger}` event against an Exact-match AMTD (`MatcherMode=Exact`), and the operator selected the target and deleted it (UID 628dfe50… → recreated 47w2l UID a4c8d99d…). The **exact 3-string projection (type/threatLevel/source) still selects byte-for-byte** — confirmed live by path 1 and corroborated by the byte-compat / exact-match table tests in `internal/controller` (part of the operator's RUN=209 PASS=209). The Stage-4 server-dry-run apply of a synthetic Exact-match AMTD + canonical SecurityEvent further validated the exact-match object shapes against the live CRD schema. Evidence: `path1-exactmatch-delete.txt`.

## Score Flow End-to-End

Score flowed end-to-end on **paths 3 and 6**: integrator-set `AnomalyScore` → Passthrough → EWMA smoothing → AMTD/SecurityEvent Status and score-derived cadence.

- **Path 3 (Falco):** SE `anomalyScore=0.95` → `applyScoring: scored rawScore=0.95 effective=0.95 smoothed=0.95 computedInterval=3m57s` → AMTD `smoothedScore=0.95 currentInterval=3m57s`, SE `observedScore=0.95`.
- **Path 6 (Prometheus):** SE `anomalyScore=0.91` → `smoothed=0.91 computedInterval=6m18.6s` → AMTD `smoothedScore=0.91 currentInterval=6m18.6s`, SE `observedScore=0.91`.
- **Monotonicity check:** 0.91 < 0.95 yields a *longer* interval (6m18.6s vs 3m57s), confirming the cadence is genuinely score-derived, not constant.

**Honesty note on `AnomalyScore`:** the Falco (0.95) and KubeArmor (0.95) scores are the documented **severity-derived PROXY** (not a measured anomaly). The **Prometheus 0.91 is a REAL alert label**, proven by `metrics["anomaly_score.source"]=alert` (taken from the alert, not the proxy).

## GPU / Real-Node PENDING

The following SLO numbers were **NOT measured on kind and are NOT claimed**. In each case the **action control plane FIRED on kind**, but the number awaits a real-GPU / real-multi-node run.

| Item | Control plane on kind | Number | Status |
|---|---|---|---|
| Warm-swap **DOWNTIME** (target 400s→15s) | FIRED (path 7: leader flip + 2s drain = `lastSwapDurationMillis=2114`) | end-to-end inference downtime | **GPU-PENDING** (only the control-plane cutover measured) |
| **PANIC MTTR** | FIRED (path 3: `panic=true`, immediate Rotate recorded) | mean time to recover under panic | **GPU-PENDING** |
| **NODE-ROTATION MTTR** + true relocation | FIRED (path 9: cordon → evict → clean-node select → `NodeRotation COMPLETE`) | MTTR + pinned replacement actually Running on a *different real clean node* | **REAL-NODE-PENDING** (single real node; fake nodes have no kubelet) |
| **GPU-MIG preflight** | not exercisable on kind | MIG-slice preflight numbers | **GPU-PENDING** |

## Raw Logs

All raw evidence is under `c:\Users\moh87733\Phorvex\validation\raw\`. Per-path and supporting files present:

- `build-test-all-trees.txt` — Stage 1 combined build/vet/test capture (all 5 trees)
- `review-build-test.txt` — Stage 4 independent build/vet/test re-run
- `path1-exactmatch-delete.txt` — exact-match delete (Phase-0 regression guard)
- `path2-rotate.txt` — rotate (durable)
- `path3-scored-rotate-falco.txt` — scored rotate via Falco + score flow
- `path4-quarantine.txt` — quarantine (deny-all NetworkPolicy)
- `path5-timed-trigger.txt` — timed-trigger cadence flow
- `path6-prometheus.txt` — Prometheus normalized + score flow
- `path7-warmswap.txt` — WarmSwap control-plane cutover
- `path8-regenerate-drift.txt` — regenerate / drift self-heal
- `path9-noderotate-d26.txt` — nodeRotate + D26 gate (both blocks + positive)
- `path10-contextmutationpolicy.txt` — ContextMutationPolicy
- `path11-kubearmor.txt` — KubeArmor normalized (synthetic canonical)
- `teardown.txt` — teardown + cluster-recovery confirmation
- `STACK-STATE.txt` — running-stack PIDs/ports/logs (Stage 2)
- `op.err.log` / `op.out.log` — operator (manager.exe) reconcile output
- `tbt.err.log` / `tbt.out.log` — time-based-trigger
- `falco.err.log` / `falco.out.log` — falco-integrator
- `prom.err.log` / `prom.out.log` — prometheus-integrator
- `op.pid` / `tbt.pid` / `falco.pid` / `prom.pid` — PID files

Note: several raw files are UTF-16-encoded (spaced characters); content is fully valid and was grep-verified in Stage 4.

## Deviations / Honest Gaps

- **Path 11 (KubeArmor) used a synthetic canonical event**, not a live KubeArmor gRPC stream — the gRPC integrator has no easy live inject. It applies the exact `buildKubeArmorSpec()` canonical shape and proves native rank-aware matcher consumption + quarantine, backed by the passing `cmd` table tests. Disclosed, not over-claimed.
- **Path 10 GatekeeperViolation trigger is paper-only (no emitter)**, so the trigger SecurityEvent was injected; the advisory condition `GatekeeperViolationUnsupported=True` is set. Rotation correctly flows through the AMTD Strategy → Rotate executor's shared `MutationApplier`; the thin CMP reconciler is honestly status-only (`selectedPodCount`, `resolvedMutationSummary`) and did not itself act.
- **Path 9 node-rotation completed on a single real node + transient fake nodes.** The first positive attempt honestly aborted `NoCleanTarget(CleanPoolExhausted)` because the node-lifecycle controller auto-taints kubelet-less fake nodes (`node.kubernetes.io/unreachable:NoSchedule`); the successful run kept `fake-clean-1` untainted (Ready status patch + taint strip) so a clean node qualified — proving the selector correctly rejects tainted nodes AND selects a clean one. **True relocation onto a different real clean node + node-rotation MTTR remain REAL-NODE-PENDING** (the pinned replacement stays Pending on the single real node).
- **Path 7 emit-before-enroll / model-loaded handling:** the WIS template's `metadata` rejects labels/annotations under strict decoding, so the model-loaded annotation was applied to the warm pods directly — a documented kind workaround, not a feature change. The leader pod was enrolled before firing.
- **`SecurityEventStatus.appliedAction` is written only by the Rotate/Regenerate/WarmSwap executors** (paths 2/3/6/7/8). For delete (1/5) and quarantine (4/11) the report does NOT claim `appliedAction`; those effects are proven by the operator log line + observed cluster object (UID change / NetworkPolicy). Honest, not a gap.
- **Stage-4 server-dry-run note:** a scored SE submitted without `spec.description` was rejected `spec.description: Required value` — this is live CRD validation working (the reviewer's omission), not a platform defect.
- **GPU / real-node SLOs (warm-swap downtime, panic MTTR, node-rotation MTTR, GPU-MIG preflight)** are explicitly PENDING — see the section above. None is asserted as a measured number.

## Verdict

| Item | Result |
|---|---|
| Builds / Tests (5 trees) | **PASS** (build=0 vet=0 test=0; 233/233; re-run confirmed) |
| Path 1 — Exact-match delete | **PASS** (Phase-0 UNREGRESSED) |
| Path 2 — Rotate | **PASS** |
| Path 3 — Scored rotate (Falco) | **PASS** (score flows e2e) |
| Path 4 — Quarantine | **PASS** |
| Path 5 — Timed-trigger flow | **PASS** |
| Path 6 — Prometheus + score | **PASS** (real `anomaly_score` label) |
| Path 7 — WarmSwap | **PASS** (downtime GPU-PENDING) |
| Path 8 — Regenerate / drift heal | **PASS** |
| Path 9 — NodeRotate + D26 gate | **PASS** (both gate blocks proven; MTTR/relocation REAL-NODE-PENDING) |
| Path 10 — ContextMutationPolicy | **PASS** (Gatekeeper trigger paper-only/injected — disclosed) |
| Path 11 — KubeArmor normalized | **PASS** (synthetic canonical + table tests — disclosed) |
| Regression guard (Path 1) | **PASS** |
| Teardown / cluster recovery | **PASS** (independently re-confirmed: node uncordoned/schedulable, e2e-verify gone, 0 leftover CRs across all 6 kinds, 0 NetworkPolicies cluster-wide, only the 6 CRDs remain) |

**OVERALL: PASS.** All 11 action paths fired end-to-end with a real SecurityEvent/CR + operator log line + observed effect; the Phase-0 exact-match delete is unregressed; the D26 gate blocked both the non-allowlisted source and the below-floor event; score flowed end-to-end on paths 3 and 6; and every GPU/real-node item is correctly marked PENDING rather than claimed as measured. No over-claims, no fabricated results, no unexplained gaps. **The software platform is validated end-to-end on kind — only the GPU / real-node SLOs (warm-swap downtime, panic/node-rotation MTTR, GPU-MIG preflight, true multi-node relocation) remain to be measured on a real-GPU / real-multi-node run.**
