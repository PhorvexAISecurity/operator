# Round 1 — precondition evidence (PC-1 … PC-9)

All commands run 2026-08-25 ~14:10–14:35 UTC from the jump host against the shared test cluster.
**Deployed build at collection time: `phorvex:0.4.50` (brain + console).** This is SEVEN releases newer than the register's currency banner (0.4.43) — see PC-5.

---

## PC-1 — deployed image tag + git SHA — ✅ RECORDED

```
$ kubectl get deploy phorvex-phorvex -n phorvex-system -o jsonpath='{.spec.template.spec.containers[*].image}'
753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:0.4.50 753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex-console:0.4.50
```

Git (local repo, fetched 2026-08-25): `v0.4.50` tag = release commit `b163c69` ("release: v0.4.50 [skip ci]"), `origin/main` HEAD = `b163c69`.

**Surprise:** the cluster was upgraded 0.4.43 → 0.4.50 between the campaign design and Round 1 (releases v0.4.44…v0.4.50, 23+ commits, 38 non-test Go files). Rule 1 fired on the very first precondition. Full window diff in `pc-5-gating-screen.md`.

## PC-2 — CRD enum accepts all 16 actions — ❌ FAIL (M-2 persists at 0.4.50, LIVE-verified)

Server-dry-run apply of a policy enabling `adapter-rotate` (no state persisted):

```
$ kubectl apply --dry-run=server -f pc2-policy.yaml
The PhorvexPolicy "pc2-probe" is invalid:
* spec.actions.enabled[0]: Unsupported value: "adapter-rotate": supported values: "rotate", "quarantine", "noop", "debugger", "custom-inject", "identity-rotate", "route-rotate", "warm-swap", "mig-rebind", "kv-reset", "endpoint-rotate", "model-shard-replace"
* spec.assetValue: Required value
```

Installed CRD enum = 12 values. Missing: `adapter-rotate`, `request-drain`, `guardrail-rotate`, `kv-migrate-invalidate`, `disable`.
Cross-check at repo tag v0.4.50: the kubebuilder marker in `api/v1alpha1/phorvexpolicy_types.go` lists the same 12 — marker and CRD agree with each other and both omit the five. §10 matrix rows for those five stay ⛔.

## PC-3 — actuator SA can perform the writes its handlers need — ◐ CHANGED at 0.4.50 (deviation no longer in force)

Brain SA: `phorvex-phorvex-manager`. Effective cluster-wide rules (`phorvex-phorvex-manager-role`):

```
[''] ['pods','namespaces','nodes','services','configmaps'] ['get','list','watch']        # NO pods delete
[''] ['events'] ['create','patch']
['networking.k8s.io'] ['networkpolicies'] ['get','list','watch']                        # NO netpol CUD
['rbac.authorization.k8s.io'] ['roles','clusterroles','rolebindings','clusterrolebindings'] ['get','list','watch']
['amtd.r6security.com'] ['securityevents'] ['get','list','watch','create','update','patch','delete']
[''] ['pods/log'] ['get']
[''] ['pods/exec'] ['create']                                                            # cluster-wide, console debugger path
['amtd.r6security.com'] ['adaptivemovingtargetdefenses'] ['get','list','watch','create','update','patch']
['phorvex.ai'] ['phorvexpolicies'] ['get','list','watch','update','patch'] + /status + /finalizers
```

A `phorvex-actuation` ClusterRole (pods delete/update/patch, pods/ephemeralcontainers create, netpol CUD, services update) exists and is bound ONLY namespace-scoped:

```
RoleBinding litellm/phorvex-actuation -> SA phorvex-phorvex-manager (phorvex-system)
RoleBinding vllm/phorvex-actuation    -> SA phorvex-phorvex-manager (phorvex-system)
```

**Verdict:** the audit-era hand-applied cluster-wide grant is GONE. Actuation writes are now per-namespace RoleBindings (presumably EnsurePolicy-created — note they exist only in `litellm` and `vllm`, NOT in `nats`/`voice` which also have policies — consistent with M-135's actuation-path-only EnsurePolicy). k8s-native writes (rotate, quarantine) flow via AMTD → Phoenix. Residuals for the register: (a) unbound `phorvex-actuation` ClusterRole still exists as a latent grant; (b) cluster-wide `pods/exec create` remains on the brain SA; (c) bindings lag in namespaces without selections yet (M-135 shape persists).

**Campaign consequence:** in arm namespaces, direct-write actuators need the per-namespace binding, which appears on the first actuation-path EnsurePolicy — or fails observably (itself evidence, labelled M-135-class).

## PC-4 — actuator backend — ✅ RECORDED

```
PHORVEX_ACTUATOR = hybrid
```

## PC-5 — register re-screened against deployed build — ◐ PARTIAL (gating entries screened; full 38-file re-screen OWED)

The register's currency banner says 0.4.43; the cluster runs 0.4.50. Window: `git diff v0.4.43..v0.4.50` — 38 non-test Go files incl. decision core (`coverage.go`, `optimality.go`, `ablation.go`), cost model (`p1cost.go`, `rls.go`, `conformal.go`, `switching.go` — PR "feat/phorvexsec-91-cost-model"), `killchain/hazard.go`, NEW package `internal/pendinggate` (phorvexsec-83), recon cover taxonomy (phorvexsec-125), console "per-app attack launcher with actuator verdicts" (PRs #72/#73 — possible Phase-C harness!), CRD yaml.

Gating spot-screen at v0.4.50 (details in `pc-5-gating-screen.md`):

| Entry | Verdict at 0.4.50 |
|---|---|
| M-2 (CRD enum) | **PERSISTS** — marker and installed CRD both list 12 (PC-2 live-verified) |
| M-22 (maxMovesPerTick 0→3) | **PERSISTS, and got worse** — new `EffectiveMaxMovesPerTick()` (defaults.go:95) comment says "preserve an explicit 0 only when the field was deliberately set", then `if == 0 { return defaultMaxMovesPerTick }`. The comment claims the fix; the code keeps the bug. `manager.go:1126` uses it. Field is `int` with `+kubebuilder:default=3`, so explicit-0 reaches the function and becomes 3. Textbook "green-but-wrong fix" — PHVX-115/PR#70 touched this exact function |
| M-140 (tenant-state resurrection) | **PERSISTS** — `Manager.Remove` still prunes metrics only, byte-identical to 0.4.39/0.4.43 |

**Owed:** full re-screen of the register against 0.4.50 (new pendinggate package + cover-taxonomy rework change the measurement surface H2/H8 observe). Recommend as its own work item before Phase B/C interpretations.

## PC-6 — detectors deployed — ✅ RECORDED (two, vllm namespace only)

```
vllm  detector-adapter-inv-6f8b4cd85f-lhls4  1/1 Running (restarted 5h before collection)
vllm  detector-kv-canary-9f98c66b5-9srrg     1/1 Running (up 4d20h)
```

Both watch the `vllm` namespace only. Arms have NO detector coverage → per §9.1 `detection stage` rule, arm-C events will be hand-fired and Detected = N/A.

**Important for H1:** the adapter-inventory detector continuously marks the vllm pod suspect (`SuspectAdapter != ""` satisfies the reactiveOnly backing check in coverage.go). Arm A has no such marker — so arm A is the natural control that distinguishes *detector-sustained* churn from *endogenous* churn. This refines H1's interpretation, not its procedure.

## PC-7 — pressure types independently controllable — ◐ PARTIAL: request YES per-app, GPU indirect, CPU/memory NO

loadgen env (deployment `loadgen` in `phorvex-loadgen`):

```
LOADGEN_APPS = crm,voice,vllm,litellm,mcp,chroma
LOADGEN_RATE_SCALE = 1.0
CRM_SPM=6  VOICE_CPM=1.2  VLLM_SPM=4  LITELLM_SPM=3  MCP_SPM=2.5  CHROMA_SPM=5
DIURNAL=1  ENABLE_WRITES=1  WRITES_PER_MIN=2
```

- **H7a (request pressure):** controllable per-app via *_SPM/*_CPM env + RATE_SCALE. ✅
- **H7b (CPU/memory):** NO primitive exists (no stress-ng or equivalent). ⛔ NOT TESTED unless a pressure source is added.
- **H7c (GPU):** only indirectly, via vllm request load (prompt/token mix). Not independent of request rate. ◐ report as coupled, not independent.

## PC-8 — node inventory / can each arm get its own GPU node — ❌ IMPOSSIBLE on this cluster

```
NAME                          GPU    INSTANCE
ip-172-27-11-122              -      c5.xlarge
ip-172-27-11-153              -      t3.medium  (CriticalAddonsOnly)
ip-172-27-11-28               -      t3.medium  (CriticalAddonsOnly)
ip-172-27-12-134              -      t3.medium  (CriticalAddonsOnly)
ip-172-27-12-137              true   g4dn.xlarge  (taint nvidia.com/gpu)
ip-172-27-12-51               -      t3.medium  (CriticalAddonsOnly)
```

- **Exactly ONE GPU node.** All arm GPU pods would co-reside with the production vllm pod on it — and per M-26 that manufactures the H2 condition.
- GPU VRAM is ~97% consumed by the production vllm pod (~15GB of 15.4GB on the T4) — a second serving-model pod cannot even schedule.
- Four t3.medium nodes carry `CriticalAddonsOnly` taints; usable capacity for arms: the c5.xlarge + toleration overrides.

**Placement decision forced:** no per-arm GPU nodes exist. Arm A (Round 1) runs 2 CPU nginx pods on the c5 node. **H2 cannot be exercised on arm A at all** — it must be measured on the production `vllm` tenant (which already has co-residency: vllm pod + 2 detector pods share the GPU node = co-residency 3, open anti-decoy gate per M-26). Recommend re-scoping H2's arm from A to the production vllm tenant as a *reference arm*; record the deviation per rule 7.

## PC-9 — load source targets arm pods — ❌ FAIL as deployed; retargetable cheaply

loadgen is a single env-driven Python script (`/app/loadgen.py` in a generic python:3.11-slim image; full boot command in evidence). Targets are pure env (`VLLM_URL` etc.), so a **second loadgen Deployment per arm** with arm-scoped URLs delivers request pressure into arm services — no code change needed. Requires arm services to exist (arm B needs at minimum a served-model service to point at).

**Status:** FAIL as-is (the deployed instance cannot see arm namespaces), but the retarget path is trivial: clone deployment, override env. Blocked on the arm-workload decision (PC-8 consequence): with no GPU capacity, what serves inference in arm B? Options: (a) CPU-vLLM with a tiny model (heavy image pull, slow but real reset endpoint), (b) request pressure against arm HTTP services only (no serving-model shape — H7a measurable, H7c not), (c) point arm-B loadgen's VLLM_URL at… nothing — invalid. **This is the open design question Claude's H7 measurement design is waiting on; answering it needs Claude + human, not just K3.**

---

## New apparatus in the 0.4.43→0.4.50 window worth the campaign's attention

- `internal/pendinggate` (phorvexsec-83): a new gate stage — decision pipeline now has a pending-rotation gate whose metrics exist (`calib` readydelay work earlier). Watch it in the tick logs.
- Scoped cover taxonomy (phorvexsec-125, `recon/`): changes fact-key shapes — §8 capture of "cover keys claimed" will observe the new format.
- Console per-app attack launcher **with actuator verdicts** (`console/attack_compat.go`, `runs.go`, `effectiveness.go`): the team's own attack surface now tracks verdicts — evaluate as the Phase-C attack-agent harness before building anything new.
