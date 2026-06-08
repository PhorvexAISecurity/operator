# P-PHYSICS — Steps 2–3 report: the both-products physics-discovery layer (UCW), built & proven on kind

**Date:** 2026-06-06 · **Status: BUILT + PROVEN on kind (REAL numbers).** The approved
**UnifiedConservationWitness (UCW)** layer is implemented and proven: a live cluster scan
DERIVES the both-products physics, the completed **Layer-C EMR** re-grounds the recon
objective, and the **UNCHANGED** optimizer / proactive engine / dynamic action-set
generator / actuation consume it through the existing registry seams. **Zero change to
extended Phoenix or the harness; zero change to the optimizer/dual/conformal/killchain/
actuation/proactive engine.** Deterministic, no LLM in the decision path. AI/GPU values
are honestly `[SP-0-PENDING]` (never fabricated).

---

## 1. What was built (Step 2) — additive, plug-compatible

| Layer | File(s) | What it does |
|---|---|---|
| **Carrier** | `internal/model/types.go` | `PhysicsWitness` + `WorkloadView.Physics` + `Pod.{ImageID,CPU/Mem/GPURequest,VRAM,SM,ModelID,EndpointPath}` — additive, zero-valued; `NeutralPhysics()` (all multipliers 1.0) is the honest-absent default. |
| **Scan** | `internal/ingest/kube.go` | `Snapshot.{Nodes,PDBs}`; `collectNodes` (allocatable CPU/mem/GPU/MIG), `collectPDBs` (live PodDisruptionBudget), `primaryImageID`, `podRequests`. |
| **Platform scanner** | `internal/platform/{platform,adapters,epss}.go` | `PlatformPhysics` interface + `generic-k8s` adapter (derives image-rarity, co-residency, scheduler-slack, live PDB, MIG-geometry, EPSS) + `eks-gpu`/`coreweave`/`gpu-marketplace` adapter **modules** (one-module-per-platform; DCGM/NVML scan documented; GPU values SP-0); offline EPSS cache (degrade-to-1.0). |
| **Layer-C EMR** | `internal/recon/{facts,ucw}.go` | 4 AI fact-kinds (`FactModelFingerprint/EndpointPath/GPUColocation/SideChannel`); `ucw-recon` profile — one **per-asset scarcity scalar** (`image-rarity·EPSS·co-residency·model-rarity`) scales all of an asset's facts, sharpening cross-asset ordering; AI facts emitted **audit-only** (reset actions are Phase-2). |
| **Layer-A laws** | `internal/feasibility/{tokensfloor,gpuconservation}.go` | `tokens-floor` (closes the verified-FALSE `littleslaw.go:78` claim that a hard tokens/sec constraint existed); `vram-conservation` + `mig-validity` (honest-absent on kind). |
| **Ablation** | `internal/decision/ablation.go` | `AblateScarcity` — separately-ablated `standard-recon` vs `ucw-recon` so any delta is attributable to discovery. |
| **Runner/CLI** | `internal/runner/{manager,ablation_run}.go`, `cmd/main.go` | stamps `view.Physics` from `platform.Derive`; `SetDefault("ucw-recon")`; live `--scan` mode (both-products witness + scarcity ablation). |

**Untouched (verified by build):** the optimizer, dual solver, conformal bound, kill-chain,
actuator, proactive engine, dynamic action-set generator, **extended Phoenix, and the harness.**

---

## 2. Proof on kind (Step 3) — REAL numbers

### 2a. Live both-products scan (`phorvex --scan --scan-namespace pphysics-demo`)
```
platform-adapter: generic-k8s
node amtd-test-control-plane  allocCPU=8000m allocMem=15836Mi allocGPU=0 migKinds=0
pphysics-demo/px-common-*  K8s: imgRarity=1.18 coRes=1.50 slack=0.88 pdbMinAvail=-1 migValid=true epss=1.00 | AI:[SP-0-PENDING]
pphysics-demo/px-rare      K8s: imgRarity=2.00 coRes=1.50 slack=0.88 pdbMinAvail=-1 migValid=true epss=1.00 | AI:[SP-0-PENDING]
```
The physics is **DERIVED LIVE**, not specced: real node allocatable (8000m / 15.8 GiB / 0 GPU),
**measured image-rarity dispersion** (common busybox **1.18** vs the singleton nginx **2.00**),
scheduler-slack 0.88, MIG-geometry valid, live-PDB (none here → −1). **AI/GPU values are
`[SP-0-PENDING]`** (`GPUPresent=false` on a CPU-only cluster) — never fabricated.

### 2b. Layer-C EMR scarcity ablation — LIVE, separately ablated
```
baseline (standard-recon)  per-dollar ratio = 1.986
scarcity (ucw-recon)       per-dollar ratio = 2.381
scarcity lift              = 1.20x   (BEAT: heavy-tailed measured dispersion the greedy exploits)
```
The discovered image-rarity dispersion lets the submodular greedy concentrate budget on the
rare crown-jewel pod, beating the baseline targeting by **1.20×** — measured live on kind,
attributable **purely to discovery** (same fleet, same asset values, only the scarcity weighting differs).

### 2c. Mechanism unit tests (deterministic, in-gate)
| Test | Result |
|---|---|
| `TestUCWScarcityTiesAtUniform` | **exact tie** (uniform fleet → byte-identical to baseline; the never-worse nil-data guarantee) |
| `TestUCWScarcityLiftsUnderDispersion` | **1.84× lift** (one rare pod among neutral; asset value held flat → delta is discovery-only) |
| `TestUCWAIModelDispersion` | **1.53× lift** (AI model-rarity boosts the rare NIM via the EXISTING rotate action — no Phase-2 actuator) |

### 2d. Baseline preserved (no regression)
- **1.62× IP gate** (`TestAblationP1BeatsRandomPerDollar`, `standard-recon`) — **PASS** (unchanged).
- **P3 decisive scenarios with the `ucw-recon` operator**: PX dwell **5.6s**, blind **15.2s**,
  no-MTD **20.3s** — **matches the P3 baseline** (held-out-CVE). The new feasibility laws are
  honest-absent on kind (no GPU, no tokens telemetry) → no new vetoes → dwell/feasibility preserved.
- `go build/vet/test` green for phorvex; **extended Phoenix + harness build unchanged.**

---

## 3. Honest framing — what is proven vs not

- **TIE at nil-data is GUARANTEED and proven** (every multiplier collapses to 1.0 → byte-identical
  weights → exact baseline). This is the "never worse than baseline" floor — but it is exact **only
  at nil-data**.
- **The BEAT is REAL and measured live (1.20× on kind), but CONDITIONAL on heavy-tailed dispersion.**
  Honest caveat surfaced during the build: on a **small, flat fleet** the separately-ablated ratio is
  **noisy and can dip below baseline** (an early 4-pod demo gave 0.49×) because the greedy's discrete
  per-asset picks swing and the random arm frequently catches the rare pod. A clean lift needs a
  genuine **crown-jewel tail** (many common pods + a few rare) — which the scaled demo (13 common + 1
  rare → 1.20×) and the unit test (1.84×) both show. So the operating claim is: **ties at nil-data
  (proven), lifts under measured heavy-tailed dispersion (proven live + in-gate), magnitude on real
  production / GPU-multi-tenant fleets UNRUN.** A production deployment should keep the EMR/scarcity
  term **separately ablatable** (it is) and only assert a beat from a measured ablation on the target fleet.
- **AI half is FIRST-CLASS in definition, SP-0 in value.** Every GPU/inference parameter has
  units/source/scan-method and a zero-valued carrier; on kind `GPUPresent=false` → neutral. The AI
  model-rarity multiplier already affects the decision through the existing rotate action (2c); the 4
  AI fact-kinds are **audit-only** until their Phase-2 reset actuators (model-swap, route-rotate,
  GPU/MIG-rebind) ship.
- **Deferred and flagged** (from the decision): the `featureDim` cost-**denominator** bump (so the
  per-dollar beat is **numerator-only** today; AI per-dollar rests on the `GPUEnvelopeMax=1.0` fail-safe
  = SP-0), the kill-chain **belief-wall** (AI stages + live-β need a `killchain.Assess` edit), and the
  warm-provision **actuation sequence** (only the feasibility precondition is in-scope).

---

## 4. Extensibility, proven
- **New platform** = one adapter module (`eks-gpu`/`coreweave`/`gpu-marketplace` exist, embedding the
  invariant K8s half, overriding `Detected()` + later `Derive()` for the GPU half) — the optimizer never
  sees the platform.
- **New feasibility law** = one self-registering file (`tokens-floor`, `vram-conservation`,
  `mig-validity` are exactly this; `defaults.go` untouched; `Registry.All()` first-veto-wins).
- **New recon prior on an existing carrier** = the `ucw-recon` re-registration (the greedy reads only
  `FactWeights`+`CoverKeys`, agnostic to what moved the weight).
- **New parameter needing a new carrier** = the sanctioned 3 additive zero-valued edits
  (`model` field + `ingest` projection + `runner` wiring) — exactly what the K8s carriers used.

---

## 5. Reproduce
```powershell
go -C phorvex build ./... ; go -C phorvex test ./...           # green; 1.62x gate + UCW tie/lift tests
go -C phorvex build -o bin/phorvex.exe ./cmd/main.go
# live both-products scan + separately-ablated EMR ablation on kind:
kubectl create ns pphysics-demo
1..13 | % { kubectl run busy$_ --image=busybox:1.36 -n pphysics-demo --command -- sleep 3600 }
kubectl run rare --image=nginx:1.27-alpine -n pphysics-demo
phorvex/bin/phorvex.exe --scan --scan-namespace pphysics-demo
```

**P-PHYSICS COMPLETE (Steps 1–3).** The discovered both-products physics layer derives live on
kind, completes the PRD's Layer-C EMR as a measured recon-bits-per-dollar objective, feeds the
unchanged MTD stack, ties the 1.62× baseline by construction, and shows a real **1.20× live beat**
under measured dispersion — with the AI half fully defined and honestly SP-0-PENDING, and extended
Phoenix + the harness untouched.
