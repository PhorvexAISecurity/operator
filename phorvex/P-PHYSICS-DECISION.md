# P-PHYSICS — Step 1 decision: the both-products physics-discovery layer

**Date:** 2026-06-05 · **Status: DECISION FOR APPROVAL — STOP before building (Steps 2–3).**

Replace today's HAND-SPECCED physics with **DISCOVERED, per-platform, multi-parameter
physics for BOTH the K8s and the AI/inference products (co-equal, neither deferred)**,
re-ground context on it, and feed the UNCHANGED optimizer / proactive engine / dynamic
action-set generator / actuation through the existing interfaces. Baseline to beat = the
**full PRD physics** (Layers A/B/C incl. the Layer-C EMR core IP), not the implemented
1.62× subset.

**Method.** A re-scoped multi-agent search (17 agents) with **6 senior-expert personas**
(cloud architecture, GPU/accelerator infra, AI/ML inference & MLOps, physics-informed AI,
DevOps/K8s, offensive-security/red-team): 4 mapped the PRD-vs-implemented gap for both
products; 6 experts contributed fully-quantified parameters; 3 cohesive both-products
candidates (distinct EMR spines) passed an **eligibility gate** (ineligible if K8s-only,
any unquantified feature, or fails to complete+beat the PRD incl. Layer-C EMR) and were
**adversarially scored**; 1 synthesized. Every load-bearing claim was verified against
`phorvex/internal` source. I authored this decision from the structured result; the prior
**K8s-only CapacityWitness** decision (scored 22, "matches floor, beat unproven") is now
**superseded** by this both-products definition.

---

## 1. Candidates (all eligible; all both-products-first-class + fully quantified)

| Candidate (EMR spine) | Total | Beat? | Note |
|---|---:|---|---|
| **UnifiedConservationWitness (UCW)** ✅ | 29/35 | ties (strict beat unrun) | GPU+K8s conservation supply/demand + scarcity-conditioned recon-coverage. Won the tie-break: **fewest residual over-claims under source-checking** — it alone disclosed the ctxprov non-additivity, the featureDim core edit, and the belief-wall crossings, and corrected the seam to byte-safe same-name re-registration. |
| PHORVEX-EMR-Information-Theoretic | 29/35 | ties (strict beat unrun) | Tightest IP: `EMR(S)=Σ P(learned∧holds)·bits(f)·m(f)`, `bits=-log₂(freq)` — the entropy-superset of weighted-fact-coverage (only one to score both-products = 5). Most infra-gated beat. |
| Phorvex Continuity-Witness | 29/35 | ties | Most operationally honest (self-grades "ties", ran `go build` clean). Continuity-of-service as the single quantity grounding cost-denominator + feasibility + EMR-weight. |

**They are the same mechanism from three angles. The recommendation is to MERGE them**, not
pick one in isolation.

---

## 2. RECOMMENDATION — build the merged **UnifiedConservationWitness (UCW)**

Take **UCW's** GPU+K8s conservation-first spine and disclosed-deferral discipline, frame the
IP with **EMR-Information-Theoretic's** `bits(f)=-log₂(freq)` entropy-superset proof, and use
**Continuity-Witness's** continuity-of-service invariant as the single quantity that
simultaneously grounds the cost denominator, the feasibility gate, and the EMR weight.

### 2a. The completed Layer-C EMR (the core IP — for BOTH products)

> **EMR(move) = Σ_f  base(f) · bits(f) · m_dispersion(f)** — the **Expected Reconnaissance
> Invalidated per Move**: the attacker re-acquisition cost a move destroys. `base(f) =
> AssetValue · clamp01(P(hold)) · urgency` is the **existing** `standardRecon` weight
> (`profile.go:36,40`) re-read as a literal expectation (`P(hold)` is already the
> Beta-Bernoulli still-holds posterior). The new factors are **bounded, honest-absent = 1.0**
> multipliers: image/model **rarity** `bits = -log₂(freq)`, per-node/GPU **co-residency**, and
> CVE/**EPSS** exploitability. Maximize **invalidated-recon-bits per defender-dollar**.

Because every new factor is `≥1.0` and collapses to `1.0` at nil-data, the weighted coverage
term stays monotone submodular, while the implemented `coverage − λ·cost` objective remains
non-monotone. The classic monotone/cardinality approximation guarantee does **not** apply under
the truncated partition constraint. These multipliers require **zero optimizer touch**, and at
nil-data the FactWeights are **byte-identical to `standardRecon`** (provable tie). Exactness for
the shipped asset-keyed profiles comes separately from block ownership/modularity; no generic
ratio is claimed for future overlapping profiles. The K8s fact universe is finished (emit `FactImage`/`FactNodePlacement` with measured
dispersion); **4 new AI fact-kinds are DEFINED NOW**: `FactModelFingerprint` (reset by
NIM/model-rotate), `FactEndpointPath` (endpoint/route-rotate), `FactGPUColocation`
(MIG-rebind/node-rotate), `FactSideChannel` (audit-only). Per the **falsifiability gate**, a
fact is selectable iff *(perturbable v)* AND *(an action provably resets v)* AND
*(fingerprintable)* — so `FactSideChannel`/`FactNodePlacement`/`FactImage` stay **audit-only**
until their reset actions ship (they never inflate selectable cover).

### 2b. Both-products physics — measurable-NOW (K8s) vs structure-now/values-SP-0 (AI)

**K8s half — fully measurable on real clusters TODAY (no SP-0):** every value has units/source/scan.

| Parameter | Units | Source / scan |
|---|---|---|
| schedulerSlack | [0,1] | `Σ(allocatable−requests)/Σ(allocatable)` from `NodeList.Status.Allocatable` + request-bucketing by `spec.nodeName` (NodeList **not read today**) |
| livePDB | int minAvailable / disruptionsAllowed | `policy/v1 PodDisruptionBudgetList` (**not read today**) — *adds* a veto via first-veto-wins (does **not** "replace" the static proxy) |
| imageRarity | [1,2] | `1+(-log₂ freq)/log₂N` from `pod.Status.ContainerStatuses[].ImageID` (currently **discarded** by `projectPod`), O(pods) histogram |
| coResidency | count/node | distinct-tenant count by `Spec.NodeName` grouping (live) |
| MIG legal-partition geometry | partition validity | device-plugin resource key `nvidia.com/mig-*` on `Node.Allocatable` — **zero DCGM dependency** (`gpuInfo` already parses the key but discards the quantity) |
| cveEpssExploitability | [1,2] | NVD + FIRST-EPSS cache keyed by image digest — reproducible against **public** data |
| tokensFloor | tok/s vs floor | `Telemetry.TokensPerSec` vs `Policy.MinTokensPerSec` (both already on the structs) — **closes a verified-false claim** (`littleslaw.go:78` asserts this hard constraint exists; no constraint consumes it) |

**AI/inference half — co-equal in STRUCTURE + PARAMETERS now; every VALUE [SP-0-PENDING]:**
each rides a declared zero-valued carrier off the existing `HasGPU`+`MIGDevice` pair, entering
today only as the `GPUEnvelopeMax=1.0` fail-safe (never a measurement).

| Parameter | Units | Source (SP-0) |
|---|---|---|
| VRAM / SM / MIG-validity / interconnect conservation | bytes / fraction / valid / B·s⁻¹ | DCGM/NVML + device-plugin (Present iff GPU-Operator installed) |
| modelColdLoadSec, kvCacheRebuildSec-vs-sessionLengthSec | seconds | SP-0 GPU run → `cost.ObserveRotation` (the **dominant** inference `C_flow`) |
| p99 rotate-vs-warm-swap excursion, $/move | ms, $ | SP-0 |
| FactModelFingerprint / FactEndpointPath / FactGPUColocation weights | recon-bits | model-version rarity + per-GPU co-residency (FactSideChannel = audit-only leakage-bits/s) |
| AI feasibility: vramConservation, smBudget, migValidity, tokensFloor, p99/warm-swap | hard vetoes | structure-now / values-SP-0 |

---

## 3. The PRD-completed-and-beaten map (verified against source)

- **Model#1 (Little's-Law residual)** — `littleslaw.go` **BUILT**. (Optional: finish the unused `LatencyMs`-as-W + `SyscallRate` terms.) No beat needed.
- **Model#2 (spread)** — static blast-radius **BUILT** (`graph/reachability.go`); **live-β DEFINED** (`dI/dt=βSI−γI` from `TargetsPod` events) but **crosses the belief wall → DEFERRED, not claimed**.
- **Layer A (feasibility)** — availability-floor / slo-headroom / anti-over-rotation / stateful-bool **BUILT**; **COMPLETED additively** (each a self-registering `FeasibilityConstraint`, `defaults.go` untouched): **livePDB** (real `policy/v1`), **schedulerSlack + reschedulability** (fixes R6 pain #4 — an un-landable rotate is infeasible), **warmProvisionReady** precondition (sharpens the stateful stub; the actuation *sequence* is a flagged gap), **tokensFloor** (makes the false claim real), **VRAM/SM/MIG-validity/interconnect** (structure-now/SP-0; MIG-validity is enforceable with **zero DCGM** — stronger than the PRD's DCGM-only framing).
- **Layer B (cost)** — switching/RLS/dual/conformal **BUILT**; the measured `C_norm` (the frozen `LiveExposureVariables=2`) + GPU/KV `C_flow` features are the **DEFERRED `featureDim 6→≥9` bump** (a genuine `rls.go` core edit). **Numerator-only** beat claimed now.
- **Layer C (EMR — the core IP, PRD-deferred, only the 1.62× subset shipped)** — **COMPLETED + BEATEN as a definition** for both products (§2a). Beat is **provable-at-the-tie** + a sound-but-**unrun** strict beat under measured dispersion (separately ablatable).
- **Context 5 signals** — CVE/CVSS via a ctxprov provider folding EPSS/CVSS into `AssetValue` (**requires wrapping the default `sensed-context` provider — not a pure drop-in**); kill-chain **BUILT** (AI stages model-theft/LLM-jacking/prompt-injection-persistence/GPU-side-channel **deferred**, need a `killchain.Assess` edit); asset/blast **BUILT** + co-residency prior; exposure **BUILT**; SLO/cost **BUILT** + real tokensFloor + GPU conservation.

---

## 4. Honest baseline assessment — the baseline **TIES**; the strict beat is **unrun**

This is the candid answer the mandate asks for. **No candidate has a provable strict beat yet.**
- **Provable today, in-gate, on kind:** every candidate reproduces **1.62× bit-for-bit** at
  nil/uniform data (neutral-1.0 contract: `freq=1 ⇒ -log₂(1)=0 ⇒ m=1.0`; no scan ⇒ `m_cve=1.0`),
  so FactWeights are byte-identical to `standardRecon` and the CI gate (`Ratio>1.0`,
  `ablation_test.go:49`) passes identically. **Adoption is strictly dominant** — worst case is an
  exact tie, never a regression — and feasibility/harm can only improve (real PDB + slack + GPU
  conservation + tokensFloor vetoes only ADD correct exclusions; honest-neutral defaults never
  veto on absent data, so the **P3 dwell-ordering + infeasible=0/harm=0 are preserved**).
- **Not proven:** the strict **>1.62×** beat. The mechanism is sound (heavy-tailed *measured*
  dispersion lets the submodular greedy concentrate budget on high-surprisal crown-jewel facts
  the uniform-random arm provably cannot exploit; monotone-increasing in dispersion; separately
  ablatable so any delta is attributable to discovery), but it has **never been run**, the
  dispersion that drives it **does not exist on kind** (every GPU/co-residency carrier
  `Present=false` ⇒ exact tie there), and the magnitude is directional only.
- **Defensible Step-1 claim:** *"guaranteed tie now (dominates the baseline, never worse); real
  beat pending one measurement (an EKS/CoreWeave SP-0 multi-tenant ablation with the EMR/scarcity
  term separately ablated)."* Presenting a strict beat as already-proven would be over-claiming.

---

## 5. Honest scope envelope + extensibility

**Zero change to:** the optimizer, dual solver, conformal bound, kill-chain, actuator,
proactive engine, dynamic action-set generator, extended Phoenix, and the harness.
**Bounded additive, zero-valued edits to Phorvex's OWN foundation** (the sanctioned 3-edit
envelope per new carrier: `model` field + `ingest` projection + `runner` wiring): `NodeList`
+ `PDBList` in `CollectSnapshot`, image-digest projection, the declared GPU/inference carrier
fields. New recon prior on an existing carrier = **one file** (re-register `standard-recon`;
the greedy reads only `FactWeights`+`CoverKeys`). New feasibility law = **one self-registering
file** (`Registry.All()` first-veto-wins). New platform (EKS/CoreWeave/GPU-marketplace) = **one
adapter** — three source tiers: (A) **K8s-API-invariant** (slack/PDB/rarity/co-residency/MIG —
LIVE today), (B) **DCGM/NVML-conditional** (VRAM/SM/NVLink — add a Sig query; `DCGM_FI_DEV_GPU_UTIL`
already scraped), (C) **runtime-conditional NIM** (KV/session/cold-load/tokens — `nim_tokens_total`
already scraped). **The one genuine exception (flagged):** a new cost *feature* additionally bumps
`featureDim`+`priorTheta` (`rls.go`) — a bounded core edit, deferred.

---

## 6. Open risks (carried openly)

1. **Beat unproven / data-dependent** — strict >1.62× is sound but UNRUN; an exact tie on a
   homogeneous/kind fleet. Gate any beat claim on the separately-ablated ablation.
2. **Belief wall (hard)** — AI kill-chain stages + live-β need a `killchain.Assess` edit (outside
   the zero-core envelope); AI urgency meanwhile rides only the recon-base/AssetValue multiplier.
3. **Cost-denominator deferred** — the per-dollar beat is **numerator-only** until the `featureDim`
   bump; AI per-dollar rests on the `GPUEnvelopeMax=1.0` fail-safe (SP-0-PENDING).
4. **SP-0 dependency for AI values** — VRAM/SM/bandwidth/cold-load/KV-rebuild/$ enter only as the
   fail-safe ceiling until one real-GPU run feeds `ObserveRotation`; never presented as a measurement.
5. **Actuation gap (hard)** — the warm-provision provision→health-gate→retire *sequence* touches the
   actuator (out of scope); only the feasibility *precondition* is in-scope.
6. **ctxprov non-additivity** — folding CVE/EPSS into `AssetValue` must wrap/swap the default
   `sensed-context` provider (it computes AssetValue itself); not a pure drop-in.
7. **Carrier-field + NFR1 discipline** — `FactContext` is a fixed no-fleet-handle struct, so all
   fleet stats must precompute in the ONE O(pods+nodes) ingest pass (a per-asset recompute breaks
   the <1s/≤1000-pod budget). NodeList+PDBList reads must land in that single pass.
8. **Falsifiability gate** — audit-only facts (`FactSideChannel` etc.) must not inflate selectable cover.

---

## 7. If approved — Step 2 build + Step 3 proof

**Step 2 (build), in order, each a bounded additive change:** (1) the **live-on-kind K8s carriers**
(NodeList + PDBList + image-digest projection + co-residency + MIG-geometry) + the `tokensFloor`
constraint; (2) the **`standard-recon` re-registration** carrying scarcity-conditioned EMR weights
(byte-safe same-name, inherited by `Default()`); (3) the **4 AI fact-kinds + cover-by-AI-action**
(structure-now/values-SP-0) + the GPU-conservation feasibility files; (4) the **`PlatformPhysics`/
`CapacityProbe` interface** + kind adapter, with EKS/CoreWeave/GPU-marketplace adapters scaffolded as
modules (GPU values Present=false). **Defer** the `featureDim` bump and the killchain belief-wall
crossings (AI stages, live-β) — explicitly.

**Step 3 (prove on kind, REAL numbers):** live scan derives **both-products** physics on kind (K8s
values shown; AI/GPU honestly `[SP-0-PENDING]`); physics-DERIVED decision traces; re-run the **IP
ablation with the EMR/scarcity term separately ablated** (ratio with/without) + the **P3 decisive
scenarios** — **match-or-beat** 1.62× + dwell/feasibility, claiming only what is measured (the
in-gate result will be an exact **tie** at 1.62× by construction — reported as such, honestly).

**PASS filters:** go build/vet/test green; live scan derives both-products physics on kind;
context+MTD consume discovered physics; per-platform adapter structure in place; extensibility proven
(one module = one parameter/platform); the PRD-completed-and-beaten map present; ablation + P3 re-run
with real numbers; deterministic, no LLM in the decision path; extended Phoenix + harness build
unchanged; nothing fabricated (SP-0-PENDING kept honest).

---

## 8. Decision

**Build the merged UnifiedConservationWitness (UCW)** — a both-products (K8s + AI/inference,
co-equal) discovered-physics layer that **completes the PRD's Layer-C EMR** as an information-theoretic
recon-bits-per-dollar objective, **completes Layer-A** (livePDB, schedulerSlack, tokensFloor, GPU
conservation), and re-grounds context with the missing CVE/EPSS + rarity + co-residency priors — all
through the existing registry seams with the optimizer/proactive/actuation/Phoenix/harness **untouched**.
Honest headline: **it ties the 1.62× baseline by construction (dominant adoption, never worse) and has
a real, falsifiable, separately-ablatable mechanism to beat it once measured on dispersed/GPU data.**
AI is first-class at the definition level now; its values are honestly SP-0-PENDING.

**>>> STOPPING for your approval before building Step 2/3. <<<**
Approve UCW (merged, as scoped), or tell me to adjust the spine / scope / deferral boundaries first.
