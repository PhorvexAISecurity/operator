Workstream input. The architecture docx (Rev 4) is the source of truth.

# WS-1 — Plug-and-play scan & dynamic roster sizing

**Workstream:** WS-1 (scan surface → verification-loop roster sizing)
**Mode:** READ-ONLY design. No production code touched.
**Scan boundary under design:** "PX-SCAN-01" — the task's name for the recon/inventory
boundary. The literal string does not appear in the repo `[UNVERIFIED]`; it is mapped
here to the real boundary formed by `currentinventory` + `currentobserver` (protected-asset
observation), `epssfeed` (cluster image inventory + Trivy + EPSS), `exposure` (per-variable
clocks), and `recon` (fact/cover universe over the assembled `model.WorkloadView`).

Every claim is tagged `[CODE-CITED file:line]` (literal in code; where the tag is bare, the
`file:line` is given inline or in the adjacent table column), `[DOC-CITED]` (a doc, report,
markdown file or paper), `[INFERRED]` (derived from cited code, logic mine), or `[UNVERIFIED]`
(asserted, not yet grounded). Paths are relative to `phorvex/internal/`.

Numeric parameters in this workstream (generator fan-out, `w_v`, `λ`, `R_floor`) are
**configurable parameters (docx §14, P1)** read from policy/config at run time with a safe
default and logged with the verdict — not hardcoded and not routed to any external owner.

---

## (a) What the scan actually yields (grounded)

The scan is not one call; it is three cooperating producers whose outputs are assembled into
one `model.WorkloadView` per pod per tick (`recon/profile.go:18`, `model/types.go:1105`
`WorkloadView`). The discoverable dimensions, each with its code anchor:

| # | Discovered dimension | Where it comes from | Tag |
|---|---|---|---|
| 1 | **Pods** (`ObservedPods`) | `epssfeed/sync.go:57,239`; one `WorkloadView` per pod | `[CODE-CITED]` |
| 2 | **Running containers** (`RunningContainers`) | `epssfeed/sync.go:58,240` | `[CODE-CITED]` |
| 3 | **Unique images** (`UniqueImages = len(inv.targets)`) | `epssfeed/sync.go:59,241`; image-rarity key | `[CODE-CITED]` |
| 4 | **EPSS/CVSS pairs** per image digest | `epssfeed/feed.go:212` `Build`; `model/types.go:1042` `EPSSMultiplier` | `[CODE-CITED]` |
| 5 | **Models** (served `ModelID`) | `model/types.go:506`; `ModelRarity` `model/types.go:1088` | `[CODE-CITED]` |
| 6 | **Endpoints / routes** | `model/types.go:546-548` `ServingEndpointReady`/`RouteService`; `:507` `EndpointPath` | `[CODE-CITED]` |
| 7 | **RBAC / identity** | `model/types.go:460-461` `ServiceAccount`/`PodBoundKubeAPIAuth`; `:457` `MountedSecrets`; gate `:556` | `[CODE-CITED]` |
| 8 | **GPU / MIG** | `model/types.go:474-475` `HasGPU`/`MIGDevice`; DCGM `PhysicsWitness.GPUPresent` `:1083` | `[CODE-CITED]` |
| 9 | **Lateral edges / blast** | `recon/profile.go:136-143`; `model/types.go:1114-1116` `Neighbors`/`NeighborCount`/`BlastRadius` | `[CODE-CITED]` |
| 10 | **Nodes + co-residency** | `model/types.go:454` `Node`; `:1039` `CoResidency` | `[CODE-CITED]` |
| 11 | **Named attack-vector observations** (per pod) | `recon/ucw.go:138-253` (`AttackVectorKV`, `…Adapter`, `…VoiceMemory`, `…EndpointLeaseReuse`, …) | `[CODE-CITED]` |
| 12 | **Stable workload owner** (the "app" unit) | `currentinventory/contract.go:47` `StableWorkloadOwner`; resolved `currentobserver/observer.go:76,133` | `[CODE-CITED]` |

From these, the scan produces two derived universes the roster must mirror:

- **The fact-universe (the "assets"/kill-chain-stage surface).** Per pod, `ucwRecon`
  mints a weighted `Fact` set: the always-present in-pod/network facts (`podIdentity`,
  `session`, `inMemory`, `networkIdentity`, one `lateralEdge` per neighbor) plus
  AI/inference facts conditioned on the discovered dimensions — `modelFingerprint` only if
  `HasModelDeclaration`, GPU co-location/contention only if `HasGPU`, serving facts only
  if `HasServingDeclaration`, and one named-vector fact per observed `AttackVector*`
  (`recon/ucw.go:99-263`, kinds in `recon/facts.go:36-151`). `[CODE-CITED]`
- **The cover-universe (the actuator surface).** Per fact, the profile records which
  actions *deterministically invalidate* it (`CoverByAction`, `recon/facts.go:194-197`).
  Crucially, cover is granted **only where an actuator can prove the effect**: audit-only
  facts (`modelFingerprint`, `endpointPath`, `guardrailBypass`) and all Tier-2/Tier-3
  facts carry **no cover** (`recon/facts.go:63-69,134-150`; proven by
  `recon/taxonomy_test.go:69-107`). `[CODE-CITED]`

**Kill-chain stages discovered/attributed:** 9 total — 5 generic (`recon`, `exploit`,
`persist`, `lateral`, `impact`) + 4 AI (`gpu-side-channel`, `model-theft`, `llm-jacking`,
`prompt-inject-persist`) (`killchain/hazard.go:19-36`). The AI stages are **honest-absent**:
`aiStageFromView` returns `false` when `ModelID=="" && !HasGPU`, so a non-AI app only exposes
the 5 generic stages (`killchain/hazard.go:~300`). GPU-side-channel/model-theft require a GPU
witness; llm-jacking/prompt-inject require a serving/model witness (same function). `[CODE-CITED]`

**Autonomously-selectable actuators:** `MutatingActions` lists 23 actions
(`model/types.go:159-174`), but the roster-relevant set is the **cover-granting** subset.
Enumerating the grants in `recon/profile.go:57-145` + `recon/ucw.go:99-263` yields **17**
cover-granting actuators (rotate, quarantine, warm-swap, model-shard-replace, kv-reset,
mig-rebind, request-drain, adapter-rotate, kv-migrate-invalidate, sensitive-output-policy-activate,
and 7 voice/litellm/endpoint-lease actuators). `identity-rotate` is declared-only
(`model/types.go:68-72`); `debugger`/`custom-inject` are manual-by-design with no cover
(`model/types.go:59-66`); `noop`/`disable`/`route-rotate`/`endpoint-rotate`/`guardrail-rotate`
carry no cover. With a **nil policy the default is only `rotate`+`quarantine`**
(`model/types.go` `ActionEnabled`), so the baseline cluster floors at 2 actuators. `[INFERRED]`

---

## (b) Sizing formula: scan facts → roster

**App unit.** Let `Apps` = the set of distinct `StableWorkloadOwner`s observed in the scan
(`currentinventory/contract.go:47`; `currentobserver/observer.go:76`). An app `a` is
characterized by the discovered dimensions of its pods: `isAI(a)` (any pod with
`ModelID≠"" || HasGPU`), `serving(a)`, `gpu(a)`, and `V(a)` = the set of distinct named
`AttackVector*` observations on its pods. `[INFERRED from CODE-CITED fields]`

**Per-app applicable stage set** `S(a)` (how many kill-chain stages the scan actually
unlocks for `a`), from `killchain/hazard.go:19-36` + `aiStageFromView` gating:

```
|S(a)| = 5                                   (generic chain, always)
       + 2·[gpu(a)]                          (gpu-side-channel, model-theft)
       + (1 if serving(a) else 0)            (llm-jacking)
       + (1 if (serving(a) || isAI(a)) else 0)  (prompt-inject-persist)
```
so `|S(a)| ∈ [5, 9]`. `[INFERRED]`

**Per-app cover-granting actuator set** `K(a)` = the set of actions with a non-empty
`CoverByAction` entry for `a`'s archetype (evaluated exactly as `recon` does per
`model.WorkloadView`). `|K(a)| ∈ [2, 17]`: 2 on a bare web pod (rotate+quarantine default),
up to ~8–10 on a rich GPU/serving/voice pod. `[INFERRED from recon/profile.go, recon/ucw.go]`

### Generator roster (attack-generator agents) — per stage × per app

```
G = Σ_{a ∈ Apps}  ( |S(a)|  +  w_v · |V(a)| )
```

- `|S(a)|` is the **per-kill-chain-stage × per-discovered-app** term the task asks for:
  one generator seat per stage the scan proves is reachable for that app.
- `w_v · |V(a)|` adds generator seats for **live, named attack vectors** observed on the
  app, because those facts are weighted `×3` (`vectorDominance`, `recon/ucw.go:363`) — the
  scan says the attacker is actively there, so the generator loop must exercise them harder.
  `w_v` is a configurable parameter (docx §14, P1; see §d). `[INFERRED]`

### Validator roster (actuator-validator agents) — per actuator × per app

```
Val = Σ_{a ∈ Apps}  |K(a)|
```

One validator seat per (cover-granting actuator, app-archetype): each verifies that the
actuator actually invalidates every fact key it claims in `CoverByAction`, with the
deterministic brain as referee comparing claimed vs. observed invalidation. Audit-only and
Tier-2/3 facts generate **zero** validator seats (no actuator proves them —
`recon/facts.go:63-69,134-150`), which is the single largest natural cap on `Val`. `[INFERRED]`


### Design roster (actuator-design agents) — only on CANNOT-HELP (docx §3.4, §7.3)

```
Des = Σ_{CANNOT-HELP attacks}  |enforcement-levels the attack spans|
R   = G + Val + Des
```

Design agents are instantiated **only when the competition reaches CANNOT-HELP** for a confirmed
attack: one proposer per enforcement level the attack spans (network/dataplane, K8s, AI/GPU,
credential, process, artifact), with critics drawn from the validator personas. A cluster with no
CANNOT-HELP spawns **zero** design agents; a large cluster spawns them only where an attack is
genuinely uncontained. The envelope stays tens (small) to low hundreds (large), derived from the
scan, never a fixed count. `[DOC-CITED docx §3.4, §7.3]`

### Total and min/max envelope

```
R = G + Val
```

- **Floor (`R_floor`).** Smallest honest cluster = 1 app, no AI, nil policy:
  `G = 5` (generic stages), `Val = 2` (rotate+quarantine) ⇒ **`R_floor = 7`**. A
  dimension absent from the scan contributes **0** seats (honest-absent, mirroring the
  `=1.0`/omit-not-zero discipline in `recon/ucw.go:24-27` and `epssfeed/feed.go:13-24`). `[INFERRED]`
- **Structural ceiling.** `G ≤ Σ_a (9 + w_v·|AttackVectors|)` and `Val ≤ Σ_a 17`
  (`model/types.go:159-174`). For a small cluster (~2–4 apps, mostly generic) this lands in
  the **tens**; for a large cluster (~30–60 apps, many AI) it lands in the **low hundreds** —
  derived from `|Apps|`, `|S(a)|`, `|K(a)|`, never a fixed 500/1000. `[INFERRED]`
- **Safety cap (defense-in-depth, not the primary sizer).**
  `R ≤ λ · (ObservedPods + UniqueImages)` using the scan's own counts
  (`epssfeed/sync.go:57,59`) to bound pathological blowup; `λ` is a configurable parameter
  (docx §14, P1). `[INFERRED]`

**Worked envelope** `[INFERRED]`:
- *Small:* 3 apps, all generic ⇒ `G = 3·5 = 15`, `Val = 3·2 = 6`, `R ≈ 21`.
- *Large:* 40 apps, 20 AI-serving-GPU (`|S|≈9`, `|K|≈9`) + 20 generic (`|S|=5`, `|K|=2`):
  `G ≈ 20·9 + 20·5 = 280` before `w_v`, `Val ≈ 20·9 + 20·2 = 220` → capped by
  `λ·(ObservedPods+UniqueImages)` into the **low hundreds**. Tens → low hundreds, as required.

---

## (c) Efficiency budget & early-stop rule

**Dynamic count.** The roster is recomputed every scan epoch from the live
`Result`+`WorkloadView`; nothing is pre-provisioned. The scan emits before/after digests
(`ScopeSHA256`, `CacheSHA256`, `MetadataSHA256` — `epssfeed/sync.go` `Result`) so the
orchestrator resizes only when a digest changes. `[CODE-CITED]`

**Early-stop rule (three independent short-circuits):**

1. **Absent-asset short-circuit (hard).** A pod whose facts are *absent* — any non-finite
   input to the weight path, or a non-finite physics multiplier — mints **no facts**
   (`recon/profile.go:43,187-204`; `recon/ucw.go:72-74`; `recon/finite.go:12`), so it fields
   **0 generators and 0 validators**. `[CODE-CITED]`
2. **No-cover short-circuit (hard).** Any fact with no cover-granting actuator (audit-only,
   Tier-2, Tier-3) is excluded from `Val` by construction — the brain never spins a validator
   for an effect no actuator can prove (`recon/facts.go:63-69,134-150`;
   `recon/taxonomy_test.go:69-107`). `[CODE-CITED]`
3. **Marginal-gain stop (soft).** Generators for a given (stage, app) are dispatched in
   **descending fact EMR weight** (`recon/ucw.go:21-27`) and halted once the marginal
   facts-invalidated-per-dollar falls below the objective's cost penalty — the same
   `−λ·C(S)` term the selection objective carries (`recon/ucw.go:40-48`). (This `λ` is the
   objective's own cost coefficient, distinct from the roster safety-cap `λ` of §b / docx §14
   P1.) `[INFERRED]`

**Termination of the competition** is separate from these scan-side stops: the round loop is
bounded by the configurable max-rounds budget (docx §3.2, §14 P2). `[DOC-CITED docx §3.2]`

**Caching.**
- *EPSS/physics cache:* the EPSS cache is byte-stable — `Marshal` sorts keys so an unchanged
  fleet yields a byte-identical ConfigMap and is not rewritten (`epssfeed/feed.go:235-267`);
  the roster reuses last-epoch physics when the digest is unchanged. `[CODE-CITED]`
- *Validator-result cache keyed by archetype:* validator outcomes are keyed by
  `(actuator, archetype, image-digest, cover-key-set)` and reused across epochs until the
  key changes. The distinct archetypes are already enumerated by the cover-invariant probe
  set (generic / stateful / model / gpu+MIG / api-token, `recon/cover_invariant.go:53-85`),
  so validators run **once per archetype, not once per pod** — the dominant cost saving on a
  large homogeneous fleet. `[INFERRED]`
- *Exposure-clock reuse:* per-variable "time since last change" is already cached across ticks
  and restart-safe (`exposure/clock.go:5-16,61-103`), so generators need not re-probe an
  unchanged variable. `[CODE-CITED]`

---

## (d) Configurable parameters (docx §14) — NOT asserted here

Numeric thresholds are **configurable parameters (docx §14)** read from policy/config at run
time — not hardcoded, and not routed to any external owner. Each ships with a safe default and
is logged with the verdict. The WS-1 numbers fall under docx §14 **P1** (roster sizing:
generator fan-out per (stage,app), vector-boost `w_v`, safety-cap `λ`, `R_floor`). The
implementer wires the formula and reads these values from config, not from this document:

1. **Per-(stage,app) generator fan-out** and the **vector-boost weight `w_v`** — configurable
   (P1). Tied to `vectorDominance = 3.0` (`recon/ucw.go:363`). Whether 1 seat per stage is
   statistically sufficient to exercise the heavy-tailed fact-weight distribution is not
   asserted here. `[UNVERIFIED]`
2. **Marginal-gain stop threshold** and whether stopping preserves any optimality guarantee. The
   code **explicitly retracts** the `1−1/e` and Fisher–Nemhauser–Wolsey `1/2` bounds and
   states *"No replacement approximation constant is claimed here without a proof tied to the
   implemented selection rule"* (`recon/ucw.go:40-48`). Consistent with the docx (§13,
   optimization-theorist verdict), **no roster near-optimality may be claimed without a fresh
   proof**; none is claimed here. `[CODE-CITED recon/ucw.go:40-48]`
3. **Global safety-cap coefficient `λ`** in `R ≤ λ·(ObservedPods+UniqueImages)`, and the
   **floor `R_floor`** — configurable (P1). Whether "tens for small, low hundreds for large"
   holds across the real fleet-size distribution is not asserted beyond the worked envelope.
   `[UNVERIFIED]`
4. **Stage multiplicity weighting.** Whether `|S(a)|` should be a flat count or weighted:
   the AI stages have a *non-linear* successor map (`model/types.go` `aiNextStage`), so stage
   count ≠ linear chain depth and a naive sum may over- or under-seat AI apps. Left open; the
   docx (§4.2) uses the flat count. `[CODE-CITED structure: model/types.go aiNextStage]`
5. **Dispersion-cap interaction.** `MaxDispersionMult = 4.0` (`recon/ucw.go:55`) makes weights
   heavy-tailed; whether generators should be seated by **EMR mass** rather than uniformly per
   stage (concentrating seats on the few dominant facts) is an open measurement question, not
   asserted here. `[CODE-CITED structure: recon/ucw.go:55]`

---

## Open questions

**None for the implementer.** The structural derivation (app unit, `S(a)`, `K(a)`, `G`, `Val`,
`R`, the three early-stops, the three caches) is fully grounded in cited code. Every remaining
*numeric* value is a configurable parameter (docx §14, P1) per §d, which is the intended
mechanism for "derived, not asserted." The one unverifiable string is cosmetic: "PX-SCAN-01"
is the task's label for the `currentinventory`+`currentobserver`+`epssfeed`+`recon` boundary
and does not need to exist in code for the formula to bind.
