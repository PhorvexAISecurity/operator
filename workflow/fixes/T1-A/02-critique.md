# T1-A — 02-critique (Skeptic: K3)

Base commit: `016361c` (v0.4.72) · Deployed image: `phorvex:0.4.72` (measured live 2026-09-02; cluster moved 0.4.67 → 0.4.72 since yesterday) · Branch: `t1/sensing-separate-residency-activity`

---

## §A — Blind derivation (written and committed BEFORE reading `01-proposal.md`)

### A.0 Disclosure

While grepping for `SMOccupancy`/`VRAMFraction` readers I inadvertently saw that the working tree already contains uncommitted proposer edits: a `T1-A:` comment block at `hazard.go:246`, a new `internal/killchain/leakage_gate_test.go`, and a new `Assessment.Leakage` field. I did **not** read `01-proposal.md` and did not read the diff. Everything below is derived from the **committed** baseline (`git show HEAD:...`), the ticket, R-8, bus 084, the module-graph SENSING→BELIEF row, and live cluster state. The glimpse told me only that the proposer chose the SMOccupancy-only option — one of the two options R-8 itself names — and that a new output field exists (attacked in A.6 either way).

### A.1 The pre-fix gate (committed baseline)

`git show HEAD:phorvex/internal/killchain/hazard.go` (lines 246–255):

```go
leakage := ph.SMOccupancy + ph.VRAMFraction // [0,2]; 0 on kind; PHORVEXSEC-115

// (1) model theft in progress: co-resident GPU reconstructing a rare model.
if p.HasGPU && ph.CoResidency > 1 && ph.ModelRarity > 1.3 && leakage > 0.8 {
	return StageModelTheft, true
}
// (2) GPU side-channel recon primitive: co-resident on a shared GPU, no theft yet.
if p.HasGPU && ph.CoResidency > 1 && ph.ModelRarity > 1 {
	return StageGPUSideChannel, true
}
```

### A.2 The two facts the proposer told me to weigh — and what they actually imply

**Fact 1 — `DCGM_FI_PROF_SM_ACTIVE: 0 series` on our T4 (bus 084, VALIDATION_REPORT:1655).**
`internal/ingest/prometheus.go:91-100` refuses to substitute `GPU_UTIL` for `PROF_SM_ACTIVE`, so on T4 hardware `SMOccupancy` is honest-absent ≡ 0 *forever*. Therefore any fix of the form "leakage := SMOccupancy" makes arm (1) **unfireable on this hardware** — the model-theft stage becomes honest-absent on exactly the fleet that motivated the ticket. That is a defensible outcome (the hardware cannot measure activity, so the stage says nothing), but it must be a *declared* outcome: on T4 fleets the fix converts "always misfires" into "never fires", and there is no in-between.

**Fact 2 — `platform.go:115` keys CoResidency by NAMESPACE; `platform.go:163` makes ModelRarity population-relative.**

(a) `nodeTenants[p.Node][p.Namespace]` counts *namespaces*, and `contributesToFleetPhysics` (`platform.go:84-86`) filters only on `Running` — so **DaemonSet system pods count as co-tenants**. Measured live today: the vllm node hosts 6 namespaces (`amazon-network-flow-monitor, gpu-telemetry, kube-system, litellm, monitoring, vllm`) → `CoResidency = 1 + clamp01(5/4) = 2.0` (cap `CoResidencyCap = 4.0`, `platform.go:47`). On *any* node running kube-system/monitoring daemons — i.e. every node — `CoResidency > 1`. The conjunct is not "shares a node with another tenant"; it is "the node has system daemons". **Vacuous fleet-wide.**

(b) `rarity(count, n) = 1 + log2(n/count)/log2(n)` with `n < 2 → 1.0` (`platform.go:192-198`), and `ModelRarity = rarity(modelFreq[p.ModelID], tot)` where `tot` counts only model-annotated pods. This **inverts** the R-8/bus-084 premise. The report's chain — "one-model fleet ⇒ f = 1/N ⇒ ModelRarity = 2.0 ⇒ the > 1.3 test cannot fail" — is wrong in the code: a sole model occupies 100% of its own population ⇒ `rarity(N,N) = 1.0` (pinned by `TestRarityIsPopulationRelative`, `rarity_test.go:24` — "do NOT fix to 2.0"). The true structural behavior:

- **1 distinct ModelID fleet-wide ⇒ ModelRarity = 1.0 ⇒ BOTH arms dark.** The misfire cannot occur.
- **≥2 distinct ModelIDs ⇒ every 1-of-2 model scores 2.0 ⇒ the > 1.3 conjunct is near-vacuous** in the other direction. Small fleets saturate; the signal measures *fleet model diversity*, not theft-relevant rarity.

The 0.4.50-era report's `BOUNDED > 1.3` remains valid evidence — the gate *fired*, so the fleet then had ≥2 distinct ModelIDs. But "structurally true on single-model fleets" was an artifact of misreading the formula.

### A.3 Live state today (measured 2026-09-02, deployed 0.4.72)

- Exactly **one** distinct ModelID fleet-wide: `Qwen2.5-7B-Instruct-AWQ` × 1 pod ⇒ `modelFreq = {Qwen:1}`, `tot = 1` ⇒ `rarity(1,1) = 1.0` (n<2 honest-neutral).
- ⇒ Arms (1) and (2) are **both dark right now**. Consistent with yesterday's audit lines: the vllm pod's decisions showed generic `stage: recon → exploit/lateral`, never `model-theft`.
- **The R-8 misfire is LATENT, not live.** It re-arms the instant any second distinct `phorvex.ai/model-id` is annotated anywhere in the fleet (then the Qwen pod is 1-of-2 → 2.0 > 1.3, CoResidency 2.0 > 1, VRAMFraction 0.99 > 0.8 → model-theft with zero compute activity).

**Consequence for the test plan (falsifiable):** a golden baseline captured on the *current* fleet **cannot exercise the gate**. Red-before-green requires either a unit fixture that sets `ModelRarity`/`CoResidency` by hand, or a hand-authored ≥2-ModelID topology in the L2 battery (§4's adversarial-topology rule). A claim "verified against the live cluster" without a second ModelID is vacuous for this fix.

### A.4 Predicted behavioral delta (Class B — belief layer)

The touched state is the stage classification; its readers are: `Assess` (hazard, StageUrgency, PreemptMargin, ProjectedNextStageSec, AIClassified→HasEvidence), `recon/ucw.go:72` (`urg = 0.5 + 0.5·clamp01(StageUrgency)` scaling **every** fact weight of the asset), the coverage objective (per-$ = cov/cost vs λ), audit/decision-trace fields, and console narrative.

**On the current 1-ModelID fleet: NO observable delta.** Gate already dark via ModelRarity = 1.0. Post-fix decision records should be **byte-identical**. Any diff on this fleet = the fix touched something out of scope.

**On a ≥2-distinct-ModelID topology (where R-8 is live):**

1. `stage`: `model-theft` → 0% of GPU records (from ~100%); `gpu-side-channel` → ~100% of co-resident GPU records (arm 2 still fires: CoResidency 2.0 > 1, ModelRarity 2.0 > 1).
2. `StageUrgency` at saturated hazard: `0.5·0.9 + 0.5·1·1.0 = 0.95` → `0.5·0.15 + 0.5·1·0.9 = 0.525`. Band **[0.45, 0.60]** (hazard saturates later under the 300s sojourn vs 180s, so early-dwell values sit lower).
3. Fact weights via `urg`: `0.975 → 0.7625`, ratio **[0.74, 0.82]** on all six AI facts of the asset.
4. **Selections/actuations: UNCHANGED (band: zero change).** Live economics: endpoint-rotate per-$ on vllm ≈ 17 (cov 2.38 / $0.14), kv-migrate ≈ 13–26, against λ ≤ 0.6 (seed 0.6, decaying to the M-144 floor). A ×0.78 weight shift never crosses a >10× margin at any reachable λ (max 10). **If the proposal claims this fix reduces the endpoint-rotate churn, that claim is refutable on its face.** The churn's selection-layer causes are M-144 (λ floor), M-23 (inert cadence guard), unconditional fact minting (`ucw.go:80-90`), and M-27 (stale events keeping `reactiveOnly` actionable) — not the stage label. This fix corrects the *belief*; the *behavior* is owned by other register entries.
5. Non-GPU pods: byte-identical (honest-absent guard, `hazard.go:227`).
6. `HasEvidence`: unchanged on ≥2-model fleets (side-channel still sets `aiClassified`); unchanged on 1-model fleets (dark before and after).

### A.5 The undeclared-delta I predict the proposal may miss — precedence inversion, unmasked

`aiStageFromView` checks arm (2) side-channel (consequence **0.15**) *before* arm (3) `persistEvent` (0.6) and arm (4) jacking (0.6), and `Assess` lets the AI result **overwrite** the event-derived stage unconditionally (`hazard.go:291-293` — no `max`). The header comment claims "precedence by consequence/specificity (theft > side-channel > persist > jacking)" but the code order makes side-channel beat persist and jacking.

Pre-fix this ordering bug was **masked** wherever the misfire was live: arm (1) (0.9) fired first and dominated everything. Post-fix, on a ≥2-model fleet, a GPU pod with a **live persist-class event** (Panic / drift / named attack vector) or a jacking signal (`GPUUtil > 0.8`) gets `stage = gpu-side-channel` (0.15) — the AI arm **downgrades detector evidence**. That is M-25's pathology in a new direction, created by this fix. The proposal must either re-order (persist/jacking events before side-channel) or explicitly declare and defend the downgrade. A fixture for "GPU pod + live Panic event" must show stage = persist-class, not side-channel.

### A.6 Secondary attacks to run against the proposal/diff

1. **New `Assessment.Leakage` field** (glimpsed): if serialized into decision traces, every golden record gains a field — must be declared as a delta (and it changes the trace schema consumers read).
2. **Red-for-the-right-reason:** fixture (a) must fail on the pre-fix build *at the stage assertion* (`StageModelTheft`), with `ModelRarity`/`CoResidency` set explicitly — not fail to compile.
3. **Scope:** does the diff touch `ModelRarity`/`rarity()` or `CoResidency`? Those are adjacent defects (A.2) but **out of this ticket's scope**; if untouched, I will file them as new register items (DaemonSet-co-tenancy; small-fleet rarity saturation; and the corrected R-8 premise).
4. **T4 declaration:** does the proposal state plainly that on non-DCP hardware the model-theft stage becomes honest-absent (never fires), and is that the intended security posture rather than an accident?
5. **Sojourn:** arm (2)'s 300s scale vs arm (1)'s 180s — hazard trajectory and `PreemptMargin`/`ProjectedNextStageSec` shift must appear in the declared delta (they feed the predictive-horizon measurable).

### A.7 Class

**Class B** (belief/objective inputs). Bands as in A.4: on the current-fleet battery the only acceptable diff is *none*; on a 2-model fixture, stage mix flips ~100%→0% model-theft, SU lands [0.45, 0.60] at saturation, per-$ scales [0.74, 0.82], selections unchanged. Outside those bands = REOPENED; outside any model = INVALIDATED.

---

## §B — Diff against the proposal (written after §A was committed as `5ae7b6b`)

### B.0 Where the proposal and the blind derivation agree — credit

1. **The T4 consequence is declared, not hidden** (§3 "the consequence the ticket does not state") — matches A.2/Fact 1. The proposer went further and commissioned the register issue; filed as **M-149**.
2. **Population-relative ModelRarity is correctly understood** (§4: "iff `ModelRarity > 1` (i.e. ≥2 distinct models)… otherwise arm (2) also misses") — matches A.2(b). The L3 positive control correctly requires *a second pod serving a different model in a different namespace* — both `platform.go:115` and `:164` respected.
3. **Fixture (b) correction is right** — dropping a non-negative term can only lower `leakage`; (b) cannot be red pre-fix. Reclassifying it as a positive control is the honest call.
4. **Pin-drift re-verification at `016361c`** with per-file line deltas is exemplary §3.6 hygiene; the `fb52e6c` evidence marked SUPERSEDED.
5. **The P2 scope tension is declared** (§2) rather than smuggled — the four-file plumbing is justified by the ticket's own stated purpose for the record fields. I accept the widening *provided B.2 is fixed* — otherwise the plumbing fails that purpose.

### B.1 — ATTACK: undeclared delta — post-fix, arm (2) becomes the active M-25 vector

The proposal's §4 exact set is *not* restricted to zero-event pods: every pod satisfying `HasGPU && CoResidency>1 && ModelRarity>1.3 && (SM+VRAM)>0.8 && !(SM>0.8)` changes record — **including pods with live persist-class SecurityEvents**. For those, on a ≥2-model fleet, the stage goes `model-theft` (0.9) → `gpu-side-channel` (0.15) while detector evidence implies persist (0.6): arm (2) is checked *before* arms (3)/(4), and `Assess` overwrites with a bare `=` (`hazard.go:291-293`).

Pre-fix, arm (1) masked the event arms wherever the misfire was live — so M-25's override was exercised *only* by arm (1). Post-fix, **arm (2) becomes the masking arm**, and its direction is a *downgrade below detector evidence*. The proposal names M-25 as "downstream of arm (1)" but nowhere declares that the fix changes which arm exercises the M-25 override, nor the security sign of the new override (inflation → deflation; neither correct).

**Demand (declare, don't fix):** §4 must name this subcase explicitly — "GPU pod + live persist/jacking evidence on a ≥2-model fleet: stage becomes `gpu-side-channel`, below the event-implied stage; this is M-25's known surface, unchanged in kind, fix owned by M-25" — and the test plan must pin it with a fixture (GPU pod, `ModelRarity > 1`, live Panic event → assert post-fix stage, whatever is declared). I explicitly recommend **against** folding M-25's one-line `max()` into this diff (one issue per cycle) — but silence is not an option; an undeclared downgrade of real detector evidence is exactly what §3.4 exists to catch.

### B.2 — ATTACK: the four record fields are `omitempty` — re-creating M-146 in the fields whose purpose is honest-absence visibility

On T4, post-fix: `Leakage = 0`, `SMOccupancy = 0`, `SMSource = ""` — all three **omitted** by `omitempty`. The audit record on the only hardware we have shows *only* `VRAMFraction` and cannot distinguish "SM honest-absent" from "SM measured 0" — which is **M-146's exact defect class** (HIGH, 🔴 LIVE, filed after the eighth pass), recreated in the very fields whose stated purpose (§2: "the post-deploy diff can show both signals and the gate result") is absence visibility. The codebase already has the correct convention: `DecisionTraceV2` uses present-flags — `coverage.go:672`: `SMOccupancy: traceOptional(v.Physics.SMSource != "", v.Physics.SMOccupancy)`.

**Demand (must-fix before TESTED):** the audit fields follow the trace convention — emitted whenever the pod is an AI/GPU workload (`HasGPU || ModelID != ""`), with `SMSource` emitted verbatim including `""`, or via `OptionalFloat`/present-flags. With `omitempty`-on-zero, the plumbing is inert on T4 and §2's justification for widening P2 collapses.

### B.3 — ATTACK: the churn bullet is attribution language, not a falsifiable band

§4's last bullet ("kv-reset selections driven by `model-theft` → 0 for that cause") is unfalsifiable as stated, and reads as churn reduction. My derivation (A.4.4): on this fleet the gate is dark (N = 0 by construction — one ModelID ⇒ `ModelRarity = 1.0`; consistent with the 0.4.67 decision samples showing generic stages), and on ≥2-model fleets **selection counts do not change at all** — observed per-$ on vllm is 13–26 against λ ≤ 0.6 (max reachable 10), and the ×[0.74, 0.82] weight shift never crosses. Only stage/hazard/urgency/reason *fields* change.

**Demand:** replace with the falsifiable form — *"selection sets identical on every scenario; only belief-layer fields change"* — or produce a scenario where a selection flips. If none exists, adopt my band. This matters beyond ceremony: the ticket's motivation was the 5-hour churn, and this fix must not be sold as stopping it. (Minor: "kv-reset" is stale — vllm's enabled set no longer includes it; the observed churn actions are `endpoint-rotate`/`kv-migrate-invalidate`/`request-drain`.)

### B.4 — Minor: §2 file table contradicts §3

Table row says "`aiStageFromView` also returns `leakage`"; §3 says "Its signature is **not** changed: `leakage` is computed by a package-private helper `leakageOf(ph)`". The working tree (`Leakage: leakageOf(view.Physics)` in `Assess`) matches §3. Fix the table row.

### B.5 — Version anchor: deployed tag supplied, and it changes the evidence plan

Deployed image is **`phorvex:0.4.72`** (measured 2026-09-02; the cluster moved 0.4.67 → 0.4.72 in the last ~24h). Base commit `016361c` == deployed tag — alignment is as good as it gets; the pre-fix golden baseline captured on the current deployment is the correct baseline. Consequence for 05-evidence: the Class-B band is **vacuous on this fleet** (N = 0 by construction; I will confirm empirically from the 0.4.72 audit log that zero `model-theft` records exist). L2's real value here is the non-GPU byte-identity assertion. The gate's red-before-green is unit-level (fixtures a/d); the live positive control exists only if DCGM profiling can be enabled on the T4 (L3 step 2) — I accept the §5.3 coverage-admission path, with the admission recorded on **M-149**, not on the ticket.

### B.6 — Test-plan addition demanded

The B.1 fixture (GPU pod + live persist-class event on a 2-model topology) is a behavior-change pin: pre-fix `model-theft`, post-fix whatever §4 declares. Add it to `leakage_gate_test.go`.

### B.7 — What I verified independently

- Committed gate text at `016361c` (`git show HEAD:...hazard.go` :246-255) — matches proposal §1 quote.
- `rarity()` semantics + `TestRarityIsPopulationRelative` — proposal's "≥2 distinct models" condition confirmed; R-8's structural premise found inverted (filed **M-151**, with the report erratum).
- `nodeTenants` namespace keying + `contributesToFleetPhysics` Running-only filter; live census: 6 namespaces on the vllm node ⇒ CoResidency 2.0 saturated (filed **M-150**).
- Live ModelID census: exactly 1 distinct fleet-wide ⇒ gate dark today (§A.3).
- `hasEvidence := eventAlpha > 0 || lateralPressure > 0 || aiClassified || SuspectAdapter` — confirmed no HasEvidence flips in any topology (arm (1) requires `ModelRarity > 1.3`; wherever it fired pre-fix, arm (2) fires post-fix).
- `StageModelTheft`/`StageGPUSideChannel` have no consumers outside `killchain` (grep, whole module) — no stage-specific gating elsewhere.
- No local Go toolchain and no docker socket access on this box — **I cannot run `go test ./...` here**; L0/L1 execution must be CI or the proposer's environment, with raw output committed to 05-evidence. I can and will run the live (L3) half.

### B.8 — Register/anatomy filings completed this cycle

- **M-149** (proposer's §3 issue, commissioned to me), **M-150**, **M-151** (from my blind derivation) — TIER ∥; header 142→145, TIER ∥ 104→107, theme index T4/T9 updated, tenth-pass note added.
- **V2 erratum on M-20**: LOCUS platform → runner (`internal/runner/actions_supported.go:55`; keyword-match artifact).
- **Anatomy v2**: struct-field data-flow exclusion added to "What this map does not assert" (the physics→killchain relation rides `view.Physics`, no call site → invisible to the operation matrix).

**State recommendation:** PROPOSED → CRITIQUED. Round 1 of ≤3. Blocking demands: B.1 (declare + fixture), B.2 (present-flag emission), B.3 (falsifiable selection band). Non-blocking: B.4.

---

## Addendum (2026-09-02, post-baseline collection) — the trace's VRAM field is confounded

While collecting the bus-257 baseline I found the live trace shows `vramFraction {present:false, value:0}` on all 1,193 vllm records despite the DCGM feed answering the brain's exact witness query. Root cause is static: `stampGPU` (`platform/adapters.go:19-29`) never copies `VRAMPresent` — filed as **M-152** with the full chain in `evidence/live-baseline/06`. Two consequences for this cycle:

1. The proposal's L3 expectation "VRAMFraction present=true ~0.99" (bus 257 fact 3) **cannot be met by any build** until M-152 is fixed — post-fix records will show `present:false` regardless. The L3 pass criteria must key on the gate outcome and the new `leakage` field, not on the VRAM trace flag.
2. My §A.3 statement "the gate is dark today" stands, but the *reason* is solely `ModelRarity = 1.0`; the VRAM float may well be stamped and live (the gate reads the float, not the flag). The trace cannot distinguish these states — which is precisely the defect M-152 records.

This also sharpens B.2: the fix's new record fields must use present-flags keyed on source (`SMSource != ""`, `VRAMPresent`) — and should be specified so that a future M-152 one-liner flips the record to truthful without another schema change.
