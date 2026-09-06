## Make the model-theft leakage gate activity-only and record it in the decision trace

**Ticket:** T1-A (register recommendation R-8) · **Base:** `016361c` (v0.4.72) == deployed `phorvex:0.4.72`

### What was wrong

`killchain/hazard.go` gated the `model-theft` stage on `SMOccupancy + VRAMFraction > 0.8`. `VRAMFraction` is *allocation* (a loaded model), not *activity*. A loaded, idle model server satisfied the gate permanently — measured live at `VRAMFraction = 0.9931, SMOccupancy = 0` — so "model theft in progress" reduced to "has a GPU and shares a node".

### What changes

- `leakage` is activity only: `leakageOf(ph) = ph.SMOccupancy`. Threshold `0.8` unchanged; no weight moved onto `LinkBandwidth`/PCIe (insufficient evidence to calibrate; Tier 3).
- The gate's input is recorded: `DecisionTraceV2.Inputs.leakage` (`OptionalFloat`, present only when `SMOccupancy` was measured — `SMSource != ""`), registered in `Canonical()`. Honest-absent stays absent.
- Nothing else: `audit/log.go`, `model.Decision`, `rarity()`, `CoResidency`, feasibility — untouched. 3 code files, 3 test files.

### Behavioural delta

- **Selection sets are identical on every scenario; only belief-layer fields change.** No churn claim is made — churn is owned by M-144/M-23/M-27.
- On a fleet with two or more models: `model-theft` → `gpu-side-channel` for residency-only pods; `stageUrgency` 0.95 → 0.525 at saturation; AI fact weights ×[0.74, 0.82].
- **On the current fleet (one model ⇒ `ModelRarity = 1.0`) there is no record change** except the new absent `leakage` field — the misfire is latent: 0 `model-theft` in 6,139 live records at v0.4.72.
- **Declared and pinned by a test:** on a ≥2-model fleet a GPU pod with a live persist-class event now reads `gpu-side-channel`, below the event-implied stage — the arm ordering in `aiStageFromView` (M-25), fixed there, not here.
- **On T4 hardware without DCGM profiling the `model-theft` stage becomes unreachable** (`PROF_SM_ACTIVE` has 0 series). Filed as M-149. This PR trades a permanently-true gate for a permanently-false one on that hardware and does not pretend otherwise.

### Evidence

- The loaded-idle, allocation-carries-no-weight and live-event tests fail on the previous gate at their named assertions and pass here; the extraction-load (SM 0.85 ⇒ `model-theft`) and threshold-strictness tests pass on both builds as controls.
- Trace test: the live shape (VRAM 0.9931 present, SM unmeasured) records `leakage` as absent; measured 0.85 records present; `Canonical()` keeps the field.
- Whole offline suite green across the affected packages; `go vet` clean.

### Live verification after deploy

Mandatory, because the effect depends on dcgm-exporter (outside this codebase): confirm zero AI-GPU-stage records on the fleet (a no-change assertion); if DCP profiling can be enabled and `PROF_SM_ACTIVE` appears, run the live positive control (extraction load on one pod, a second pod serving a different model in a different namespace) → must read `model-theft`; otherwise record a coverage admission on M-149. Criteria key on the gate outcome and the `leakage` field — not on the trace's VRAM presence flag, which is dark until M-152.

### Rollback

`git revert` of this commit. No persisted state; the trace field is additive and absent by default.
