# 01 — Proposal · T1-A · separate GPU residency from activity in the leakage gate

**Proposer:** Claude · **Skeptic:** K3 · **State:** CRITIQUED (round 1) · **Schema:** FIX_LOOP §3 (all seven sections) · **Response to critique:** `03-decision.md`
**Note on ordering:** a candidate diff exists on the branch as `04-diff.patch` (DRAFT) with pre/post evidence. It was produced to make §2–§4 concrete and to capture red-before-green at the base; it is **subordinate to `02-critique.md`** — the Skeptic's blind derivation was requested (bus 255) before any of this was visible, and the diff does not advance STATUS past PROPOSED.
**Base:** `016361c` (v0.4.72) · **Branch:** `t1/sensing-separate-residency-activity` (rebased from `fb52e6c` after main moved 25 commits — bus 256) · **Deployed image:** `phorvex:0.4.72` == base (K3, 02-critique B.5, measured live 2026-09-02)
**Pin drift check:** the ticket was verified at `aedd218` (v0.4.58). Between `aedd218` and `fb52e6c` (19 commits) every file below was byte-identical. Between `fb52e6c` and `016361c` (25 commits) **six of them changed** — re-verified line by line at `016361c`: the gate moved `:241/:244 → :246/:249` (one 5-line insertion above it in `stageFromEvent`, attack-vector cases, unrelated); the witness fields, the SM honesty rule, and the namespace/rarity keying are unchanged. The ticket's *line numbers* no longer hold; its *claims* do. Pre-fix RED evidence was re-captured at `016361c`; the `fb52e6c` capture is retained as SUPERSEDED.

---

## 1. Root cause

`internal/killchain/hazard.go:246` (inside `aiStageFromView`):

```go
leakage := ph.SMOccupancy + ph.VRAMFraction // [0,2]; 0 on kind; PHORVEXSEC-115
```

tested at `:249`:

```go
if p.HasGPU && ph.CoResidency > 1 && ph.ModelRarity > 1.3 && leakage > 0.8 {
    return StageModelTheft, true
}
```

`VRAMFraction` is allocation (`types.go:328`: "pod VRAM demand / device VRAM allocatable"). `SMOccupancy` is activity (`types.go:329`: "pod SM compute share"). Summing them lets residency alone satisfy an activity gate. This is the cause, not a symptom: no other input to arm (1) can compensate, and the live observation (bus 084, `VALIDATION_REPORT.md:1655`) is exactly the degenerate case — `VRAMFraction = 0.9931`, `SMOccupancy = 0`, gate true, stage `model-theft`, zero SecurityEvents.

Why `SMOccupancy` was 0 live is itself load-bearing: `prometheus.go:91-94` — *"only PROF_SM_ACTIVE may feed SMOccupancy… On T4 stacks without DCP profiling, SMOccupancy stays honest-absent (zero with an empty source)."* Our T4 exposes **0 series** of `DCGM_FI_PROF_SM_ACTIVE`. So on this fleet the activity term has never contributed, and the gate has been a residency gate in practice.

## 2. The fix (minimal)

**One semantic change, in `killchain`:**

```go
// hazard.go:246
leakage := ph.SMOccupancy // [0,1]; activity only — allocation (VRAMFraction) carries no weight (T1-A)
```

`:249` unchanged. Threshold `0.8` unchanged (INSUFFICIENT EVIDENCE to move; Tier 3). No weight on `LinkBandwidth`/PCIe (the ticket's `MemBW` field does not exist in the witness — `types.go:319-336`; PCIe exists as `LinkBandwidth`; both stay at weight 0).

**Plus the record field the ticket requires — and T0-D has landed, which changes where it goes.** Commit `c53258d` (PR #90, `t0/record-decision-trace-v2`, in the 25 commits) added `DecisionTraceV2` — the versioned decision-reconstruction payload nested in the audit record. Its `Inputs` **already carry both raw signals with honest-absent semantics**: `coverage.go:672-673` records `SMOccupancy` (present iff `SMSource != ""`) and `VRAMFraction` (present iff `VRAMPresent`). The only thing missing is the gate's own input, `leakage`. So the plumbing is three files, and `audit/log.go` and `model.Decision` are **untouched**:

| file | change |
|---|---|
| `internal/killchain/hazard.go` | the one-line fix via a package-private `leakageOf(ph)`; `Assessment` gains `Leakage float64`, set in `Assess` from the same helper (one source of truth, caller of `aiStageFromView` untouched) |
| `internal/model/decision_trace.go` | `DecisionModelInputsV2` gains `Leakage OptionalFloat` — **the one audit field** — plus its registration in `Canonical()`, which normalizes every optional explicitly (an unregistered optional would be the only one not cleaned of NaN/absent) |
| `internal/decision/coverage.go` | one builder line: `Leakage: traceOptional(v.Physics.SMSource != "", ac.assess.Leakage)` — present iff SM was measured, so an honest-absent scrape records as absent, not as idle |

**Scope against the ticket's P2 ("`internal/killchain` plus one audit field. Nothing else"):** this *is* one audit field; it lives in the trace type (`internal/model`) rather than `internal/audit` because that is where T0-D put the record's inputs, and it needs one line at the single site that fills them. No `Decision` struct change, no `audit/log.go` change, no schema version bump (`phorvex.decision-trace.v2` is additive-compatible: the round-trip and legacy-read tests cover it). Skeptic: if you read P2 as forbidding the `model` and `decision` lines, the alternative is to record nothing — and the ticket's stated reason for the field is the post-deploy diff.

## 3. Blast radius

**Readers of the touched state:**
- `leakage` — read only at `hazard.go:249`. Nowhere else (grep, whole module).
- `VRAMFraction` — after the fix, still read by `feasibility/gpuconservation.go:28` (`> 1.0` VRAM-conservation veto). It does **not** become a dead field. Unchanged by this fix.
- `SMOccupancy` — written only at `prometheus.go:377` (with `SMSource` at `:378`); read only at `hazard.go:246`. Unchanged.
- `Assessment` — consumed at `decision/coverage.go:521-529` (copy to Decision — untouched), at the `DecisionTraceV2` inputs builder (`:672-690`, since v0.4.68 — where the one new line goes), and in `coverageReason` (formatting only). Adding `Leakage` alters no existing consumer.
- `model.Decision` / audit record — **untouched**. The trace gains one `OptionalFloat`; for every pod without a measured SM series it serializes as `{present:false}`, exactly like `smOccupancy` does today. Non-GPU records change by that one absent field and nothing else (declared; the L2 byte-identity assertion is stated modulo this field).

**Callers of touched functions:** `aiStageFromView` has exactly one caller (`hazard.go:291`, inside `Assess`). Its signature is **not** changed: `leakage` is computed by a package-private helper `leakageOf(ph)` used by both the gate and `Assess`, so the caller is untouched.

**Register entries whose behaviour this could alter:**
- **M-25, M-26, M-28** — downstream of arm (1) (`HasGPU && CoResidency>1 && ModelRarity>1.3 && leakage>0.8`). The ticket's whole point is to land this *before* them so their diffs isolate the gating fixes. All three are still OPEN on the frozen register; ordering holds.
- **M-142** (`Telemetry.Present` universally true) — adjacent, not touched; see §P-SENSING below.

**The consequence the ticket does not state — and the Skeptic's blind derivation should find:**
On any fleet where `DCGM_FI_PROF_SM_ACTIVE` is absent — which is *this* T4 (bus 084: 0 series) — post-fix `leakage = 0` **permanently**, so arm (1) `model-theft` becomes **unreachable**. The fix trades a permanently-true gate for a permanently-false one on the shipped hardware. Two things follow:
1. The ticket's live diff "zero-event model-theft: N → 0" will pass **vacuously** on this cluster. It must not be read as evidence the gate now discriminates.
2. This is a **new register issue** (there are zero mentions of `SMOccupancy` / `PROF_SM_ACTIVE` in the frozen register). Proposed title: *"AI model-theft stage is unreachable on GPU fleets without DCGM profiling (T4); the leakage gate's only activity input is honest-absent."* K3 files it (R1). It is not a reason to keep the wrong gate; it is the honest description of what the right gate can and cannot see on this hardware.

## 4. Declared behavioural delta — Class B (belief layer), with a band the Skeptic can fail

**Exact set of records that change:** every decision on a pod satisfying `HasGPU && CoResidency>1 && ModelRarity>1.3 && (SMOccupancy + VRAMFraction) > 0.8 && !(SMOccupancy > 0.8)`. For each such pod: `Stage` changes from `model-theft` to whatever arm (2)–(4) yields (`gpu-side-channel` when `ModelRarity > 1`), `NextStage`/`StageHazard`/`PreemptMargin`/`ProjectedNextStageSec` re-derive from the new stage (`Assess` recomputes them from `stage`), and `Reason` text changes accordingly. **Nothing else in any record changes** except the four new fields.

**Band (rev 2 — Skeptic's, adopted after independent re-derivation in `03-decision.md` B.3):**
- **Selection sets identical on every L2 scenario; only belief-layer fields change** — `stage`, `nextStage`, `stageHazard`, `stageUrgency`, `preemptMargin`, `projectedNextStageSec`, `reason`, the six AI fact weights (×[0.74, 0.82] via `urg`), and the new `leakage` trace field. **Any selection flip on any scenario = REOPENED.**
- `StageUrgency` on a changed record: pre `0.45 + 0.50·h` → post `0.075 + 0.45·h` (h = stage-exit hazard); at saturation 0.95 → 0.525, band [0.45, 0.60]. Re-derived from `hazard.go:75/:334`, `consequence()`, `aiNextStage`.
- **On the current fleet (one ModelID ⇒ `ModelRarity = 1.0`, K3 A.3): NO record changes** except the new absent `leakage` field. The misfire is latent; N is 0 *before* the fix. Any other diff on this fleet = the fix touched something out of scope.
- **Non-GPU pods: byte-identical** modulo the one absent trace field (honest-absent guard, `hazard.go:227`).
- **Declared subcase (K3 B.1):** GPU pod + live persist/jacking evidence on a ≥2-model fleet → `stage = gpu-side-channel` (0.15), *below* the event-implied persist (0.6): arm (2) precedes arm (3) and `Assess` overwrites with `=` (`:291-293`). This is M-25's override surface, unchanged in kind; the fix changes which arm exercises it and flips its sign from inflation to deflation. Pinned by fixture (e). The `max()` re-ordering is M-25's, not this ticket's.
- The earlier "kv-reset churn → 0 for that cause" bullet is **withdrawn** (unfalsifiable; read as a churn claim). This fix corrects a belief. The churn belongs to M-144 / M-23 / M-27 / unconditional fact minting.

Skeptic: derive your own band from the ticket + bus 084 before reading this section. If yours is materially narrower or points elsewhere, that is a finding, not a negotiation.

## 5. Test plan

**L0 / regression lock — `internal/killchain/leakage_gate_test.go` (written; compiles on the pre-fix build):**

| test | pre-fix | post-fix | role |
|---|---|---|---|
| `TestLeakageGate_LoadedIdleIsNotTheft` — fixture (a): VRAM 0.9931, SM 0, `SMSource ""` | **RED** at *"residency alone satisfied the leakage gate"* | green | the lock; red for the right reason |
| `TestLeakageGate_AllocationCarriesNoWeight` — fixture (d): SM 0.79, VRAM 1.0 | **RED** | green | ticket trap "no smaller weight" |
| `TestLeakageGate_ExtractionLoadIsTheft_PositiveControl` — fixture (b): SM 0.85 | green | green | proves the rig still detects theft |
| `TestLeakageGate_ThresholdIsStrict` — SM exactly 0.80, VRAM 0 | green | green | ticket trap "do not lower 0.8" |
| `TestLeakageGate_LivePersistEventOnTwoModelFleet_DeclaredDowngrade` — fixture (e): bus-084 physics + live Panic, 2-model topology | **RED** (reads `model-theft`) | green (reads `gpu-side-channel`) | K3 B.1: pins the declared M-25-owned downgrade; retire when M-25 lands |

Correction to the ticket: fixture (b) **cannot** fail on current code — dropping a non-negative term can only lower `leakage`. (b) is a positive control that must pass on both builds, not a red-before-green test. The pre-fix run is captured in `evidence/pre-fix/02-red-run.txt` before any change to `hazard.go`.

Record fields get their own tests, shipped **with** the fix (a test referencing fields that do not yet exist would be red-by-compile-failure — §4 forbids): `killchain/leakage_record_test.go` asserts `Assessment.Leakage == SMOccupancy` for measured, `== 0` for honest-absent, and that it equals the gate helper (one source of truth); `decision/leakage_trace_test.go` asserts the trace records `leakage` as **absent** when `SMSource == ""` even with VRAM saturated (the bus-084 shape), as `0.85` when measured, and that `Canonical()` keeps it.

**L1:** whole offline suite, unscoped, before and after (`evidence/pre-fix/03-l1-baseline.txt` vs post-fix). Any newly-red ENFORCED test = REOPENED.

**L2 golden diff:** the existing battery is on-cluster capture; K3 runs pre-deploy baseline and post-deploy re-run. Class B bands above; plus the hard byte-identity assertion on non-GPU records.

**L3 — REQUIRED, and here is the sharp reason (§4 L3 gate):** the fix's live effect depends on an actor outside this codebase — dcgm-exporter's profiling series. Whether `PROF_SM_ACTIVE` exists is a property of the exporter/driver config, not of Go code. Post-deploy, K3:
1. counts zero-event `model-theft` records on the GPU fleet → must be **0** (band);
2. (human-gated) DCP profiling is off on the exporter (K3, `live-baseline/02`); enabling it is a DaemonSet patch whose outcome on this T4/driver is unknown. If approved and `DCGM_FI_PROF_SM_ACTIVE` appears: **If yes:** fixture (b) runs live — an extraction-shaped load on one pod, in a *different namespace* from a second pod serving a *different model* (both required by `platform.go:115` and `:164`, see §3) — and must read `model-theft`: the live positive control. **If no:** the positive control is unit-only, recorded as a **coverage admission** (§5.3) on the new register issue, and the fix is CLOSED on that admission — not on the vacuous N → 0.

**Trace VRAM flag (K3 M-152):** live records show `vramFraction {present:false}` because `stampGPU` drops `VRAMPresent`; L3 criteria must not key on that flag. Out of scope here.

**Expected post-fix register status:** no M-number closes (ticket says so). `PHORVEX_MODULE_GRAPH.json` `SENSING → BELIEF` row re-classed defect → working by K3 (that file is the aedd218 fix graph, not the frozen anatomy). New issue filed per §3.

## 6. Version anchor

- Base commit: `016361c` (tag `v0.4.72`), branch `t1/sensing-separate-residency-activity`, rebased from `fb52e6c` (v0.4.64) after origin/main moved 25 commits (bus 256). Zero commits on the branch at rebase time.
- Line references in this proposal are as of `016361c`. The ticket's `aedd218` line numbers are stale for `hazard.go` (+5) and are NOT to be used for closure (P1 source fidelity).
- Files re-verified at `016361c` against `fb52e6c`: `hazard.go` (+5 lines, gate untouched), `types.go` (+79/−26: `Telemetry.PresentSignals`, attack-vector rule types, `DecisionTraceV2`; witness fields untouched), `coverage.go` (+342/−27: trace builder; copy site now `:521`), `audit/log.go` (+5: `DecisionTrace` field), `prometheus.go` (+8/−1; SM honesty rule and `SMSource` untouched), `platform.go` (+4/−1; keying untouched). `gpuconservation.go`, `aicontext_test.go` identical.
- Deployed image tag: **`phorvex:0.4.72`** (K3, 02-critique B.5) — equal to the base commit's release tag. Alignment is exact; the pre-fix golden baseline on the current deployment is the correct baseline.

## 7. Rollback

`git revert` of the single fix commit. No persisted state is created: the four record fields are `omitempty` and purely additive; no CRD, chart, threshold, weight, or policy value changes. A rolled-back build re-emits the pre-fix stage assignments on the next tick. Nothing to migrate.

---

## P-SENSING (honest observation) — handled now, not deferred to M-142

`SMSource == ""` already distinguishes *unmeasured* from *measured zero* (`types.go:329-330`; set only at `prometheus.go:378`). The record carries `SMSource` verbatim, so an absent scrape is visible as absent in the audit field today. No dependency on M-142 for this ticket.

## P-NO-CALIBRATION

`0.8` untouched; weights on `LinkBandwidth`/PCIe stay 0, tagged INSUFFICIENT EVIDENCE in the code comment. The EMA fallback (`leakage = max(0, SM − baseline_p)`) is **not built**: it only matters if fixture (b) false-negatives, and (b) cannot run live until SM reads at all (§3). Building it now would be speculative — the ticket forbids that.
