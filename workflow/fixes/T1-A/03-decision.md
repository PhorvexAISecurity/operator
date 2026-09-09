# 03 — Decision · T1-A · converged fix spec after critique round 1

**State:** CRITIQUED → (this memo) → AGREED on Skeptic sign-off · **Base:** `016361c` (v0.4.72) == deployed `phorvex:0.4.72` · **Round:** 1 of ≤3
**Inputs:** `01-proposal.md` (rev 2), `02-critique.md` (K3, §A committed blind as `5ae7b6b`, §B as `1367cfa`)

Every Skeptic attack is either **adopted** (with the change named) or **answered with evidence**. Nothing is answered with argument alone.

---

## B.1 — Precedence inversion unmasked · **ADOPTED (declare + pin; do not fix here)**

**Verified from source at `016361c`, not from the critique:** `aiStageFromView` checks arm (1) theft → arm (2) side-channel → arm (3) prompt-inject-persist (`p.ModelID != "" && persistEvent`) → arm (4). `Assess` first raises `stage` from events (`if s := stageFromEvent(e); s > stage`), then **overwrites** it with the AI result by bare assignment (`hazard.go:291-293`, no `max`). So on a ≥2-model topology, a GPU pod with a live Panic event reads: pre-fix `model-theft` (0.9, arm 1 on residency alone); post-fix `gpu-side-channel` (0.15) — *below* the event-implied persist (0.6). The fix does not create the override; it changes which arm exercises it and flips its sign from inflation to deflation. That is M-25's surface.

**Decision:**
- §4 of the proposal names the subcase explicitly (done, rev 2).
- Fixture (e) pins the declared post-fix stage: `TestLeakageGate_LivePersistEventOnTwoModelFleet_DeclaredDowngrade` — RED on the pre-fix gate (reads `model-theft`), GREEN post-fix (reads `gpu-side-channel`, `HasEvidence` still true). Its failure message says what to do when M-25 lands: retire the pin. Evidence: `evidence/pre-fix/05-fixture-e-red.txt`, `evidence/post-fix/05-fixture-e-green.txt`.
- The `max()` re-ordering is **not** in this diff. One issue per cycle; M-25 owns it. Recorded on M-25 by K3 (R1) as "post-T1-A the active vector is arm (2), direction deflation".

## B.2 — `omitempty` recreating M-146 · **ANSWERED: already discharged by the rev-2 design the critique predates**

The attacked four `omitempty` fields no longer exist. T0-D landed in the 25 commits (`c53258d`, `DecisionTraceV2`); the one field is `DecisionModelInputsV2.Leakage OptionalFloat`, filled as `traceOptional(v.Physics.SMSource != "", ac.assess.Leakage)` — the exact convention the critique cites at `coverage.go:672` — and registered in `Canonical()`. On T4: `smOccupancy {present:false}`, `leakage {present:false}`. **Correction (K3 M-152, live record `evidence/live-baseline/05`):** `vramFraction` is ALSO `{present:false}` live today — not because data is absent (the witness query returns 14,488 MiB) but because `stampGPU` (`platform/adapters.go:19-29`) never copies `VRAMPresent` across the adapter seam. The builder is right (my unit test sets the flag directly and sees `present:true`); the seam is wrong, and that is M-152's one-line fix, not this ticket's. Consequence: **L3 pass criteria key on the gate outcome and the new `leakage` field, never on the VRAM presence flag.** Absent-vs-measured for SM/leakage is distinguishable by construction. Pinned by `decision/leakage_trace_test.go` (bus-084 shape ⇒ absent; measured 0.85 ⇒ present).

Open question to the Skeptic (bus 258): the trace does not carry the `SMSource` *string*; presence encodes it. Adding the string is a second field. Proposer's position: presence discharges the M-146 class; the metric name is a debugging nicety, not an honesty requirement. **Skeptic rules.** If K3 wants the string, it is one more `TraceNotAvailable`-style field and a one-line builder change — declared here in advance so it cannot be an undeclared delta later.

## B.3 — Churn bullet unfalsifiable · **ADOPTED: Skeptic's band replaces it, after independent re-derivation**

Re-derived from source, not copied:
- `StageUrgency = 0.5·c(stage) + 0.5·h·c(next)` (`hazard.go:75`, `:334`); `c(model-theft)=0.9, c(impact)=1.0, c(side-channel)=0.15`, `aiNextStage[side-channel]=model-theft` (`hazard.go:40-45`, `:90-112`).
  - pre-fix: `SU = 0.45 + 0.50·h` → **0.95** at saturation.
  - post-fix: `SU = 0.075 + 0.45·h` → **0.525** at saturation. K3's band [0.45, 0.60] at saturation: **confirmed** (0.525 sits inside; sojourn 300 s vs 180 s, `hazard.go:176-177`, makes early-dwell values lower, as K3 said).
- `urg = 0.5 + 0.5·clamp01(SU)` (`ucw.go:72`) scales every AI fact weight of the asset (`ucw.go:81-82`): 0.975 → 0.7625, ratio **0.782**. K3's [0.74, 0.82]: **confirmed**.
- Selections: K3's live per-$ (13–26 on vllm vs λ ≤ 0.6, max reachable 10) is a cluster measurement I cannot re-derive statically. The *checkable* form is the band itself.

**Replacement band (falsifiable, adopted verbatim in §4):**
> *Selection sets identical on every L2 scenario; only belief-layer fields change (`stage`, `nextStage`, `stageHazard`, `stageUrgency`, `preemptMargin`, `projectedNextStageSec`, `reason`, the six AI fact weights by ×[0.74, 0.82], and the new `leakage` trace field). Any selection flip on any scenario = REOPENED.*

The "kv-reset churn → 0 for that cause" bullet is **withdrawn**. K3 is right that it read as a churn claim; this fix corrects a belief, and the churn is owned by M-144 / M-23 / M-27 / the unconditional fact minting — not by the stage label. (Also corrected: vllm's enabled set no longer includes `kv-reset`; observed churn actions are `endpoint-rotate` / `kv-migrate-invalidate` / `request-drain`.)

## B.4 — Table row contradiction · **FIXED** in proposal rev 2 (`leakageOf(ph)`, caller untouched).

## B.5 — Deployed tag · **RECORDED**: `phorvex:0.4.72` == base. STATUS updated.

## What the Skeptic's blind derivation found that the proposal did not — credit, and disposition

- **A.2(a)** `CoResidency` counts namespaces incl. DaemonSet system namespaces ⇒ `> 1` vacuous fleet-wide (live: 6 namespaces on the vllm node ⇒ 2.0). **Out of scope here; filed M-150.**
- **A.2(b)** the R-8 / bus-084 premise "single-model fleet ⇒ rarity 2.0" is **inverted** — `rarity(N,N)=1.0` (`TestRarityIsPopulationRelative`). Single-model fleets are dark on *both* arms; two-model fleets saturate at 2.0. **Out of scope; filed M-151, with the report erratum.** The proposal's own §4 text ("iff ≥2 distinct models") was already consistent with the code; the *report's* chain was wrong.
- **A.3** the live fleet today serves exactly **one** ModelID ⇒ the misfire is **latent, not live**; the current golden baseline **cannot exercise the gate**. Consequence adopted: the gate's red-before-green is unit-level (fixtures a/d/e with `ModelRarity`/`CoResidency` set by hand); on the current-fleet L2 battery the only acceptable diff is **none** except the new absent `leakage` field. A live claim without a second ModelID is vacuous — stated in §5.

## L3 plan (unchanged in kind, sharpened by A.3)

Mandatory, because the effect depends on dcgm-exporter (outside the codebase). Post-deploy, K3:
1. Confirms **zero** `model-theft` records on 0.4.72 (expected: zero *before* as well, per A.3 — so this is a no-change assertion, not an N → 0).
2. DCP profiling is **not enabled** on the dcgm-exporter (default collectors, no CSV — K3 `live-baseline/02`); enabling it is a **human-gated DaemonSet patch** (the image ships `dcp-metrics-included.csv`), and whether the T4 + driver 580.159.03 then emits `PROF_SM_ACTIVE` is unknown until tried. **If approved and the series appears:** live positive control = fixture (b) shape — extraction load on one pod, a second pod serving a *different* ModelID in a *different* namespace (M-151/M-150 make both mandatory) — must read `model-theft`. **If not approved, or the series does not appear:** coverage admission recorded on **M-149**, not on the ticket; the fix closes on the admission with the unit-level positive control (b) as the only positive control. On the current fleet the post-fix expectation is **zero AI-GPU-stage records** (K3 A.3 / live-baseline 03: rarity 1.0 ⇒ both arms dark), i.e. a no-change assertion.

## Scope of the diff (unchanged)

3 code files: `killchain/hazard.go` (gate + `leakageOf` + `Assessment.Leakage`), `model/decision_trace.go` (one `OptionalFloat` + `Canonical()` registration), `decision/coverage.go` (one builder line). 3 test files. `audit/log.go`, `model.Decision`, `rarity()`, `CoResidency`, threshold, weights: **untouched**.

## Open for Skeptic sign-off (→ AGREED)

1. B.2 as discharged by presence-flags — yes/no (and whether `SMSource` string is wanted).
2. Fixture (e)'s declared stage `gpu-side-channel` — agreed as the M-25-owned surface.
3. Band text above — adopted verbatim.
4. Register: M-149/150/151 are in **v1** (`PHORVEX_MASTER_ISSUES.md`, 144 live); the frozen **V2** (ticket attachment) carries only the M-20 erratum. K3 to state whether V2 is amended or v1 is now the live register — Proposer has no opinion on which, only that the ticket must cite one.
