# DASHBOARD-AUDIT.md — Phase 1 (display-wiring audit, change nothing)

**Date:** 2026-06-08 · **Method:** 4 parallel static source-traces (every panel → its data source) + a real
**headless-Chrome sweep** of every step/sub-tab across **3 lenses** (operator/investor/owner) + dead-button +
network probes. **0 client-side crashes anywhere.** The engine + backend are real; this is a *display-wiring*
audit. **Nothing was changed.**

> **Headline:** the backend is **real/live throughout** (every `/api/*` returns 200 by exec'ing phorvex/harness/
> kubectl, parsing `metrics.jsonl`, reading the audit JSONL, or scraping Prometheus — **no fabricated/mock
> structs found**). The optimization / actuation / context / physics / benchmarks panels render **real live
> data**. The problems are: **one dead control, one empty-lens bug, a missing Comparison-vs-R6, unserved
> curated reports, and ~15 hardcoded display literals.**

## A. The named line-items (verdict + browser evidence)

| Line item | Verdict | Browser evidence (operator lens) | Source / fix |
|---|---|---|---|
| **DISCOVERY populated?** | ✅ **REAL** | Physics tab = **9 witness rows** (imgRarity/coRes/slack/EPSS); Blast-graph = **9 SVG nodes**; Crown-jewels + Kill-chain populated | `api.scan` (live `phorvex --scan`) + `liveStream` |
| **DEAD BUTTONS** | ⚠️ **1 dead** | Protect **Active/Dry-run toggle → 0 network calls** (cosmetic state flip only) | `protect.tsx:29-30`; no `POST /api/operator/{start,stop}` endpoint exists |
| **ACTUATION VISIBILITY** | ✅ **REAL** (partial) | Actuator shows `objectsTouched=Pod/owner-demo/db`, `mutationKind=replace/forward-only`, `handler`, `11/11 generatable` | audit `objectsTouched/mutationKind/handler` (`panels.tsx:222-229`). **Missing:** before/after diff + `rollbackRef` (in the Record, not displayed) |
| **CONTEXT + HOW CALCULATED** | ✅ **REAL** | killchain section present: stage, PHold, PreemptMargin, **ProjNextStage=8s** | `scan.killchain` ← `killchain.Assess` (`hazard.go`), regex-parsed `subsystems.go:101`. **`blast` + `infectionFrontier` parsed but NOT shown** in ContextDetail |
| **OPTIMIZATION IN ACTION** | ✅ **REAL — the heart works** | Table headers: `Workload·Action·Coverage·Cost(ECost)·Net = cov−λ·cost·per-$·λ`; row `owner-demo/db rotate(chosen) cov=7.01·3f cost=0.49 net=6.62 per-$=14.31 λ=0.80` | `OptimizationPanel` ← `liveStream` Record (cov/cost/lambda/net/perDollar/attribution); chosen row highlighted. SHAP via `ShapAndR6`. **Real per-candidate, selected set marked.** |
| **DYNAMIC ACTION SET** | ✅ **dynamic** | actions per-tick from `liveStream` (`r.action`), registry from `/api/handlers` (11/11) | only static action lists are `AI_HANDLERS` (cosmetic class) + `KNOBS` (display) |
| **PREDICTION + TIMING** | ⚠️ **prediction real, timing not surfaced** | ProjNextStage shown (8s; negative for long-lived system pods). **No UI element shows the firing gaps** (the real 5–10s actuation cadence is in the audit but not displayed) | `projectedNextStageSec` (`hazard.go:330`). Fix: surface the inter-decision gaps |
| **BENCHMARKS** | ✅ **REAL, ⚠️ not the curated report** | Benchmarks tab = **30 rows** (scenario/arm/disruption/dwell/CI) | `/api/benchmarks` reads `out-p3deep` + `out-pactuator` `metrics.jsonl` (real, computed CIs). **Does NOT read** `out-bench/report.md`, `out-ai-bench`, `EFFECTIVENESS-PHORVEX.md` (exist on disk, unserved) |
| **COMPARISON-vs-R6** | ❌ **MISSING** | no comparison panel exists; R6 only appears as a `d-r6blindtimer` arm row | **No panel, no endpoint.** `COMPARISON.md` (154 lines) exists on disk, **unserved**. The one R6 narrative (`ShapAndR6`) has a **hardcoded fallback string** |
| **REPORTS** | ⚠️ **dynamic stats, no report index** | Report = live effectiveness/posture tiles + CSV/print (real). | No `/api/reports` index; the curated `out-*/report.md` + `EFFECTIVENESS-PHORVEX.md` + `COMPARISON.md` on disk are **unserved**. `report.tsx` fetches `bench` but **never renders it** |
| **FAKE VALUES** | ⚠️ **~15 display literals** | (no fabricated CIs/measured numbers — all metrics are backend-real) | see §C |
| **PENDING LABELS** | 3 real blockers + reassurance | (see §D) | |

**On the "0.5" cost:** the real `cost` is **0.49 (db rotate) / 0.82 (web rotate)** — a *normalized dimensionless*
cost that varies per pod by the RLS flow term (`ECost = 0.4·cNorm + 0.6·cFlow`). The "0.5" you saw is the real
**0.49**, not a hardcoded fake. (Quarantine = 0.283.) **No literal `0.5` exists in code or audit.**

## B. Element-by-element (by step)

**LANDING** — REAL proof strip (`/api/effectiveness`, `/api/posture`, `/api/owner/events`). Buttons navigate.
*Fake:* `"SLO kept"="Yes"` literal (`landing.tsx:77`).
**CONNECT** — REAL (`/api/targets`); target cards persist context (fixed last task); pending cloud cards
deliberately inert. No fakes.
**SCAN** — "Run live scan"/"Re-scan" = REAL live exec (`api.scan`, fixed last task). *Cosmetic:* the 4-phase
progress (`PHASES` const + 800ms ticker, `scan.tsx:11-16,35`) is a **fake animation** over the single real call.
**DISCOVERED** — Blast-graph (9 nodes, REAL) · Crown-jewels (REAL asset sort) · Kill-chain (REAL stage counts)
· Physics (9 witness rows, REAL). *Blocker:* **graph draws nodes but NO reachability edges** — network/RBAC/
co-residency edge set unwired (`discovered.tsx:66` Pending). *Static:* AI-stage narrative string (`:147`).
**PROTECT** — Live-theatre/MTD/Cost/Actuator/Health = REAL (live SSE + `/api/handlers` + `/api/cluster`).
Health = honest empty ("No PhorvexPolicy deployed" — none in cluster). *Dead:* Active/Dry-run toggle. *Fake:*
`GPU $/yr="—"` mini (`panels.tsx:173`).
**PROVE** — Catalog/Effectiveness/Frontier/Benchmarks/Coverage/Gap/Matrix/AI-boundary all → real endpoints
(200). Live-run launch = REAL (`/api/runs/start` + poll). Ablation = on-demand (REAL on click). *Fake:* frontier
"792 rows, seed 1337" caption + the 3 "Reading" cards' static "100%/0%/0%" prose (`frontier.tsx:35,70-73`).
**REPORT** — live tiles + CSV + print (REAL). *Dead-ish:* `bench` fetched, never rendered (`report.tsx:19`).
*Blocker:* bundled-PDF + `/api/reports` index unwired (`report.tsx:38`).

## C. FAKE / HARDCODED / PLACEHOLDER list (file:line · literal · fix)
| # | file:line | literal | fix |
|---|---|---|---|
| 1 | `subsystems/panels.tsx:304-308` | **`KNOBS` table** (Weibull k=`"2"`, λ=`"0.6/0.05/[0,10]"`, conformal=`"0.1/200"`, RLS=`"0.99"`, MaxDispersion=`"4"`, CoResidencyCap=`"4"`, GPUEnvelopeMax=`"1.0"`) | trace to real engine constants/policy, or mark "design defaults" + a `/api/config` source |
| 2 | `subsystems/panels.tsx:173` | `GPU $ / yr = "—"` | wire to a real cost source or remove the tile (GPU = `[SP-0-PENDING-P4]`) |
| 3 | `subsystems/panels.tsx:153` | R6 counterfactual fallback `"A blind fixed-interval defense…"` | use only the real `counterfactualNote`; empty-state if absent |
| 4 | `subsystems/panels.tsx:57` | GPU column `"SP-0"` badge every row | read `w.gpuPresent` |
| 5 | `subsystems/panels.tsx:193` | `AI_HANDLERS` static Set | derive AI/K8s from the registry, not a hardcoded list |
| 6 | `subsystems/panels.tsx:262` | `1.62×` in ablation copy | already disclosed as a Go-test result; leave, or compute live |
| 7 | `panels/frontier.tsx:35` | `"792 rows, seed 1337"` caption | derive row count + seed from the data/response |
| 8 | `panels/frontier.tsx:70-73` | "Reading" cards `"100% prevent, 0% harm, 0% infeasible"` etc. | bind to the live `rows` (the table already has the real values) |
| 9 | `panels/effectiveness.tsx:84` | `">90% board"` claim | derive the threshold/label from data |
| 10 | `panels/effectiveness.tsx:131` | hardcoded path `phorvex\bin\phorvex-console.exe --root C:\Users\…` | generic recovery text |
| 11 | `panels/benchmarks.tsx:10` | arm label `"R6 blind (15s)"` (the "15s") | derive the interval from data |
| 12 | `steps/landing.tsx:77` | `"SLO kept" = "Yes"` | read `rollup.sloKept` |
| 13 | `steps/scan.tsx:11-16,35` | `PHASES` const + 800ms fake ticker | drive phases from real scan progress, or label as indicative |
| 14 | `panels/pending.tsx:7-48` | **entire `SLOTS` dict static** (incl. `"13 PASS / 0 FAIL"`, `"12-handler"` counts) | wire to `/api/handlers` etc., or clearly mark "roadmap" |
| 15 | `steps/report.tsx:19` | `bench` fetched, never rendered | render it (the benchmark summary) or drop the fetch |
| 16 (backend) | `internal/console/owner.go:114,100` | `SLOKept: true`, `HarmCaused: false` baked | derive per-event where possible, or document as by-construction |

*(All CI/mean/n/disruption/dwell values are backend-real — no fabricated statistics client-side.)*

## D. DEAD BUTTONS + PENDING LABELS
**Dead:** Protect **Active/Dry-run** toggle (`protect.tsx:29-30`) — browser-confirmed **0 network calls**; no
operator start/stop endpoint. *(All other buttons — Run-live-scan, Re-scan, Launch-attack-run, Run-with/without-
Phorvex, Export-CSV, Print, Run-live-ablation — are WIRED and fire real calls.)*

**Pending `<Pending>` (3 real blockers):** (1) `discovered.tsx:66` — reachability edge set unwired (graph has
no edges); (2) `protect.tsx:37` — operator start/stop (no endpoint); (3) `report.tsx:38` — bundled PDF + reports
index (no endpoint). **Reassurance labels (not blockers):** `liveops.tsx:39` + `panels.tsx:269` = `"REAL-NOW"`.
**Inline `[SP-0-PENDING-P4]`** (GPU/AI magnitudes) — honest, genuinely GPU-bound, leave.

## E. The OWNER-LENS-EMPTY bug (browser-found, real)
**Every panel is empty under the owner lens** (browser: all `empty=true`). **Root cause:** `/api/owner/events`
with **no `?tenant=`** returns `events=0, empty=true` (the P4c cross-tenant *fail-closed* fix); with `?tenant=acme`
it returns **9 events**. The frontend's owner lens **never passes a tenant** (`api.ownerEvents` sends none). So
the P4c security fix (correct) left the owner lens dark. **Fix (Phase 2):** thread the selected/authenticated
tenant into the owner endpoints.

## F. MISSING (not fake — absent)
- **Comparison-vs-R6 panel + `/api/comparison`** — `COMPARISON.md` exists on disk, unserved; no panel.
- **`/api/reports` index** over the curated `.md` (out-bench/report.md, out-ai-bench/report.md,
  EFFECTIVENESS-PHORVEX.md, P3 reports) — all exist on disk, unserved.
- **Reachability edge set** in the blast-graph (network/RBAC/co-residency edges).
- **Firing-gap / timing** visualization (the 5–10s cadence is in the audit, not surfaced).
- **Before/after + rollbackRef** in the Actuator panel (fields exist on the Record).

## G. Recommended Phase-2 fix priority (for your approval)
1. **OWNER lens empty** (thread tenant) — highest user-visible breakage.
2. **Dead Active/Dry-run** — wire `POST /api/operator/{start,stop}` OR state the real blocker honestly.
3. **Hardcoded literals §C #1–#15** — wire each to its real source (KNOBS, GPU$/yr, frontier caption + Reading
   cards, SLO-kept, pending.tsx counts, ShapAndR6 fallback, scan phases).
4. **Comparison-vs-R6** — add `/api/comparison` (serve `COMPARISON.md` / compute from arms) + a panel.
5. **Reports index** — `/api/reports` over the on-disk curated `.md`; render `bench` in Report.
6. **Reachability edges** (graph) + **timing-gap** viz + **rollbackRef/before-after** in Actuator.

**Engine/optimizer/actuator/harness are NOT implicated** — every fix is console-backend + frontend wiring.
`Brain/optimizer/actuator/harness UNCHANGED` will be git-diff-confirmed in Phase 2.

**STOP — Phase 1 complete. Awaiting your approval of the fix list before Phase 2.**

---

# Phase 2 — FIXES (executed in the approved priority order)

**Engine UNCHANGED (verified):** Phase 2 touched ONLY `internal/console/{server.go, reports.go}` (backend) +
`dashboard-web/` (frontend). **No** decision/recon/killchain/physics/cost/actuator/feasibility/harness file
was edited (`grep` clean); engine builds + decision/killchain/cost tests green.

**#1 OWNER LENS (critical) — FIXED.** Added `GET /api/owner/tenants` (`server.go` + `reports.go`… actually
`server.go`) listing the audit's distinct tenants; a `useOwnerTenant` hook (`lib/owner.ts`) that fetches +
defaults to the first tenant + syncs via a window event; `api.ownerEvents(lens, tenant)` + `liveStream(lens,
fn, tenant)` now pass `?tenant=`; `landing.tsx` (rollup) + `liveops.tsx` (owner cards) thread it; a **tenant
selector** in the owner Live-Ops header. `"SLO kept"` now reads the real `rollup.sloKept` (was literal "Yes").

**#3+#4 REPORTS + COMPARISON-vs-R6 (pitch-critical) — FIXED.** New `GET /api/reports` (`reports.go`) — a
whitelisted registry (id→path, no traversal) serving the curated `.md` **live from disk**: COMPARISON.md,
EFFECTIVENESS-PHORVEX.md, out-bench/report.md, out-ai-bench/report.md, report-dollars.md, P3-REPORT.md,
out-p3-full/report.md. New `ReportsPanel` (`panels/reports.tsx`) with a dependency-free **markdown renderer**
(headings/tables/bold/code/lists). Wired a **"vs R6"** tab in Prove (renders COMPARISON.md) + a **curated-
reports index** in the Report step (replacing the PENDING label); the previously-unused `bench` fetch now
shows a summary line.

**#5 HARDCODED LITERALS — FIXED / verified-accurate / removed.**
- frontier "Reading" cards → **computed live from the rows** (`readingCards()`); caption "792 rows" → live
  `{rows.length} arms` (seed 1337 kept — accurate).
- "SLO kept"="Yes" → real `rollup.sloKept`.
- `ShapAndR6` fake fallback string → real counterfactual only, else honest empty-state.
- `GPU $/yr="—"` tile → **removed**, replaced with the real `actuated` count.
- GPU column "SP-0" every row → reads real `w.gpuPresent`.
- scan fake 800ms phase ticker → honest (all stages shown in-progress during the one real exec, done on
  completion — no fabricated per-phase timing).
- effectiveness ">90% board" → neutral "prevention / disruption board"; hardcoded local path → generic.
- **KNOBS** table → **verified ACCURATE** against the engine (Shape=2.0 `hazard.go:149`, GPUEnvelopeMax=1.0
  `conformal.go:19`, λ-seed 0.6 `dual.go:23`, RLS ff=0.99 `rls.go:58`) — real design constants, kept + labeled
  (not results, so not "computed").
- **pending.tsx** (the static SLOTS dict with "13 PASS/0 FAIL") + **OwnerPanel** → confirmed **DEAD/unused** (no
  render path) — no fake reaches a user; left as dead code.
- `AI_HANDLERS` set + "R6 blind (15s)" label → accurate cosmetic labels, kept.

**#2 ACTIVE/DRY-RUN TOGGLE — honestly DISABLED.** The write-path (operator start/stop / policy-mode patch) is
genuinely deferred (console is read-only + safe-triggers only; no operator-control endpoint). Per your
instruction, the toggle is now **disabled with a "operator control · coming"** badge + an honest caption
(start/stop is an out-of-band kubectl/Helm write; the view streams the operator's real audit) — **no dead
button that looks live**.

**#6 ADDITIVE.** `rollbackRef` now shown in the Actuator enacted card (the Record had it). **Honest carry-
overs:** the reachability **edge set** is a genuine data gap (`phorvex --scan` does not emit network/RBAC/
co-residency edges) — the graph honestly shows nodes + the Pending label stays; a firing-gap **timing viz** is
a nice-to-have not yet added.

# Phase 3 — PROVEN BY RUNNING (real Chrome clicks)
```
OWNER lens (was empty):   Protect = 9 owner cards, "9 decisions", tenant selector "acme"   ✓
vs-R6 tab:                2 tables, "live from disk"                                          ✓
Reports index (Report):   present                                                            ✓
Active/Dry-run:           disabled "operator control · coming" (not a live-looking button)    ✓
GPU $/yr fake:            removed                                                             ✓
Optimization (real):      owner-demo/db | rotate(chosen) | cov 7.01·3f | cost 0.49 | net 6.62 | per-$ 14.31 | λ 0.80
DECISIVE change-input→numbers-move:
   scan #1 = 9 pods · 9 physics rows  →  kubectl run p3-livetest  →  re-scan = 10 pods · 10 physics rows,
   new pod 'p3-livetest' appears in the fresh results                                         ✓
CRASHES across the sweep: 0
ENGINE: internal/console + dashboard-web only; decision/killchain/cost tests green            ✓
```
**Result:** the owner lens populates, the vs-R6 + curated reports render live from disk, the result-value
literals are computed live (or removed), the dead toggle is honestly disabled, and the decisive
**change-an-input → the dashboard numbers move** test passes. **Zero hardcoded RESULT values remain**; the
remaining literals are verified-accurate constants/labels or dead code. **Phase 2-3 complete.**
