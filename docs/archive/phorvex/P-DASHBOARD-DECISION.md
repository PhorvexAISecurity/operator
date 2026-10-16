# P-DASHBOARD — Step 1 decision: the Phorvex Console (web app)

**Date:** 2026-06-06 · **Status: DECISION FOR APPROVAL — STOP before building (Steps 2–3).**

Build Phorvex's production-grade, demoable, **investor- and customer-facing web-app console** — a
GROWING SHELL that later stages (RL pentester, multi-tenant, real-fleet/GPU) plug into. Professional,
**not vibe-coded** (this is what investors judge). Real data where it exists (kind); honestly-labeled
`demo/kind` or `[PENDING]` where a later stage is needed — **never fake live-production data.** Both
products (K8s + AI). No hardcoded values where a value should come from the live system/reports. **It
READS the brain/actuator/harness outputs and TRIGGERS their existing entrypoints — it does not change
the brain, actuator, or harness core.**

**Method.** A 5-expert search (enterprise security-product UX, investor/demo storytelling, frontend
architecture, data-viz, B2B SaaS): 4 data/IP/entrypoint mappers → 5 experts → 3 dashboard
architectures, **adversarially scored** against an eligibility gate (ineligible if it misses the
metric-completeness audit, the owner view leaks any IP, it's K8s-only, it fakes/hardcodes a
buyer-checkable number, or it's not a professional extensible shell). The scorers **verified headline
numbers against the real files and traced the owner-view field paths.** I authored this from the result.

---

## 1. Candidates (all eligible, all investor-grade)

| Candidate (spine) | Total | Note |
|---|---:|---|
| **Unified Web-App SPEC** ✅ (single-binary pure-Go; balanced spine) | **34/35** | only candidate with full marks on BOTH professional-not-vibe-coded (5) and demoable-investor-grade (5); strongest owner-view leak trace |
| Evidence-Spine Dashboard (metric audit as spine) | 32/35 | identical verified evidence base + IP-wall; narrower spine |
| Investor-Spine (demo flow as spine) | 32/35 | identical evidence base + IP-wall; demo-first spine |

All three share the same verified evidence base and the same **server-side whitelist IP-wall**; the
winner balances the demo, the evidence, and the live-operator views and is the most buildable.

---

## 2. Tech architecture (Requirement F) — single-binary pure-Go, buildable TODAY
**Stack:** one binary `phorvex-console.exe` — Go stdlib `net/http` + `html/template` + `//go:embed`,
a hand-crafted **modern-CSS design system** (not a generic component kit), small **vanilla-JS / SSE
islands** for live tails, charts as **server-rendered SVG or vendored embedded Chart.js (no bundler)**.
- **Toolchain reality (verified in-env):** **Go 1.26.3 is present → buildable today with `go build`,
  zero install.** Node v24 / npm 11 are also present but **NOT needed** — React would reintroduce a
  bundler + `node_modules` and hurt the single-binary demoability. Greenfield (no existing `web/` dir).
  **Recommendation: the single binary** — the most demoable, professional artifact (one `.exe` an
  investor/customer runs with no dependencies). React is reserved only if rich client charting later
  demands it.
- **Read path (the backend is the ONLY reader):** `out-*/metrics.jsonl` (streaming `json.Decoder`),
  `phorvex.exe --audit-json` (tail/fsnotify), `phorvex/*.md` reports (read-only parse for
  headline/provenance), `provenance.json`. A read-only append-only run-history store backs trend panels.
- **Trigger path (safe `os/exec` of EXISTING entrypoints):** `phorvex.exe --scan / --ablation /
  --native-demo / --audit-json`, the operator loop (`active|dry-run`, `PHORVEX_ACTUATOR=native|phoenix`),
  `harness.exe -config <yaml>`, the `p3report`/`p3deep` post-processors. **Nothing edits core.**
- **Extensibility:** one panel = one self-registering module `{id, audience, dataSource, render}` — the
  growing shell. Each carries a **green (real) / amber (labeled-pending) / red (forbidden-fake)** state.

---

## 3. The 21-tab inventory (3 lenses: Investor | Operator | Customer-Owner)
The persistent **Lens toggle** re-scopes both the visible tab set AND the server payload — enforced at
the **auth scope / handler**, not by hiding DOM (three lenses, not three apps).

**Spine (product working in real time):** 1. Live Phorvex — Decisions + WHY (SSE tail of `--audit-json`,
selected + rejected/infeasible, predictive-horizon) · 2. Run Attack Agents on-demand (trigger
`harness -config`, stream `metrics.jsonl`+`report.md`) · 3. **My Platform — Owner View (IP-protected)**.
**Effectiveness + proofs:** 4. Defense Posture / NOC Home (controls banner: `negativeControl` PASS,
`masterSeed=1337`) · 5. **Effectiveness — the >90% hero board (every number with 95% CI)** · 6. Benchmarks
(sub-tabbed: Zero-Day Frontier | Dwell | Feasibility/Harm | Learnability/Reuse | Schwartau | Recon/Ablation
1.62×+1.20× | Recon-validity-lifetime law | Controls/Provenance) · 7. P3-DEEP Structural Frontier · 8.
Platform Physics Scan (`--scan`, honest-absent on kind) · 9. Live Kill-Chain Context (moved-before-next-stage)
· 10. Decisions/Audit (full rationale — **vendor scope only**) · 11. Native Actuator Proof (13 PASS/0 FAIL)
· 12. **AI / Inference Product** (attack surface REAL-NOW; **AI defense `[SP-0-PENDING-P4]`**).
**Narrative (investor dock):** 13. Narrative Cockpit · 14. **The Moat — Deterministic Brain (investor-only:
1.62×, EMR, scarcity scalar, submodular, SHAP, no-LLM)** · 15. TAM & Both-Products Matrix · 16. ROI / Unit
Economics (real `roi{}` $, labeled kind/modeled; GPU `[PENDING-P4]`) · 17. Comparison vs R6 · 18. Validity &
Provenance (the BS-detector: `masterSeed`, `rawLogPath`, `commands[]`, pre-registered H1/H2/H3).
**Governance + customer + shell:** 19. Configs & Policies · 20. Acceptance Loop / Evaluation Mode · 21. Auth &
Multi-User (scaffolded-but-simulated-until-P-VCLUSTER) · + a Threat-Coverage (MITRE ATLAS/OWASP) panel + a
Tech & Shell Architecture panel.

---

## 4. Data-source map (every panel → a REAL source or labeled `[PENDING]`)
**Real-now (verified on disk):** disruption ~98–100% + CI ← `out-p3-full/metrics.jsonl disruptionVsOracle`
(792 rows) · work-preserved 100% ← `[work-preserved]` marker · fast-attacker 21/21 ← `oracleAchieved` ·
explainability 139/139 ← `--audit-json` · dwell PX 5.1 / blind 12–15 / no-MTD ~20s + CI ←
`attackerDwellSeconds` (verified `d-nomtd`=20.276s) · P3-DEEP frontier + recon-validity law ←
`out-p3deep` (792 rows) + `P3-DEEP-REPORT.md` · 1.62× ← `--ablation` · 1.20× EMR ← `--scan` · native
actuator 13/13 ← `--native-demo` + `out-pactuator` · ROI $ (avoidedBreach $4.88M, gpuOverheadSaved $2628)
← `roi{}` block **labeled modeled-assumption, not measured production savings** · AI attack surface ←
`out-ai-bench` (2310 rows) + ATLAS/OWASP. **CI methodology:** Wilson on proportions, t/bootstrap on dwell.

---

## 5. Metric-completeness audit (Requirement A) — nothing silently absent
Every VC+customer-expected metric is mapped (above) or labeled `[PENDING]`+stage. The audit hunted its
own gaps; the two that matter:
- **[RED FLAG — MUST NOT FAKE] AI-product DEFENSIVE efficacy is ABSENT.** Verified: `d-phorvex-slot`
  `disruptionVsOracle=0` on **all 462 ai-bench rows** ("registered stub") — the AI product has **zero
  measured PX defense today**; the 2310 rows prove the AI **attack surface**, not PX defense. **Added: an
  explicit `AI-defense efficacy [SP-0-PENDING-P4]` status on every relevant tab; no panel may ever derive
  an AI "effectiveness" from attack-surface rows** (that would be a fabrication and an eligibility-killer).
  This is the single biggest VC trap — handled honestly.
- **[MISSING → serialize] `preemptMargin`/`projectedNextStageSec`** are on `model.Decision` but **not in
  `audit.Record`** — so the moved-before-next-stage column can't populate from the audit JSONL yet. It
  sources from `--scan` stdout meanwhile, the audit column labeled `[PENDING-serialize]` (a small additive
  audit serialization may close it later — not a brain change).
- Added tiles flagged as derivable-or-pending: MTTR-equiv, FP/precision (from `out-fpprobe` +
  `falseDefensiveActions=0`), rollback-success, coverage-breadth, deployment-profile.

---

## 6. Owner view (Requirement C) — server-side whitelist DTO; an IP leak is structurally impossible
**Verified NECESSITY (not theater):** `audit.Record` (log.go L24–71) carries `Risk/Cost/Net/Residual/
ThreatPosture/Exposure/Belief/AssetValue/BlastRadius/PerDollar/CoveredWeight/Lambda/ProactiveRate/
Attribution` + the raw `Reason` **all inline**, and `coverageReason` (coverage.go L383–393) formats
`cov=.../$...=... per-$ > λ=... hazard=... pHold=...` **verbatim into the Reason string**. A naive
`json.Marshal(Record)` on the owner path **would leak the entire moat instantly.**

**SHOW** (the ONLY fields the owner endpoint returns — built by explicit field-copy into a NEW
`OwnerEvent` struct): tenant/ns/pod (their own), action, selected, actuated, dryRun, handler,
objectsTouched[] (their own objects), rollbackRef, mutationKind (as a reversible|forward-only **chip**),
attacker dwell, attacks-evicted counter, work-preserved, harm (boolean), attack-prevented (derived),
**SLO-kept (BOOLEAN only — never the numeric score)**, a coarse plain-English attack-stage label, a
**server-authored plain-English "why" one-liner** (templated from owner-safe outputs only), and
r6Counterfactual (the **outcome**, sanitized — not the math). The owner sees the outcome: *"targeted,
harm-free protection that kept your work and SLO."*

**HIDE** (must not even be CONTAINED in the payload): the EMR formula + scarcity scalar
(`image-rarity·EPSS·co-residency·model-rarity`) + every PhysicsWitness multiplier; all FactWeights +
the recon-fact taxonomy + CoverByAction; the submodular objective + greedy/budget internals; PerDollar +
the 1.62× gate + ProactiveRate; Lambda + all dual/cost math; raw Risk/Cost/Net/Residual/ThreatPosture/
Exposure/Belief/PHold/StageHazard/PreemptMargin/ProjectedNextStageSec/AssetValue/BlastRadius; the entire
Attribution[]/SHAP; and the **raw Reason/CounterfactualNote/coverageReason** strings (re-templated
server-side, never passed through).

**ENFORCEMENT (whitelist, never blacklist):** (1) the owner handler builds `OwnerEvent` by explicit
field-copy and **never** marshals `Record`/`Decision` — a newly-added IP field can never leak by default;
(2) a **serializer unit test asserts the owner JSON contains none of the redacted field names** (emr,
scarcity, lambda, perDollar, coveredWeight, attribution, risk, residual, threatPosture, exposure, belief,
pHold, stageHazard, preemptMargin, …, and the raw reason) — **this test IS the eligibility gate**; (3) the
vendor/investor tabs are a **separate auth scope the owner scope is physically barred from**; (4) the owner
may trigger only the operator loop / `--native-demo` against THEIR OWN namespace — `--ablation` and the
`--scan` EMR-ablation are vendor-only; (5) the template layer does **no** redaction itself (a panel cannot
render a field absent from the payload).

---

## 7. Customer-acceptance loop (Requirement D) — Evaluation Mode (the buyer-question funnel)
A built-in "Evaluation Mode" that acts AS IF a customer is evaluating: each buyer question resolves to a
real on-disk artifact OR an honestly-labeled `PENDING-<stage>`. Q1 *"Am I defended now & is it sound?"* →
Defense Posture + controls (PASS) · Q2 *"What did it do & why not just blind rotation?"* → Live decisions
+ Compare-vs-R6 (PASS) · Q3 *"Did it help MY platform without breaking it?"* → Owner view (PASS, kind) ·
Q4 *"How effective, with confidence?"* → Effectiveness hero + CIs (PASS) · **Q5 *"Show me the one case
where you LOSE"* → the unconstrained zero-day where blind cleanly wins, printed plainly (PASS — the honesty
gate)** · Q6 *"Reproducible / not cherry-picked?"* → Provenance drawer (PASS) · Q7 *"Does it work on AI?"*
→ AI attack surface REAL, **AI defense `[SP-0-PENDING-P4]`** (PENDING, labeled) · Q8 GPU/$ magnitudes →
PENDING · Q9 tenant isolation → P-VCLUSTER PENDING. **Acceptance = complete when every question resolves
to a real artifact or an honestly-labeled pending, with zero faked answers and zero owner-view leaks.**

---

## 8. Growing-shell slots (E) + both products + both lenses
**Slots pre-wired into the registry today as labeled-`[PENDING]` modules** (plug in with no rebuild):
**P-REDTEAM** (RL pentester — the weakest-wired slot; no data contract yet), **P-VCLUSTER** (multi-tenant —
**half-real now**: `PhorvexPolicy` is namespace-scoped + tenant-keyed from line one, so data partitioning +
scope-enforced redaction work today; only identity/SSO + isolation evidence is pending), **P4** (real-fleet/
GPU magnitudes + live real-cluster streaming, bound to `capabilityPending` carrier fields), and
Integrations/SIEM. **Both products:** K8s is proven-on-kind (real CI-backed numbers); the **AI product is
first-class in design** — attack surface real-now, **all AI defensive magnitudes honestly `[SP-0-PENDING-P4]`**.
**Live streaming:** kind-now / real-after-P4a, labeled.

---

## 9. Honest open risks (eligibility-critical, carried openly)
1. **AI defense is UNPROVEN** — `d-phorvex-slot disruptionVsOracle=0` across 462 rows; any panel deriving an
   AI effectiveness number would be a fabrication. Must render `[SP-0-PENDING-P4]` everywhere; the
   acceptance-loop RED-state guard must catch any slip.
2. **Owner-view leak is STRUCTURAL** — the whitelist DTO + serializer unit test + server-re-templated "why"
   is the ONLY safe construction; a blacklist would silently leak any newly-added IP field.
3. **Serialization gap** — `preemptMargin`/`projectedNextStageSec` are on `Decision` but not `audit.Record`;
   the moved-before-next-stage audit column is `[PENDING-serialize]` until added (sources from `--scan` now).
4. **ROI $ are modeled carrier values** (`avoidedBreachValue $4.88M`, `gpuOverheadSaved $2628`), not measured
   production savings — must be labeled "modeled assumption, kind-scale," never "measured."
5. **Scope** — 21 tabs is a large build; the shell + the real-data tabs ship first, the pending slots ship as
   labeled modules, so the console is demoable early and grows without a rebuild.

---

## 10. If approved — Step 2/3 + pass filters
**Build** the single-binary pure-Go console: the shell + the module registry + the 3-lens auth scoping; the
real-data tabs (Effectiveness/Benchmarks/Frontier/Physics/Actuator/Decisions/Comparison/Provenance/ROI/Configs);
the **owner view via the whitelist `OwnerEvent` DTO + the serializer redaction unit test**; the run-attack-agents
trigger; the AI-product split (attack-surface real, defense `[SP-0-PENDING-P4]`); the growing-shell `[PENDING]`
slots; a professional bespoke design system. **Prove:** the app runs; every panel shows correct REAL data from
the actual reports/metrics/harness (or honest `[PENDING]`); run-attack-agents triggers a real harness run and
shows results live; **the owner view provably exposes ZERO IP internals (the serializer test asserts the redacted
names are absent)**; the >90% numbers display with CIs; all three lenses work; the acceptance loop runs.

**PASS filters:** app builds + runs; all features present (metric-completeness audit satisfied); **owner view
exposes ZERO IP internals (verified by the serializer test)**; real data where it exists, pending honestly
labeled (nothing faked/hardcoded); both products + both/three lenses; run-attack-agents works live; growing-shell
slots in place; professional UI; **Phorvex brain/actuator/harness unchanged**.

---

## 11. Decision
**Build the Unified Web-App SPEC** — a single-binary pure-Go console (buildable today on the in-env Go 1.26.3,
no Node), 21 tabs as self-registering modules across 3 lenses (Investor | Operator | Customer-Owner), every
panel sourced from a real report/metrics/entrypoint or labeled `[PENDING]`, the **platform-owner view enforced
by a server-side whitelist DTO + a redaction unit test that makes an IP leak structurally impossible**, the
run-attack-agents trigger over the existing harness, and growing-shell slots pre-wired for P-REDTEAM/P-VCLUSTER/
P4 — **brain/actuator/harness unchanged**.

**Honest headline:** a genuinely investor-grade, IP-disciplined console where **every buyer-checkable number
traces to a real file**, the **K8s product is proven-on-kind**, the **AI product's attack surface is real but
its defense is honestly `[SP-0-PENDING-P4]`** (never implied proven), and the owner view leaks **zero** IP by
construction. Demo-ready after this stage; the moat math lives only behind the vendor/investor auth scope.

**>>> STOPPING for your approval before building Step 2/3. <<<**
Approve the Unified Web-App SPEC (single-binary pure-Go, 3-lens, server-side IP-wall, growing shell, as
scoped), or tell me to adjust scope first (e.g. ship the spine + effectiveness + owner view + run-attack
first, dock the rest as modules).
