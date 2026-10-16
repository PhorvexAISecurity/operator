# Mathematical Assurance: source manifest (Phase 1)

This manifest fixes the review baseline for Part I of the PHORVEX Mathematical Assurance
program: the exact code, deployment, documents, rulings, configuration, registries,
schemas and tests that the [decision flow](PHORVEX_CURRENT_DECISION_FLOW.md) and the
[delta ledger](BRAIN_TICKET_CODE_DELTA_LEDGER.md) were built against.

**Reconstruction rule (from the program plan):**
`Brain baseline + post-Brain approved rulings + current implementation = candidate current PHORVEX truth`.
Where those disagree, the ledger records the disagreement; it does not guess.

**Exit criterion for Phase 1:** the team agrees on the pins in §1 and the authority order
in §3. Every pin below was observed on 2026-10-06.

---

## 1. Code and deployment pins

| Artifact | Version / date | Location | Authority | Notes |
|---|---|---|---|---|
| Code | `f8787fa81e5a9844cda01a4910a8ece68f7d2748` (2026-10-06, `release: v0.4.215`) | branch `main`, github.com/PhorvexSecurity/operator | **current implementation** | Go module `phorvex/` |
| Deployed operator | `phorvex:0.4.215`, image digest `sha256:86dad3caca17c07d16d82f8f3c5f3ff16a6e5499d58f25927011bcbee5abc738` | EKS `phorvex-dev-eks`, `phorvex-system` | runtime truth (dev) | Argo `phorvex-stack` synced to `f8787fa8` |
| Deployed console | `phorvex-console:0.4.215` | same | runtime truth (dev) | |
| Harness release pin | `workflow/releases/CURRENT.yaml`, recorded 2026-09-16, `v0.4.119` | repo | **stale, not used** | predates ~95 releases; must not be read as current |

Code and deployment agree, so "current code" and "what is running in dev" are the same
pin for this review.

## 2. Brain baseline

| Artifact | Version / date | Location | Authority | Notes |
|---|---|---|---|---|
| Method decision (approved P1 method) | **revision `803dfe68`, 2026-06-07** | `phorvex/METHOD-DECISION.md` (`git show 803dfe68:phorvex/METHOD-DECISION.md`) | **Brain baseline** | States "Deterministic brain, NO LLM in the decision path." The approved text claimed a "(1−1/e) guarantee" and "λ solved". |
| P1 build & live-run report | dated 2026-06-05 (last edit 2026-08-17) | `phorvex/P1-REPORT.md` | **Brain baseline** (as-built P1) | |
| Later edits to METHOD-DECISION.md | `00f7be82` (2026-08-17, PHVX-22: removed false optimality-bound claims); `fe3ef74c` (2026-09-01, T0-B: separated λ audit semantics) | same file | **treated as post-Brain rulings** | The current file is therefore *not* the baseline; see ledger DL-004, DL-023 |
| Earlier product documents | 2026-06-04 | `PHORVEX_PRD.md`, `PHORVEX_V1_MVP.md` (Word documents despite the `.md` extension) | context only | product scope, not math |
| Phoenix locked architecture | 2026-06-07 | `architecture.md`, `decisions.md` | context only | R6/Phoenix substrate, predates the Phorvex brain |

**Not a baseline:** `workflow/assessments/20260912-brain-recommendations/REPORT.md` is a
recommendation report. Its BR-1…BR-10 are explicitly not filed issues or approved changes.

## 3. Authority order for math semantics

When sources disagree, the review uses this order. It records the conflict in the
ledger; it does not resolve it by rank alone.

1. A signed ruling for the item, i.e. one of:
   - `workflow/fixes/<id>/03-decision.md`;
   - `workflow/campaigns/2026-09-20-post25-live/math-design/*-LEAD-CONTRACT.md` or
     `*-LEAD-DISPOSITION.md`;
   - a math ruling in `reports/`.
2. Current semantic contracts:

   | Document | Last change |
   |---|---|
   | `phorvex/AUDIT-CONTRACT.md` | 2026-09-21 |
   | `phorvex/docs/decision-trace-v2.md` (V2–V7) | 2026-09-24 |
   | `phorvex/docs/actuator-repertoire.md` | 2026-10-04 |
   | `phorvex/docs/recon-cover-map.generated.md` (CI-checked) | 2026-10-05 |
   | `phorvex/PARAMETER-GOVERNANCE.md` | 2026-09-21 |
   | `phorvex/CONSTANTS-REGISTRY.md` | 2026-09-17 |
   | `phorvex/M99-EXISTENTIAL-CONTAINMENT.md` | 2026-09-08 |
   | `phorvex/docs/M100_REPRESENTATION.md`, `scoped-outcome-runtime.md` | 2026-09-22 |
   | `phorvex/docs/operation-journal.md` | 2026-09-19 |

3. Earlier decision documents:

   | Document | Last change |
   |---|---|
   | `phorvex/P-PHYSICS-DECISION.md` | 2026-08-23 |
   | `P-OPTIMIZE-RATIO-DECISION.md` | 2026-08-23 |
   | `P-GPU-OBSERVABILITY-DECISION.md` | 2026-08-20 |
   | `P-ACTION-FLOW-COST-DECISION.md` | 2026-08-17 |
   | `P-THREAT-POSTURE-DECISION.md` | 2026-08-12 |
   | `P-CONTEXT-DECISION.md` | 2026-08-12 |
   | `P-ACTUATOR-SET-COMPLETENESS.md` | 2026-09-19 |
   | `docs/archive/coversets/COVERSETS-DECISION.md` | 2026-08-16 |

   Several are partly stale; see §8.
4. The Brain baseline (§2).
5. The code. It is the implementation truth, never the *intended* rule by itself.

## 4. Post-Brain ruling set

This is the "resolved tickets newer than the Brain" set. It was built from:
- 193 issue entries;
- 195 fix records;
- 18 math-design documents;
- 2 assessments + 5 tier dispositions;
- ~45 merges touching math packages.

**Merge state on `main` is the authority for "resolved"** (§8 explains why the register
is not).

| Category | Count | Meaning |
|---|---|---|
| A | 66 | signed decision/contract/ruling **and** code merged |
| A\* | 14 | merged, but no signed decision document in the repo (implementation report or commit only) |
| R | 5 | signed ruling that keeps the current design (no code change) |
| No-change closure | 1 | M-118 |
| HELD | 1 | M-79 (wiring merged) |
| P / OPEN | 4 | M-41, M-105, M-139, M-149 (no approved change) |
| Merged without an issue ID | ~21 | T0/T1/CAT/POST25 records + 10 later PRs, 9 of them with **no ruling record** (§4.6) |

Abbreviations in the tables below:
- `fx/` = `workflow/fixes/`
- `md/` = `workflow/campaigns/2026-09-20-post25-live/math-design/`
- PR numbers are on `main`.

### 4.1 Post-stable math-design program (rulings 2026-09-20/21; delivered in combined PR #262)

| ID | Area | Status | Ruling | Summary |
|---|---|---|---|---|
| M-98 / M-144 | objective, λ | A | `fx/POST25-ECONOMICS/03-decision.md`; `md/M098-M144-CONTRACT.md` | opt-in β replaces λ as the ECost coefficient; legacy λ otherwise; zero λ valid; no floor; trace V4 |
| M-156 | cost, missing data | A | `md/M156-LEAD-CONTRACT.md` | missing load ≠ measured zero; Unknown/Draining floors; unsupported-regime bound via max with slack; trace V5 |
| M-106 | belief learning | A | `md/M106-LEAD-CONTRACT.md`; `fx/POST25-M106*` | self-update removed; typed outcomes reporting-only, never feed pHold/cost/ranking |
| M-135 | dispatch gates | A | `md/M135-LEAD-CONTRACT.md` | per-tick policy observation; brakes are read-only |
| M-103 | shared capacity | A | `md/M103-LEAD-CONTRACT.md` | typed integer capacity vectors; unknown inventory fails closed; trace V6 |
| M-54 | rotate grace | A | `md/M054-LEAD-CONTRACT.md` | cap 1–300 s, default 30 s |
| M-43 | model-shard cover | A | `md/M043-LEAD-CONTRACT.md` | process cover only under warm-cutover witnesses |
| M-44 | route cover | A | `md/M044-LEAD-CONTRACT.md` | selector epochs earn no networkIdentity credit |
| M-100 | loss representation | A | `reports/m100-representation-209/M_100_MATH_RULING_2026-09-08.md`; `md/M100-LEAD-CONTRACT.md` | loss only from authenticated disclosure evidence; nothing enters gain/cost/λ |
| M-104 | EPSS | A | `md/M104-M151-LEAD-DISPOSITION.md`; `fx/POST25-M104-*` | `1 + EPSS·CVSS/10` at the recon weight only; missing → neutral with reason |
| M-108 | parameter provenance | A | `md/M108-LEAD-CONTRACT.md`; `md/M108-RETENTION-REVIEW-RULING.md` | `decision-parameters.v1` registry, manifest + override hashes per decision |
| M-101, M-117, M-102, M-151, M-125 | existential priority, singleton feasibility, cover vs containment, rarity, operator record | R | `md/M101-M117-LEAD-DISPOSITION.md`, `md/M102-…`, `md/M104-M151-…`, `md/M125-…` | design retained |

### 4.2 Objective, selection, eligibility, feasibility

| ID | Area | Status | Ruling | Summary |
|---|---|---|---|---|
| M-99 | existential priority | A\* | `phorvex/M99-EXISTENTIAL-CONTAINMENT.md` (cites `M_99_MATH_RULING.md`, **absent**) | qualified containment ranks above the economic score |
| M-107 | p0 engine retired | A\* | commit `8b1773a9` | |
| M-110 | λ demand provenance | A\* | commits `e5c9f3e1`, `784951bd` | |
| M-140 | state ownership | A | `fx/M-140/03-decision.md` | policy UID owns λ, RLS, conformal, conjugate memory, clocks |
| M-20 / T1-E / T1-M020 | capability gate | A | `fx/T1-E/03-decision.md` | boolean gate before scoring |
| M-21 | backend support | A | `fx/M-21/03-decision.md` | Phoenix supports only rotate/quarantine |
| M-158 | CRD enum discovery | A | `fx/T3-M158/03-decision.md` | unknown = unverified |
| M-160 | RBAC follows routing | A | `fx/T1-M160/01-proposal.md` | SSAR error fails open as unknown |
| M-68 | TP/PP cutover | A | `fx/T18-M068/03-decision.md` | group model-shard-replace unsupported |
| M-79 | node-exec | HELD | `fx/T1-M079/TICKET.md` | mig-rebind transport-unwired until opted in |
| M-19 | failure feedback | A | `fx/T4-M019/03-decision.md` | exponential cooldown 30 s → 5 min |
| M-22 | zero budget | A | `fx/T6-M022/03-decision.md` | unset = 3; explicit 0 = decide and trace only |
| M-124 | opt-out/brake | A | `fx/T8-M124/03-decision.md` | |
| M-127 | kill-switch recheck | A | `fx/T7-M127/03-decision.md` | refused = selected-not-attempted, no learning |
| M-128 | policy ordering | A | `fx/T18-M128/03-decision.md` | ties by namespace/name/UID (policy order, not Pod order) |
| M-174 | cadence | A | `fx/T2-M174/03-decision.md` | |
| M-183 | PDB in rotation | A | `fx/POST25-VOICE-PDB/03-decision.md` | eviction; exhausted/unobserved PDB refused |
| M-147 | route-rotate SLO | A | `fx/T11-ROUTE/03-decision.md` | zero → unknown |
| M-163 | shadow isolation | A | `fx/V3-M163/03-decision.md` | |

### 4.3 Belief, hazard, clocks, fact weights

| ID | Area | Status | Ruling |
|---|---|---|---|
| T1-A, T1-B, M-25 | stage, clocks, merge | A | `fx/T1-A`, `fx/T1-B`, `fx/M-25` `03-decision.md` |
| M-143 | pHold | A\* | `M_143_MATH_RULING.md` (**absent**) |
| M-27 | event aging | A\* | `M_27_MATH_RULING.md` (**absent**) |
| M-29 | event horizon | A | `fx/T13-M029/03-decision.md` |
| M-26 | anti-decoy | A | `fx/T3-M026/03-decision.md` |
| M-28 | proactive cadence | A | `fx/T1-M028/EVIDENCE_SIGNAL_FIX.md` |
| M-23 | per-action clocks | A (DEPLOYED_PENDING_L3) | `fx/T1-M023/03-decision.md` |
| M-30 | nodePlacement clock | A\* | `reports/m030-20260908/T1_M030_BASELINE.md` |
| M-94 | event trust | A | `fx/V3-M094/03-decision.md` |
| M-153 | ×3 vector steering | A | `fx/T2-M153/03-decision.md` |
| M-150 | co-residency | A | `fx/T5-M150/03-decision.md` |
| M-95 | adapter fact | A | `fx/T4-M095/03-decision.md` |
| CAT-EXACT-TARGET | event binding | A | `fx/CAT-EXACT-TARGET/03-decision.md` |
| M-118 | detector silence | closed, no change | `workflow/assessments/20260910-readiness/MASTER_ISSUES_V3.md` |
| M-149, M-105 | theft stage / exposure double-count | **P (no ruling)** | — |

### 4.4 Cover, effect credit, dispatch and audit semantics

| ID | Status | Ruling |
|---|---|---|
| M-33, M-34, M-35, M-37, M-42, M-45, M-123, M-184, CAT-GUARDRAIL-COVER | A | `fx/T3-M033`, `fx/T8-M034`, `fx/M-035` + `fx/T9-M035`, `fx/M-037`, `fx/T2-M042`, `fx/T11-M045`, `fx/T2-M123`, `fx/CAT-POD-TOKEN{,-VECTOR}`, `fx/CAT-GUARDRAIL-COVER` |
| M-36 | A (MAIN_PENDING_DEPLOY) | `fx/T14-M036` |
| M-46, M-47/M-55, M-14, M-32 | A\* | commit `fc736dc4`; `reports/m047-20260908`; `reports/m014-20260908`; `reports/m032-20260909` |
| M-9, M-10/M-15, M-64/M-73/M-39, M-67, M-40, M-71, M-178, M-16, M-146, M-188, M-191, M-18 | A | `fx/T9-M009`, `fx/T10-M010`, `fx/T13-M064` + `fx/POST25-SERVING-JOURNAL-GATE`, `fx/T25-M067` + `fx/POST25-M067-DRAIN`, `fx/T7-M040`, `fx/T9-M071`, `fx/T14-M178` + `fx/T26-M178`, `fx/T2-M016`, `fx/T5-M146`, `fx/CAT-RESOURCE-TRACE`, `fx/CAT-DISPATCH-REASON`, `fx/M-18` |
| tier-2 credential-claims ruling | A (lead) | `workflow/assessments/20260913-tier2/catalogue-gaps/LEAD-DISPOSITION.md` |
| M-41 | P (PR #185 unmerged) | — |

### 4.5 Sensing, physics, missing data, cost

| ID | Status | Ruling |
|---|---|---|
| T0-C | A (CLOSED) | `fx/T0-C/03-decision.md`: complete decision path, C_hi |
| M-109 | A | `fx/T17-M109`: GPU envelope always applied |
| T1-C (M-111, M-113, M-130) | A (CLOSED) | `fx/T1-C/03-decision.md`: telemetry absence ≠ 0 |
| T1-D, M-142, M-173 | A | `fx/T1-D`, `fx/T7-M142`, `fx/V3-M173` |
| M-115, M-141, M-114 | A\* | `reports/m115-20260908/T1_M115_CONFORMANCE.md`; commits `a7ef4456`, `fe05cc62` |
| M-139 | **P** | flow priors other than kv-reset remain `[ESTIMATE-UNVALIDATED]` |

### 4.6 Merged decision-semantics changes with no ruling record

These add facts, cover, cost/flow and SLO entries for new application-scoped actions.
They are merged but have no workflow fix record or signed ruling, so for Math Contract
v1 they count as **implementation without an approved ruling**:

| PRs | Change | Record status |
|---|---|---|
| #356 | `sensitive-output-policy-activate` | recorded in `fx/CAT-GUARDRAIL-OUTPUT` (approved) |
| #360, #362, #367 | voice-memory-note-revoke, litellm-client-revoke, voice-refund-pair-deny, endpoint-lease-revoke | delivery notes only |
| #363, #364 | LiteLLM eligibility; voice-output-policy-activate, voice-mcp-tool-pin | design notes only; #364's note is a proposal |
| #374, #379, #396 | kv-migrate gate, journal RBAC namespace, voice-session-admission-enforce | no record |
| #434, #437, #438 (2026-10-04/05) | crm-refund-revoke (actuator, Live producer, reachability) | no record |
| #359, #397, #403, #408 | actuator effect semantics | no record |

## 5. Active configuration

| Artifact | Version / date | Location | Notes |
|---|---|---|---|
| Stack values | `f8787fa8` | `deploy/helm/phorvex-stack/values-eks.yaml` | `PHORVEX_ACTUATOR=hybrid` (quarantine via Phoenix/AMTD, every other action native) |
| Trusted detectors | same | `values-eks.yaml` `trustedDetectors` | `vllm/detector-kv-canary`, `vllm/detector-adapter-inv`, `phorvex-system/operator-controller-manager`, **console ServiceAccount**; the chart appends the e2e detector |
| EPSS data | same | `values-eks.yaml` (hand-entered, legacy mode, no expiry) | feed CronJob runs with apply disabled |
| GPU envelope | `0.2925` | `phorvex/charts/phorvex/values.yaml` | value has no ruling (ledger DL-017) |
| Tenant policies | live generations below | `deploy/policies/*.yaml` (manual-sync Argo app `phorvex-policies`) | see table |

| Policy | Generation | λ | Economics mode | Notes |
|---|---|---|---|---|
| ci-reports/ci-reports-defense | 10 | 0.4 | legacy-runtime-lambda-v1 | |
| crm/crm-defense | 11 | 0.4 | legacy | `crm-refund-revoke` on, quarantine off (2026-10-05) |
| document-store/chroma-defense | 9 | 0.4 | legacy | |
| document-store/mongo-defense | 10 | 0.4 | legacy | |
| litellm/litellm-defense | 31 | 0.5 | legacy | |
| mcp/mcp-defense | 10 | 0.4 | legacy | |
| nats/nats-defense | 8 | 0.4 | legacy | |
| vllm/vllm-defense | 59 | 0.5 | legacy | |
| voice/voice-defense | 11 | 0.4 | legacy | |
| verification fixtures (M100, M106) | 1 | 0.4 | **fixed-disruption-aversion-v1** (β = 0.4) | only policies using β |

All nine tenant policies use normSparsity 0.4, flowDisruption 0.6 and cost ceiling 1.2.

## 6. Registries, schemas and calibration artifacts

| Artifact | Version | Location | Notes |
|---|---|---|---|
| Action vocabulary | `v10-live24`: 24 mutating actions (tie-break order is load-bearing) | `phorvex/internal/model/types.go` `MutatingActions`; `decision_trace.go` | 10 vocabulary tiers v2-output16 … v10-live24 |
| Fact kinds | 29 declared kinds | `phorvex/internal/recon/facts.go` | CI drift check: `tools/covermap` + `docs/recon-cover-map.generated.md` |
| Feasibility laws | 12 registered | `phorvex/internal/feasibility/*.go` | |
| C_norm rubric | provisional constants | `phorvex/internal/cost/p1cost.go` `NormCost*` | registry `cost/parameters.go` has 16 entries for 24 actions (ledger DL-009) |
| Parameter manifest | `decision-parameters.v1` | `phorvex/internal/decision/parameter_manifest.go` | manifest + override hashes per decision (M-108) |
| Audit schema | `phorvex.audit.v2` | `phorvex/internal/audit/log.go`; `AUDIT-CONTRACT.md` | |
| Decision trace | `phorvex.decision-trace.v7` (reads v2–v6) | `phorvex/internal/model/decision_trace.go`; `docs/decision-trace-v2.md` | |
| Economics | `legacy-runtime-lambda-v1`, `fixed-disruption-aversion-v1` | `phorvex/internal/model/economics.go` | |
| Learned state | RLS θ/P, conformal residuals, λ, clocks | in process memory only | no persisted calibration artifact; resets on restart |
| Calibration exports | shadow only | `phorvex/internal/calib` | not consumed by production scoring |

## 7. Tests and validators relevant to math

| Artifact | Location | Runs where |
|---|---|---|
| Decision-trace validator `DecisionTraceV2.Validate()` | `phorvex/internal/model/decision_trace.go` | tests + console read path; **no operator caller** |
| Frozen independent trace validator (15 checks incl. greedy replay) | `workflow/fixes/T0-C/validator/audit_trace_validator.py` | CI via `decision/post25_economics_test.go`, `m156_trace_test.go`; not run on live audit |
| Cost audit, regimes, GPU envelope, off-switch | `phorvex/internal/cost/*_test.go` | `pr-validation.yml` go-unit |
| SLO bounds, contracts | `phorvex/internal/slo/*_test.go` | go-unit |
| Cover map drift, fact-kind fixtures | `phorvex/tools/covermap` | go-unit |
| Exactness / optimality | `phorvex/internal/decision/optimality_test.go` | exhaustive sweep needs `PHVX_EXACT_SWEEP=1` (off in CI) |
| Golden decision stream | `phorvex/internal/decision/o1_golden_test.go` | go-unit |
| Envtest gate | `tools/envtest_gate.py` | `pr-validation.yml` go-envtest |
| Claim-language gate | `tools/check-claim-language.py` | `pr-validation.yml` charts (wording only; does not certify math) |

`pr-validation.yml` holds all of the above. `ci.yml` (build/deploy) runs no Go tests.
Whether branch protection requires `pr-validation` was not verified.

## 8. Record-keeping caveats

These do not change the math, but they limit what the records can prove:

- **Issue register is stale.** `workflow_state` reads OPEN for 173 of 193 entries,
  including most whose fixes are merged. About 60 fix `STATUS.yaml` files still read
  IN_PR/PR_READY after merge.
- **Release pin is stale.** `workflow/releases/CURRENT.yaml` (v0.4.119); see §1.
- **Cited rulings are absent from the repo:**
  - `M_99_MATH_RULING.md`
  - `M_27_MATH_RULING.md`
  - `M_143_MATH_RULING.md`
  - `M_115_MATH_RULING.md`
  - `M115-MEASUREMENT-v1`
  - `D-16`
  - `T1_M029_CLOSURE.md`

  Two fix records point to plans under a personal home path.
- **Older decision documents are partly stale:**
  - `P-CONTEXT-DECISION.md` still gates on CoResidency > 1 (removed by M-150).
  - `P-GPU-OBSERVABILITY-DECISION.md` gives a fixed link ceiling (replaced by M-114).
  - `P-PHYSICS-DECISION.md` says Little's law is built (absent by default since M-115).
  - `build/test-harness/ACTUATOR_COVERAGE.md` and a comment in `model/types.go` still
    credit guardrail-rotate with guardrailBypass cover (removed by
    CAT-GUARDRAIL-COVER).
- **Existing anatomy tag.** The workflow anatomy already uses an `anatomy_tag: MATH-GATE`
  (on M-156). Later phases should align with that vocabulary instead of inventing a
  parallel one.
