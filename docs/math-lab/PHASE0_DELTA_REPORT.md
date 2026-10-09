# Math/OR Benchmark Lab: Phase 0 delta report

**Reconciliation:** audit `84aabf0` (image 0.4.211) against deployed `085a9fae` (image 0.4.216), dated 2026-10-09.

**Audience:** OR/Math owner and the Brain maintainer.

**Deliverables:**

| File | Contents |
|---|---|
| `benchmark/mathlab/registry/ALL_MATH_PARAMETERS.refreshed.csv` | 246 rows, 42 columns |
| `benchmark/mathlab/registry/parameter_registry.json` | Schema `math-lab.parameters.v1`, registry `2026-10-09.1` |

Nothing in the operator, charts or policies was changed.

**Citation conventions:**

- Paths are relative to `phorvex/` at `085a9fae` unless they start with `deploy/`.
- `[recon/...]` cites the Phase 0 reconciliation working papers. These are the per-group CSV and MD files, `new-parameters.csv` and `replay-prerequisites.md`. They are not committed; this report and the registry `notes` and `evidence_085a9fae` fields carry their content.
- **Live** means facts read from the cluster on 2026-10-09.
- **Inference** marks a claim derived from source without observing it.

---

## (a) Version reconciliation

| | Audit baseline | Deployed (live 2026-10-09) |
|---|---|---|
| Source SHA | `84aabf0fac751eb588b326a81e063aa57128644b` (merge of PR #430, 2026-10-03) | `085a9fae1c2cc480e17b48fd009ff9d5dd406031` (merge of PR #444, 2026-10-07) |
| Image | `phorvex:0.4.211` | `753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex:0.4.216` |
| Digest | `sha256:73b7590a…6a41` (release commit `cdbf037e`) | `sha256:08364fc17a0092d0abdd9041b8df0bb08444c67597782c2087f62de3b1312ccc` (release commit `a63c7ea3`) |
| Branch | `main`, first-parent | `main`, first-parent |
| `values-eks.yaml` pin inside the source SHA | 0.4.210 / `d2fae6e4` | 0.4.215 / `d43545eb` |
| `values-eks.yaml` pin on `main` | n/a | 0.4.216 / `085a9fae` / digest above (`a63c7ea3`). This equals live. |

**Why the pins differ.** The release job writes the image pin after it builds the image, so the pin inside any source SHA lags one release behind. Only the release commit on `main` matches live. `main` has no `phorvex/` changes after `085a9fae` (`git log 085a9fae..main -- phorvex` is empty). The only later commits are `a63c7ea3` (release) and benchmark-only commits.

**Live state vs git:**

- **Operator: git matches live.** Argo deploys it from `values-eks`, and its flags were verified live.
- **Policies: git does not match live.** The Argo app `phorvex-policies` is manual-sync and OutOfSync. Git declares `spec.objective.costPreferences` in all 9 defense policies. Live has neither `costPreferences` nor `disruptionAversion` in any of them.
- **Other live values:** kill-switch ConfigMap `{engaged:false}`; operator memory limit 256Mi.

**Diff `84aabf0..085a9fae`:**

| Scope | Commits / files | Lines |
|---|---|---|
| Whole repository | 44 commits, 189 files | +20,508 / −1,124 |
| `phorvex/` | 88 files | +6,845 / −1,044 |
| `phorvex/`, non-test | 65 files | +5,698 / −1,033 |
| ↳ of which `docs/recon-cover-map.generated.md` | 1 file | +4,282 |
| ↳ of which `internal/console` | 20 files | +995 / −74 |
| Brain path (non-test `internal/`, excluding console) | 31 files | +941 / −48 |
| `api/` + `charts/` + `config/` | 12 files | +393 / −5 |
| `deploy/` (9 policy files, `values-eks.yaml`, crm app) | 15 files | |

The first-parent merges in the range are PRs #431 to #444, plus releases 0.4.212 to 0.4.215:

| Theme | PRs |
|---|---|
| crm-refund-revoke | #434, #437, #438, #441 |
| crm-defense drops quarantine | #440 |
| Independent cost preferences | #444 |
| Math-assurance docs | #443 |
| Guardrail repins | #436, #439, #442 |
| Harness and console | #431, #432, #433, #435 |

**Brain-path files changed** (non-test; line counts are insertions+deletions):

| Area | Files |
|---|---|
| `decision/` | `coverage.go` (82), `optimality.go` (16), `parameter_manifest.go` (6), `existential.go` (2), `localsearch.go` (2) |
| `model/` | `decision_trace.go` (86), `economics.go` (66), `types.go` (43) |
| Generator and capability | `actionset/generator.go` (33); `capability/gate.go` (14) |
| `runner/` | `manager.go` (26) |
| `recon/` | `ucw.go` (11), `facts.go` (4) |
| `feasibility/` | `actions_native.go` (4), `defaults.go` (2) |
| `cost/` | `p1cost.go` (2), `action_flow.go` (2) |
| `ingest/` | `crm_refund.go` (new, 80), `events.go` (1), `kube.go` (1) |
| Other | `slo/bound.go` (2); `controller/phorvexpolicy_validation.go` (3) |
| New packages | `crmrefund/{contract,live}.go` (34, 159) |
| `actuator/` | `crm_refund_revoke.go` (new, 290), `verbs.go`, `backend.go`, `native.go` |
| `api/v1alpha1/` | `defaults.go` (+29), `phorvexpolicy_types.go` (29) |
| Charts | CRD (32), `rbac.yaml` (30), `values.yaml` (13) |

**Unchanged (byte-identical):**

- packages `killchain/`, `ctxprov/`, `graph/`, `belief/`, `exposure/`, `platform/`, `calib/`, `authz/`;
- files `cost/{rls,conformal,phase_encoding,dual,parameters}.go`, `feasibility/constraint.go`, `cmd/main.go`.

---

## (b) Counts: before and after

**Classification, protection, status and verification:**

| | Audit (198) | Same 198 at `085a9fae` | Registry (246) |
|---|---|---|---|
| CONFIGURABLE_NOW | 36 | 37 | 39 |
| CONFIGURABLE_WITH_REDEPLOY | 13 | 14 | 22 |
| INTERNAL_CONSTANT | 114 | 109 | 133 |
| LEARNED_STATE | 6 | 5 | 5 |
| DERIVED_RUNTIME | 5 | 5 | 10 |
| OBSERVED_INPUT | 3 | 3 | 4 |
| REPORT_ONLY | 13 | 18 | 26 |
| UNSUPPORTED_OR_UNKNOWN | 8 | 7 | 7 |
| **Protected** | 33 | 33 | 53 (+20 new) |
| active ACTIVE / CONDITIONAL | 148 / 21 | 127 / 24 | 145 / 42 |
| active INACTIVE | 7 | 19 | 21 |
| active REPORT_ONLY | 15 | 19 | 27 |
| active NO_RUNTIME_SELECTION_EFFECT | 7 | 9 | 11 |
| Verification VERIFIED / PARTIAL / NOT_VERIFIED | 179 / 17 / 2 | 193 / 5 / 0 | 238 / 8 / 0 |

The active-status columns apply one mapping to the audit `status` text and the reconciled status. The live column reflects the deployed configuration.

**PARTIAL rows** have their source verified but a live or runtime aspect left open:

| Group | Rows |
|---|---|
| From the original 198 | P-FEA-017, P-FEA-018, P-FEA-029, P-FEA-031, P-SEC-073 |
| New rows | P-FEA-038, P-FEA-044, P-SEC-092 |

**Recon status of the 198 rows:**

| recon_status | Count |
|---|---|
| VERIFIED_UNCHANGED | 130 |
| LOCATION_MOVED | 48 |
| VERIFIED_CHANGED | 20 |
| REMOVED / NOT_VERIFIED | 0 |

20 rows have `changed_since_84aabf0=YES`. Across the registry the count is 35, which includes the 14 new-since rows and P-CST-059.

**Origin and control:**

| Field | Values |
|---|---|
| Origin | AUDIT_84aabf0 198; NEW_SINCE_84aabf0 14; MISSED_BY_AUDIT 34 |
| Control | EXPERIMENT_KNOB 2 (P-OBJ-003, P-FEA-006); READ_ONLY 185; NO_LIVE_EFFECT 59 |

**Reclassifications.** These follow the recon files; the audit value is kept in `notes` as "audit said …".

| Row | Change | Reason |
|---|---|---|
| P-RUN-008 | UNSUPPORTED → INTERNAL_CONSTANT | Q14; also gates dispatch |
| P-RUN-009 | INTERNAL_CONSTANT → CONFIGURABLE_WITH_REDEPLOY | The 5 s value is the `--epss-authoritative-timeout` fallback; the flag is inactive live |
| P-OTH-002 `spec.tenant` | REPORT_ONLY → CONFIGURABLE_NOW | Names the Phoenix AMTD |
| P-CST-037 | INTERNAL_CONSTANT → REPORT_ONLY | |
| P-SEC-022, -023, -024, -026, -047 | INTERNAL_CONSTANT → REPORT_ONLY | |
| P-SEC-063 | LEARNED_STATE → INTERNAL_CONSTANT | Never updated in production |

The source references are in [recon/group-OBJ-RUN-OTH.md, group-CST-B.md, group-SEC-A.md §4, group-SEC-B.md].

### New parameters (48) and deduplication decisions

**ID rules applied:**

1. One id per real quantity.
2. Ids from `new-parameters.csv` are kept.
3. Proposals that appear only in a group MD file are numbered after the highest id already used in their group. The group-file name is kept as an alias in `notes`.
4. Ids proposed but merged into an existing row are **retired** (listed below). This leaves gaps P-FEA-041, P-RUN-010 and P-SEC-078.

**Collisions and conflicts:**

| Topic | Decision |
|---|---|
| P-OBJ-023 and P-OBJ-024 | The same `costPreferences.norm` and `.flow` in `new-parameters.csv`, group-OBJ-RUN-OTH.md and group-CST-A.md (as NEW-CST-A6/A7). One row each. |
| P-RUN-010 | group-OBJ-RUN-OTH.md meant `--epss-authoritative-timeout`, which is P-RUN-009 itself. `new-parameters.csv` meant "audit and calibration export sinks", which is covered by P-CST-053 (`--calibration-export-dir`, also NEW-CST-B7) and P-OTH-005 (`--audit-max-bytes`). **Retired.** |
| P-OTH-006 | group-OBJ-RUN-OTH.md meant `--admission-webhook`, which is now **P-FEA-040** (from `new-parameters.csv`). `new-parameters.csv` meant loss and inventory observers, which stays P-OTH-006. |
| P-FEA-041 (MIG allocation helper flags) | Already in the P-FEA-028 recon `config_key`. **Retired** into P-FEA-028. |
| P-SEC-078 (EPSS authoritative config) | Already in the P-SEC-069 recon `config_key` (`cmd/main.go:240-260`). **Retired** into P-SEC-069. |
| P-SEC-076 | `new-parameters.csv` bundled three literals. They are split because they are independent constants at different sites (Ticket A requirement 7): ingest horizon 60 s (`ingest/crm_refund.go:17`, stays P-SEC-076), skew 1 s (`:39`, now **P-SEC-081**) and enact-time max age 60 s (`actuator/crm_refund_revoke.go:58`, now **P-FEA-042**). |
| Folded proposals | NEW-CST-B1 (uncertainty bound 2) → P-CST-015 (same constant). NEW-CST-A5 (quarantine component count 3) → P-CST-008. NEW-CST-A3 (9 missing manifest keys) → a P-CST-004 warning. P-SEC-NEW-05 (CRM scope constants) → P-FEA-034. SSAR TTL 5 min → P-FEA-031. Quarantine bound 128 → P-FEA-008 validation. |
| Attribute conflicts | P-SEC-075 is classed DERIVED_RUNTIME, not INTERNAL_CONSTANT (a per-asset weight). P-OTH-006 is REPORT_ONLY and protected (a trust allowlist). P-SEC-076 is protected (`new-parameters.csv`) against "NO" in group-SEC-A.md; P-SEC-083 follows it. |
| Factual conflicts in recon files | `new-parameters.csv` gives the P-FEA-006 default as **0.5**; the source has **1.2** (`model/types.go:33`; CRD default `"1.2"`, `crds/phorvex.ai_phorvexpolicies.yaml:460-461`). group-OBJ-RUN-OTH.md says `MutatingActions` holds **25**; a direct count of `model/types.go:150-168` gives **24** (23 at `84aabf0`), as group-CST-A.md states. group-CST-B.md cites `ingest/pcie.go:97-115`; the file has 112 lines (corrected to 97-112). |

**The 48 new parameters:**

| id | name | class | active | prot. | origin |
|---|---|---|---|---|---|
| P-OBJ-023 | Independent norm cost preference β_N | CONFIGURABLE_NOW | CONDITIONAL | no | new |
| P-OBJ-024 | Independent flow cost preference β_F | CONFIGURABLE_NOW | CONDITIONAL | no | new |
| P-OBJ-025 | Objective economics mode | DERIVED_RUNTIME | ACTIVE | no | new |
| P-OBJ-026 | Frozen per-candidate objective penalty | DERIVED_RUNTIME | CONDITIONAL | no | new |
| P-FEA-033 | CRM deny-guard ledger capacity (256) | INTERNAL_CONSTANT | CONDITIONAL | yes | new |
| P-FEA-034 | CRM serving-topology capability contract | INTERNAL_CONSTANT | CONDITIONAL | yes | new |
| P-FEA-035 | crm-refund-revoke RBAC grant toggle (Helm) | CONFIGURABLE_WITH_REDEPLOY | ACTIVE | yes | new |
| P-FEA-036 | crm-refund-revoke SLO bound classification | REPORT_ONLY | REPORT_ONLY | no | new |
| P-FEA-037 | Native-rotate ownership law flag | DERIVED_RUNTIME | ACTIVE | yes | missed |
| P-FEA-038 | `--serving-security-file` | CONFIGURABLE_WITH_REDEPLOY | ACTIVE | yes | missed |
| P-FEA-039 | `--operator-namespace` | CONFIGURABLE_WITH_REDEPLOY | ACTIVE | yes | missed |
| P-FEA-040 | `--admission-webhook` (live `true`) | CONFIGURABLE_WITH_REDEPLOY | ACTIVE | yes | missed |
| P-FEA-042 | CRM enact-time observation max age (60 s) | INTERNAL_CONSTANT | CONDITIONAL | yes | new |
| P-FEA-043 | Code-exec system-namespace denylist | INTERNAL_CONSTANT | CONDITIONAL | yes | missed |
| P-FEA-044 | Code-exec verifier timing (2 s / 30 s / 10 s) | INTERNAL_CONSTANT | CONDITIONAL | yes | missed |
| P-FEA-045 | Protected-serving capability read timeout (1 s) | INTERNAL_CONSTANT | ACTIVE | yes | missed |
| P-FEA-046 | Quarantine-capacity ledger bounds | INTERNAL_CONSTANT | CONDITIONAL | no | missed |
| P-FEA-047 | Shared-capacity ledger bounds | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-FEA-048 | Actuator namespace grants + startup preflight | CONFIGURABLE_WITH_REDEPLOY | ACTIVE | yes | missed |
| P-CST-057 | Phase conservative CFlow floor (`switchPrior`) | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-CST-058 | Phase → RLS feature-bit map | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-CST-059 | Action → CFlow-family routing | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-CST-060 | Respawn regime uncertainty slack (CHi) | DERIVED_RUNTIME | ACTIVE | no | missed |
| P-CST-061 | Rotation observation censor deadline (800 s) | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-CST-062 | `calib` ready-delay reference (duplicate 400 s) | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-CST-063 | Conformal regime-applicability flag | REPORT_ONLY | REPORT_ONLY | no | missed |
| P-CST-064 | Phase Idle veto on queue depth / tokens per s | INTERNAL_CONSTANT | CONDITIONAL | no | missed |
| P-CST-065 | Conformal order-statistic rule | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-SEC-075 | CRM refund-abuse recon fact weight | DERIVED_RUNTIME | CONDITIONAL | no | new |
| P-SEC-076 | CRM observation freshness horizon (ingest, 60 s) | INTERNAL_CONSTANT | CONDITIONAL | yes | new |
| P-SEC-077 | CRM trusted producer identity | INTERNAL_CONSTANT | CONDITIONAL | yes | new |
| P-SEC-079 | EPSS feed producer (one-shot) | OBSERVED_INPUT | NO_RUNTIME_SEL. | no | missed |
| P-SEC-080 | Recon / context provider selection | INTERNAL_CONSTANT | ACTIVE | no | missed |
| P-SEC-081 | CRM observation clock-skew tolerance (1 s) | INTERNAL_CONSTANT | CONDITIONAL | no | new |
| P-SEC-082 | CRM payload size bounds | INTERNAL_CONSTANT | CONDITIONAL | no | new |
| P-SEC-083 | Per-vector bound-observation horizons | INTERNAL_CONSTANT | CONDITIONAL | yes | missed |
| P-SEC-084 | Live-vector console creator anchors | INTERNAL_CONSTANT | CONDITIONAL | yes | missed |
| P-SEC-085 | Infection-severity vocabulary | INTERNAL_CONSTANT | CONDITIONAL | no | missed |
| P-SEC-086 | `ctxprov` severity normalizer 4.0 | REPORT_ONLY | REPORT_ONLY | no | missed |
| P-SEC-087 | Shadow dispersion-cap override | REPORT_ONLY | REPORT_ONLY | no | missed |
| P-SEC-088 | Per-fact AI multipliers (no cover) | REPORT_ONLY | REPORT_ONLY | no | missed |
| P-SEC-089 | Cross-tenant hierarchical persistence prior | INTERNAL_CONSTANT | INACTIVE | yes | missed |
| P-SEC-090 | Scoped-outcome cohort prior Beta(1,1) | REPORT_ONLY | REPORT_ONLY | no | missed |
| P-SEC-091 | Scoped-outcome observation window | REPORT_ONLY | REPORT_ONLY | no | missed |
| P-SEC-092 | SecurityEvent creator-identity policy toggle | CONFIGURABLE_WITH_REDEPLOY | ACTIVE | yes | missed |
| P-RUN-011 | Controller infrastructure flags | CONFIGURABLE_WITH_REDEPLOY | NO_RUNTIME_SEL. | no | missed |
| P-OTH-006 | Loss / current-inventory observer trust | REPORT_ONLY | REPORT_ONLY | yes | missed |
| P-OTH-007 | One-shot / non-production modes | CONFIGURABLE_WITH_REDEPLOY | INACTIVE | yes | missed |

**Not registered:**

- The legacy `cost/switching.go` literals. They live in a `CostModel` that nothing reads [recon/group-CST-A.md].
- The gate and dispatch steps listed in (c). These are mechanisms, not parameters.

---

## (c) Material behavioral deltas

### c.1 PR #444: three economics modes

Source: `model/economics.go:38-71`; `api/v1alpha1/defaults.go:104-131`; [recon/replay-prerequisites.md B].

**Exact precedence.** `Policy.Economics(λ_runtime)` resolves the mode in this order:

1. Reject any λ seed or runtime λ that is non-finite or outside [0,10] (`economics.go:39-44`).
2. `CostPreferencesConfigured` selects **independent-cost-preferences-v1** (`:45-50`). This is an error if β is also configured, or if a preference is outside [0,10].
3. Otherwise, if β is not configured, the mode is **legacy-runtime-lambda-v1** and the coefficient is λ_t (`:51-59`).
4. Otherwise the mode is **fixed-disruption-aversion-v1** and the coefficient is β (`:60-70`).

β counts as unconfigured when absent or `""`. An explicit `"0"` is fixed mode with coefficient 0.

**Penalty per candidate:**

| Mode | Penalty |
|---|---|
| Legacy | λ_t·ECost |
| Fixed | β·ECost |
| Independent | β_N·CNorm + β_F·CFlow on **unweighted** CNorm and CFlow, frozen in `assembleSet` (`decision/coverage.go:732-742`) and applied by `candidatePenalty` (`:2127-2132`) in every comparator |

**What holds in all three modes:**

- The CHi gate always uses w_n and w_f (`cost/p1cost.go:188-232`; `actionset/generator.go:515`).
- λ is still stepped every persisted tick (`coverage.go:946-968,1178`).

**What differs in independent mode:**

- `ProactiveRate` is withheld (`coverage.go:1051,1126`).
- The trace schema is v8 instead of v7 (`coverage.go:2134-2139`).

**Mutual exclusion** is enforced in four places:

| Layer | Location |
|---|---|
| CRD CEL | `api/v1alpha1/phorvexpolicy_types.go:196` |
| Webhook and reconcile | `controller/phorvexpolicy_validation.go:46-48` |
| `Upsert` | `runner/manager.go:622-624` |
| `Economics` | `economics.go:45-46` |

**Live vs git:**

- **Live: legacy runtime-λ in all 9 defense policies.** costWeights 0.4/0.6; λ seed 0.4 or 0.5; costCeiling 1.2.
- **Git: all 9 policies declare `costPreferences`.** The values are 0.16/0.24, or 0.20/0.30 for vllm and litellm, which equal λ₀·w (`deploy/policies/*-defense.yaml`; README).

**If `phorvex-policies` is synced:**

- Every policy moves to independent mode.
- The cost term becomes a fixed penalty that does not decay. Today, by inference, it is likely about 0; see (f).
- The per-policy overrides gain `Present=true` preference entries (`decision/parameter_manifest.go:185-191`).
- The in-cluster CRD must already carry the field (chart CRD `crds/…:329-353,397-399`). An old CRD prunes it. NOT_VERIFIED.

**Requirement for any campaign that spans a sync:** record `decisionTrace.economicsVersion` per decision and treat a mode change as a baseline break.

**Seed lifecycle, re-verified unchanged** [recon/group-OBJ-RUN-OTH.md §3]:

- The seed is consumed once per policy UID when the cost bucket is created (`coverage.go:384-431`).
- A same-UID PATCH does not reseed (`runner/manager.go:654-706`).
- The bucket is created at `coverage.go:786`, *before* parameter-set validation at `:795`.
- β and preferences are re-read on every due tick (`runner/manager.go:1941,3527-3536`).

### c.2 New action `crm-refund-revoke`

PRs #434, #437 and #438; [recon/group-FEA.md §3.1; group-SEC-A.md §2; group-CST-A.md D1].

| Layer | Wiring at `085a9fae` |
|---|---|
| Vocabulary | CRD enum (chart CRD :123). `MutatingActions` is now 24 (`model/types.go:150-168`, appended at :167, so tie-break order is unchanged for the existing 23). Trace vocabulary `v10-live24`. |
| Cost | CNorm 0.25 serving-configuration (`cost/p1cost.go:157`). CFlow family serving-state, 0.05 + 0.10·L (`cost/action_flow.go:92`). CHi = ECost with no slack. No manifest key, the same gap as 8 other actions. |
| Generation gates | G1 policy identity and epoch (`actionset/generator.go:385-394`). G4.5 (`capability/gate.go:318-323`). G4.6 AI context (`gate.go:431-432`) and `configWhy` (`:560-564`). Law F1 (`feasibility/actions_native.go:23,60-61`). |
| Capability (EXT-READ) | `crmRefundCapability` → `crmrefund.ValidateLive` makes 4 live API calls per evaluation with **no capability-specific timeout** (`actuator/crm_refund_revoke.go:30-42`; `crmrefund/live.go:34-137`). |
| Clocks | `ExposureVarFor` maps it to pod identity (`feasibility/defaults.go:123`). Anti-over-rotation (P-FEA-004) and proactive cadence (P-FEA-005) therefore apply. |
| Evidence | New binder `ingest/crm_refund.go`: 60 s horizon, 1 s skew, a hard-coded console creator **in addition to** `--trusted-detectors`, and a 256-entry guard. New recon fact `crmRefundOrderAbuse` with weight ×3 `vectorDominance` (`recon/ucw.go:243-253`). |
| Kill chain | `killchain/hazard.go` is unchanged. The new vector reaches it through the severity fallback (critical → **exploit**, not persist; `hazard.go:252-268`). It also marks the pod "infected" for neighbours (P-SEC-009). |
| Authority | RBAC verbs (`actuator/verbs.go:59-63`). Startup preflight (`startupauthz/preflight.go:180-203`). Helm toggle `phorvex.crmRefundRevoke.enabled` (true in git `values-eks`). Dispatch requires a selection id (`runner/manager.go:3026-3052`). Enact-time authority check with 60 s max age (`crm_refund_revoke.go:48-70`). |
| Policies (git) | `crm-defense` replaced `quarantine` with `crm-refund-revoke` (#440). Live action lists NOT_VERIFIED. |

### c.3 Gate order at `085a9fae`

Source: `actionset/generator.go:204-541`, built by `decision/coverage.go:597-743`; [recon/group-FEA.md §2].

**Evaluation order.** Gates run per (asset, action) in `MutatingActions` order. The first veto wins. There is one exception: RetainSLO assets (G6, G9).

The IDs below are the ones the implementation stamps on every `actionset.Exclusion` (`actionset/gates.go`, PR #448), so traces, metrics (`phorvex_candidates_gated_total{first_gate}`) and this report use one numbering. It keeps the package contract's "G9 = cost ceiling".

**Purity legend:**

| Label | Meaning |
|---|---|
| PURE | Deterministic in memory |
| PURE\* | Pure, but its input came from a live read earlier in the tick |
| EXT-READ | Uncached apiserver GET or LIST |
| EXT-AUTHZ | Creates a SelfSubjectAccessReview and writes the shared cache |

| Gate | Check | file:line | Nature |
|---|---|---|---|
| G0a | Recon fact absent (non-finite input): asset unactionable | `generator.go:269-283` | PURE |
| G0b | Cover-key collision: **whole set rejected** | `generator.go:288-298` | PURE |
| G1 | Bound-observation policy identity and epoch (9 actions incl. crm) | `generator.go:315-404` | PURE |
| G2 | `identity-rotate` unsupported | `generator.go:405-413` | PURE |
| G3 | Quarantine capacity (unknown, or used ≥ limit) | `generator.go:414-441`; inventory `runner/manager.go:1943-1956` | PURE\* |
| G4 | Composite `Eligible`; sub-legs below | `generator.go:442-457` | mixed |
| G4.1 | Pod opt-out | `runner/manager.go:133-135` | PURE |
| G4.2 | CRD vocabulary | `capability/gate.go:263-265` | PURE |
| G4.4 | No cover | `gate.go:269-275` | PURE |
| G4.5 | Bound-observation identity | `gate.go:276-329` | PURE |
| G4.6 | `Capable` incl. `SupportsAction` | `gate.go:371-406` | **EXT-READ** |
| G4.7 | Code-exec admission (cached) | `gate.go:337-341` | PURE |
| G4.8 | RBAC SSAR; an error is **fail-open** | `gate.go:342-364`; `authz/ssar.go:120-239` | **EXT-AUTHZ** |
| G4.9 | M99 fallback | `runner/manager.go:185-188` | PURE |
| G4.10 | Failure cooldown | `coverage.go:611-626`; `runner/action_failures.go:66-74` | PURE |
| G5 | Shared resource capacity | `generator.go:468-481,543-608` | PURE\* |
| G6 | Feasibility laws F1–F12, alphabetical; a panicking law vetoes | `generator.go:482-493`; `feasibility/constraint.go:47-69` | PURE |
| G7 | Cost NaN or Inf: unactionable | `generator.go:494-513`; `cost/p1cost.go:198-241` | PURE |
| G8 (`G8-objective-pricing`) | Whole set: preferences configured and `Economics()` errors, so no candidate set (**new**). Set-level; never excludes one candidate | `coverage.go:732-743` | PURE |
| G9 (`G9-chi-ceiling`) | **CHi > c̄** (`conformal-slo`); skipped when c̄ ≤ 0 | `generator.go:514-525` | PURE |

**RetainSLO exception** (`mayBreachSLO` plus a qualified outcome; `coverage.go:688-694`):

- G6 evaluates all 12 laws (`constraint.go:74-94`). F3 availability-floor (including its PDB vetoes), F9 slo-headroom and F11 tokens-floor become tags instead of vetoes.
- G9 keeps a CHi breach as a tagged candidate (`generator.go:520-524`).

**Post-selection runner steps D1–D7** (`runner/manager.go:2226-2257,3026-3165`; `actuation_brake.go:17-43`; `crm_refund_revoke.go:48-70`) never remove candidates.

**Pure vs external authority:**

- G4.6 `SupportsAction` (the serving journal, request-drain, output-policy, voice-\*, litellm, crm and endpoint-lease checks) and G4.8 SSAR are the external-authority gates.
- The shadow path (`EligibleObserved`) suppresses only the SSAR. It still performs the G4.6 live reads.
- So a side-effect-free replay must inject recorded per-(asset, action) verdicts. The trace field `actionStatus[]` carries them.
- Everything from G5 to G9 is pure given the recorded inputs.

**Diff check.** Only insertions changed the order: the crm branches, G9 and the D4 crm branch. No gate was reordered or removed.

**Numbering (resolved).** The package docs call the cost-ceiling gate "G9" (`01_DATA_AND_API_CONTRACTS.md`, ticket F). The implementation keeps that: the cost ceiling is `G9-chi-ceiling` and the set-level economics check is `G8-objective-pricing`. Gate IDs are named constants, not ordinals. A source-level guard test fails if a new exclusion site omits its gate, so future insertions cannot renumber gates silently.

### c.4 Smaller deltas

- **P-SEC-015** (vector dominance) gains a consumer: the CRM fact.
- **P-SEC-068** gains a downstream conjunct: `ingest/crm_refund.go:33-35`.
- **P-OTH-001** has a new consumer at `ingest/crm_refund.go:63`.
- **P-RUN-008:** the list of actions that need a decision trace to dispatch now includes crm-refund-revoke.
- **P-OBJ-013** (`MaxDisruptionAversion` = 10, `economics.go:16`) now also bounds β_N and β_F.
- **`EffectivePolicyOverrides` gained entries** (`parameter_manifest.go:185-191`, plus `policy.action-enabled.crm-refund-revoke`) while its schema stays `phorvex.policy-overrides.v1` (`model/parameters.go:15`). Whether the overrides hash changes for an identical spec is NOT_VERIFIED, which matters for Ticket A requirement 9.
- **The global parameter-manifest hash** is expected to equal the 0.4.211 hash `sha256:505c3f02…4243`. That makes it blind to the 23→24 vocabulary change. This is an inference that was not computed: no Go toolchain was available [recon/group-CST-A.md Q3 §4].

---

## (d) Audit corrections (wrong at both SHAs)

The full text of each correction is in the row `notes`.

### Classification and status

**Classification changes:**

| Rows | Change |
|---|---|
| P-RUN-008 | → INTERNAL_CONSTANT (always on; also gates dispatch) |
| P-RUN-009 | → flag fallback |
| P-OTH-002 | → actuation identity |
| P-CST-037; P-SEC-022/023 (rarity bounds read by the manifest only); P-SEC-024/026 (ThreatPosture only); P-SEC-047 | → REPORT_ONLY |
| P-SEC-063 | → constant prior |

**Status changes:**

| Rows | Correction | Source |
|---|---|---|
| P-SEC-031…034 (lateral, impact, gpu-side-channel, model-theft sojourns) | INACTIVE: never a current stage | `killchain/hazard.go:248-271,326-331,443-449` |
| P-SEC-042, -043 | INACTIVE: stages unreachable | |
| P-SEC-046 | INACTIVE: default arm unreachable | `hazard.go:107,125` |
| P-SEC-062 | INACTIVE: no production `Observe` | |
| P-SEC-035, -036, -044, -045 | CONDITIONAL: AI pods only | |
| P-SEC-012 | CONDITIONAL: only when AssetValue·P(hold) ≤ 0 | `recon/profile.go:48-51` |
| P-CST-035 | Slack applies to every rotate in every regime | `p1cost.go:217-227` |
| P-CST-038 | 0.1 is used only while the window is empty (n = 0) | `conformal.go:91-93` |
| P-CST-019 | Shapes cutover and serving-state CFlow for every policy | `action_flow.go:199-201` |
| P-CST-052 | Effectively report-only | |
| P-CST-054 | Report-only even if activated | |
| P-CST-008, -016, -017 | Quarantine is no longer enabled in crm | |

### Validation stated as "none" but enforced

| Row | Enforcement |
|---|---|
| P-RUN-002 | CEL > 0 |
| P-RUN-006 | Exit 2 if < 1 |
| P-OBJ-019, -020 | Values ≤ 0 fall back to the default |
| P-OTH-001 | Must parse; non-empty in active mode (`controller/phorvexpolicy_validation.go:31-37`) |
| P-OTH-003 | `listType=set`, items `MinLength=1` |
| P-OTH-005 | Helm template and writer checks |
| P-FEA-027 | Strict enum; operator refuses to start |
| P-SEC-057 | Pattern, CEL and webhook; outside (0,1) is rejected |
| P-SEC-064 | CEL bounds |
| P-SEC-028…036 | CRD ≥ 1; runtime (0,604800], otherwise **every tick is rejected** (`parameter_manifest.go:216-222`) |
| P-SEC-027 | A CRD-valid shape > 10 **rejects every tick** |
| P-CST-052 | Malformed table: exit 1 |
| P-CST-053 | Exit 2 on bad durations |

**Domains that were NOT_VERIFIED and are now resolved:**

| Row | Domain |
|---|---|
| P-FEA-008 | ≤ 128 (`actuator/quarantine_capacity.go:25`) |
| P-FEA-026 | {0} ∪ (0,1) |
| P-CST-041 | Finite [0,1], else exit 2 (`conformal.go:42-48`) |
| P-CST-056 | `math.MaxFloat64` (`p1cost.go:22`) |

### Consumers and semantics

- **Negative cost weights (Q18).** A negative `costWeights` or `weightSecrets` value is never scored. The whole tick is rejected and the status gives no reason. See (e) Q18.
- **P-OBJ-008:** existential-active candidates bypass the `gain > 0` test (`existential.go:209`).
- **P-OBJ-012:** the negative clip is a literal −1 (`dual.go:124-126`).
- **P-FEA-001** has omitted consumers:
  - the Service capacity limit (`generator.go:590-603`);
  - the dispatch floor checks. route-rotate requires effective m = 1, so nats with m = 2 is refused.
- **P-FEA-002** vetoes every non-noop action.
- **P-FEA-014:** the PDB vetoes are relaxed together with the floor.
- **P-FEA-018** is also the first candidate exclusion (G4.1).
- **P-FEA-030** is a dispatch input, not a gate.
- **P-CST-006:** model-shard-replace uses `float64(ParallelSize)` (`p1cost.go:146-151`), not the constant.
- **P-CST-024 and P-CST-026:** the conservative floor is `switchPrior` (now P-CST-057), not `priorWeight`.
- **P-CST-044:** a freeze affects RLS only and reverts θ to the prior. The conformal window keeps learning.
- **P-SEC-001:** not monotone near 0.
- **P-SEC-009:** no event-age weighting.
- **P-SEC-073** feeds the GPU-conservation law only.
- **P-SEC-072** feeds reporting cohorts only.
- **P-OTH-005:** the code default is 512 MiB, though the comment says 256 MiB.

### Provenance and units

- **Mixed units in CHi.** `max(q, w_f·G)` compares an unweighted q with a weighted term (`p1cost.go:218-227`). This is conservative at w_f = 0.6 and anti-conservative if w_f > 1, and `flowDisruption` has no upper bound.
- **Conformal coverage.** The order statistic `int((n−1)(1−α))` (`conformal.go:96`) gives coverage k/(n+1) below the nominal 0.9, for example 0.857 at n = 20. It is now P-CST-065.
- **Missing from the overrides hash:** `fromLabels` is not in the effective-policy overrides hash.
- **Missing from the manifest:** P-SEC-004…009 and P-SEC-024…026 are not exported.
- **Wrong manifest unit:** P-SEC-058 is labelled dimensionless but is in seconds.
- **Duplicate literals, kept independent:**
  - P-CST-043 vs `calib` 400 s (P-CST-062);
  - sojourn defaults in both `api/v1alpha1/defaults.go:19-22` and `hazard.go:216-225`;
  - P-CST-018 vs P-CST-030 (200);
  - P-SEC-002 vs P-SEC-005 (0.8);
  - P-CST-055 vs the CRD default.

### `BRAIN_ARCHITECTURE_AUDIT.md`

- **§3 gate order.** Opt-out (G4.1) comes first. The identity and epoch gate (G1) precedes quarantine capacity. The cooldown runs after SSAR inside `Eligible`. G5 sits between capability and the laws.
- **§4:** the PDB is relaxed together with the floor.
- **§5:** the cold-start slack applies at n = 0, not "until 20".
- **§6 and lines 161, 197, 216:** persistence learning is not wired (Q10).
- **Stale code comments:** `coverage.go:1175-1177`, `:543-552`; `hazard.go:355-357`.

---

## (e) Open questions

### Resolved

| Q | Answer at `085a9fae` |
|---|---|
| Q3 | All 8 newer actions and crm-refund-revoke use CNorm 0.25 (`p1cost.go:157-158`) and serving-state CFlow 0.05 + 0.10·L (`action_flow.go:92,119-120`). 9 of 24 mutating actions have no `cost.norm.action.*` manifest key (`cost/parameters.go:49-67`), and no test checks coverage. Q3's premise is partly wrong: sensitive-output and voice-session-admission are enabled in no git policy [recon/group-CST-A.md]. |
| Q5 | `MeasuredT4GPUEnvelopeMax` (`conformal.go:27`) has **no production reader**; only tests read it. The live 0.2925 is a Helm literal (`charts/phorvex/values.yaml:41`) passed as `--gpu-envelope-max` and validated at `cmd/main.go:329-332` [recon/group-CST-B.md Q5]. |
| Q6 | `ReadyDelayReference` 400 s (`p1cost.go:365`) sets the censor deadline at 2×400 s (`runner/manager.go:1421,1444`) and the abandonment and censoring rules (`:1480,1589,1628,1684-1698`). The **live label normalizer is `calib.RotationRecord.Normalized`** (`manager.go:1704-1706`; `calib/readydelay.go:87-99`). `cost.NormalizeReadyDelay` is test-only. |
| Q8 | `ctxprov/sensed.go:99-112,176`: AssetValue = (max label weight + w_sec·\|secrets\| + 1[graph]·BR) × frontier. It then enters `recon/ucw.go:81` and `profile.go:48` as `AssetValue·P(hold)`. The `sensed.go:104` flag is the only path by which the graph score enters a decision [recon/group-SEC-A.md §3]. |
| Q10 | Persistence learning is inactive **with or without** `--scoped-outcome-config`. There is no non-test caller of `ConjugateMemory.Observe`, `ObserveBernoulli` or `SetCrossTenantPrior`. `AdmitPersistenceObservation` updates reporting cohorts only (`decision/persistence_observation.go:436-529`). P(hold) uses the constant Beta(1,4) prior [recon/group-SEC-B.md Q10]. |
| Q14 | Decision trace is hard-wired on: `DecisionTraceEnabled: true` (`runner/manager.go:574`), copied to the policy every tick (`:1973`). There is no flag. Disabling it would block 10 trace-bound actions at dispatch (`:3026-3052`). |
| Q17 | The pod-identity exposure clock is rebuilt from pod `StartedAt` (`exposure/clock.go:58-86`; `ingest/kube.go:681-687`). In-place action clocks also read pod age. **Emit intents and stage-entry history are lost** on restart. So an in-place move, or a Live serving action, can repeat right after a restart, and stage dwell becomes an upper bound [recon/group-SEC-B.md Q17]. |
| Q18 | A negative `costWeights` or `weightSecrets` value passes CRD validation, the webhook and `Upsert`, then fails `EffectivePolicyParameterSet` (`parameter_manifest.go:146-152`). The tick is rejected as a decision-contract-error (`coverage.go:795-798`; `runner/manager.go:2167-2192`). There are **zero decisions and no status reason**, the policy is re-due every base interval, and the bucket and seed are still created (`coverage.go:786`). The `nanFeature` guards are unreachable in production [recon/replay-prerequisites.md Q18]. |
| Q21 | **No reusable snapshot-replay harness exists.** The closest seam is `decision.EvaluateSensitivity` (`sensitivity.go:51-173`). It has no non-test caller and supports only dispersion, `economics.fixed-beta`, exposure-cap, shape and sojourn variants. **There is no cost-ceiling variant**, and fixed-beta errors on policies that have `costPreferences` [recon/replay-prerequisites.md Q21]. |
| Q24 | The shadow arm is `--calibration-shadow` (live `true`). It runs `DecideShadowChecked` with the **same policy** and only `Physics.CoResidency` and `DispersionCap` replaced (`calib/runtime.go:321-357`; `runner/manager.go:2142-2155`). Its decisions are discarded; only `SelectionComparison` is exported (`calib/export.go:312-354`). It cannot vary a policy parameter without a code change [recon/replay-prerequisites.md Q24]. |

**Also resolved:**

| Q | Answer |
|---|---|
| Q1 | Both SHAs are on `main`'s first-parent history. |
| Q2 | The `api/` and `charts/` diff is enumerated in (a). |
| Q12 | SSAR TTL is 5 min; errors are never cached (`authz/ssar.go:34,198-239`). Fail-open frequency is still open. |
| Q13 | There are two scope kinds, `move-count` and `unavailable-ready-replica` (`model/types.go:366-367`). |
| Q16 | Current state only: calibration is not frozen (the kill-switch ConfigMap has no `costCalibration` key). The state during the Oct 3 run is unrecoverable. |

### Still open

| Q | Topic | Note |
|---|---|---|
| Q4 | Realism of the CNorm rubric | |
| Q7 | NaN-path frequency | Prometheus |
| Q9 | Graph 0.8 vs `weightSecrets` | Design decision; independent today |
| Q11 | Live values of the approved-digest env vars | |
| Q12 | RBAC fail-open frequency | |
| Q15 | Annotations during runs | |
| Q19 | Does the vLLM p99 template match? | |
| Q20 | Zero `timeToDefend` and `dwell` | |
| Q22 | Brake persistence | Brakes are read fresh from annotations at dispatch (`runner/actuation_brake.go:17-43`), so there is probably no in-process state; not confirmed |
| Q23 | Repeat-attack harness | |
| Q25 | Kill-chain ground truth | |

---

## (f) Implications for the two MVP sweeps

### P-OBJ-003 β sweep (objective only)

**Unset means legacy runtime λ: confirmed.** With `disruptionAversion` absent or `""` and no `costPreferences`, the coefficient is λ_t (`economics.go:51-59`). All live defense policies are in this mode.

**λ_t: zero in the audited run; likely near zero at 0.4.216, but unverified.**

- The audit observed λ_t = 0 on all 524 updates (audit §2).
- At 0.4.216 the value is NOT_VERIFIED.
- `cost/dual.go` is byte-identical, so the same mechanics apply. λ rises only when demand > B and spent = B (`dual.go:118-120`). Otherwise it decays by up to 0.05/B per persisted tick (`:124-135`). It is clamped at 0 (`:136-139`).
- **Inference:** after any restart the seed decays to 0 within about 8 ticks for B = 1 (40–80 s at 5–10 s ticks), or 80–100 ticks for B = 10 (about 7–17 min), unless the budget saturates.
- **Replay must therefore use the recorded `lambdaRuntime` per decision, not assume 0.**

**β changes scoring only:**

- The CHi gate and every other gate are β-independent (`generator.go:515`).
- So the admitted candidate set is invariant across β arms, and the arms differ only in selection.
- β = 0 explicit is selection-equivalent to unset only when the recorded λ_t = 0. The two arms still differ in `economicsVersion`, `coefficientSource` and `ProactiveRate`. This makes them a cheap replay invariance check.

**Feasibility from traces (inference, to be proven by a Ticket F golden):**

- Trace v7 carries per-candidate `expectedCost`, `marginalCoverage`, `provenance` and `facts`/`coverKeys`/`resources` (`coverage.go:1345-1720`).
- So a **selection-stage** β replay can re-run the greedy per `tickID`, in the way the existing validator re-derives selection (`workflow/fixes/T0-C/validator/audit_trace_validator.py:426,460`).
- It cannot show future-state effects.

**Validity rules:**

- A β arm is **invalid** on any snapshot whose policy carries `costPreferences` (CEL and `Economics`). That is the post-Argo-sync state.
- `EvaluateSensitivity('economics.fixed-beta')` also errors there.
- β takes effect on the next tick with no recreate. The replay override domain is [0,10] inclusive, and "unset" is allowed.

### P-FEA-006 cost-ceiling sweep (gate only)

**The gate:** exclude when `CHi > c̄`, with live c̄ = 1.2 everywhere (`generator.go:515`). CHi composition is from [recon/group-CST-B.md "CHi composition"]. At w = 0.4/0.6 and live G = 0.2925, w_f·G = 0.1755:

| Case | CHi |
|---|---|
| Rotate in an uncertain regime (missing-load, draining, unknown-phase) | ≥ w_n·1 + 2·w_f = **1.6**; always excluded at 1.2, and at any c̄ < 1.6 |
| mig-rebind | 1.7 |
| model-shard-replace, ParallelSize ≥ 3 | > 1.2 |
| Rotate at the RLS prior (q = 0.1): GPU Warm | **1.2655**, excluded |
| Rotate at the RLS prior: GPU ColdStarting | 1.4455, excluded |
| Rotate at the RLS prior: CPU Warm | 0.92–1.04, admitted while q ≤ 0.26–0.38 |
| Rotate at the RLS prior: GPU Idle | 0.9355 |
| All non-rotate actions (CHi = ECost) | kv-reset 0.572; warm-swap and model-shard-replace (P = 1) 0.46–0.55; quarantine 0.28–0.37; serving-state and cutover ≤ 0.29 |

**Where the sweep has an effect:**

- Rotate is CHi-admissible only with fresh request-rate telemetry and a known, non-draining phase. That makes P-CST-048 and P-CST-050 load-bearing.
- **Inference:** a warm GPU rotate cannot be learned down from the prior, because it is excluded at the prior.
- Over [0.6, 1.8] the sweep therefore moves only rotate, model-shard-replace with P ≥ 2, and mig-rebind. Below about 0.58 it starts excluding kv-reset, warm-swap and model-shard-replace.
- These thresholds hold only at the live w and G. CHi uses w_n and w_f in every economics mode.

**Monotonicity.** The eligible set is monotone non-decreasing in c̄ with other inputs fixed. Selection, realized security and closed-loop learning are not monotone: admitting rotates feeds RLS and conformal, which changes future CHi. Snapshot replay cannot show that.

**Feasibility from traces:**

- Cost-evaluated exclusions are exactly G9 rejects. They are recorded with `costHigh`, `expectedCost`, `provenance` and `grossFullValue` (`coverage.go:1660-1693`, comment at :1691-1693).
- So raising c̄ can re-admit them, and lowering c̄ can exclude admitted rows by their `costHigh`.
- Candidates vetoed before G7 have no CHi, so their status is `NOT_EVALUATED` (M-P23).
- There is no built-in sensitivity variant for the cost ceiling (Q21).

**Domain:**

- Production maps empty, unparseable or ≤ 0 values to 1.2 (`api/v1alpha1/defaults.go:147-156`; `cost/p1cost.go:33-38`). So "disable" is not expressible.
- The replay override must reject ≤ 0 values rather than remap them. Its domain is (0, 1000].
- P-FEA-006 is protected, with safe direction "lower".
- For RetainSLO assets, the gate tags instead of excluding. `mayBreachSLO` is unset in every git policy.

---

## (g) Replay prerequisites (headline)

Full inventory: [recon/replay-prerequisites.md C.1–C.2].

**Missing pieces:**

| # | What must exist | Why |
|---|---|---|
| 1 | **Ordered per-tick view capture** (`[]*model.WorkloadView`, `model/types.go:1145-1179`) | No recorder exists. The trace `inputs` block is a subset: no full Pod fields, neighbours, raw events or OutcomeEvents, per-variable exposure and intent maps, PDB and scheduler physics, or InfectionFrontier. View order (unsorted informer list) decides tie-breaks (`existential.go:118-129`). |
| 2 | **Policy capture gaps** | `fromLabels` is a func field, so `model.Policy` is not JSON-serializable. `Mode`, the quarantine-capacity inventory, shared-resource reservations, `DecisionAssets` and trust-boundary inputs are not captured. The overrides have no inverse. |
| 3 | **Engine state export/restore** | RLS θ and P, and the conformal window, are the real blockers once `primed=true`. StageClock is reproducible unless a stage transition occurred. Dual λ is restorable from `lambdaRuntime`. Conjugate memory is deterministic (never learns). |
| 4 | **Collaborator stubs** | Capability and SSAR verdicts (`actionStatus[]`), failure cooldown, `NativeRotate` and capacity inputs are impure. They must be injected. |
| 5 | **Determinism hooks** | Inject `Now` (`e.Now` is nil in production, so `time.Now()`). Call `cost.ConfigureGPUEnvelopeMax(0.2925)` and `recon.Registry.SetDefault("ucw-recon")`. Use the same binary or manifest hash. |

**Usable seams:**

- `DecideShadowChecked`, which is non-mutating (M-163).
- `EvaluateSensitivity` for frozen-`Now` baseline/variant pairs. It needs `costCeiling`, `costPreferences` and `costWeights` variants added.
- The runner's shadow hook (`runner/manager.go:2142-2155`), which is the natural place for a production parameter shadow.

**MVP shortcut (inference).** Both MVP sweeps can start as **selection-stage replays over trace v7 records**, as described in (f). They need neither the view capture nor the state restore. Their limits must be labelled `MECHANISM` only.

---

## (h) Items still NOT_VERIFIED

| Item | Rows | Owner | Evidence plan |
|---|---|---|---|
| Live runtime λ_t per policy at 0.4.216 | P-OBJ-002 | SRE + Brain maintainer | `phorvex_policy_lambda`; `decisionTrace.lambdaRuntime` in `/audit/live.jsonl` |
| Live economics mode per decision (derived legacy from live specs) | P-OBJ-025 | Brain maintainer | `decisionTrace.economicsVersion` from the live audit |
| Live policy fields not in the 2026-10-09 summary: `minAvailableReplicas`, `reactiveOnly`, `actions.enabled` (crm-refund-revoke, quarantine), `antiOverRotationWindow`, `proactiveFloor`, `assetValue`, `killChain`, `exposurePressureCap`, `eventAgeHorizon`, `selector`, `mode`, `tenant` uniqueness | P-FEA-001/004/005/019, P-OBJ-014/016, P-SEC-001…003, -027…036, -057, -064, P-OTH-001/002 | SRE | Hash a `kubectl get phorvexpolicies -A -o yaml` snapshot into each experiment manifest (Ticket C) |
| In-cluster CRD carries `costPreferences` (prerequisite before syncing `phorvex-policies`) | P-OBJ-023/024 | SRE | `kubectl get crd phorvexpolicies.phorvex.ai -o yaml` |
| Approved-digest env, serving-security file, operator namespace, rendered event-identity policy, `actuatorNamespaces` and crm RBAC | P-FEA-029, -035, -038, -039, -048, P-SEC-092 | SRE | Capture the operator Deployment spec and rendered manifests |
| `--calibration-export-dir` live (chart renders it; absent from the flag summary) | P-CST-053 | SRE | Deployment args |
| Namespace dry-run and pod opt-out annotations | P-FEA-017, -018 (Q15) | SRE | Capture metadata at run start |
| RBAC fail-open frequency | P-FEA-031 (Q12) | Brain + SRE | `phorvex_candidates_rbac_unknown_total` |
| NaN-path frequency | P-CST-056 (Q7) | Brain + SRE | `phorvex_cost_nan_unactionable_total` |
| DCGM series present | P-SEC-073 | SRE | Prometheus query |
| Code-exec verifier timing overrides | P-FEA-044 | Brain maintainer | Trace the constructor at `cmd/main.go:586-588` |
| Manifest and overrides hash identity between 0.4.211 and 0.4.216 | P-CST-004, P-OBJ-016 | Brain maintainer | Run `cmd/parameter-manifest` at both SHAs; recompute the overrides hash for one fixed spec |
| Restart behaviour of clocks and intents (empirical) | P-RUN-007, P-FEA-004 (Q17) | Test owner | Sandbox restart test |
| Effect of proactive cadence on crm-refund-revoke (expected nil) | P-FEA-005 | Brain maintainer | Trace exclusion kinds on crm decisions |
| Historical audited-run values, carried over (λ_t = 0 on 524 updates; run policies) | P-OBJ-002 | OR/Math | Accept as historical, or re-derive from the archived export |
| Selection-stage replay sufficiency for both MVP sweeps | P-OBJ-003, P-FEA-006 | Brain/OR tooling | Ticket F golden: reproduce recorded selections from trace v7 before any sweep |
