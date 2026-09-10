# The check catalogue, audited against the source

Every check in `pipeline/checks.py` is listed here with the inputs its verdict rests on,
the assumption that makes those inputs meaningful, and what the check does when an input is
absent. The last column is the one that matters: a check that reads an absent input as a
zero, an empty list or a `False` is not testing a contract, it is manufacturing one.

The inputs were read against the deployed producers, not against the dashboard's field
names. `pipeline/fixtures.py` builds records in that same shape, so a test cannot pass
against a schema the operator does not write.

## What the audit changed

Three of the 39 were reading fields that no longer exist, and none of them said so —
they returned SKIP or PASS, which on a board of 39 is invisible.

| Check | Was reading | Actually emitted | Effect before |
|:--|:--|:--|:--|
| `B01` | `risk` | `coverageValue` (`internal/audit/contract.go:36` renames it; `internal/audit/log.go:133` *rejects* a v2 record still carrying `risk`) | The engine's central identity `net = gain − λ×cost` skipped on every run against the deployed operator |
| `C03` | `belief` | `pHold` (retired in the same rename) | One component of the composite could never be evaluated; combined with the composite bug below, an all-absent C03 reported PASS |
| `PH02` | top-level numbers and one level of list-of-objects | `decisionTrace` and `pHoldInputs` are nested objects | The global NaN sweep could not see the optimiser's own nested inputs — the exact place the bug class it exists for lives |

Two further notes from the same read:

- `p0-greedy` is in `invariants.known_engines` but was removed from the product
  (`internal/decision/select.go:16`, M-107). `B02` still allows it, because an allowlist is
  not the place to assert a removal; `B01` maps a gain term for `p1-coverage` only and
  reports any other engine as unevaluated rather than asserting this identity against it.
- `C08`'s identity is exact and still holds: `projectedNextStageSec = median − dwell`
  (`internal/killchain/hazard.go:521`) and `stageHazard = weibullCDF(dwell)`
  (`hazard.go:415`) share one dwell clock, and `weibullCDF(median) = 0.5` for every scale
  and shape. `margin < 0 ⟺ hazard > 0.5` is arithmetic, not a tuned threshold.

## Coverage

Status answers "did the contract hold". Coverage answers "over how much".

| Coverage | Meaning |
|:--|:--|
| `full` | Every input the check claims was observed. |
| `partial` | Some records or components were unavailable, or the capture was scoped to fewer namespaces than the check's wording implies. |
| `none` | Nothing observable at all. A critical check at `none` blocks a PASS headline — it is an unanswered question, not a satisfied contract. |
| `not-applicable` | The situation the check is about did not arise (nothing was actuated, no target was given). This is a legitimate part of a passing run. |

## 0 · Preflight

| Check | Inputs | Assumption | If an input is absent |
|:--|:--|:--|:--|
| `P01` | console `/api/health`, `/api/version` | The console under test is the one in front of the operator that writes this audit | `ok != true` fails; no version is reported in evidence only |
| `P02` | `/api/version` console + operator | One build ships both | SKIP — no version reported |
| `P03` | `record.time`, capture completeness | Records are a live tail, not a replayed archive | No record at all: FAIL, coverage `none`. Unparseable timestamps: WARN. Incomplete capture: WARN, coverage `partial` |
| `P04` | pod `.status.phase`, `.status.conditions[Ready]`, `.metadata.deletionTimestamp` | The attack must land on something serving; `Running` is scheduling, `Ready` is the probe passing | No baseline: SKIP `not-applicable`. A pod with no Ready condition is `unknown`, never `not ready` — it reduces coverage to `partial` |
| `P05` | Deployment→ReplicaSet→Pod inventory, `restartCount`, Ready condition | The named Deployments are the controllers whose health decides whether later stages mean anything | An unreadable or malformed inventory is FAIL with coverage `none` — never an empty, healthy-looking set |

## 1 · Ingest

| Check | Inputs | Assumption | If an input is absent |
|:--|:--|:--|:--|
| `I01` | `tenant`, `namespace`, `pod` | Ingest genuinely saw the pod it is deciding about | Empty identity fields FAIL; no records at all is SKIP `none` |
| `I02` | `record.time` | The audit is appended in tick order | Fewer than two timestamps: SKIP |
| `I03` | `record.namespace`, `target.namespace` | Silence about the target means "decided nothing", not "never saw it" | No target: SKIP `not-applicable`. Target absent from the stream: FAIL |

## 2 · Physics

| Check | Inputs | Assumption | If an input is absent |
|:--|:--|:--|:--|
| `PH01` | `residual` | Always written by the v2 schema (not `omitempty`) | Absent from every record: SKIP `none`, reported as "unavailable, not zero". Absent from *some*: FAIL — the schema says it is always there |
| `PH02` | every numeric leaf, recursively | A NaN anywhere in the record can reach the optimiser or the dashboard | Booleans are excluded (they are `int` in Python and finiteness says nothing about them). Recursion is depth-bounded |
| `PH03` | `residual`, `threatPosture`, `selected` | Physics reports; context decides | Records missing either field are excluded from the population and reduce coverage — an absent `threatPosture` is not `0` |

## 3 · Context

| Check | Inputs | Assumption | If an input is absent |
|:--|:--|:--|:--|
| `C01` | `assetValue` | Non-`omitempty`; finite and ≥ 0 | As `PH01` |
| `C02` | `blastRadius` | Normalised to the cluster's worst pod | As `PH01` |
| `C03` | `threatPosture`, `exposure`, `sloHeadroom` | All dimensionless, all always written | Every component absent: SKIP `none`. Some absent: PASS at `partial`. `belief` is not read — it was retired to `pHold` and is covered by `C07` |
| `C04` | `phase`, `invariants.known_phases` | The allowlist matches `ctxprov` | No record carries a phase: SKIP `none` |
| `C05` | `stage`, `invariants.known_stages` | Includes the parallel AI chain | As `C04` |
| `C06` | `stage`, `nextStage` | Linear successor, lateral jump, or the AI map | No record carries both: SKIP `none` |
| `C07` | `stageHazard`, `pHold`, `preemptMargin` | All three are `omitempty` probabilities | All absent: SKIP `none` — never PASS. Some absent: `partial` |
| `C08` | `projectedNextStageSec`, `stageHazard` | Both from one Weibull and one dwell clock | A record with a margin but no hazard is **not** evaluated; reading the absent hazard as `0.0` would assert the identity against a value the operator never produced |

## 4 · Brain

| Check | Inputs | Assumption | If an input is absent |
|:--|:--|:--|:--|
| `B01` | `engine`, `coverageValue`, `cost`, `net`, `lambda` | Under `p1-coverage`, `net := cov - lambda*ecost` (`decision/coverage.go:662`) | `lambda` is `omitempty` and its zero genuinely means no budget pressure — the one absence this identity may read as `0`. Any other engine is unevaluated, not asserted |
| `B02` | `engine`, `invariants.known_engines` | The record names the engine that produced it | No engine named: SKIP `none` |
| `B03` | `action`, `invariants.known_actions` | Every action has a handler | No action named: SKIP `none` |
| `B04` | `lambda` | `omitempty`, finite, ≥ 0 | Absent everywhere: SKIP `none`; absent on some: `partial` |
| `B05` | `selected`, `feasible` | Reads the record's own two fields — it does **not** re-run the feasibility laws | No selection: SKIP `not-applicable` |
| `B06` | `reason` | The explanation is generated, not a constant | An identical string across ≥ 8 records is a WARN, not a PASS |
| `B07` | PhorvexPolicy `.metadata.uid`, `spec.budget.maxMovesPerTick`, `record.namespace/time/selected` | The budget is a ceiling on **one policy's own** assets | No single governing policy observed (none, several, or unreadable): SKIP `none` — an owner-wide budget cannot be established without an owner. Selections outside the policy's namespace are counted and excluded, reducing coverage to `partial` |
| `B08` | `time`, `namespace`, `pod`, `selected` | One asset, one action per tick | No selection: SKIP `not-applicable` |
| `B09` | `r6Counterfactual` | The three-way dashboard comparison comes from this | Missing: WARN at `partial` |
| `B10` | `attribution[]` | Contribution weights reach the dashboard | No attribution anywhere: SKIP `none`. A non-object entry is malformed and fails |

## 5 · Feasibility

| Check | Inputs | Assumption | If an input is absent |
|:--|:--|:--|:--|
| `F01` | `feasible`, `infeasibleWhy`, `invariants.law_reason_prefixes` | Every rejection names a law or the RBAC gate; prefixes are the literal strings in `internal/feasibility/*.go` | No rejection in the window: SKIP `not-applicable`. An unmapped reason FAILs rather than being tolerated |
| `F02` | `actuated`, `feasible` | Fail-closed also holds at the issue boundary | No actuation: SKIP `not-applicable` |
| `F03` | pod `ownerReferences[0].kind`, `spec.volumes[].persistentVolumeClaim`, `record.action/selected/actuated` | Mirrors `ingest/kube.go:406` | A rotate target whose stateful status was **not observed** is reported as unobserved (WARN, `partial`), never as stateless. No stateful pod at all: SKIP `not-applicable` — passing on an empty set is the green-board-built-on-nothing failure |

## 6 · Actuator

| Check | Inputs | Assumption | If an input is absent |
|:--|:--|:--|:--|
| `A01` | `actuated`, `selected`, `dryRun` | A consistency check on the audit record, **not** an independent observation of the actuator | No actuation: SKIP `not-applicable` |
| `A02` | `handler`, `objectsTouched`, `invariants.phoenix_actions` | The fingerprint is the record's own claim; `A03` is what checks the cluster | Phoenix-delegated actions are excluded and reduce coverage to `partial` |
| `A03` | `groundTruth[].verdict`, `groundTruth[].attribution` | Independent cluster observation, never Phorvex's report | Nothing actuated: SKIP `not-applicable`. Any `unverifiable` prevents a PASS: all unverifiable is WARN `none`, a mix is WARN `partial`. Confirmed effects whose cause could not be attributed pass at `partial` |
| `A04` | `dryRun`, `actuated` | Under dryRun nothing is actuated | No dryRun decision: SKIP `not-applicable` |
| `A05` | injection `eventUID`/`targetUID`, record `eventUID`/`podUID` (feature-detected), `time`, `namespace`, `actuated` | A reaction is attributable only when the record carries **both** the event UID we created and the target Pod UID we aimed at | The deployed `phorvex.audit.v2` carries neither (it has `events[].name` and a Pod *name*), so A05 reports `unsupported` at coverage `none` and **cannot pass**. PR171/M18 supplies the forensic event UID; support is detected from the records, never assumed. No reaction at all remains a FAIL |
| `A06` | metric `phorvex_kill_switch_engaged`, `selected`/`feasible`/`dryRun`/`actuated` | The writer's own gauge separates deliberate suppression from a broken actuator | A **failed scrape** and a **successful scrape with no such gauge** are different facts and both are reported with their reason. Neither is read as `0` |
| `A07` | metric `phorvex_kill_switch_engaged`, `record.killSwitch` | A decision mirror must stamp every record | Unreadable metric: SKIP `none`, with the scrape's reason |

## Capture scope

`I01`, `PH02`, `PH03`, `B08` and `A07` are worded as claims about "every record". When the
run declares a scoped capture (`capture.namespaces`), those claims cover that scope only,
their summaries say so, and their coverage drops to `partial`. A scoped run is never
reported as cluster-wide coverage.
