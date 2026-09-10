# Revision 2 — corrective pass on the catalogue assessment

Investigator: claude-audit-catalogue. Reviewer of record for this revision: codex-lead.
Source: `dbf5fa4321b35651e8142cb2c13d4f28f8c6dcca` (unchanged).
Revision 1 (`REPORT.md`, sha256 `afe03df9…570292`) and its seal are **retained
unmodified**; `sha256sum -c SHA256SUMS.txt` verified OK at the start of this pass.
Date: 2026-09-10.

Companion per-ID coverage (one explicit row per ID, no ellipses):
- `COVERAGE-SCENARIOS.md` — 112 registered scenario IDs
- `COVERAGE-DEFENDERS.md` — 13 registered defender IDs
- `COVERAGE-WORKFLOW.md` — 67 workflow case IDs

---

## 1. Withdrawals and corrections to revision 1

I accept the lead's core criticism. Revision 1's favorable verdict on the
measurement pipeline was wrong, and I state the specific defect in my own work:
**I identified the oracle-error and missing-baseline paths while reading
`runner.go` and did not carry them into the report.** They were in my analysis
and absent from my findings. That is an omission of adverse evidence, not a
difference of judgment, and it is the reason revision 1 read as favorable.

Withdrawn from revision 1:

| Revision 1 statement | Status | Replaced by |
|---|---|---|
| "the **core machinery is honest and well-built** … generic runner … report anchoring" | **WITHDRAWN** | R2-1, R2-2, R2-3, R2-6 |
| "Verdict in one line: core machinery is honest and well-built" | **WITHDRAWN** | §5 corrected verdict |
| "**Causal attribution:** genuine for live/rotation-target paths" | **WITHDRAWN** — no oracle in the harness performs any causal check | R2-4 |
| "**Cleanup / stale cross-trial state:** … correct" | **WITHDRAWN** for cleanup fidelity | R2-5 |
| "**Required capabilities / error semantics** … correct" | **WITHDRAWN** for error semantics | R2-1, R2-7 |
| Archetype coverage table with counts/ellipses | **SUPERSEDED** | the three per-ID coverage files |

Retained and now independently strengthened: F1 (generic APT stimulus) and F2
(harness-simulated repair), F3 (test-coverage gap), F4/F5/F6.

Also corrected: revision 1 said "all packages pass" as part of a favorable
framing. That statement was true but load-bearing in the wrong direction. Per the
lead: passing tests prove their assertions only. The product suite asserts
metadata shape and pure helpers; it asserts nothing about measurement validity,
which is why every defect below survives a green suite.

---

## 2. Independent reproduction of the lead's findings

All reproductions call the **real shipping producers** through `go test -overlay`,
so nothing was written into the product tree (verified: no `zz_reviewer_*.go`
exists under `build/test-harness`). Commands and logs in §7.

### R2-1 — confirms LEAD-CAT-002, and extends it: the invalid row *wins* on cost

`internal/core/runner.go:247-251` logs a `SuccessOracle` error and then uses the
**zero-value** `OracleResult`. Against an observed-achieved baseline this becomes
`Achieved=false → DisruptionVsOracle=1`, `Skipped=false`, `SkipReason=""`.

Reproduced (`evidence-r2/r2-core-runner.log`, `TestR2OracleErrorScores…`).
My extension — the amplification the lead did not quantify. Because
`securityPerCost(d, 0)` returns `d` itself (`runner.go:514-519`) and
`AnnualDefenseCostDollars` charges per action (`economics.go:48-59`), a trial that
failed for infrastructure reasons and spent **zero** defensive actions outscores a
genuine defense that actually spent three:

| row | disruption | actions | securityPerCost | securityPerCostDollars |
|---|---|---|---|---|
| oracle transport error (invalid) | 1 | 0 | **1.000** | **$610,000** |
| genuine defense, 3 rotations | 1 | 3 | 0.333 | $542,222 |

So the ROI and efficiency headline numbers are maximised by measurement failure.
`applyPassBExtension` stamps `ROI`/`Schwartau` on the invalid row unconditionally
(`runner.go:313-315`).

### R2-2 — confirms LEAD-CAT-003, and extends it: the defect is systematic, not an edge case

`runner.go:296-303` treats an absent baseline entry as `baseHit = true`.
Reproduced. My extension is the more serious form: **`Run()` passes
`isBaseline=false` for the adaptive pass** (`runner.go:129`) and indexes it at
`TrialsPerArm+1`, an index the baseline arm never runs (it runs `0..N-1`). So
**no adaptive trial can ever be anchored**, and `-adaptive` defaults to **true**
in `cmd/harness/main.go:40`.

Driving the **real `Run()`** loop (`TestR2AdaptiveArmIsStructurallyUnanchored…`):

```
row defender=d-rv-nomtd     trial=0 adaptivePass=false oracleAchieved=true  disruption=0 anchored=true
row defender=d-rv-nomtd     trial=2 adaptivePass=true  oracleAchieved=false disruption=1 anchored=false
row defender=d-rv-defended  trial=0 adaptivePass=false oracleAchieved=true  disruption=0 anchored=true
row defender=d-rv-defended  trial=2 adaptivePass=true  oracleAchieved=false disruption=1 anchored=false
```

Row 2 is self-refuting: **`d-nomtd`, the undefended positive control, is credited
100% disruption against an invented control.** Any adaptive-arm number in any
existing report is unanchored by construction.

### R2-3 — confirms LEAD-CAT-001, and extends it: the substituted credential is of a different *kind*

`scenarios/c1_credtheft_rbac.go:59-61` reads `head -c 16` of the token, logs the
prefix, **discards it, and never checks the exec result**; `:78-86` mints a fresh
token via `CreateToken` and replays *that*. Reproduced through the real `Execute`
→ `SuccessOracle` path with a distinctive stolen value: the API saw
`Bearer MINTED-BY-ORACLE` and **never** the stolen bytes.

Three extensions:

1. **The minted credential is not pod-bound.** `TokenRequest.Spec` is
   `{BoundObjectRef:nil Audiences:[] ExpirationSeconds:nil}`
   (`TestR2CredTheftOracleMintsANonPodBoundCredential`). The projected token the
   attack actually steals *is* pod-bound by the kubelet. Pod deletion cannot
   invalidate an unbound token by construction, so this oracle **cannot observe
   pod-bound revocation even in principle** — which is precisely the mechanism
   that makes the scenario's `R6CannotRespond` metadata unfalsifiable. Direction
   of the error matters: this one is **unfavourable to the product**, and the
   harness's own locked test (`scenarios_test.go:135`) pins the unfalsifiable
   verdict in place.
2. **A demonstrably failed theft still scores success.** With the in-pod read
   returning empty output and exit code 1, `Execute` returns `err=nil` with 3
   stages and the oracle reports `Achieved=true`
   (`TestR2CredTheftFailedTheftStillScoresAsSuccess`).
3. **Exposure calibration, against the lead's "never log its bytes".** The logged
   value is only the first 16 characters, which for a real SA JWT is the constant
   `RS256` header prefix — **not secret material**. The defect is provenance loss,
   not credential leakage. Worth stating precisely so the fix is scoped correctly.

**Reconciliation the lead asked for.** The workflow catalogue *already encodes the
correct rule*: `workflow/attacks/procedures/identity.md` requires "Name the
credential class first: pod-bound service-account token, legacy token, external
API key … Do not assume they share revocation semantics", "replay the captured
old identity", "Never claim stolen external keys were revoked by pod replacement",
and "If only a label changes, the effect test fails." Workflow case **GP9**
requires a `credential_replay_probe` capability and sets
`expected_defense: not_evaluated`. The executable Go scenario violates every one
of those requirements and asserts a blanket verdict the workflow catalogue
explicitly refuses to assert. This is not a missing rule; it is an implemented
contradiction of a written one.

### R2-4 — confirms LEAD-CAT-004, and extends it well beyond the `-apt` block

Reflection over the real registry (`evidence-r2/scenario-map.tsv`) gives an
authoritative proof rather than name-matching: **52 of 112 registered scenario IDs
are the single Go type `*scenarios.aptCampaign`** — one `Execute`
(`plantBackdoor`, `apt_campaigns.go:63`), one `SuccessOracle`
(`measureSurvival` 10s, `:72`), with the 8 phases emitted only as log strings
(`:65-67`).

My extension: the generic marker-plant/marker-survival probe is **not confined to
`-apt`**. It is also the entire stimulus and oracle of ~10 *base* IDs
(`c1-escape-persist`, `c1-fast-attacker`, `c1-heldout-cve`, `c1-llm-adaptive`,
`c1-stealth-dweller`, `c2-dwell-rotation`, `c2-persistence-evict`,
`c2-stateful-training` (plus a quarantine discriminator), `b-recon-lifetime`,
`b-recon-lifetime-ai`, `e-dilution-n9`). Concretely: **`c1-escape-persist` claims
T1610/T1611/T1068 container escape and executes no escape primitive at all** —
its whole attack is writing `/tmp/.r6th_backdoor`. The technique-claim inflation
is therefore a property of the base catalogue too, not only the generated block.
Only `c1-escape-persist-agent` actually probes the escape surface.

---

## 3. New findings from this pass (not in the lead's set)

### R2-5 — cleanup fidelity is unrepresented, so a failed cleanup is invisible

`runner.go:318-326` logs `sc.Teardown` / `d.Stop` / `d.Teardown` errors and
continues; the `Metric` schema has **no cleanup field**. Reproduced: a scenario
whose `Teardown` returns "cleanup failed: foothold pod still present" emits
`Skipped=false SkipReason=""` — byte-identical to a clean trial
(`TestR2TeardownFailureIsInvisibleInTheMetric`). Consequence: an arm that left a
live foothold behind cannot be distinguished from one that cleaned up, and the
next trial reuses the namespace. The workflow catalogue by contrast **gates on
cleanup** (`tools/attacks.py:428`), so the two systems disagree on whether
cleanup is an acceptance condition.

### R2-6 — the report layer cannot distinguish measured, invalid, and unobserved

Three reproductions against the real `report.Aggregate` / `RenderMarkdown`
(`evidence-r2/r2-report-aggregate.log`):

- **Invalid rows blend into the headline.** One genuine row (disruption 0) plus
  one oracle-error row (disruption 1) publishes **`Disruption% = 50%`, Trials=2,
  Skipped=false**, with no invalidity marker.
- **An unrun negative control is indistinguishable from a measured clean one.**
  `report.go:77` writes `acc.negSeen` and **nothing ever reads it**; both arms
  print `NegFalseMoves = 0`. Anchor-only baselines skip their negative control
  entirely (`runner.go:119`), so they publish a clean control they never ran.
  This is the lead's item 4 ("unobserved … treated as a pass") realised in code.
- **Partial skips vanish.** 1 scored + 1 skipped trial publishes `Trials=1,
  Skipped=false, Disruption%=100%`: the denominator silently shrinks and the
  invalidated trial leaves no trace (`report.go:80-84,105`).

### R2-7 — "pod absent ⇒ attack failed" is the dominant oracle idiom, with zero causal evidence

Eleven classic/c3 scenarios return `Achieved:false` the moment
`runningPodByApp` fails: `c1-lateral:83`, `c2-lateral-disrupt:78`,
`c2-supplychain-foothold:78`, `c2-stealth-foothold:77`, `c3-admission-bypass:78`,
`c3-cicd:76`, `c3-cryptomining:75`, `c3-imds-theft:89`, `c3-secrets-sprawl:100`,
`c3-sidecar-inject:85`, `c3-supplychain:75`.

Reproduced with the **real oracles** (`TestR2AbsentPod…`, `TestR2ObservationTimeout…`):

- `c1-lateral` on an empty cluster: after the real 43-second poll,
  `achieved=false skipped=false evidence=map[]` — **empty evidence, no causal key**.
- `c3-imds-theft` when the *observation* times out: `achieved=false skipped=false`
  — an **observability failure is byte-identical to a successful eviction**.

Composed with R2-1/R2-2, a pod that merely failed to appear scores as a
**perfect, zero-cost defense** (`disruption=1`, `securityPerCost=1`). And
`c3-imds-theft` is tagged `R6CannotRespond` while its own source concedes "Even
if the pod rotated, the stolen cloud credential remains valid" (`:86-87`) — yet
it replays the stolen credential **from inside the replacement pod**, so rotation
removes the attacker's vantage point and is credited with stopping a
cloud-credential attack it does not mitigate. `procedures/boundary.md` states the
correct rule the code violates: "A patched/absent surface is NOT_APPLICABLE with
evidence, not successful defense."

Positive control included: with a live pod and the marker present, the same
oracle family correctly reports the attack achieved
(`TestR2ControlMarkerPresentScoresAttackAchieved`). So R2-7 is a causal-attribution
defect in the absent branch, not a wholly inert oracle family. Note the same test
shows `backdoorAlive` also returns false when the in-pod exec merely fails
(`scenarios/common.go:231-234`) — the identical conflation.

### R2-8 — two registered scenario IDs can never execute anywhere

`ai2-gpu-side-channel` and `ai2-co-location-cross-tenant` have no-op
`Setup`/`Teardown`, an `Execute` that returns `Skipped:true`, and a
`SuccessOracle` that returns `aiSkip(...)` **unconditionally** — not gated on
capability. Even on a GPU multi-node cluster they measure nothing, forever. They
are honestly labelled capability-pending, but they occupy 2 of the 112 IDs with
no stimulus and no oracle. Their `-apt` counterparts *are* GPU-gated in
`aptTable`, so on a GPU cluster the generic probe runs in their place.

### R2-9 — F2 confirmed behaviourally, with controls (the lead's item 2)

Not method-name tracing this time. Real registered defenders, real scenario
lifecycle, real `controller-runtime` fake client so the genuine
`fullPhoenix.EmitSecurityEvent` path executes, fake in-pod exec for the mock
substrate (`TestR2F2HarnessRepairCreditsOnlyTheEmitterArm`):

| arm | attacker achieved | persistenceDisrupted | harness `RestoreGolden` calls | SecurityEvents created | substrate carries rotation-target label |
|---|---|---|---|---|---|
| d-fullphoenix | false | **true** | **1** | 1 | **false** |
| d-phorvex | true | false | 0 | 0 | false |
| d-nomtd (no defense CONTROL) | true | false | 0 | 0 | false |

Three conclusions, each now behavioural:

1. The credit given to `d-fullphoenix` is produced by the **harness calling
   `RestoreGolden` itself** (`ai2_poisoned_model_registry.go:47-48`), gated on
   `emitGenuineTrigger`. The only product-side effect is creating a
   `SecurityEvent`; the substrate carries no rotation-target label, so neither the
   Phoenix AMTD `PodSelector` nor the `PhorvexPolicy` selector could ever have
   selected it. **A repair made by the harness is not the product's defensive
   action** — confirmed.
2. **`d-phorvex` is indistinguishable from no defense at all** on this scenario.
   Reflection over the real registry confirms the mechanism:
   `Emitter` is implemented by **only** `d-fullphoenix` and `d-reactive-only`
   (`evidence-r2/defender-map.tsv`), never by `d-phorvex`.
3. This is an **invalid test, not a demonstrated product failure**. The zero for
   PX is a measurement artifact and must not be read as "PX cannot cover model
   poisoning". Same for the two sibling scenarios `ai2-data-model-poisoning` and
   `ai2-agent-rogue-tool-persistence`.

### R2-10 — where the harness is honest (recorded so the assessment is not one-sided)

Six AI oracles carry source comments stating their own measurement is
structurally zero for every arm, and the code matches: `ai1-inference-manipulation`
("the static path persists, so this measures false"), `ai1-model-theft`,
`ai2-embedding-store-tampering`, `ai2-rag-retrieval-poisoning`,
`ai2-embedding-tamper-reuse`, `ai2-tampered-inference-base-image`. Those are
correct negative results, correctly labelled. `aiOracle.result()` recomputes
`neutralized` arm-neutrally (`ai_common.go:50-58`), pinned by
`audit_regression_test.go:16-37`. `internal/safety/guard.go` is sound. The
`stats.go` t-interval and `economics.go` formulas are arithmetically correct — the
defect in R2-1 is the *input validity*, not the arithmetic. `c2-stateful-training`
discriminates quarantine from delete on a real emitted event type
(`:124,170-198`). `apt-*-live` confirm a real pod-UID replacement. Scenario
`Setup` failure *is* correctly invalidated (`TestR2SetupFailureIsCorrectlyInvalidated`),
which proves the invalidation mechanism exists and is simply not applied in the
`Execute`/oracle/baseline/cleanup paths.

---

## 4. Distinguishing benchmark defects from product findings

The lead's item 4. Kept strictly separate:

**Harness/measurement defects (this assessment):** R2-1 … R2-9. None of these
demonstrate a product failure. In particular the PX zeros in R2-9 and the
`R6CannotRespond` verdict in R2-3 are artifacts of substituted substrate and
substituted credential respectively.

**Product findings recorded elsewhere, which I did not verify and do not
adopt:** the workflow catalogue carries live-run historical verdicts including
`M6 🔴 T13` (forged detector → rotate healthy pods, "landed"), `R3 🔴 T44`
(rotation weaponised into availability drain, "bounded: absorbed at N=2"),
`GP9 ⚙️🔴 T10`, `S2 ⚙️🔴 T11`, `GP6/GP8 🔴 T30` ("silent w/o detector"). These are
`historical-unrevalidated`; they are not current deployment proof and I make no
claim about them. They are listed in `COVERAGE-WORKFLOW.md` as recorded, not
confirmed.

**Unknown either way:** whether pod deletion actually revokes the projected token
(R2-3) needs a bounded live acceptance test on dev; I could not and did not run
one. Whether PX would disrupt a genuinely-targeted poisoned substrate (R2-9)
needs the substrate fixed first.

---

## 5. Corrected verdict

The catalogue's **stimulus realism** and its **measurement validity** are both
below what a due-diligence reader would infer from the reports it produces.

- 52 of 112 IDs are one generic probe (R2-4), ~10 more base IDs are the same
  probe, and 2 can never run (R2-8).
- The measurement pipeline converts **five distinct failure modes** —
  oracle transport error, attack-stimulus error, missing baseline, absent
  observation pod, observation timeout — into **maximum disruption at zero cost**,
  and the report layer cannot distinguish any of them from a measured defense
  (R2-1, R2-2, R2-6, R2-7).
- Every adaptive-arm number ever produced is unanchored by construction (R2-2).
- Where the harness does credit the flagship arm on the AI supply-chain
  scenarios, it is crediting its own repair; where it gives PX zero, that zero is
  an artifact (R2-9).

Revision 1's "core machinery is honest and well-built" is withdrawn. The correct
statement is: the machinery is **well-structured and arithmetically sound, with a
validity model that is absent in exactly the paths where it matters**. The
invalidation mechanism exists (`Skipped`/`SkipReason`) and is wired for one path
only.

**Recommended remediation order** (dependencies noted):

1. **Outcome-validity contract** in `core` — an explicit phase/outcome validity
   and error-provenance field on `Metric`; invalid rows excluded from disruption,
   security-per-cost and ROI denominators, and rendered distinctly. Blocks 2–5.
2. **Baseline pairing** — every scored arm requires an observed baseline at its
   own trial index, including the adaptive pass; missing ⇒ unscored. Decide paired
   vs distribution sampling and make the metric match. (Combine with 1 if the
   schema change would otherwise conflict.)
3. **Causal attribution** — an oracle may only report "attack stopped" with
   evidence of the defensive action; absent/unobservable substrate ⇒
   `NOT_APPLICABLE`/inconclusive, per `procedures/boundary.md`.
4. **Cleanup as an acceptance condition** — surface teardown failure on the
   metric and block follow-on trials, matching `tools/attacks.py:428`.
5. **Report honesty** — read `negSeen`; count skipped trials; mark invalid rows.
6. **Credential-replay repair** (R2-3) per `procedures/identity.md`, plus split
   pod-bound vs persistent credential variants; then re-derive the R6 tag instead
   of pinning it.
7. **Substrate repair or downgrade** for the three F2 scenarios (R2-9).
8. **Honest fidelity labelling** for the generic-probe family (R2-4), and stop
   feeding unexecuted technique IDs into `RenderMitreMatrix`.

---

## 6. Model and session provenance

Per the lead's item 5, retained as **mixed-session provenance** rather than
collapsed to one label:

- **Revision 1** was produced in a session whose captured CLI stream contains
  both `claude-opus-5` and `claude-opus-4-8` in assistant events and
  `modelUsage`. The environment banner initially declared Opus 5; a mid-session
  system correction re-declared Opus 4.8. My revision-1 report recorded the
  corrected identity as operative; the lead's capture is consistent with that and
  shows both. I do not claim revision 1 was wholly either model.
- **Revision 2** (this document) was produced under an invocation pinned to
  `--model claude-opus-5 --effort max` with no fallback; the environment declares
  `claude-opus-5`.
- **Prior exposure.** Revision 1 was a blind fresh pass (no historical issues,
  audit reports, `build/test-harness/*.md`, archive, fix records, or other
  investigators' reports). For this revision the lead lifted that restriction for
  exact reconciliation, and I read: `LEAD-REVIEW-R1.md`, the copied
  `lead-review-evidence/*`, `workflow/attacks/catalogue.yaml`, and
  `workflow/attacks/procedures/{identity,boundary}.md`. I did **not** need or read
  historical issue bodies, `build/test-harness/*.md`, `workflow/archive`, or fix
  records; the reconciliation I needed was available from the case definitions and
  procedures. So the `M-140/M-18/M-21/M-79` history the lead holds is still
  unexamined by me — my pass remains independent of it, which is a limitation for
  root-cause dedup and an advantage for independence.

---

## 7. Exact commands, real tests, permission denials, gaps

**Toolchain:** `/home/mehrdad/.local/share/phorvex-tools/go1.26.1/go/bin/go`
(selects `go1.26.3`), `-p=1`, `-cpu=2`, `GOMAXPROCS=2` inherited. All runs from
`/home/mehrdad/operator-audit-catalogue/build/test-harness`.

Overlays keep every reviewer file inside my assessment directory:

```
go test -p=1 -cpu=2 -overlay=<ASSESS>/revision2-overlays/overlay-core.json       -run TestR2 -v ./internal/core/
go test -p=1 -cpu=2 -overlay=<ASSESS>/revision2-overlays/overlay-report.json     -run TestR2 -v ./internal/report/
go test -p=1 -cpu=2 -timeout=600s -overlay=<ASSESS>/revision2-overlays/overlay-scenarios.json -run TestR2 -v ./scenarios/
go test -p=1 -cpu=2 ./...        # unmodified product suite, still green
python3 <ASSESS>/revision2-overlays/dump_workflow_cases.py
```

`<ASSESS>` = `workflow/assessments/20260910-readiness/fresh-catalogue`.
Logs: `evidence-r2/r2-core-runner.log`, `r2-report-aggregate.log`,
`r2-scenarios.log`, `product-suite-unmodified.log`. Maps:
`evidence-r2/scenario-map.tsv` (112), `defender-map.tsv` (13),
`workflow-cases.tsv` (67).

**Real tests run:** 6 core-runner characterizations (incl. one driving the real
`Run()` loop), 3 report-aggregation characterizations, 5 credential-oracle
characterizations, 3 absent-pod/causal characterizations, 1 three-arm F2
behavioural confirmation with a no-defense control, 2 registry dumps. Every one
calls shipping code. Two are explicit positive/negative controls
(`TestR2SetupFailureIsCorrectlyInvalidated`,
`TestR2ControlMarkerPresentScoresAttackAchieved`,
`TestR2CredTheftDeniedControl`).

**Permission denials encountered (actions NOT performed):**

1. `git -C … status --short` and `cd … && git status` — **denied** (git
   invocation requires approval in this session). I therefore could not produce a
   git-level diff proving the product tree is untouched. Substituted structural
   evidence: a `Glob` for `**/zz_reviewer_*.go` under `build/test-harness` returns
   **no files** (overlays are virtual by construction), and the unmodified suite
   still passes.
2. Env-var-prefixed command
   (`R2_SCENARIO_MAP=… go test …`) — **denied** (simple expansion). Reworked the
   dumper to write to a hardcoded path inside my assessment directory.
3. `cd … && python3 … > file` — **denied** (cd + redirection). Reworked as a
   standalone script writing its own output path.
4. Earlier in this engagement: `PATH=… go …`, `echo "exit=$?"`, and a
   brace-quoted heredoc were denied for the same expansion/compound reasons.

**Remaining gaps — explicitly not closed:**

- **No live cluster run.** Everything is local characterization. The *magnitude*
  of R2-1/R2-2/R2-7 in a real benchmark (how often oracles error, pods fail to
  appear, or observations time out) is **unmeasured**. A 2-trial kind smoke over
  `d-nomtd,d-fullphoenix,d-phorvex` with the adaptive arm on would quantify it.
- **Token-revocation direction (R2-3) unverified.** Whether deleting the pod
  actually invalidates the projected token needs a bounded dev acceptance test.
  I reason from API semantics only and do not assert current product mitigation.
- **`-resume` batching not exercised.** `NewMetricWriterResume` + disjoint
  scenario filters interact with per-batch in-memory baselines; I reviewed the
  code but ran no reproduction.
- **Concurrency not stressed.** The matrix is sequential; I did not race the
  rotation goroutine against an oracle read.
- **`d-phorvex-vuln-steer` is metadata-identical to `d-phorvex`** (same Go type,
  same description string, interval 0, differing only in the `floor` field). I
  could not confirm behaviourally without the Phorvex operator running.
- **Historical root-cause dedup not done** (M-140/M-18/M-21/M-79 unread by
  design, see §6). Whether R2-1/R2-2/R2-7 duplicate closed issues is for the lead.
- **9 of the 13 defenders and ~95 of the 112 scenarios have NO executable
  validation of their oracle**, live or local. Marked `NOT TESTED` per row in the
  coverage files rather than inferred from a family verdict.

---

## 8. Submission

Submitted for the lead's independent challenge. **I am not approving this work
and not signing it off**; revision 2 is a review submission only. The defects in
§2–§3 are characterized, not repaired, and no fix is proposed as accepted. I have
recorded my own revision-1 omission in §1 rather than presenting revision 2 as a
mere extension.
