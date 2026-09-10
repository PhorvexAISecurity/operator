# PHORVEXSEC-209 / M100 — representation implementation submission

**For:** Zeinab Alizadeh, mathematical conformance review
**Prepared:** 2026-09-09
**Status:** implementation submitted for review; no independent approval, math sign-off, merge, deployment, or ticket closure is claimed.

## Source identity and evidence boundary

The implementation is submitted on `parallel/claim-m100-representation`, based on `345c0ade12ac5b0d6ec71fe96c70cb9bc1d9cbac`. Go source/tests were frozen at **2026-09-09 06:03:54 UTC**. `GO_SOURCE_FREEZE.sha256` binds that tested tree and `SOURCE_MANIFEST.sha256` binds submitted source, tests and documents. The exact implementation commit and ready PR are recorded in the accompanying Plane submission receipt.

The governing input is the full 2026-09-08 representation ruling supplied in `/tmp/current-209.md`, copied here as `M_100_MATH_RULING_2026-09-08.md`, including T01–T16. Task209's complete description in `/tmp/phvx-status-cards.json` was also read. The ruling supersedes the earlier proposal; its E1–E4 are historical evidence, not statements about today's code or deployment.

**Current source differs from E1:** base `345c0ad` already contains M99's `ProtectedOutcome`, `OutcomeEvidence`, and raw `OutcomeAssertion` inventory, plus ingestion of the `phorvex.ai/protected-outcomes-v1` annotation. These carry protected-property/version descriptions, creator/trust information, and event creation time. They do **not** supply a retained ingestion timestamp and a reviewed outcome-specific completed-event predicate mapping for M100. Raw `Qualified`, `StateBasis`, `ClassBasis`, outcome names, or source strings are not accepted as M100 proof. The new adapter reports these supplied assertions as unresolved; it does not ignore their existence or classify them as losses.

No live mutation or live positive-control experiment was performed. All positive losses and numeric ratios in this package are **synthetic contract examples**. The runner example is also synthetic, exercising the real source adapter. It is not a deployment observation. CI/workflows were unchanged and no TypeScript/Next build was run. The final full Go suite and vet passed on the frozen source, as recorded below.

## Delivered behavior, in plain terms

The production runner now captures a detached reporting input **before actuation**, using the current tick reference, tenant, pod namespace/name, pod UID, available trace facts, configured detector identities and raw protected-outcome inventory. A single namespace/name-to-UID map avoids a decisions-times-views lookup. It appends the report after the existing actuation path. The only post-actuation addition to the copied input is a dispatch observation; this never becomes confirmation of security effect. Replaying that retained input reproduces the dispatch qualification too.

The existing top-level `claim` schema and construction point are preserved. The new representation has its own frozen claim metadata. If detector configuration changes during actuation, its pre-actuation metadata can differ from the legacy claim's later capture; neither is overwritten or backfilled. No earlier claim field is renamed or repurposed.

The production output is deliberately conservative:

- Current trace facts are retained as **known unknown entries**, with original recon keys, pod UID and the reason that protected-assertion semantics are unbound. Fact-kind names and covering actions do not prove reversibility or historical loss.
- Known raw protected outcomes appear as **unresolved entries**, with scoped properties/versions and a redacted event/assertion reference. The capability-map gap is separate from these individual entries.
- The trace is a subset of the modeled inventory, not the full denominator. No complete same-snapshot final-weight/cover binding is exposed at this reporting boundary. Thus all weighted amounts and the share are unavailable, with `value: null`; the principal reason is `inventory-incomplete` and other missing bindings are retained alongside it.
- The current event-to-loss mapping is empty: `lossAssessment: unavailable`. The live history source is also unavailable. A recorded loss count of zero means **no loss recorded in the available evidence**, not zero actual loss.
- Empty configured detector sets retain `recallCap: unknown`; configured identities never imply connectivity or positive recall. Out-of-band scope is always `unmeasured`.

There is no new optimizer input, severity, weight, cost, objective term or selection constraint. M99's existing selection behavior is not revised under this task.

## Representation and mathematics

An assertion is scoped by **tenant, asset, asset version, protected property**. `unknown` is the safe zero enum value. The classifier applies:

1. A valid retained loss for the same scoped assertion gives `already-lost`.
2. Otherwise a documented positive observation, rule version and reversible-condition binding can give `at-risk`.
3. Otherwise the entry is `unknown`, with its reason retained.

An ambiguous mapping of one original qualified recon key to multiple assertions is unknown. Ambiguity is detected across the supplied tenant population **before** narrowing the report by property/asset/version; a property filter cannot hide a conflicting mapping and manufacture a denominator. An ambiguous *different key* belonging only to an excluded asset does not invalidate the requested population. Duplicate identical facts and overlapping cover sets are deduplicated. A tenant and original fact key form an unambiguous qualified key; no property annotation receives a new optimizer weight.

Actionability is independent: unsupported, policy-disabled, infeasible and unavailable actionability do not remove an established at-risk entry from the denominator. Unknown and lost entries receive no reported cover credit. Asset summaries preserve requested property scope and version. A known loss has primary-label precedence, while at-risk components and unresolved flags remain visible. Incomplete classification or a relevant broad observation gap makes the applicable specific asset/version summary unknown unless a known loss takes precedence. A replacement pod version does not inherit the old version's primary loss label. Gaps with a nonmatching tenant, asset, version or property do not contaminate the requested primary label; only intersecting scopes propagate.

For a complete declared population, let R be the at-risk subset, K the union of cover sets for the explicit action basis, and C the eligible-candidate cover union. The report computes:

- representable = sum of unchanged final engine weights over R;
- covered = sum over K intersect R;
- coverable = sum over C intersect R, when that candidate snapshot is available;
- share = covered / representable only when the required inputs exist and the denominator is positive.

The complete population can include explicitly classified unknown entries X and known losses L. Their existence does not itself suppress a valid R-only share. Missing/ambiguous classification completeness is different and does suppress it. Weighted amounts have their own availability. No fact-count percentage substitutes for missing weights.

Missing, negative, NaN/infinite weights, mismatched snapshots, unavailable covers, incomplete inventory, missing metadata, empty R and a zero-weight denominator produce explicit unavailable reasons. NaN/infinity are removed only from the retained copy, with **per-key invalid-value markers**. No input map is changed and no value becomes zero. An invalid key outside R does not contaminate an otherwise valid ratio during replay. Accumulation follows sorted qualified keys, independent of map iteration or cover ordering. No display rounding changes stored legacy numbers.

The selected/candidate relation is checked when both are available; a mismatch is unavailable rather than a false weighted bound. The pure function supports `selected-modeled` and `actuated-modeled` cover bases supplied by a trusted adapter. The runtime adapter currently uses selected-modeled with unavailable cover data. It does not reconstruct actuated cover sets from dispatch alone.

The separate `requiredSetCovered` predicate uses set inclusion. A weighted 100% with an uncovered zero-weight required entry has this predicate false. Even true is **not** M99 authorization or T2-01 effect confirmation.

## Loss evidence, retention and redaction

A positive synthetic loss witness includes authenticated identity, ingestion trust reference, complete protected scope, event reference, event and ingestion times, rule version, payload-predicate reference, completed-unauthorized-outcome reference, irreversibility semantics and classification reference. The input adapter is responsible for verifying the referenced predicate and security semantics. The pure function checks structural admissibility; nonempty strings are not authentication or an approved security taxonomy. No production caller currently creates such witnesses.

A declared current mapping version is required to assess newly supplied witnesses. An empty current mapping reports unavailable. Historical admissible witnesses are handled independently of current mapping or detector configuration. Loss identity is stable for the scoped assertion, and repeated witnesses are canonicalized and deduplicated. Disappearing facts, adding actions and changing a detector set do not erase supplied retained history. Malformed identity, empty witness lists, invalid witnesses and mismatched witness scopes downgrade retained history to partial rather than reporting an available empty history.

Every report retains its complete **reporting input snapshot**, including any supplied history and evidence references, in audit JSON. Replay uses those saved inputs; it does not ask today's configuration to reconstruct yesterday's truth. Audit conversion takes a detached copy. Legacy records with nil representation remain absent on disk. `RepresentationForRead` returns a separate unknown projection, with no borrowed detector set, build, weight or state.

The existing credential redactor is applied at the canonical reporting boundary. Raw annotation properties and event references therefore cannot bypass redaction in either the stored report or its structured-log object. Credentials in **weight map keys** are dropped instead of replaced, with an explicit missing-binding limitation: distinct sensitive keys cannot merge or receive positive credit. Input maps stay unchanged. A protected scope altered by redaction cannot establish a positive fact/loss classification. The persisted representation also has a defensive JSON redaction boundary.

**Retention limitation:** this change supplies the retained representation, audit persistence and deterministic replay of supplied history. It does not introduce a live durable loss-ledger loader or an authenticated evidence archive. Existing transient event windows are not silently treated as that archive. The production adapter reports history unavailable. Authentic historical records from an eventual external ledger must be supplied through a reviewed adapter; a correction requires explicit provenance in that ledger, not a claim that an irreversible loss recovered. There is no correction-ingestion mechanism or automatic cross-tick import implemented here. These limits are visible and remain handoff items before any positive live loss classification can be asserted.

## Owner/API boundary and language gates

The owner API has a small explicit allowlist: scoped primary state, `representationPresent`, loss-history/assessment availability, the fixed out-of-band marker and server-authored explanatory text. It exposes no snapshot, fact keys, weights, amounts, predicates or raw annotation payloads. Availability values are filtered through a fixed allowlist. Primary labels require matching tenant, namespace/name, version and requested property; relevant unknown summaries take precedence over at-risk, with matching known losses first. `representationPresent` means that a report exists, not that coverage is measurable.

The legacy owner fields `AttackPrevented` and `SLOKept` still have their base behavior. **PR139/M14 is an independent pending gate fix.** This task neither repairs those fields nor treats them as confirmation. The new report is explicitly unconfirmed, including successful dispatch. The language gate still allows exact historical wire tokens and documented lexical exceptions. No ratio, maximum, dispatch or new state authorizes a containment claim. Full M14/T2-01 conformance is not asserted by this submission.

## Actual-source binding

Paths below identify implementation homes; the explanations are sufficient to review the intended semantics without opening code.

| Semantic requirement | Source binding and actual behavior |
|---|---|
| State vocabulary, property/version scope, frozen inputs | `phorvex/internal/model/representation.go`: reporting-only types, unknown zero value, explicit amounts, witnesses/history, snapshot and summaries. |
| Classification and partial measure | `phorvex/internal/representation/report.go`: pure classifier, loss precedence, pre-filter ambiguity detection, union/intersection, deterministic sums, scoped summaries and availability. |
| Real runtime source adapter | `phorvex/internal/runner/representation.go`: `representationSnapshotV1` binds trace keys and raw outcomes only to unresolved reporting entries; `appendRepresentation` adds dispatch qualification on a value copy. |
| Timing and asset identity | `phorvex/internal/runner/manager.go`: pre-actuation capture from tick/pod UID and post-actuation append before audit; original claim construction remains in place. |
| Trace denominator limitation | Unchanged `phorvex/internal/decision/coverage.go`, trace fact loop: it skips a fact if the final map has no entry. `DecisionFactV2.FinalWeight` is real for retained entries, but this does not establish complete R or a complete matching candidate/cover snapshot. The adapter does not manufacture missing weights. |
| New raw-outcome schema since E1 | Unchanged `phorvex/internal/model/existential.go`, `internal/ingest/events.go`, `internal/runner/existential.go`: protected-outcomes-v1 parsing, evidence types and pre-qualification policy inventory. None is treated as a qualifying M100 rule. |
| Audit persistence and legacy reads | `phorvex/internal/audit/log.go`, `representation.go`: additive `representation,omitempty`, detached conversion, retained snapshot; unknown read projection does not mutate the record. |
| Credential boundary | Model representation canonicalization uses existing M99/trace redaction, additionally drops credential-bearing map keys. |
| Owner privacy and scope | `phorvex/internal/console/representation.go`, additive allowlisted field in `owner.go`; existing IP and action/confirmation fields otherwise unchanged. |

The runtime reports per-decision scope. The pure classifier supports compatible fleet unions, tested with tenant-qualified keys; no production fleet percentage is synthesized. Raw policy outcomes with no matching decision remain in the existing policy inventory audit, rather than disappearing from storage. They do not receive a new per-decision representation when no decision exists. There is no owner percentage UI or new fleet roll-up endpoint in this change.

## Acceptance matrix: T01–T16

All named tests below are passing focused tests in this working tree. Positive evidence is synthetic unless explicitly called a source/dataflow check. Passing these fixtures is not universal proof or team approval.

| Ruling ID | Executed evidence | Result and boundary |
|---|---|---|
| T01 | `TestT01T02UnboundKindsAndInsufficientLossEvidence`; source-adapter test | Cannot-help kinds and incomplete completed-loss evidence never create a loss; positive reversible binding remains independently required. |
| T02 | Same test's missing identity, trust, property/version, predicate, occurrence, rule and timing cases; `TestM100SourceAdapterFrozenUnboundOutcomesAndDispatch` | Unbound raw outcome/stage/high pHold/irreversible defender mutation do not create loss proof. No new detector mapping was invented. |
| T03 | `TestT03T06MixedRXLPartition`; T15 | R-only amounts exclude the covered lost assertion. Existing solver/audit fields compare identically. |
| T04 | `TestT04T05T16HistoricalLossRetention` | Saved witness survives empty current detector set and unavailable current mapping. Current limitations remain separate. |
| T05 | Same history test | Removing current facts and changing replacement version preserves original scoped history; the replacement condition can remain at-risk. |
| T06 | Mixed R/L/X test; `TestReviewPropertyFilterCannotHideOriginalKeyAmbiguity` | Unknown has no credit. A scope filter cannot hide a competing assertion binding. |
| T07 | `TestT07T10PartialFunctionAndInvalidReplay`; credential-key and ambiguity review tests | Explicit missing/invalid/incomplete/mismatch results, nullable values, JSON-safe invalid inputs and stable replay; no weight defaulting. |
| T08 | `TestT08ActionabilityDoesNotShrinkDenominator` | Policy-disabled, infeasible, unsupported and unavailable actionability preserve R; missing weight makes the share unavailable. |
| T09 | `TestT09UnionDedupAndTenantScope`; `TestAmbiguousBindingAndCandidateBasis` | Overlaps and duplicate facts count once; same raw key in different tenants stays distinct; incompatible candidate basis unavailable. Fleet case is a contract fixture. |
| T10 | Partial-function test's empty and zero cases | Distinguishes `no-at-risk-facts` from `zero-weight-denominator`; neither yields a percentage. |
| T11 | `TestT11T14Weighted100IsNotContainment` | Positive mass covered plus uncovered zero-weight entry yields weighted 1 with required-set coverage false and no authorization. |
| T12 | `TestT12RelevantGapAndEmptyTrust`; historical-read tests; `TestReviewIncompleteClassificationAndBroadGapReachVersions` | Empty/missing trust and relevant gaps remain unknown; broad gaps reach specific versions; no backfill from today's configuration. |
| T13 | Actual runner kill-switch test; source adapter test; `TestReviewDispatchSnapshotReplaysActualReport` | Existing actuation gates remain intact; dispatch stays unconfirmed and replays exactly. Independent legacy M14 fix remains pending. |
| T14 | Weighted-maximum test; mixed fixture and all samples | Every ratio retains snapshot/population/weight/action/detector metadata, known losses and unmeasured out-of-band scope. No maximum becomes an unqualified claim. |
| T15 | `TestT15M100OptimizerLegacyIdentity`; unchanged arithmetic source check | NATS, mixed-fleet and AI/GPU each produce 2 real optimizer decisions, 2 selected. Each decision is checked with 3 reporting states × 2 trust configurations: all old Decision and audit bytes unchanged after removing only the additive representation. This is 36 report variants. |
| T16 | Historical-loss, immutable-input and invalid-input replay tests; actual dispatch replay test | Canonical output from retained snapshots, including old trust references and rule versions; detached maps/slices; no current config lookup. |

Additional review regressions cover malformed retained history, owner status injection/privacy, exact property-scoped loss through classifier-to-owner integration, and recreated versions. The five independently reported blockers have dedicated regressions: pre-filter ambiguity, broad/classification gaps, preserved property scope, retained dispatch observation and sensitive map keys. Two follow-up scope defects were also fixed: `TestReviewDisjointGapsDoNotChangeRequestedSummary` covers nonmatching tenant/asset/version/property in both entry and kind gaps (plus a multi-version property control); `TestReviewUnrelatedAmbiguousKeyDoesNotInvalidateScopedShare` proves that an excluded different ambiguous key does not suppress a valid scoped ratio. Broad intersecting gaps and same-original-key ambiguity still have negative controls. `final-scope-tests.txt` records the passing pre-freeze checks.

## Test commands and outcomes

`focused-tests.txt` contains the verbose focused run (five packages passed):

```sh
cd phorvex
GOMAXPROCS=2 go test -p 2 ./internal/representation ./internal/model ./internal/audit ./internal/runner ./internal/console \
  -run 'TestT[0-9]|TestM100|TestReview|TestMalformedRetained|TestAmbiguous|TestClaim|TestHistoricalRecord|TestKillSwitch|TestOwnerViewLeaksZeroIP|TestOwnerHistoricalClaimUnknown' -count=1 -v
```

`python3 tools/check-claim-language.py` passed over 95 current product source files. `python3 tools/test_claim_language.py` passed both tests. `git diff --check` passed. No arithmetic files or workflows differ from the base. The representation package imports model and standard-library packages; production solver packages do not import the new classifier. New fields are attached only after selection/actuation, never fed to the optimizer. Test fixtures demonstrate unchanged values for those cases; the unchanged dataflow/source review supports the narrower reporting-only scope, not a universal mathematical proof over arbitrary programs.

Final coordinator verification on the frozen source: `GOMAXPROCS=2 go test -p 2 ./...` passed (see `full-go-tests.txt`) and `GOMAXPROCS=2 go vet -p 2 ./...` exited 0 with no diagnostics. An earlier run overlapped a test-file edit and failed to import standard-library packages; only the subsequent frozen-source run is the final result. The separate automated reviewer rechecked all seven original cases and both scope follow-ups with no open findings, recorded in `AUTOMATED_REVIEW.md`. This automated review is not Hami's DEV approval or Zeinab's conformance decision; those remain pending.

## Labeled samples

The four files under `samples/` were generated by `TestM100ConformanceSamples` and `TestM100RunnerConformanceSample`; The final frozen-source generation is included in `focused-tests.txt`; `sample-tests.txt` also records the earlier focused sample-generation check. Each JSON envelope explicitly labels its synthetic origin and contains the complete report/snapshot.

| Sample | Concrete interpretation |
|---|---|
| `runner-unavailable.json` | Actual runner adapter on a synthetic tick: no trusted detector configured; a raw claimed-loss annotation remains unresolved; share and all amounts null with `inventory-incomplete`; recorded loss count 0, history/assessment unavailable; dispatch-only-unconfirmed; out-of-band unmeasured. |
| `mixed-r-l-x.json` | Three distinct assertions: one R with weight 3, one qualified synthetic L, one X. All are referenced by cover sets; only R contributes. Covered/representable/coverable are 3 and share is 1. Known loss and unknown entry remain visible. |
| `weighted-maximum-uncovered-zero.json` | R has weights 3 and 0; only the positive-weight entry is covered. Share is 1; required-set coverage is false. |
| `retained-loss-empty-current-map.json` | The historical synthetic disclosure is retained with its original witness after current facts disappear and the current detector set/mapping is emptied. Assessment is unavailable; history still contains the loss; share is unavailable because no at-risk facts remain. |

An example unavailable field is exactly `{"present":false,"value":null,"reason":"inventory-incomplete"}`. The stored fraction `1` means a weighted 100% of that stated R-only population; it is not system-wide recall, a measured security improvement, or permission to use a containment claim. None of these sample losses is a reported production incident.

## Remaining boundaries and handoff

1. Use the exact commit and PR in the accompanying Plane submission receipt for sign-off.
2. Obtain independent DEV review and Zeinab's mathematical conformance decision. No approval is presumed from review comments or passing tests.
3. Keep unavailable results until reviewed protected-assertion semantics, complete population/final-weight/cover snapshots, applicable detector capabilities, and authenticated event-to-outcome predicates actually exist. Empty current mappings are the ruled output, not evidence of zero loss.
4. A durable live loss/evidence source and explicit corrections require a separately reviewed source adapter. This submission demonstrates retention/replay of supplied history and does not claim a live ledger integration.
5. Coordinate the unchanged M14/T2-01 gate limitations with PR139. No claim upgrade is introduced here; the legacy owner booleans remain that PR's responsibility.
6. M99 may consume the shared scoped definition in `M99_HANDOFF.md`; no M99 constraint change or consumption is implemented or claimed here. Documentation for operators is in `phorvex/docs/M100_REPRESENTATION.md`.
7. Merge/deployment/build tag, register closure and any broader rollout verification remain coordinator/team actions. The Plane submission receipt records delivery actions separately from these remaining approvals.
