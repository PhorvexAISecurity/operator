# Independent V4 readiness review

**Readiness map ACCEPTED; full Phase1 execution NOT_READY.** This supplements [REVIEW-V4](REVIEW-V4.md). It grants no execution authority and does not modify historical outcomes or the owner stop.

Reviewer `/root/agentic_reviewer` is independent of author `/root/agentic_defense`. Final checks: 2026-10-10T20:17:14.058784Z. Reviewed [IMPLEMENTATION-READINESS-V4.md](IMPLEMENTATION-READINESS-V4.md), SHA-256 `45e297f03298324f7a2976cb99e065b8e8df87585753f5b0e3ce63da57aa816f`.

## Snapshot and checks

The map remains a preserved snapshot of HEAD `cbc89e440b4bb6948346d4b75cecfad1571e9945`. Before the merge I independently reproduced its seven listed file hashes and the actual 1,486-file tracked source closure `42964d2e23c59b419d81d7ff3f8014ada834ef960fea36a0614e51c88747e630`. During this review HEAD changed to `aabd753d768904bdfa3a5e051e54821e45278406`. The additive compatibility assessment below binds current closure `b75454dc45d76fa0e1a986066cd5778792460f5fc271d7692b0c64e65cc66575`; all seven listed individual pins still match.

I read the entire map and directly inspected the critical SLO bound/contract/ledger, feasibility, capability, shadow/owner-state and MathLab/local replay paths, plus representative ingest/platform/action/actuator/catalogue interfaces. Exact inspected current source pins are in [READINESS-REVIEW-V4.json](READINESS-REVIEW-V4.json). The tree closure hashes actual tracked file bytes; it is not a claim that every file was read or that the installed binary matches it. Relevant tests were read, not executed. The coordinator's reported37 tests remain separate evidence. No runtime, SSH, cluster action, source edit or commit was performed.

## Confirmed distinctions

`BoundFor` rejects UNKNOWN. Adapter rotation, request drain and other serving actions remain UNKNOWN. Their observed successful durations cannot prove recovery under failure or timeout. The only ZERO registry entries are noop, declared-not-implemented disable and metadata identity rotation; identity rotation is explicitly capability-excluded. They cannot establish a meaningful capability-removing G1 winner.

`AvailabilityFor(adapter-rotate,2,1)` follows the declared maximum-loss/headroom branch and can return ZERO while the action bound remains UNKNOWN. This is a direct source-path deduction, not a new test result. It is narrower service-floor evidence; it does not certify safe recovery, request continuity or all affected/co-tenant availability. Selection feasibility likewise cannot supply the external formal proof and can be neutral when owner/telemetry data is missing.

`DeriveContract` computes supplied complete-path/phase claims, enforced deadlines, stopping, provenance and safe-return fields. It does not independently demonstrate that those assertions are installed and enforced or update the proof registry. `slo.Ledger` remains process-local and distinguishes measured/unknown replica disruption and availability breach; total-service history is explicitly not collected. Empty/reset history cannot establish zero disruption throughout the required window.

MathLab records predecision inputs and owner state, restores a fresh offline engine, then calls `DecideChecked`; it dispatches no physical response. Its baseline normalization removes `ScopedOutcomes`. Dedicated `DecideShadowChecked` and local `ReplayFile` canonical-trace replay exist, but a full V4 capture/profile/global/witness/control service remains missing. `EligibleObserved` explicitly retains authorization-UNKNOWN fail-open diagnostics; V4 requires positive current witnesses at its external admission boundary rather than counting unknown as proof.

## Blocking implementation findings

### V4-RD-01: No certified meaningful action bound

BoundFor rejects UNKNOWN. Useful serving defenses are UNKNOWN. ZERO entries are noop, declared-not-implemented disable and metadata identity rotation; the latter is capability-excluded. These do not establish an actual G1 winner.

Owner: ORCH + native-contract/actuator engineer + independent REVIEW. Review complete native success/failure/deadline/rollback enforcement and safe recovery for a baseline-relevant candidate; implement missing native contract under separately recorded bounded engineering scope before new source/runtime admission.

### V4-RD-02: Service Ready floor and incomplete history cannot replace G2

AvailabilityFor can return ZERO despite UNKNOWN action recovery when maximum declared loss preserves the Ready floor. Feasibility can be neutral on missing owner/telemetry. Ledger is in-memory and total-service history is not collected. Neither an empty ledger nor successful traffic samples establishes the mandatory gate.

Owner: availability/ledger engineer + METRICS + independent EXECUTOR. Implement source-valid complete scoped history/window coverage, measured affected and cotenant census/streams, all failed requests and formal bound/headroom proof. Never promote observed maxima or narrower service-floor status.

### V4-RD-03: Dedicated strict shadow/control adapter is missing

MathLab restores owner state then calls DecideChecked offline and omits ScopedOutcomes from baseline comparison. True shadow and local canonical replay primitives exist but not the full V4 profile/global/witness capture, matched predecision G3 branch and no-write validation adapter. EligibleObserved retains explicit authorization-UNKNOWN fail-open diagnostics.

Owner: brain capture/replay engineer + independent REVIEW/EXECUTOR. Build exact-state/clock/profile/globals capability-witness capture and DecideShadowChecked wrapper; require positively observed authorization and independently validate pre/post state plus the clean branch input difference.

### V4-RD-04: Generic V4 lifecycle remains unimplemented

Case executables and fixed-suite functional metrics/reconciliation are narrower than authenticated admission/scan/C1–C6/minority queue, persistent physical twin, exact selected-action execution, external cards, adaptive round/reproduction and proven-record publication. Searches found no Go declarations for the proposed ScenarioFragment,SendQueue,SevenMetricCard,TwinRef; this alone is not proof no equivalent implementation exists.

Owner: ORCH + bounded adapter engineers + independent REVIEW. Follow the map dependency order and bind actual typed interfaces/authority/source descriptors and required outputs; missing mandatory tools block full competition admission.

## Current-source compatibility addendum

I inspected all seven changed `phorvex/` files between the map snapshot and current HEAD. Owner-state shadow assembly now returns `(set, stampedViews, error)` so diagnostics use the generator's evidence stamp. Bucket creation uses the decision tick's time rather than a later clock read. MathLab adds an explicit proactive-floor replay arm, accepted parameter metadata and bounded whole-second validation; its production-semantic replay and reporting-field normalization remain distinct from strict shadow.

The source map's central G2/capability/ledger distinctions remain valid: those files did not change in this merge. New wrappers must use the actual three-result shadow-assembly signature and current descriptors; historical snapshot pins cannot silently become current runtime identity. This is source compatibility review, not a build/test/runtime acceptance. Replay parameter overrides remain separately authorized diagnostic/shadow proposals; they do not permit tuning a frozen competition to obtain a winner.

## Conditional engineering and build order

The user's full-loop request supplies the objective. ORCH must record the exact bounded product engineering needed by the chosen pilot: allowed handler/contract/registry and any necessary policy/API/registration paths, truthful covered capability, all permitted success/failure/deadline/rollback paths, enforced stopping and independently verifiable safe return, legitimate-service preservation, relevant adverse regressions and deployment/recovery prerequisites.

A meaningful structural ZERO proof or enforced finite BOUNDED action contract must be tied to the actual implementation and supported assumptions. If proof cannot be supplied, retain UNKNOWN/unavailable. Do not merely change a registry flag, substitute Ready-floor status, force choice, disable competing protections or select a quiet interval. Independent code/oracle review precedes new deployed pins and prospectively accepted physical scope; a distinct executor verifies acceptance.

The proposed minimal order is sound: admission/ownership → immutable scan/qualification and queues → formal G2 feasibility/proof resolution → persistent isolated twin/control → strict shadow capture/replay → reviewed baseline/detector/exact selected-action native execution → external G1–G3/S1 card → persistent winner/re-attack/round records → fresh independent reproduction and publication. Source/pure preparation can precede physical admission. A winning timed verdict does not complete the adaptive competition or Phase2 secondary measurement.

No material correction to the preserved readiness map is needed. Next owner ORCH should compile the exact accepted design/readiness/reviews into the manual and translate missing prerequisites into bounded assignments. No full V4 physical admission is justified by the current source map alone.
