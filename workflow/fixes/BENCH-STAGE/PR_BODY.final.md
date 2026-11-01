# Summary

Make the bot run source-pinned brain benchmarks against isolated stage recordings, including validated parameter changes, scoped code proposals and explicit offline V2/V3 endpoint studies. The live parameter and endpoint paths now execute the real brain/replay pipeline and retain exact baseline, input and image provenance.

## Problem

The bot previously used a legacy operator clone and historical snapshots. Split-brain capture could not reach Console because the manager had no snapshot relay, and no qualified endpoint history was available. Source/schema validation alone could therefore succeed while execution failed or lacked the evidence needed for a comparison.

## Behavioral change

- Add the actual brain store → bounded authenticated RPC → manager audit → Console capture path, truthful recorder-process source/image identity, same-source replay companion and default-off capture settings. Package the reviewed source chart changes in the vendored umbrella chart.
- Freeze stage-only source/image/policy-UID cohorts before execution. Validate exact baseline replay before parameter/code comparisons; preserve immutable inputs, reader/writer cache coordination, bounded synchronization and reproducible reports.
- Export the real pre-cost candidate population with existing provenance, capability, resource, containment and other non-cost gates. Typed V2/V3 studies use the shared brain selection path and brain-owned endpoint kernel, with explicit cross-source identity and parity checks. Default live decision behavior remains unchanged.
- Collect durable watch-observed Service-ready-backend intervals and explicitly labelled calibration moves. Refuse gaps, ambiguous attribution, incomplete pricing or unsupported history; retain known versus missing data distinctly. Use bounded lossless journal encoding, atomic normalized generations and periodic refresh. Match the actual exporter's nanosecond clock exactly.
- Update English/Farsi HTML/PDF guides and request templates. Run bot, worker and stage regressions permanently through current CI, including real Go controls and benchmark-only local preflight selection.

## Tests and evidence

Actual stage results, independently checked:

| Path | Recorded result |
| --- | --- |
| Three parameter requests: cost ceiling, proactive cadence, disruption aversion | Each completed on 64 distinct source-bound snapshots with 64/64 exact baselines. No changed decisions in this benign cohort. |
| Actual brain V2/V3, W=L=600s, s=.90, theta=0 | Both arms select on all 64 ticks; baseline reproduction is exact. |
| Actual brain V2/V3, W=240s, L=300s, s=.95, theta=.25 | Both arms return NOOP on all 64 ticks. Requested settings affect the outcome. |
| Original W=30 days / L=1 day | Correctly unavailable: retained continuous history and operational capacity/runtime readiness are not established. No historical completeness is fabricated. |

There are zero between-arm changes in these endpoint demonstrations; they show working replay/configuration paths, not measured security efficacy, independent samples or realized counterfactual disruption.

The coherent final-source preflight at `ec310e27` passed all 18 selected gates, followed by the dedicated invariant and integration checks. It includes 301 workflow tests; 168 bot, 72 worker and 45 stage tests with zero skips; all seven Go modules; deterministic chart/archive checks; and build/vet. The broader tools suite passed 446 tests with its existing nine expected failures and one opt-in Docker skip. Original failed/interrupted runs remain retained. Remote go-envtest and other GitHub CI jobs are separate from these local checks.

The first real V2-A code request produced a candidate whose new helper/model tests passed, but its run failed the unchanged `TestExactRuntimeMatrix` 500 ms deadline. Raw output is retained in `workflow/fixes/BENCH-STAGE/evidence/live/code-attempt-1`; the single controlled retry completed through the real bot: 465 base and 509 candidate tests passed, both exact-source binaries were built, and all 64 frozen ticks completed with zero changed decisions. Both attempts and two inherited opt-in skips remain explicit. The helper is not called by active selection, so this is a code-pipeline control, not full V2 activation. No timeout or outcome assertion was relaxed.

Evidence is retained under `workflow/fixes/BENCH-STAGE/evidence/`, including actual parameter receipts, endpoint/refresh receipts, independent real-producer counterexamples, clock parity and archive-render review. Large actual journals, source snapshots and raw candidate exports are retained as hash/size-bound local-original artifacts; compact reproduction commands and receipts remain in Git.

The subsequent GitHub lint job exposed one missing import-group blank line and raw Go evidence being treated as a source file. Delivery correction `1ae0beeda781e7063782bc7d07718f6ce64015a7` adds that single blank line; independent exact-token/AST checks confirm unchanged behavior. The raw clock source was renamed byte-for-byte to `.go.txt`, retaining its hash, provenance and reproducible original output. The unchanged Go1.26.3 formatter gate passes all 34 changed Go files, and the endpoint CLI/kernel tests and CLI build pass. Formal patch equivalence preserves the original ec310 full-preflight and actual deployed identities; these are not relabelled as new runs. The failed GitHub job remains retained and remote checks for the repaired PR are pending.

## Risk and compatibility

V2/V3 is an explicit offline experiment. It does not activate V3 in the deployed brain, perform arm choices in the cluster, or supply a complete History-aware picker/entropy model. Endpoint readiness is an observed Kubernetes signal, not measured application outage. Physical calibration moves are collector-owned and are not relabelled as brain-issued actions. Unmeasured realized cost/security effects remain unavailable. Node drain/rollout interruptions reset qualified coverage instead of being silently bridged. Original 30-day readiness remains unvalidated even after storage expansion.

## Rollout and live verification

Live components retain their actual identities: capture manager/brain `ef94fad362dabb51469211388ef80cdfa6eee1d4`, control replay from that same source, reviewed experimental replay `d552ad0c03cdc3fce8120fe8889b2efe5d55d393`, and bot/refresh source `3e11f4e7ca8424c31a387b53e04942a18ee7d977`. The full-preflight source is `ec310e276e45e6a218f7520880e22c6c1c687817`; its sole change from the installed bot release is the reviewed vendored archive, with identical benchmark and phorvex runtime trees. It does not relabel deployed components. Runtime/engine source equivalence and the exact image/header digests are retained in the source and deployment receipts.

The persistent stage bot, read-only observer and periodic refresher are active and enabled. After a real external Pod eviction/node shutdown, three automatic refreshes correctly refused insufficient coverage/cohort size while preserving the last-good generation. A later timer run recovered 64 fresh qualified ticks without backdating or lowering requirements. Owned temporary remote authentication, bounded test units and candidate scratch clones were cleaned up; reproducible source bundles, binaries and raw evidence remain retained.

Only the authorized stage namespaces and separate stage data root were used. The final reviewed generated archive adds the already-enabled capture setting to the umbrella package; independent default/opt-in renders preserve the reviewed behavior. No production rollout, main merge or active experimental decision-policy deployment is part of this PR.

## Rollback

Use the retained stage deployment/cleanup ledger to restore the prior pinned stage images, chart/configuration and bot release. Preserve journals, frozen inputs and completed reports; disabling the capture/refresh services stops new collection without rewriting historical evidence. No automatic production action or history deletion is introduced.
