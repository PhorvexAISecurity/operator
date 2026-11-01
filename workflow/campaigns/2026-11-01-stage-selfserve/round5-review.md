# Independent round5 review

Reviewer: stage-review. This review covers retained actual observations and outputs; it performs no source edits, live mutations, new replay, job dispatch or state transition.

**Verdict: PASS for the four bounded round5 controls. Overall durable-main assurance and campaign cleanup remain open.** The installed runtime is `225877a8ecb4c11eb39980ba932c114f7a8068a4`; all 169 runtime files match the reviewed composed source `287fd2e4cd97c1ef8a0475b16316b04c6938b518`. The stage chart/capture revision is287fd. The actual brain/manager source is `b1ef9ccdb258f0a94b0dad575a17cc3a4c25cab0`, with brain OCI digest `sha256:d208a9a53acd16cc146dce4c72b26d7614620862f2e1cecc1f526259033a1903`. These are distinct identities; no287fd brain image is claimed.

## Claim crosswalk and findings

The round5 specification uses different H-labels from the campaign hypotheses file. This table preserves both rather than changing preregistration.

| Round5 specification | Campaign hypothesis | Independent result |
|---|---|---|
| H1: current-source capture/native replay for both policies | H1, current-source part of H4 | PASS: actual B1 baseline 128/128 across two separate 64-tick policies, byte/header/UID/image bindings, immutable native receipts and live identities verified. |
| H2: exact-demo parameter control | Positive control for campaign H1/H2 | PASS: batch518953591ee8, child18e300921b28, experiment88aa343c-e701-4d37-ad62-22b88bb66125. Control and P-FEA-006 values1.0/1.2/1.5 each have 64 same-source OK rows; control 64 exact reproductions. All selections are NOOP on this non-attack cohort. |
| H3: exact original ten-day refusal | Campaign H2 | PASS as a negative admission control: original bytes SHA2e0a40127b9b9b65f7d42e5fa4eb1f155d8a1819aced313b8f39435ab493a9a3, policy/ticks/sync and W864000/L86400/s.999 retained. Batchce9e3ee08a1c/child52c619e5c9d8 is BLOCKED solely for absent active move attribution and endpoint dataset. Runtime itself was READY 64; no model, tests, build or replay ran. Unknown metrics remain null. |
| H4: separate fixture endpoint controls | Campaign H3 | PASS: batch9148cab8abaf/childbe9bc9fcd68f and batch9979ac0c1117/child4b45b14bbdb3 each COMPLETE 64, native same-source MATCHED_REPLAY,64 exact capture-control and 64 exact local-base rows, both paired arms executed and brain selection parity true. |
| No additional round5 mutation tests a merged future release | Durable-main portion of campaign H4 | UNAVAILABLE: current capture is provided by the temporary reviewed V8 override. Reviewed generated values/render tests and real reconciliation establish their narrower claims; they do not prove a future merged-main release preserves capture. |

## Endpoint evidence and settings effect

The refreshed immutable dataset trace is `2e0a59c7d9caffab4e91127c3aafd9ffe3e6c94674d3393eec4005c8b26718fa`. Independent verification used actual journal prefix638/hash41f0ff9cdefcd432cda1a5e6f86559f0ec9aaef3c28dafc49c1bac1573b4fb60, complete_from1793568462.225789 and sealed_until1793569504.700788. All 64 raw snapshot hashes/fractional clocks, per-tick preceding journal hashes, exact policy/workload generations, Service UID, ledger and samples matched the sealed as-of reducer. No older-source segment or future object state supplied missing history.

Both endpoint controls use these same 64 snapshots. Only declared SLO/window/worth fields changed in the trace; raw facts, gates, classes, scope, samples and ledger remained identical. Exact request bytes bind through validation to execution. Default settings are W600/L600/s.9/theta0, with default delta30. Custom settings are W240/L300/s.95/theta.25/delta2.

For every default tick, the declared shadow budget is approximately180 endpoint-seconds, and each candidate forecast is159; both arms select the maximum-value candidate. There are zero NOOP ticks and forecast totals 10176 for each arm. For every custom tick, the budget is approximately36 and each candidate forecast131; every candidate has the explicit known `BUDGET` veto. Both arms therefore have 64 NOOP ticks and forecast totals 0. All 768 candidate CSV rows match raw JSON and the arithmetic. V2/V3 changed-choice count is 0 in each experiment because lambda remains at its floor with effective price 0; this does not demonstrate adaptation under positive burn.

There were **zero calibration moves and zero measured duration samples** in this segment. The 43-second stateless duration prior, failure bound 1 and rollback proxy are explicit study assumptions. Forecast totals are not observed outages or realized charges. `counterfactual_actual_charges` and `counterfactual_verified_facts` remain null. Shadow acting admission remains BLOCKED/non-authoritative. No physical counterfactual action occurred.

## Delivery, restoration and deviations

Actual execution entered `BenchBot.receive_document`, parsing, queue, readiness, replay and report code. Only incoming download supplied the registered bytes; no incoming Telegram update is claimed. Initial acceptance has 29 actual outbound receipts/13 documents. Fixture acceptance has 34 receipts/14 documents, including both full endpoint evidence ZIPs. All document hashes match retained bytes or exact prequeue-validation/batch serialization reconstruction. Initial parameter XLSX and experiment ZIP were generated and verified but were not selected for Telegram delivery by existing run_param; do not label them delivered.

Both phases restored the stopped bot and originally active maintenance timers. Protected env/owner/members/legacy-current hashes match; observer PID 1648552 remained active throughout. The independent final poll at21:51:51 confirms fixture driver inactive/success/exit0, bot active and both timers active.

The automatic refresh first refused 4/64 eligible ticks, then encountered a real reconciliation lease and returned truthful BLOCKED/LEASE with exit2. After both services became idle, the lead started the already reviewed refresh unit under guards. It published READY 64 at21:47:14; independent verification completed21:47:43 before fixture execution. No observer restart or history extension occurred. Thus this proves the existing guarded refresh path and truthful contention response, not guaranteed timer latency under arbitrary load.

V7 was never applied after upstreambe676 advanced. The preregistered addendum authorizes V8/current closed family; rollout observations distinguish Healthy/Succeeded from residual manager/console OutOfSync due old RBAC requiring pruning. No all-apps-Synced or prune claim is made. Earlier aborted rounds, failed round4 outputs, lease refusals and superseded evidence remain retained.

## Bound evidence

Paths below are relative to `workflow/fixes/BENCH-SELFSERVE/evidence`.

- `peer-review/live-b1ef/native-prerequisite-verdict.json`: SHA256 61e28a053dcc60acc148195155f3dd00ccafdc14d6e39906ea447b5e988c8088.
- `peer-review/live-b1ef/round5-initial-artifacts-review.json`: SHA256 482fa27c5f6f2da8ea57338e7487bd47199f095ecd044fb0707deb44dd0fb907.
- `peer-review/live-b1ef/round5-delivered-report-addendum.json`: SHA256 a4af65e65ebe4ee3e623e7d464eaa467ba49c518f4fb6a6242ade423c51857ab.
- `peer-review/fixture-b1ef/ready64-verification.json`: SHA256 3ecae52a96b331981a5b1fcbab9e2889090f0e7adaed17a9f0d7e1709bfec1d8.
- `peer-review/fixture-b1ef-run/artifact-review.json`: SHA256 640fd3bc548cb9e1dd3c6b5c080bafdb6ccbe28dbf123cb0cd5aa335aad395a1.
- `peer-review/fixture-b1ef-run/request-provenance-addendum.json`: SHA256 d3042c517073b422754d77552510c6027c29360fb492db3700f8370a9c9064e8.
- Initial actual archive SHA256 246dc36f3bdff698d9916e836e61dcdd165e2881e252b6738fd7cd92129839e1; fixture actual archive SHA256 912074c2930b7f307ee1275a92e2b2231704bb810fe0065ff69927f777d30984. All 120 initial and 170 fixture files verified.

Required follow-up is explicit merge authorization/durable-main verification and exact-owned-value cleanup or a separately authorized handover extension. Those remain lead-owned; this reviewer does not transition or close the campaign.
