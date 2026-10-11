# Agentic verification architecture: deployed reference trial

**Status: bounded study closed — five physical episodes, one LIVE_CASE_PASS and four INCOMPLETE results. The deployed clean-control component passed; successful fresh independent reproduction remains unmet.** 10 October 2026.
All five physical leases are released. A sixth planned episode was not executed.
This report records the actual bounded study; it does
not accept the deployed architecture universally or authorize LangGraph implementation.
The portable orchestration specification is RUNBOOK.md.

## Question and limits

The experiment asks whether separate agents can discover a relevant runtime
surface, propose and review a discriminating case, run it through an authentic
observation and the unchanged installed Phorvex brain, establish the native
response's real effect, retain ordinary service, retest before cleanup and
independently reproduce the episode.

The selected dev case is removal of an operator-loaded, unapproved, harmless
zero-delta LoRA model route. The caller has inference authority only. Two model
roles use the same existing inference credential: A requests the owned adapter,
B requests the base model. Only authorized setup can load or clean up the adapter;
this is not proof of attacker enrollment or poisoned model answers.

Observation uses a separately authenticated observational test detector reading
real current inventory. It is neither a test-driver alert nor validation of the
legacy installed detector. The normal installed manager must choose under its
unchanged policy, scoring and safety constraints. The accepted physical effect
oracle is adapter-rotate: original adapter-route completions work before response,
then that same route fails specifically while base-model inference succeeds.
Formal availability certification, whole-binary attestation, always-on production
detection and broad customer-stack coverage remain separate unverified claims.

## Participants and actual responsibilities

| Participant | Work in this experiment | Independence |
| --- | --- | --- |
| Lead | Scope, selection boundary, worker assignments, immutable dependencies, authority, budgets, gates and portable documentation | Does not convert peer agreement into physical proof |
| Case engineer | Bounded stack discovery, route-removal proposal and runtime driver | Does not execute or certify authored driver |
| Integration engineer | Separate inventory observer, strict effect/evidence gate and adverse regressions | Does not execute or certify authored observer/gate |
| Independent verifier | Measurement plan, original runtime/TLS/audit captures, timing feasibility and four assigned episodes: 1, 2, 4 and 5 | Does not author certified runtime implementation |
| Independent reviewer | Contract/source/adverse review, portability review and source review and the third fresh physical episode | Does not certify authored implementation or relabel the first run |

Workers use the owner-requested GPT-6.1 Sol model. The role roster is functional:
four routine participants including the lead, plus integration engineering when
a concrete gap requires it. An additional permanent runtime agent was unnecessary
for this bounded case. The deterministic gate and Phorvex brain are tools, not
LLM consensus participants.

## Runtime and provenance

The source baseline is main commit
54c9273a6faaa3768e55adf15afb51de68b3241b, with earlier isolated architecture
artifacts recorded in local commit ca69456b17299aa742c5ea9275fb5e6ae9cccfa4.
New trial tools are independently source-hashed before execution; the earlier
commit alone does not identify those added bytes.

Read-only discovery observed manager tag 0.4.217, resolved image digest
sha256:efad46a75433e35864fb0e76a8e8a673969e447fb5264d7e5f827e675b8d837b,
and authenticated audit Git revision 3051797426ce51265bf2757561bffded3bb69268.
Deployment source annotations disagreed; they were not treated as attestation.
Actual policy identity, generation, relevant bytes, serving images, Pod UID,
services/endpoints, mounted sources, creator admission and authenticated native
serving authority are separately captured and refreshed before execution.

The target is the existing vLLM 0.7.3 Qwen/Qwen2.5-7B-Instruct-AWQ deployment.
The policy permits adapter-rotate among its enabled responses. That capability
and policy membership do not prove the brain will select or execute it.

## Discoveries and architecture changes before stimulus

1. **Installed presence was insufficient.** The legacy adapter detector was ready
   but received unauthenticated inventory errors and used an obsolete event
   contract. Its defect is retained separately. A reviewed test observer uses
   actual inventory and the authenticated existing detector identity; its narrower
   observation mode is explicit.
2. **The alternative KV case was non-discriminating.** Cache warming/clearing does
   not alone establish a durable unauthorized capability, and reprobes can refill
   cache. The installed KV detector was retired. It was rejected rather than
   renamed a valid security case.
3. **Future evidence cannot be frozen before capture.** The architecture separates
   proposal, execution freeze, postcapture evidence seal and cleanup seal. Expected
   pins come from independent inventory; a runner cannot authorize its own output.
4. **Every control matters.** Review found acceptance gaps in failed ordinary
   requests, counts/cadence, trace revision, inventory drift and cleanup authority.
   The separately authored gate and adverse tests were repaired and reviewed.
5. **Physical schedules need actual measurements.** A five-second baseline window
   contained five sequential cold remote calls, each approximately 1.9 seconds,
   before additional reads. A target read plus two probes likewise could not fit
   the retest cadence. The earlier local/code acceptance is preserved but explicitly
   superseded for live readiness. No stimulus ran under this impossible schedule.
6. **Resident transport is a measured repair candidate.** Independent read-only
   measurement found about 1.83 seconds startup, then clock RPC round trips at most
   113 milliseconds and approximately 56 milliseconds uncertainty. A resident
   Kubernetes proxy warmed from a 1.4-second first GET to about 120–122 milliseconds
   round trip and 97 milliseconds API service. These are feasibility observations,
   not serving or defense results. Node and host errors must add for cross-clock
   comparisons. The revised tool remains independently gated before use.
7. **Policy and event schemas are different.** The runtime driver mistakenly
   used the PhorvexPolicy API group for SecurityEvent reads. Independently captured
   installed CRD and a successful canonical list established that SecurityEvent
   is cluster-scoped `amtd.r6security.com/v1beta1`, while the policy uses
   `phorvex.ai/v1alpha1`. The observer was correct. A provisional reviewer inference
   was explicitly corrected before any event; the driver and actual-schema
   regression were assigned to their authors. Permissive fake clients cannot
   establish real producer/consumer compatibility.
8. **Failures require safe state before retry.** The portable graph now routes every
   physical failure through retained outcome and cleanup/reconciliation. A new
   shared-target attempt cannot begin while an old operation or ownership is
   ambiguous. Messages to completed workers explicitly trigger their next assigned
   task; queued messages alone do not count as running work.

Read-only audit/TLS transport was authenticated against current rotated
certificates. Stale credentials and initial forwarding failures are retained.
No TLS verification bypass was used. Temporary owned forwarding processes were
closed. No shared deployment or policy was changed.

## Preregistered physical acceptance

Two serial fresh episodes are required: reviewer episode3 and fresh verifier
episode4 under distinct leases and the same final reviewed profile. One owned
fixture is at most 8 MiB. Each
physical episode has a 180-second ceiling and 120-second response deadline.
The baseline includes actual generated adapter completions and ordinary base
inference. All requests, counts, requested/generated tokens, bodies, target
identity, UTC/monotonic timings and failures are retained.

After actual native effect, six varied inference-only retests span at least ten
seconds while the fixture directory remains present; the exact owned adapter
route stays denied and ordinary inference continues. A successful long ordinary
request must contain the entire conservative native-read bracket including
combined clock uncertainty; mere intersection earns no overlap claim. Exact
native dispatch endpoints are not measured. Cleanup follows durable evidence
and cannot earn defense credit. Unresolved native operations retain the lease.

The initial 90-minute planning budget was not met. Independently reviewed
prospective planning addenda extended planning to 15:11 UTC; original timing
history and already measured outcomes were retained.
Original budget history is preserved. Physical resources and acceptance criteria
were not expanded. No finite experiment establishes a universal optimum.

## First deployed attempt: measured result

The independent verifier executed the first physical attempt at13:46–13:49UTC.
It produced a real end-to-end causal response, but did not pass all case criteria.

| Chain stage | Actual observation | Verdict boundary |
| --- | --- | --- |
| Application baseline | Three owned-adapter and three base-model requests returned strict HTTP200 text completions | Capability and ordinary service established |
| Delayed observation | Owned load to independent observer release was2.569seconds; no matching event existed before release | Baseline/observation separation established |
| Detection/event | Separate inventory observer emitted an authenticated current-target event with exact adapter, parent, Pod UID and inventory hash | Observational test detection only; legacy detector unverified |
| Brain | Installed unchanged brain selected adapter-rotate; selected/actuated true, dry-run false, kill switch false | Normal installed selection established |
| Native operation | Protected version8 journal completed for exact policy, target, adapter, event and decision IDs | Native completion established |
| Immediate effect | Exact owned-model request returned HTTP404 NotFoundError with exact model-specific absence message | Point-in-time route removal established |
| Ordinary traffic | Fourteen concurrent ordinary completions succeeded with32 generated tokens and1.165–1.301second latency | Sampled continuity established; full-bracket containment failed |
| Retests/hold | Not executed after the strict effect-oracle failure | Persistent defense not established |
| Cleanup | Initial guard stopped; separate guarded reconciliation deleted exactly six owned resources with original UID/label/content proof and actual404readbacks | Independent safe reconciliation accepted; first lease released at14:00:22UTC |

The event UID was26a63af5-d66b-4d47-ba5c-31d0f47cd375. The authenticated
decision ID was509fc1372a303f2773cc5eda26e3e144, tick ID
e4a3984b3c0726b8861f484718765df1. The native journal bound these IDs, the exact
policy and current Pod, authenticated serving authority, and adapter-rotate.
Neither the stimulus driver nor the setup operator invoked that native action.

### Why the attempt did not pass

1. The real denial body included param:null. The frozen oracle used equality
   against four fields and rejected that extra field, although all discriminating
   model/status/type/message fields matched. The attempt stopped before B-after
   or six denied retests. Its original verdict remains INCOMPLETE.
2. Independently, no ordinary request contained the entire widened native bracket
   13:48:11.394160–13:48:12.337275UTC. Adjacent successful requests covered parts
   of it, which is insufficient under the preregistered criterion.
3. Observer Pod CREATE responses already contained the intended unique owner
   label plus topology region/zone labels. The driver recorded requested labels
   instead of the actual returned labels. Its strict cleanup guard therefore
   rejected real owned Pods. It stopped rather than deleting on an unverified
   assertion. Separate reconciliation joined original CREATE bytes to fresh exact
   UIDs/full labels/immutable ConfigMap hashes and guarded once-only deletion.

These are concrete measurement/tool findings, not evidence that the brain chose
the wrong action. A point-in-time successful response does not certify the entire
case. Neither a corrected parser nor safe cleanup retrospectively completes
missing measurements. Original failed captures and source hashes remain intact.

## Second deployed attempt: revised measurement, availability failure

The independent verifier executed `live-v3-verifier-2` at14:05:15–14:07:58UTC
under a new reviewed contract and lease. The first result was preserved. This
prospective source revision accepted only the additional optional param:null
in the same exact model-specific404 envelope, recorded full labels from actual
CREATE replies, and requested128 ordinary overlap tokens with at most22 flights.
It kept the2928-token ceiling and all physical acceptance bounds unchanged.
Local preflight and fresh read-only runtime checks passed before stimulus.

| Chain stage | Actual observation | Verdict boundary |
| --- | --- | --- |
| Application baseline | Owned adapter and base model returned strict HTTP200 completions; baseline latencies385.288ms and254.319ms; two delayed samples each also succeeded | Real capability and ordinary service established |
| Delayed observation | Owned load to independent observer release was2.571seconds | Five-second baseline window met |
| Detection and brain | Fresh authenticated inventory event; unchanged installed brain selected and actuated adapter-rotate | Same observational mode; no policy or forced selection change |
| Native operation | Protected version8 receipt completed for exact new event, decision, policy, target and adapter | Fresh native attribution established |
| Immediate effect | Exact adapter request returned specific model404; post-effect base completion succeeded; actual inventories contained only the frozen base | Scoped point-in-time removal established |
| Ordinary overlap traffic | Six public HTTP200 completions each generated128 tokens, lasting4.094–4.246seconds | All were within the10-second bound, but none contained the entire widened native bracket |
| Retests and hold | Six varied A404/B200 pairs spanned10.025seconds before cleanup; base continuity samples were227.746–419.450ms | Sampled persistent route denial and ordinary hold continuity established separately |
| Cleanup | Original UID-guarded cleanup captured exact event plus six resource404 readbacks, fixture absence and unchanged runtime; every owned channel closed | Independent failed-outcome cleanup accepted; root released the lease at 14:17:04 UTC |

The fresh event UID was23214e32-ace3-4650-bd1c-718e383c2f49,
decision ID c9a01657e68d8fa56bf5620eacaba0ae and tick
ID 5a190fc6335841202bb0d0b59d66b601. Request totals were10 A,10 B1 and6 B128,
788 actually requested output tokens and 2,836 reserved intents. The durable evidence interval lasted
124.791 seconds; complete physical delivery including cleanup lasted163.061 seconds.

### What the unchanged brain actually compared

The authenticated decision trace used `strict_gain_positive` and selected
adapter-rotate with `selected_strict_positive_gain`. Its recorded runtime lambda
and effective cost coefficient were zero. That did not prevent this response:
the modeled gain was strictly positive and greater than the other eligible
candidate gains in this selection partition.

| Candidate | Recorded net gain | Recorded expected cost | Actual trace disposition |
| --- | --- | --- | --- |
| adapter-rotate | 14.9568103902 | 0.1696 | Feasible, selected |
| kv-reset | 4.9856034634 | 0.5723113786 | Feasible; another action selected in the partition |
| request-drain | 4.9856034634 | 0.1594 | Feasible; another action selected in the partition |
| rotate | Not evaluated after exclusion | Not evaluated | Matching PodDisruptionBudget had zero allowed disruptions |
| guardrail-rotate | Not evaluated after exclusion | Not evaluated | Cyclic variant change did not establish bypass invalidation for this modeled surface |

These are the implementation's recorded modeled values, not independently
calibrated security benefit, money or certified availability. The trace's
coverage basis was `modeled-selection-opportunity`. Its dispatch message was
`emitted-unconfirmed`; the workflow separately checked the protected completed
native receipt and actual route behavior. No agent replaced this comparison,
forced the action, or treated the score/dispatch message alone as defense.
Cleanup began after durable evidence and took 37.633 seconds. Exit 0 meant terminal
delivery, not a passing case.

The conservative bracket widened by the unchanged200ms uncertainty was
14:06:31.407474–14:06:32.563631UTC. The adjacent B requests were
14:06:28.110273–14:06:32.274224 and14:06:32.274577–14:06:36.455976UTC.
The first ended before the bracket's end and the second started after its start.
Their partial intersections earn no full-containment claim. Independently sealed
`gate.evaluate` returned **INCOMPLETE**, first failed stage **availability**,
reason **conservative execution bracket not contained by B**. The six held-denial
pairs do not erase this missing criterion. No positive cleanup finalizer was
invoked; safe cleanup was assessed separately without defense credit.

Original capture identities allow the ticket and its retained evidence to be
matched without depending on a particular server's paths:

| Round2 evidence | SHA256 |
| --- | --- |
| Frozen contract | 4ff959b459a7401f6ef8f4df5fdb41b86dd48e7d44ece30a459c6b086bf056e9 |
| Frozen execution supervisor | 4403cdc86d1e425457aa70dbe4a46c50daf5347894013bfdac4e29423ce6bb62 |
| Immutable precleanup report | c2186614c2d8a377a2dc66395d19c26db060108a485b5eef6c2704fe1eace79f |
| Independent gate result | dd614fb87ba923d8c4cc66d424766766c126a80d9752a0324935e2a53fd9537e |
| Original cleanup capture | 1333d0ab6f856ab2440536b3bb1959d5f04d94b0eafb45ddee68218a9b555753 |
| Independent failed-outcome cleanup seal | c117a79e885dae2760e76a901a975d309b9a6cbab8e65595023f2a6f97490fae |
| Root safe-state lease release, 14:17:04 UTC | ed3705c9ec5fdfd59ef577d477a2373d06f516b96f8282a87f7fd84d46d91fbf |

## Third deployed attempt: overlap established, enforcement unproven

The independent reviewer executed `live-v3-reviewer-3` from 14:45:00 to
14:47:22 UTC under the final reviewed two-stream profile. Both streams shared
one resident process and node clock; each had eleven 128-token plans, with
stream 2 due 2 seconds after the first actual HTTP start, never early and at most
100 ms late. Maximum concurrency was two; the total request/token limits,
entire single-request bracket criterion, latency and hold criteria were retained.
The verifier independently checked this episode's failed-outcome cleanup.

The baseline and natural event/brain/native chain succeeded. Event UID was
b245bf90-7a70-4d50-8e82-2ac9dbbec735, decision ID
4a91d178d0ac116352a4e18d7a1b9a70 and tick ID
a56a6ef9d36d960c9e2b8316a0759883. The exact version 8 adapter journal completed.
Eight B128 completions returned 200 with latencies 4.186–5.232 seconds. Two
individual flights contained the full widened bracket
14:46:23.229370–14:46:24.382838 UTC: B-1-04 ran
14:46:20.178655–14:46:24.526096, and B-2-04 ran
14:46:22.301253–14:46:26.768331. The availability-containment dimension therefore
succeeded; this was not another overlap failure.

The first post-action A request returned **status 0, HTTP transport unavailable,
empty body**, at 14:46:44.243988–14:46:44.250219 UTC (6.230668 ms). JSON parsing
then failed. No model-specific denial was proven, and B-after and the six-pair
hold were not executed. The physical first failure is enforcement; the strict
postcapture gate remains INCOMPLETE at evidence because `inventory_after` and
`inventory_post_hold` are absent. Positive cleanup finalization was not invoked.

Read-only logs show the adapter unloaded successfully at about 14:46:23.650 UTC.
A separate native request drain began at 14:46:44.001 and reopened at
14:46:44.345, overlapping the later failed probe. Concurrent interference is a
plausible explanation, not proven causality: no server log binds the exact failed
request ID, the helper retained a generic transport error, and diagnosis log
clocks were not separately calibrated. The failed episode remains unchanged.

Two evidence corrections are explicit. An earlier CLI read used namespace
`vllm`; it does not establish native-journal absence. The native namespace is
`phorvex-system`, and original runner HTTP reads before stage/load/release were
404 there. The first capture seal also conflated missing per-field files/bindings
with missing report contents. Twelve fields exist in the immutable failed report;
a labelled derivative seal binds those exact values without inventing missing
after inventories or `evidence_persisted_at`. The original report and first seal
remain intact. Safe cleanup was independently verified and root released the
lease at 14:52:16 UTC, without defense credit.

## Fourth deployed attempt: one complete bounded pass

The independent verifier executed `live-v3-verifier-4` after third safe release,
under the same final accepted source/profile and a fresh adapter/event identity.
Pinned local preflight passed in 0.207 seconds and actual read-only check passed
in 16.922 seconds. Physical delivery ran 15:00:09–15:02:54 UTC, 164.861 seconds,
including cleanup. No physical retry or policy/source change occurred.

| Dimension | Original observation | Verdict |
| --- | --- | --- |
| Baseline/control | A adapter 200 in 263.035 ms, B base 200 in 248.173 ms; delayed A/B controls succeeded before separate observer release | Real capability and bounded no-signal control |
| Event/brain/native | Fresh authenticated inventory event; unchanged brain selected adapter-rotate; exact version 8 protected receipt completed | Deployed response attributed independently |
| Availability | Eleven B128 completions returned 200, 4.131–4.310 seconds; B-2-05 ran 15:01:23.470822–15:01:27.749535 UTC | Contains the entire widened bracket 15:01:25.006683–15:01:25.951496 UTC |
| Effect and hold | Exact A model-specific 404, B base 200, base-only inventories; six varied A404/B200 pairs over 10.025588 seconds before cleanup | Scoped persistent route blocking established |
| Budgets | 31 actual probes: 10 A, 10 B1, 11 B128; 1,428 requested output tokens, 2,836 reserved intents | Within the frozen limits |
| Cleanup | Six exact original CREATE UID/full-label/content guards, once-only UID deletes with 200 receipts, seven named 404s, fixture owner/removal/absence, unchanged runtime | Independently VERIFIED; 37.912 seconds |

Event UID was 1670f878-9c7d-4eef-a1b5-82c4435d307f, decision ID
70f3f3d8c0a99b3236eaaf0b4ae76d13 and tick ID
6c73d65214b1bdf2eb4c1e2807d88aa6. Independently measured clock uncertainty was
65.369 ms for the target channel, 62.583 ms for independent B and 16.816 ms for
the API channel. Each met 100 ms; the measured combined maximum was 82.185 ms,
within the preregistered 200 ms gate widening. Exact native dispatch endpoints
remain unmeasured; the claim uses conservative protected-journal read brackets.

The immutable precleanup report was independently bound to all fourteen field
captures, including actual clock originals and overlap schedule. Expected pins
came from the root-frozen independently captured supervisor, never from result
fields. The separate gate returned PRE_CLEANUP_PASS, then `finalize_cleanup`
returned **LIVE_CASE_PASS / BLOCKED / PROVEN_DEPLOYED_RESPONSE / cleanup VERIFIED**.
The independent reviewer reproduced the adjudication from 31 unique original
probe replies, 23 authenticated audit chunks/371 rows, the unique selected
decision and exact actual completed journal. Three owned resident channels exited
0, owned forwarding closed and the operation became terminal. Root released the
lease at 15:05:38 UTC. Exit 0 alone was never treated as case acceptance.

Concurrent manager actions remain visible. The bounded fourth audit also records
a selected/actuated KV reset on the same target at 15:01:34.750893 UTC, after the
adapter action at 15:01:24.905378 UTC. All required actual probes still passed.
This does not prove that other actions were absent, causally irrelevant, or
controlled by the trial's exclusive lease.

## Historical source and evidence identities for episodes 3 and 4

Both revision-3 physical episodes used the same independently accepted source
bytes. These identities distinguish source review, measured capture, adjudication
and cleanup; retained originals do not depend on the author's machine paths.

| Revision-3 source | SHA256 |
| --- | --- |
| Runtime driver | 75a6ccc7ac9a4282c528973b8c2c081873f54b4b0830dbcf61dfe96c7066d09a |
| Separate observer | d529718a498b341cd5c38b1670b40112cdbefe5c303f681ab81bba97edef2eaa |
| Evidence/effect gate | 6cc40c17a0eeda9b9feaba1e2abfc9cc846f7160e21b7edf4004a7421d9f01db |
| Adapter adverse tests | 5db5cd10d981bad1e1daf2827ca84b5749ac93ed86ceb210a4137583927e5b91 |
| Resident helper tests | 1f81d0530785813853af79740efb0d6ad2311b2e45d9ff0bbd6c24b37a52d503 |
| Accepted source review | 30248cd8f207ab6cbe35f532b777cfe3234f7cfb1eb063eb95c9903c45f139d9 |

| Third evidence | SHA256 |
| --- | --- |
| Frozen contract | d71c403ff4832517f849dd25f17ee46f76aa112b151a749b58c1b96ab144797d |
| Frozen execution supervisor | 64c00c6b3d657a2e298a9d3026980fc3369a19c44dd8ceb52fa3de3a2e414871 |
| Immutable precleanup report | 5efd019821b1aacd6154b9002ba8e1db84b99177cc8c437231defc69eb86af8a |
| Original cleanup | 2c13b318208b7cec8872e8206b76f9853de7329c7105ed0dd2a0003780a6357d |
| Root release | fe23afbf4cb01f583ca51861982dea3d00908cb0444863818fb659eecc3cf0f4 |
| Capture binding clarification | a711072ee552d34f70cc4b48c6de9918ad50fb20b68bc77a01d6468c8feaeb80 |
| Independent safe-cleanup seal | 51c6bbdbcfe1f35fa4f4ebf897e9964f0f621d79e245a02eee135dd3d254a2c6 |

| Fourth evidence | SHA256 |
| --- | --- |
| Frozen contract | e3b6eb06dcf3b990ee43cc600728f274f6ea2dba9b0dc12243573dad530f3d4a |
| Frozen execution supervisor | 9bf567e11e52ae0f65f2acd27f848ad25a61c015466bcb08432b50dea8b87b20 |
| Immutable precleanup report | 407675bf0c7967bc5bd20906aab8807e31863b475a5a0fdb79e7d7cf37fb58e5 |
| Original cleanup | 3ad551241020aa5b17c35682a16de12a3205b8d49927abc96896e53a5fbd082d |
| Root release | 5e1b34b9441df645a810d3873629a0956f6318d98701da8e47c10a2400b9c7f1 |
| Verifier final cleanup seal | 83b1cf236ca2367209702a7516884471a33e831bb1d140874aabab3cad838ead |
| Independent reviewer final seal | 96c49f151650870e8eae352e543ba9c9aa493c472f06ddc03cbe8eed97db9ba7 |

## Fifth episode: clean-control pass, positive availability failure

A prospectively reviewed follow-on retained the first four outcomes and raised
only the aggregate physical ceiling to six. The first follow-on time window
expired at 15:50 UTC during an orchestration interruption: no fifth/sixth effect
or lease occurred within that expired window. A separately accepted prospective
time addendum ended at 17:30 UTC. It did not backdate authorization, erase failed
results or grant physical authority on its own.

Before the fifth episode, the exact repaired public driver, separate observer,
gate and portable tests were independently accepted. The repair moved immediate
post-effect probes ahead of slower metadata reads and added an actual clean
no-threat observation. It preserved acceptance thresholds and recorded every
ordinary request. Twenty-seven meaningful portable tests passed independently;
these establish tool checks, not physical defense.

The lead froze the fifth case, expected identities, exact source and exclusive
worker lease at 17:11:51 UTC. Fresh preflight and read-only runtime admission
passed before effects. Physical execution ran 17:13:34–17:15:06 UTC; the recorded
delivery elapsed time was 92.451 seconds. There was no physical retry or change
to policy, scoring or serving deployment.

| Dimension | Actual fifth observation | Verdict |
| --- | --- | --- |
| Clean no-threat control | Separately authenticated observer made real current GETs, found no owned adapter and produced no event intent; both ordinary base requests returned HTTP200 | Component PASS |
| Clean provenance | Exact observer Pod UID, service account, node and nonce clocks; target/policy/service/single-ready-endpoint identities; two full event lists; two protected native-journal HTTP404s; 98 original authenticated audit rows | Independently bound bounded evidence |
| Clean timing | Capture window 17:14:04.132685–17:14:12.751131 UTC, 8.618446 seconds; actual active-observer interval 2.259084 seconds | Within the frozen control bounds; sampled absence only |
| Positive baseline | Short owned-adapter and base requests succeeded before observer release | Owned unwanted route and ordinary service established |
| Long ordinary request | First B128 request returned HTTP500, Internal Server Error, in 709.558228 ms | FAIL at availability; positive episode INCOMPLETE |
| Request accounting | Eight actual requests, 135 requested output tokens; second long stream never started | No invented future responses or retests |
| Native/effect/hold | Not accepted after the legitimate-request failure; positive event/response/effect fields were missing | No positive defense credit |
| Owned cleanup | Exact created standby Pod and ConfigMap removed with original UID/full-label/hash guards and actual named absence; owned fixture removed after the failed result | Safe cleanup independently reconciled |

A passing clean component is narrower than a complete positive episode or an
independent reproduction of episode 4. It establishes the actual sampled
no-threat behavior of the observational test detector and installed system in
this window. It does not establish continuous absence, universal false-positive
freedom, the legacy producer's correctness or a complete G3 architecture branch.

### Why the legitimate request failed

Original serving logs identify the same failed request,
`cmpl-c7352a029843048a950cf9db8f3138a7-0`. vLLM logged a successful native
`/phorvex/drain/begin` at 17:14:42.554284 UTC, then aborted that exact request at
17:14:42.556118. The guardrail forwarding traceback ended in
`asyncio.CancelledError` and returned the observed HTTP500. Drain/reopen followed.
Unlike episode 3's temporal coincidence, this is exact request-identity evidence
for cancellation during competing native drain activity.

The serving logs alone do not identify the selecting manager policy, prove the
caller's authority, or supply separately calibrated cross-log timestamps. Those
claims remain unknown. We did not infer a brain selection from an endpoint log,
force an alternative action, retry the failed inference or disable protection.

This exposed an architecture constraint: an exclusive agent lease coordinates
assigned workers, but it cannot prevent an installed manager or another native
actor from touching the same workload. Before asserting execution isolation,
coordinate every mutating actor or use an independently owned faithful twin.
An empty operation list at admission is an observation, not a reservation.
Additional workers would not resolve this interference.

### Failed outcome versus independently established safe state

The original result retained `transport_cleanup: UNRESOLVED`: the adverse B helper
exited nonzero after its genuine HTTP500, and the driver's normal close path did
not produce a successful B-channel closure ledger. We did not edit that original
flag to PASS. Its terminal error record nevertheless showed the begun request
answered, the stream drained and zero in-flight requests.

Separate independent readback confirmed the exact owned Kubernetes resources
and fixture absent, the failed episode's event/native objects absent, runtime
identities unchanged and all four recorded resident processes plus the owned
forwarding process absent. No missing child exit status was invented. The
cleanup path completed in 22.247 seconds; the final independent safe-state
reconciliation allowed the root lease release at 17:24:57 UTC. Cleanup and
reconciliation grant no defense credit. The HTTP500 and original transport
cleanup failure remain in the study.

### Fifth source and evidence identities

| Exact fifth source or evidence | SHA256 |
| --- | --- |
| Runtime driver | 575f010ed2ba2db67b39576e6b360f0623d672534960f71d74f1109edfaedbb4 |
| Separate observer | 01fd35f6476107da9979e4db6259afd96644c2053a321836b2098647b866bf98 |
| Evidence/effect gate | 5a6eabfeb5b416f0ccde826631a97c0fe00016702e4c11ecc05e7171d62ac97d |
| Clean-control adverse tests | 110e7e432710dcf641ff2d02090651c8e9cdeeeb2f65716b00286f7622bb400b |
| Accepted public-source review | cb1e9d3da8cd78f5025de60d8c83eb93d327b8d874e6860036dc6f3db54a9071 |
| Frozen contract | 66d14d6d30a8aa47d456887b7cf276de6127017299b6871bdee86d75f57cf285 |
| Frozen execution supervisor | 9e5b462118e85d587789528efefcd138a14cc6d751cdd06f8a99223f71efdd1f |
| Immutable precleanup report | 9777e963d5382b375a50549e35f5fab249226c0155c99bf12bc49708da477ef2 |
| Independent failed-precleanup seal | 503d0dfb282e71e0db3e8b561f513d1a01a32fb3a2f34df51920eff346ddce17 |
| Independent safe-cleanup seal | cd07dad938164f3e7a1b9bde67000408196297b884389c36fbccc87c283535e1 |
| Independent episode review | 96c7a6c95189dca5dc7d7d5f166b6aa7724209684706a16f7db5eac4ce93998c |
| Request-cancellation cause companion | b472030ae46a6c81d66e58eb2ef6ffb74afce71f1bee9c95c150a5dc8fedc97a |
| Root safe release | 8b9613daf065402f3ed998b4a5c8a845ace170304e821c9ee4af5145c58674c0 |

## Sixth planned episode: not executed

The independent reviewer completed a fresh permitted read-only readiness check;
all three channels closed with status 0. This check made no model completions
or mutations and is not a physical episode. No sixth freeze or execution lease
was granted. A successful fifth/sixth pair was already impossible after the fifth
failure, and fresh review/freeze plus the full 240-second measurement/cleanup
reservation could not fit the remaining 17:30 UTC window. The final record is
**UNEXECUTED**, not PASS, FAIL, a timeout during an attack, or a sixth consumed
physical attempt. Five physical episodes were consumed; one aggregate ceiling
slot remained unused. The final time window expired without further effects.

## Study disposition and architecture decision

| Required result | Final measured state |
| --- | --- |
| Portable roles, prompts, stages and handoffs | Independently reviewed guide; documentation acceptance is not runtime proof |
| One complete deployed positive episode | Established by episode 4 and independent adjudication |
| Two successful fresh independently executed episodes | NOT ESTABLISHED; reviewer episode 3 and follow-on episode 5 failed |
| Deployed clean no-threat control | Fifth component PASS within sampled bounds; complete architecture branch remains unproven |
| Exact owned safe state and lease release | Independently confirmed for all five actual episodes; no sixth lease |
| Fleet-scale parallelism | Specified bounded pools and conflict-aware scheduling; hundreds-of-workers throughput NOT MEASURED |
| Full deployed architecture acceptance | NOT ESTABLISHED beyond the exercised passing path |
| Formal action SLO / whole-binary attestation / production readiness | UNKNOWN / NOT CERTIFIED |
| LangGraph implementation | DEFERRED |

The architecture now specifies six functional roles, four routine participants,
conditional integration/domain specialists, typed tasks and immutable
artifacts, proposal/execution/capture/cleanup boundaries, first-failure routing,
exact ownership and recovery, bounded retries and retained verification debt.
V1/V2's isolated experiment remains a separate accepted local pilot. V3 improves
portable execution and failure handling; it is still a candidate for general
selection because the required successful independent pair is missing.

The original boss design's hundreds of agents correspond to logical assignments
across applications, attack stages and actuator validators. The proposed
architecture supports those jobs through multiple workers per role and bounded
pools: discovery, independent planning/review, disjoint implementation and
immutable-result analysis can overlap. Physical execution overlaps only on
independent environments with coordinated mutation dependencies. The portable
runbook specifies the inputs, outputs and coordination for each lane. Neither
this single-case trial nor a sizing formula proves an optimal worker count.

The next discriminating experiment requires independently coordinated runtime
ownership or a faithful owned twin, a prospectively reviewed budget and two
fresh physical episodes on the same accepted profile. Preserve the failed
ordinary requests and compare availability under concurrent native actions;
never obtain acceptance by weakening the oracle, ignoring another action or
forcing the desired brain selection. There is no active execution authority
from this closed study.

The passing claim covers removal of one operator-loaded harmless model route
using an observational test detector and the unchanged deployed manager/native
response, with sampled ordinary service and precleanup retests. It does not prove
attacker enrollment, poisoned answers, always-on production detection, universal
availability, new-actuator synthesis, broad customer-stack coverage or every
architecture discovery/learning branch. Those require their own discriminating
experiments. All original failures remain evidence.
