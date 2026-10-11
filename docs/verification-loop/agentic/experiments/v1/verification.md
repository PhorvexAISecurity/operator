# V1 independent runtime verification

The existing local credential-reuse case passed its positive response chain. Both negative controls behaved as required. This is verifier evidence for independent reproduction; it does not accept the V1 architecture or production availability.

Source: `f73d04cd6aac9f5945da1515e2dac76554869920`. Fresh Go 1.26.1 binary SHA-256: `17f86a5307ef5c7395085af1b03e58c2bd39e596330bc68c93e4da3fa3cee0a6`. The tracked checkout was unchanged. Preparation pins every relevant tracked source file; the runner separately records executing binary, fixture, brain, runtime source and envtest binary hashes. The supplied revision label alone is not source proof.

| Episode | UTC execution window | Seconds | Exit | Driver result | Threat / attribution / local acceptance |
| --- | --- | ---: | ---: | --- | --- |
| positive | 10:56:30.928–10:56:42.745 | 11.816 | 0 | LOCAL_RUNTIME_DEFENDED | BLOCKED / PROVEN / LOCAL_ACCEPTED |
| skip-dispatch | 10:56:42.746–10:56:53.064 | 10.318 | 1 | LANDED | LANDED / NOT_PROVEN / INCOMPLETE |
| unavailable-authority | 10:56:53.067–10:57:02.383 | 9.317 | 1 | INCOMPLETE | UNKNOWN / NOT_PROVEN / INCOMPLETE |

All times are 10 October 2026 UTC. Native process timings, measured probe clocks and frozen decision clocks remain distinct in the raw reports. Every command declared internal timeout 3 minutes, outer timeout 240 seconds with a 15-second termination grace, hold 2 seconds, interval 250 ms and legitimate-request ceiling 2 seconds. Exact argument arrays and measured command timings are retained beside each episode.

Each episode established successful A and B downstream baselines, refused clean/stale selections, naturally selected `endpoint-lease-revoke`, retained original identities and clock for exact replay, and left shadow owner state unchanged. Observation provenance is explicitly TEST_INJECTED. The production brain and native actuator were unchanged; no action was forced, policy tuned, or product repaired.

The positive episode completed native dispatch, durable exact-identity policy cutover and protected terminal journal readback. A-after and all seven A hold probes returned exactly 401 unauthorized with no downstream increment. B-after and seven B hold probes performed actual downstream operations. All 12 B samples succeeded, maximum latency 18.316454 ms; two request intervals actually overlapped dispatch. Measured hold was 2276.977089 ms and baseline-to-confirmed-denial interval 565.251074 ms. The seven newly generated A nonces are bounded repeated checks against the live defended state; they establish no adaptive bypass coverage.

The withheld-dispatch episode retained real brain selection and exact replay while A and B still performed downstream operations. Policy and journal data remained unchanged. Its first incomplete stage was `dispatch-withheld-negative-control`; LANDED and exit 1 are the expected control outcome. Native response attribution remains unproven.

The authority-outage episode first completed native dispatch and journal readback, then deliberately deleted the private policy. A received 503 lease_unavailable with no downstream increment. Its first incomplete stage was `unavailable-authority-negative-control`; the threat is UNKNOWN, not blocked or successfully landed. INCOMPLETE and exit 1 are the expected control outcome. B during-dispatch measurements preceded deliberate authority deletion and do not establish availability after that deletion.

The read-only retained-evidence validator passed 217 positive, 104 withheld-dispatch and 113 outage checks. It verified raw response hashes/bodies/counters, TEST_INJECTED baseline bindings, pinned source/binary/assets/artifacts, selection, replay, durable state/journal, actual dispatch overlap, complete two-second denial span and cleanup. Validation success for a negative means the configured control was honestly classified; it grants no defense acceptance. There was no unexpected failed stage, repair, targeted rework or repeated episode.

Cleanup completed at 10:57:32.316127 UTC: no remaining case API-server, etcd, fixture or driver process; no newly retained private credential or envtest directory; no cleanup errors in reports. The verifier released the runtime lease before independent reproduction. All three raw reports, commands, stdout/stderr, runtime logs, API artifacts, replay inputs, source pins, validator and cleanup receipts remain under `.git/phorvex-workflow/agentic-loop-20261010/v1/`; binary and validator are under the sibling `tools/` directory. Hashes are listed in verification.json.

Formal action SLO remains unknown. The downstream is synthetic; real API-generated identity and updates coexist with fixture Pod/endpoint metadata, local mTLS adaptation, an explicit policy, and injected event trust. No real detector, manager policy-resolution path, GPU, deployed console, customer workload, shared cluster or production guarantee was exercised.

Architecture limitations remain: the red-team provider failed before producing output and the orchestrator authored the reviewed existing-case fallback; runtime teardown prevents a separate post-run reattack; independent reproduction requires an explicit lease transfer despite the original exclusive-verifier ownership wording; configured negatives lack a dedicated control-task status; broad production failure routing remains unspecified. Independent reproduction and architecture disposition belong to the reviewer and orchestrator.
