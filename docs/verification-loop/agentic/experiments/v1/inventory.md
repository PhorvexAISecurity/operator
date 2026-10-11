# V1 source and runtime inventory — credential-reuse-local

Status: ready for source review and verifier planning; no episode was executed by the stack analyst. Source revision: `f73d04cd6aac9f5945da1515e2dac76554869920`, branch `feat/verification-loop-agentic-workflow`, main base `54c9273a6faaa3768e55adf15afb51de68b3241b`. HEAD matches the case pin, and the scoped harness/runtime source has no tracked diff from that revision. The architecture directory is untracked experiment work.

Scope and provenance: one private real Kubernetes API plus local shipped Python credential admission and a synthetic downstream. Facts below come from source inspection and read-only tool prerequisite discovery, not measured enforcement. The handoff's started_at is the first recorded worker timestamp, 2026-10-10T10:50:10Z; actual spawn start and the preceding source-read interval were not independently measured.

## Components, identities and authority

| Component | Kind and source | Role in this case |
| --- | --- | --- |
| Kubernetes API and etcd | Real private envtest processes; `run.go:194` | `UseExistingCluster=false`, RBAC authorization mode, real UIDs/resourceVersions and both CRD directories. No kubelet or workload controllers. |
| Workload route | API metadata fixture; `fixture.go` | Namespace/service/deployment `vllm`, explicit ReplicaSet and Pod `vllm-a`, Ready Pod `10.240.0.10`, EndpointSlice, service port 8000, guardrail and engine image/container IDs. Fictional image digests are not launched. |
| Caller authority | Real API immutable Secret `vllm/phorvex-endpoint-lease-keys` and real local projected bytes | Private fresh random A, B and seed. Only HMAC client IDs and seed digest enter policy/observation/status artifacts; never copy raw tokens. |
| Durable lease policy | Real API mutable ConfigMap `vllm/phorvex-endpoint-lease-policy`, key `state.json` | Canonical source/service/Secret-bound revision 0 initially allows both HMACs; revoke moves A to revoked and preserves B at revision 1. |
| Source authority | Real API immutable ConfigMap `vllm/guardrail-proxy` | Exact five-file closure and digest must match the configured approved source. Approved proxy/engine image pins are fixture metadata. |
| Admission boundary | Real shipped `dual_server.py:178` and `endpoint_lease.py:226` | Performs current named API reads, Secret/API-vs-projection comparison, HMAC admission, monotone revision checks and in-flight accounting. |
| Public/admin listeners | Real local HTTP public and HTTPS admin sockets; `runtime_fixture.py` | Four IPv4 loopback sockets: downstream, observer, public and admin. ASGI scopes map ephemeral public/admin sockets to production logical ports 8000/8443. Native status target `10.240.0.10:8443` maps through one exact verified TLS loopback transport. |
| Downstream and observer | Synthetic HTTP services; `runtime_fixture.py:123,149` | POST completions echoes marker + nonce and increments a counter; observer requires the private admin bearer. Neither performs inference nor changes policy. |
| Operator admin identity | Real private admin Secret and TLS cert/key; `fixture.go` | `phorvex-system/lease-admin`, policy-UID/service-account/profile binding, certificate server name `lease.verification.local`. Test transport token is supplied directly. |
| Event identity | TEST_INJECTED; `run.go:839` | Private envtest admin creates SecurityEvent with asserted creator `system:serviceaccount:phorvex-system:phorvex-phorvex-console`; no deployed console authenticates the assertion. |
| Response journal | Real API ConfigMap `phorvex-system/phorvex-endpoint-lease-journal`, key `receipts.json` | Durable prepared intent and terminal-full receipt; verifies operation/decision/tick, original Pod/container incarnations and exact policy state. |

The five-file source closure is ordered `guardrail_proxy.py`, `dual_server.py`, `endpoint_lease.py`, `drain_v11.py`, `drain_v11_init.py`, with NUL separators. Its SHA-256 is `870c8709a5da026d01449be737939fa35420ebd1bda341ea2371c6081926fda4`. All five files are source-authority inputs; this fixture imports EndpointLease and ServingBoundary and runs a synthetic proxy/downstream, not the complete production guardrail/vLLM server lifecycle.

## Data flow and observation admission

A request is `POST public /v1/completions` with one caller bearer and an owned printable nonce. The boundary reads the exact policy and immutable Secret through verified envtest mTLS, checks actual `..data` projection bytes and source/UID/seed/roster bindings, derives the caller HMAC and admits only current allowed IDs. It replaces caller authorization with the private upstream bearer. Only that bearer reaches the separate synthetic downstream. Success requires HTTP 200, exact marker/nonce and one counter increment. After revocation the identical A bearer must receive exactly 401 `unauthorized` and no downstream increment; 503 `lease_unavailable`, network outage or backend refusal cannot establish containment (`evidence.go:113`). B must succeed throughout sampled dispatch overlap and the 2000 ms hold, with each request at most 2000 ms.

The baseline probes' status and response hashes populate typed `endpointlease.Observation` in a real SecurityEvent. Source is `redteam`, rule `phorvex.attack.endpoint-lease-reuse`, scenario `ai2-endpoint-security`, evidence mode exactly TEST_INJECTED. Ingest requires trusted allowed creator, exact target Pod UID, unique suitable event, age below 60 seconds, current policy UID/generation/selector, live Service/ConfigMap/Secret/source/revision bindings and both A/B IDs currently allowed. The stale control is 61 seconds old. An empty approved source/image/engine configuration keeps this action unavailable (`ingest/endpoint_lease_source.go`). Proxy TLS status is independently required by native capability checks; an event alone is insufficient. Freshness and authority are checked again at dispatch.

## Fixed policy, brain and candidate fit

`fixture.go` creates active `lease-defense` selecting `app=vllm` with event-driven/reactive-only handling and enabled endpoint-lease-revoke, endpoint-rotate and rotate. The explicit resolved `model.Policy` in `run.go:344` supplies lambda seed, norm sparsity 0.4, flow disruption 0.6, secret weight 0.8, one move per tick, one-second anti-over-rotation window, one-hour proactive floor, minimum available replicas 1 and trace enabled. The runner waits a real second rather than backdating identity. This does not exercise manager policy resolution or the production five-minute timing.

A new unchanged CoverageEngine uses `ucw-recon`, a frozen decision clock and recorded native SupportsAction answers, through checked shadow evaluation. Owner state must remain unchanged. UCW binds the endpointLeaseReuse fact specifically to endpoint-lease-revoke (`recon/ucw.go:254`); endpoint rotation and Pod rotation do not receive coverage for removing the same caller credential. Candidate exclusion details still require actual traces from the verifier. The local normalized serving-configuration cost is modeled as 0.25; the formal endpoint lease SLO remains unknown because there is no calibrated safe-return deadline. Sampled legitimate latency does not supply that bound.

No new actuator is necessary on source inspection: the native revoke handler already validates event, policy epoch, action authorization, source/current route and protected history; reads authenticated status on all Ready backends; writes prepared journal intent; performs one resourceVersion CAS of the exact durable policy; checks all original/current incarnations, retained-B allowance and old-revision drain; then writes terminal-full. The harness expects one policy and two journal updates. This is an implemented capability, not an analyst enforcement certification. Existing recovery reads a prepared intent and current state, never repeats the policy CAS; unresolved old-state intent remains unknown.

## Tools and run prerequisites

Read-only discovery found default PATH lacks `go`, default `/usr/bin/python3` 3.14.4 lacks httpx, and `KUBEBUILDER_ASSETS` is unset. Explicit paths are available:

| Tool | Verified local path and prerequisite |
| --- | --- |
| Go | `/home/mehrdad/.local/share/phorvex-tools/go1.26.1/go/bin/go`: reports go1.26.1 linux/amd64, matching go.mod. |
| Python | `/home/mehrdad/.cache/phorvex-verification-loop/venv/bin/python`: 3.14.4, httpx 0.28.1, uvicorn 0.34.0, matching fixture requirements. |
| envtest | `/home/mehrdad/.cache/phorvex-verification-loop/envtest/controller-tools/envtest`: executable kube-apiserver, etcd and kubectl present. Tool binary hashes must be bound by each run. |
| Source/build | Both CRD directories, local module replacements `build/phoenix-extended` and `build/metricvalidity`, Go dependencies and unchanged case source must remain available. Compilation/readiness was not attempted by this role. |

Verifier must build a pinned binary, use explicit `--repo-root`, `--git-sha`, `--python`, `--assets` and an empty new `--out`. The caller-supplied Git revision is a label; actual binary/source/tool/closure hashes establish what ran. Default command limits are three minutes, hold two seconds, hold interval 250 ms, legitimate latency two seconds. No existing cluster/kubeconfig is used. Secrets and certificates stay in private 0600 temporary files and are deleted with the temporary environment. Every episode needs new output and a fresh private control plane; negative controls intentionally exit nonzero and their evidence must be retained.

Clean, stale and exact snapshot replay are embedded in each episode. `--skip-dispatch` must produce LANDED despite selection with no writes; `--unavailable-authority` deletes the private lease state after dispatch and must stay INCOMPLETE with 503. `ReplayFile` opens no API and dispatches nothing. Its exact input includes original API identities, clock, model policy, views, owner state and recorded capability observations; a fresh physical episode has different identities and requires semantic comparison. Runner report fields retain stages, probes, raw bodies, timestamps/counters, decisions/traces, source/binary/tool hashes and policy/journal/event artifacts. The report's single verdict vocabulary is not the architecture's three verdict dimensions; orchestrator/verifier must map it using evidence rather than the label alone. Final return tears down Python listeners, envtest and temporary credentials; cleanup errors remain evidence.

## Requirements for the next roles and actual V1 ambiguities

- Red team owns the successful baseline specification and two bounded attack variations, using caller A only for the attacker and B for the legitimate control. No admin, seed, API credential or upstream bearer may be granted to the attacker. Variations must be independent public admission probes against the same defended state, with counter sampling serialized so deltas are unambiguous.
- Defense engineer owns existing-response fit and exclusions, secure authority prerequisites and precise candidate effect; preserve the brain and policy. Source inspection supports using the existing handler. A real deployment would additionally need authenticated observation production, deployed workload/source/image verification, service-account/API permissions, secure manager/admin bindings and calibrated availability evidence; these are outside the fixed local contract.
- Verifier owns executable baseline, controls, chain evidence, timestamps, first incomplete stage and cleanup. A pure unit suite or reused historic reports cannot satisfy the fresh case. Verify A denial and B availability independently of emission/terminal receipts.
- The runner provides no CLI hook to pause after defense or submit later bypass variants. `Run` removes the environment and temporary credentials before returning. A verifier-owned test adapter/overlay must run the reviewed bounded variations after dispatch and before teardown, preserving source pin disclosure and independent probes. Product changes remain disallowed. Architecture stages B→T therefore need concrete adapter routing; a successful original run alone cannot count as later re-attack evidence.
- ARCHITECTURE-V1 grants verifier exclusive runtime mutation and states only verifier receives run_episode; PROMPTS-V1 and CASE simultaneously require independent reviewer to reproduce in a new private environment. This is an actual ownership ambiguity. The orchestrator has stated it will explicitly delegate reviewer-owned independent reproduction after verifier completion, preserving serialization, and retain the defect for V2. The analyst has not changed the frozen documents.
- CASE has required_action=null, but `run.go:460` rejects any selected action other than endpoint-lease-revoke. Selection is not forced, yet acceptance is candidate-specific in the existing runner. Orchestrator/reviewer must report this fixed runner expectation when evaluating candidate-agnostic contract claims; other candidates need independently agreed effect probes rather than silently changing the trial.
- No accidental duplicated implementation/execution by this role was observed. Analyst and defense engineer both inspect authority/capability sources, but the analyst inventories infrastructure and the defense engineer judges response fit; this deliberate read overlap is not evidence of redundant runtime work. The two concrete ownership/lifecycle gaps above are the observed V1 coordination issues.

## Declared omissions

No attack run, private control-plane start, test execution, new harness/product code, cluster mutation, commit or push occurred in this role. No independently measured readiness, enforcement, availability or SLO was obtained. Missing infrastructure includes deployed console/detector, full manager, Kubernetes workload controllers/kubelet/CNI, real vLLM/GPU inference and production image/routing/scale/continuous-service evidence. The source-relevant runtime model intentionally contains a single API-fixture backend; all-backend code is not a measured multi-replica result. Authenticated envtest admin mTLS is not service-account/RBAC least-privilege certification. Restart/resume recovery and rollback behavior were inspected only as existing code, not exercised in this inventory.

## Source pins

The handoff JSON contains all input hashes including architecture, prompt, case and source. These inspected or required closure files are pinned here for review:

| Path | SHA-256 |
| --- | --- |
| `AGENTS.md` | `f80cf49f483d15a15c9241fc26914b132c619a3c5f58cacb682d88dda7762744` |
| `workflow/AGENTS.md` | `d8378ffdb686862f8088e110d599e6f0658a63d82234ac93aea7e3b9c674b1b7` |
| `docs/verification-loop/agentic/ARCHITECTURE-V1.md` | `6a22ae0223fd0d5db4ecb11c0b1a6cb73c920c3df7628fe2a2d4d14250c2d243` |
| `docs/verification-loop/agentic/PROMPTS-V1.md` | `2feb6b2c4d6fcbc8cf04076ad61377ee2202caf7e6532d37748f6e4b94ee2910` |
| `docs/verification-loop/agentic/experiments/v1/CASE.json` | `6419e8adf51e6c0e231605e52ffad70fc6d44486742fc22ab630ef9a5ceb0fa8` |
| `phorvex/internal/verificationloop/fixture.go` | `408c6c716f250785d1c3cf8a24528427dbcbff9fce8c96ee9e9b61489547db0a` |
| `phorvex/internal/verificationloop/run.go` | `9505801c5f1d311ee2795f5d8081da10829139521bfc79b68532ace886fef1a2` |
| `phorvex/internal/verificationloop/evidence.go` | `6198dca5758cb8eb5dbbb41c8829404520fe89c12d873b422d6a0d01888ef428` |
| `phorvex/internal/verificationloop/run_test.go` | `91eac0c667ea01ea4d25f64a5b7203420a458c6fe1ed5b36ef82988205475d24` |
| `phorvex/cmd/verification-loop/main.go` | `dc0932fc7f306216f4b49e4f760deb5c4db3eb979c5651de4fa464c37641ffb3` |
| `build/test-harness/fixtures/verification-loop/README.md` | `a7c511b6eff552ea4bc7ddb434bfcf4ed4fb290cfbac4d909f286e85d9153eb8` |
| `build/test-harness/fixtures/verification-loop/runtime_fixture.py` | `30ea5593aaebd7208ac6563f9f645c37ecb6af9fc1e21b0b1327d1fd8e418194` |
| `build/test-harness/fixtures/verification-loop/requirements.txt` | `bb9d26a9fafa57be7069c2acbb014911f34bfff93055f0d103fa9e25c9f74323` |
| `phorvex/internal/endpointlease/contract.go` | `485bcc90ee7f7b595b5eaacf869d89188f909f5369b649e742f0e50f3c46d5d9` |
| `phorvex/internal/endpointlease/live.go` | `c6dff8a3c1e964e7f70f7b992d11cf981f0b128406f2efd6c2216999efe02757` |
| `phorvex/internal/ingest/endpoint_lease.go` | `37be165776b486260b8bc85effb7ca4eb6a448da9e5dcd3ba8ae9f7b7c4a0c96` |
| `phorvex/internal/ingest/endpoint_lease_source.go` | `6d65228be14d2342aef1b21ac7981f669023572d869b35644aae854298531ff3` |
| `phorvex/internal/actuator/endpoint_lease_revoke.go` | `45ef15b00f15d76e1a03ca79012a21cbca5a4c1ff5f5dd2793a35ba7b4e7e208` |
| `phorvex/internal/actuator/endpoint_lease_journal.go` | `aa164d89f3bfddbe0607b1a528876eaa0c46c3819c7843aaa10c5abb6cdfb8b4` |
| `phorvex/internal/actuator/endpoint_lease_recovery.go` | `f2289dbe8807789aeed2bc33910fe808e5f117fb951bb4ed54a06b320982f694` |
| `phorvex/internal/actuator/native.go` | `b1d43d787afd062522d13152c247291884d9b145526d3c8b49b5ef9f2f6f6980` |
| `phorvex/internal/actionset/generator.go` | `4e5649e9f6b7ac13191748ae3dd276a8a7a94de4d34469999b35c5d406ded6b4` |
| `phorvex/internal/recon/ucw.go` | `ec4762c9581d8ccff363ad572de7888fa78a0b84e92a6e49dd08f1166d4d1702` |
| `phorvex/internal/cost/p1cost.go` | `54ed4c868cca41c38b8fa2f552fb643772bd5c71a092a3f4e0ccca657c899863` |
| `phorvex/internal/cost/action_flow.go` | `ba7da439e58672734f3bed0674bf5ae8647182df03baf1f4b9ce6f2c0fe013af` |
| `phorvex/internal/slo/bound.go` | `24ccfd122519d62fdef25866e03a034ed89b4f3d6889e88c503ccea10ea50d56` |
| `phorvex/go.mod` | `bd35ce734262578442552555e770ad1189e24a2fb37a8733e4f473befca352f3` |
| `phorvex/go.sum` | `c2535bd48709b0f7e3affe598bc421558428cd3893c9fdb392286e49314649b0` |
| `build/test-harness/guardrail/guardrail_proxy.py` | `835f1e6cdb700f64f53e567353469991b865b83f8a995b19bb572e06ecf53e65` |
| `build/integrations/vllm-live-runtime/dual_server.py` | `3206ff9a49d0ed04cbd185ccf9877cf69c74ac7acf5e44babd579bea626a30af` |
| `build/integrations/vllm-live-runtime/endpoint_lease.py` | `3719b66e347f5022b11a8b33408122f9903d7630671638dd032389e3309ba8ab` |
| `build/test-harness/guardrail/drain_v11.py` | `4ffe402960d3c368d95b137e313a69818b9b33a162fcb76d09585b4d75b9c397` |
| `build/test-harness/guardrail/drain_v11_init.py` | `4e1a7a00550e8ce980b95114305027729dd5e3dddfdcbb2bca3026cb16b5dd5d` |
