# Verification-loop ticket report: one reproducible credential-revocation case

**Date:** 10 October 2026 (UTC)

**Source baseline:** `54c9273a6faaa3768e55adf15afb51de68b3241b`, latest `main` when work began; merge of PR #449.

**Delivery scope:** One isolated behavioral verification loop, independently reviewed with GPT-6.1 Sol implementation and review agents.

**Result:** `LOCAL_RUNTIME_DEFENDED` for future reuse of the tested stolen credential. This is a successful local vertical slice, not a full verification-loop architecture WIN or production-readiness approval.

## What was delivered

A new `verification-loop` command runs a complete, bounded case using the
unchanged Phorvex decision engine and existing `endpoint-lease-revoke` native
actuator. It creates a private Kubernetes API server and etcd, starts the shipped
Python caller-admission boundary over actual HTTP/TLS, establishes an attack
baseline, admits a target-bound test observation, records the brain's decision,
dispatches the selected action and measures the resulting application behavior.

The command also checks clean and stale-observation controls, reproduces the
decision from its recorded inputs, preserves evidence and cleans up its private
processes and credentials. Separate failure controls prove that selecting an
actuator without dispatch, losing the policy authority, or interrupting a trial
cannot receive a defended verdict.

New implementation is confined to the verification command, its Go package,
the local Python runtime launcher and their documentation/tests. The production
brain, cost/scoring model, ingestion contracts, native actuator and shipped
caller-admission implementation were not modified.

## Threat and declared experimental contract

Two owned synthetic caller credentials initially have access to the same
inference route. Credential A represents a stolen credential; credential B is
the legitimate caller. Before response, each must perform a real downstream
operation. After response, A must receive the specific admission result
`401 {"error":"unauthorized"}` without any downstream operation, while B must
continue receiving a valid successful response.

The downstream is an explicitly synthetic HTTP application. Each successful
operation returns the marker `verification-loop-synthetic-downstream`, echoes
the unique request nonce and increments an independently observed counter.
This distinguishes actual operation from a cached success, a fabricated
receipt, a backend refusal or an unavailable service. It does not test model
inference, GPU behavior or whether a language model discloses secrets.

Revocation prevents subsequent use of A. It cannot undo any earlier successful
access or disclosure. The experiment represents credential reuse; it does not
implement credential theft or certify autonomous detection of theft.

The initial model-policy input is declared and preserved for replay:

| Setting | Value and interpretation |
| --- | --- |
| Recon profile | `ucw-recon`, the profile explicitly configured by the manager |
| Mode | Active, not dry-run; reactive-only; event-driven |
| Enabled candidates | `endpoint-lease-revoke`, `endpoint-rotate`, `rotate` |
| Move budget | One action |
| Lambda input | Legacy runtime seed `0.6`; no production lambda calibration claim |
| Cost weights | Norm sparsity `0.4`, flow disruption `0.6` |
| Replica floor | One available replica |
| Anti-over-rotation window | One second, with actual wall-clock maturation |
| Legitimate-response ceiling | Two seconds per measured completed request |
| Independent trial hold | Two seconds requested; 2.275 seconds observed |

The API policy provides target scope, identity, enabled actions and declared
timing. The driver supplies the recorded `model.Policy` directly to the engine;
the full manager policy-resolution/controller loop is outside this experiment.
The policy is fixed across clean, stale and attack controls. No selected action
is hardcoded into the decision output.

## Evidence through the chain

| Stage | What actually ran | Observed result |
| --- | --- | --- |
| Attack baseline | Actual public HTTP operation using A | HTTP 200, correct marker/nonce, downstream counter increased by one |
| Legitimate baseline | Same operation using B | HTTP 200, correct marker/nonce, downstream counter increased by one |
| Observation admission | A real API `SecurityEvent`, bound to current target, policy, Service, Secret and source identities | Fresh typed credential-reuse observation admitted; stale observation rejected |
| Brain | Unchanged `DecideShadowChecked`, fixed clock, declared policy, current ingested views and real native capability checks | Selected `endpoint-lease-revoke` with a valid trace; shadow owner state unchanged |
| Decision replay | Fresh engine using original identities, clock, owner state, recon profile and recorded capability observations | Canonical decision traces matched exactly |
| Actuator | Full `NativeActuator.Actuate` with secure serving authority | One successful enforcement-policy update and two protected journal updates |
| Enforcement readback | Actual private TLS runtime status and durable API state/journal | Exact lease cutover confirmed; selected operation reached `terminal-full` |
| Attack after response | Identical credential A through the public application route | HTTP 401 unauthorized; zero downstream increment |
| Legitimate service during/after response | B requests overlapping dispatch and throughout the hold | All measured samples succeeded with correct marker/nonce and downstream increment |

The fixture's observation is explicitly **`TEST_INJECTED`**. The API admin
client creates it; its console-creator annotation and trusted-publisher list
are fixture inputs. This proves the admitted-observation → decision → native
response → behavioral effect chain. It does **not** prove that a production
detector independently discovered the attack or that a production console
authenticated this event.

The selection traces remain the original pre-dispatch shadow outputs, with
dispatch marked `not-attempted`. This is intentional for exact replay.
Execution evidence is separate: native response, protected journal, policy
readback, authenticated runtime readback and application probes.

## Why this actuator won

The independent trial's trace contained the typed fact
`pod|vllm/vllm-a|endpointLeaseReuse`, with value approximately **1.061531**.
The selected revocation had modeled expected cost **0.13**, coefficient **0.6**
and net gain approximately **0.983531**, satisfying the unchanged strict-positive
selection rule.

`endpoint-rotate` received no credential-revocation coverage credit and had
negative net gain **−0.06**. `rotate` was excluded because removing the single
ready replica would violate the one-replica availability floor. The trace
therefore explains the action rather than merely recording the expected name.
These are model quantities under the declared fixture inputs, not measured
economic costs or evidence of optimal action choice for every customer stack.

## Repeated physical trials

The implementation trial and the independent trial used fresh private API
servers and different API-generated object identities. Both used the same
reviewed implementation and executing binary hash. The implementation trial
requested a one-second hold; the independent trial requested two seconds.

| Measurement | Implementation trial | Independent trial |
| --- | ---: | ---: |
| Start, UTC | 07:46:37.091 | 07:48:24.963 |
| Finish, UTC | 07:46:48.311 | 07:48:37.380 |
| Verdict | `LOCAL_RUNTIME_DEFENDED` | `LOCAL_RUNTIME_DEFENDED` |
| Legitimate samples | 9 | 12 |
| Failed legitimate samples | 0 | 0 |
| Largest completed legitimate latency | 20.470 ms | 19.154 ms |
| Successful requests actually overlapping native dispatch | 2 | 2 |
| Baseline-probe start → first confirmed denial | 575.565 ms | 573.274 ms |
| Actual hold elapsed | 1,193.918 ms | 2,275.129 ms |
| Exact-input decision replay | Match | Match |
| Shadow owner state | Unchanged | Unchanged |
| Cleanup errors | None | None |

The independent native dispatch lasted approximately **206.322 ms**. All eight
post-dispatch/hold A probes in that trial received the required 401 denial with
zero downstream increment.

These are observed intervals and samples. The baseline-to-denial interval is
defined by the controlled probe; it is not the unknown total dwell time of a
real incident. Fresh physical episodes are behaviorally repeatable, while exact
decision replay occurs within each episode using its original recorded inputs.
API-generated identities are never normalized to pretend different episodes
had identical inputs.

## Failure controls and independent validation

| Control | Observed outcome | Meaning |
| --- | --- | --- |
| Clean case without attack observation | No action selected; enforcement policy and journal unchanged; A/B still succeed | No clean-run mutation credit |
| Observation 61 seconds old | No selected action or policy/journal mutation | Stale evidence cannot trigger this response |
| Selected action, dispatch withheld | A still performs the downstream operation; `LANDED`; exit 1 | Brain selection alone is insufficient |
| Authority removed after native dispatch | A receives `503 lease_unavailable`, no downstream increment; `INCOMPLETE`; exit 1 | An outage is neither defense nor proven landing |
| SIGINT during a requested 30-second hold | `INCOMPLETE`, `context canceled`, exit 1; three tracked child processes stopped and private directory removed | Interrupted trials cannot receive success credit |
| Changed response digest or raw/parsed response disagreement | Rejected by the acceptance oracle | Evidence must describe the actual response |
| Changed valid-schema replay trace | Exact replay comparison rejects it | Schema validity alone does not establish reproducibility |

Independent validation included the four Python listener/failure tests and the
Go suite with its opt-in real API/runtime integration enabled. The Go integration
also reloads the persisted input file and reruns `ReplayFile`. Saved response
bodies, retained raw response bytes, hashes, timestamps and artifact bindings
were checked independently. Production source files remained unchanged.

## Architecture metrics and remaining limits

| Architecture criterion | Disposition for this experiment |
| --- | --- |
| G1: defense effect | Passed for observed future reuse of A after native revocation |
| G2: availability | Sampled B service passed the declared local ceiling; full analytic/production availability gate remains unknown |
| G3: no-attack control | Passed for this fixed local policy and input |
| S1: attacker dwell | Baseline-to-confirmed-denial interval measured; total real-incident dwell not established |
| S2: collateral impact | B functional controls passed; broader resource/co-tenant impact not measured |
| S3: durability | Denial remained effective over the bounded hold; restart/long-duration durability not established |
| S4: predicted versus measured cost | Model cost and actual latency/time are recorded separately; a calibrated cost comparison remains unavailable |

The existing SLO registry classifies `endpoint-lease-revoke` as **unknown**:
“endpoint lease revocation and proxy readback have no calibrated safe-return
deadline.” Its zero-valued duration fields are missing bounds, not proof of
zero disruption. Local latency measurements do not change that classification.
Consequently this result does not satisfy every gate needed for a full
architecture WIN or customer deployment approval.

This environment uses Kubernetes 1.34.0 and etcd 3.6.4 with a real API server.
It has no kubelet, CNI or deployed workload containers. Pod readiness, image IDs,
owner links and endpoint membership are fixture metadata. Actual serving
processes run on loopback; an explicit transport maps the logical admin endpoint
to the verified TLS listener. Python uses an envtest client certificate rather
than a deployed service-account projection. These adaptations are recorded,
not presented as production attestations.

The experiment does not cover the console, genuine detector identity,
production RBAC, controller/projection lifecycle, model inference, GPU behavior,
multi-Pod contention, co-tenant safety or transfer to another deployment.

## Provenance and preserved evidence

The supplied Git SHA is a baseline/source label. The new harness was initially
uncommitted during verification, so that label alone cannot describe all new
code. Evidence separately hashes the actual executing binary, harness source,
decision source, Go dependencies, API-server tools and imported runtime closure.

| Evidence identity | SHA-256 |
| --- | --- |
| Executing binary used in both listed trials | `98845cf3e5d29d986d7f3190ef56392b519a40081bd1dab55498cc7b0c7d58b2` |
| Unchanged five-file serving source closure | `870c8709a5da026d01449be737939fa35420ebd1bda341ea2371c6081926fda4` |
| Independent positive `report.json` | `0b9cc505d1259d5b4d0a0f959a546352650a7ac3ed421eb9814874d05de61602` |
| Dispatch-withheld `report.json` | `76626364e6d77e6f1f56cb74582664b2aed48fdcd9a67b020b7b9965938fcf3d` |
| Authority-unavailable `report.json` | `b797ffc6a4a19050a344f1d9f5ae60cf319b21f79ac7ac7abc074b0dc11b4371` |
| Interrupted-trial `report.json` | `9a92640c798c80d82ce9ef9720bf13b937e11de1906a202ad77ed6d234ab9b43` |

Successful-episode evidence includes the complete report, raw runtime log, initial and
final enforcement policy/journal, selecting API policy, Pod fixture, fresh/stale
events, readable model inputs, canonical selection traces and serialized replay
input. Credentials are temporary and are not retained in that evidence. Earlier
failed fixture attempts are preserved separately; they are not accepted results.

One early attempt correctly declined because a bare engine used
`standard-recon`, did not score the typed lease fact, and the new Pod was inside
a five-minute cooldown. The final contract explicitly configures UCW and a
one-second local cooldown, waits actual time and applies the same policy to all
controls. This is a declared fixture correction, not a production brain fix or
proof that a five-minute production policy responds identically.

## How another team member can reproduce it

Use Linux amd64, Go 1.26.1 and a Python virtual environment containing
`httpx==0.28.1` and `uvicorn==0.34.0`. In a checkout containing this implementation:

```sh
LOOP_REPO="$(pwd -P)"
LOOP_WORK="$(mktemp -d)"
python3 -m venv "$LOOP_WORK/venv"
"$LOOP_WORK/venv/bin/python" -m pip install -r build/test-harness/fixtures/verification-loop/requirements.txt
LOOP_ASSETS="$(bash tools/provision-envtest.sh "$LOOP_WORK/envtest")"
LOOP_SOURCE="$(git rev-parse HEAD)"
(cd phorvex && go build -p 2 -o "$LOOP_WORK/verification-loop" ./cmd/verification-loop)
"$LOOP_WORK/verification-loop" \
  -repo-root "$LOOP_REPO" -python "$LOOP_WORK/venv/bin/python" \
  -assets "$LOOP_ASSETS" -git-sha "$LOOP_SOURCE" \
  -out "$LOOP_WORK/episode-1"
```

No shared kubeconfig or Docker access is required. Repeat with a new output
directory for a fresh physical episode. Add `-skip-dispatch` to require a
`LANDED` negative-control result, or `-unavailable-authority` to require an
`INCOMPLETE` outage result. Both controls deliberately exit nonzero. Existing
evidence directories are never overwritten.

The delivery implements the first behavioral spine of the proposed architecture.
Customer scanning, generated attack populations, iterative attack adaptation,
new actuator synthesis, calibrated all-affected-workload SLO bounds, learning
promotion and production verification remain separate work.
