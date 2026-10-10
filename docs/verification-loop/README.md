# One-case verification loop

This command tests a stolen inference credential against Phorvex's existing
`endpoint-lease-revoke` response. It runs the unchanged decision engine and native
actuator against a private Kubernetes API server, then checks actual HTTP
authorization and downstream operations before and after the response.

The target's caller-admission implementation is the shipped Python runtime.
Its downstream application is explicitly synthetic. No GPU, deployed vLLM
model, shared cluster, console or autonomous detector is involved. The attack
observation is explicitly `TEST_INJECTED`. Fixture-provided publisher identity
and trust settings are inputs to the experiment, rather than proof that a
production detector or console authenticated the event.

The driver supplies an explicit `model.Policy` to the engine and records it for
replay. It also creates an API policy for scope and authority checks. This
experiment does not exercise the manager's complete policy-resolution path;
the two policy representations must not be confused. The configured recon
profile is `ucw-recon`; the local anti-over-rotation window is one second, and
the driver waits for actual identity age to clear it.

The [case contract](ONE-CASE-PLAN.md) defines the required evidence and claim
boundaries. A result of `LOCAL_RUNTIME_DEFENDED` means the stolen credential
stopped working in this experiment while sampled legitimate requests continued
to work. It does not reverse an earlier disclosure or certify production
availability. The actuator's formal SLO bound remains `unknown`.

## Reproduce the experiment

Use a Linux amd64 checkout, Go 1.26.1, Python with virtual-environment support,
and enough resources for a private API server and etcd. Docker and an existing
Kubernetes cluster are unnecessary. Run from the operator repository root:

```sh
LOOP_REPO="$(pwd -P)"
LOOP_WORK="$(mktemp -d)"
python3 -m venv "$LOOP_WORK/venv"
"$LOOP_WORK/venv/bin/python" -m pip install -r build/test-harness/fixtures/verification-loop/requirements.txt
LOOP_ASSETS="$(bash tools/provision-envtest.sh "$LOOP_WORK/envtest")"
LOOP_SOURCE="$(git rev-parse HEAD)"
(cd phorvex && go build -p 2 -o "$LOOP_WORK/verification-loop" ./cmd/verification-loop)
"$LOOP_WORK/verification-loop" \
  -repo-root "$LOOP_REPO" \
  -python "$LOOP_WORK/venv/bin/python" \
  -assets "$LOOP_ASSETS" \
  -git-sha "$LOOP_SOURCE" \
  -out "$LOOP_WORK/episode-1"
```

The provisioning script downloads and verifies the repository-pinned Kubernetes
1.34.0 envtest archive. The command starts its own private API server; it never
uses your kubeconfig. API-generated UIDs and resource versions are real. Pod
readiness, image IDs, owner links and endpoint membership are declared fixture
metadata, since this environment has no kubelet or application containers.

`-git-sha` records the supplied source label. Preserve the checkout and source
hashes along with the output; a supplied label alone cannot attest to the
contents of a modified checkout. Each output directory must be new or empty.
Existing evidence is never overwritten. Temporary credentials and processes
are cleaned up at the end, including failed runs.

The default hold window is two seconds, sampled at 250 ms intervals. The local
legitimate-request latency ceiling is two seconds. These are experimental
budgets, not customer requirements or calibrated production guarantees. Use
`-hold`, `-hold-interval`, `-max-legitimate-latency` and `-timeout` to declare a
different bounded experiment.

## Controls and repeatability

Each episode includes successful attacker and legitimate baselines, a clean
no-attack decision control, refusal of stale observations, normal shadow-brain
selection, native dispatch, protected operation-journal readback, behavioral
denial, legitimate-service probes and exact-input decision replay.

Repeat the command with `-out "$LOOP_WORK/episode-2"` to repeat the physical
experiment. Compare the behavior and verdict. A fresh API server generates new
identities; this is a separate physical episode, not byte-identical input replay.
Within an episode, exact replay retains the recorded identities, frozen decision
clock, owner state and capability observations and reruns a fresh decision
engine. Recorded capabilities do not claim a second physical authority check.

The negative control deliberately withholds dispatch:

```sh
"$LOOP_WORK/verification-loop" \
  -repo-root "$LOOP_REPO" \
  -python "$LOOP_WORK/venv/bin/python" \
  -assets "$LOOP_ASSETS" \
  -git-sha "$LOOP_SOURCE" \
  -skip-dispatch \
  -out "$LOOP_WORK/no-dispatch"
```

That command must report `LANDED` and exit nonzero: a decision alone did not
revoke the credential. A timeout, authority outage or `503` response must never
receive defense credit. Repeat with `-unavailable-authority` in place of
`-skip-dispatch` and a new output directory to exercise an actual API authority
outage after native dispatch. It must report `INCOMPLETE` and exit nonzero;
its `503 lease_unavailable` is neither a defended attack nor a successful landing.

Focused tests also check denial-versus-outage semantics,
TLS/private-route isolation and rejection of malformed evidence:

```sh
"$LOOP_WORK/venv/bin/python" -m unittest discover \
  -s build/test-harness/fixtures/verification-loop -p 'test_*.py' -v
(cd phorvex && go test -p 2 ./internal/verificationloop ./cmd/verification-loop)
```

The Go suite's real API/runtime test is opt-in. Enable it explicitly to run the
private integration and replay the persisted input file:

```sh
(cd phorvex && \
  VERIFICATION_LOOP_INTEGRATION=1 \
  VERIFICATION_LOOP_PYTHON="$LOOP_WORK/venv/bin/python" \
  KUBEBUILDER_ASSETS="$LOOP_ASSETS" \
  go test -p 2 -count=1 ./internal/verificationloop ./cmd/verification-loop)
```

## Read the result

Start with `report.json`: inspect the scope, verdict, error, stage results,
complete probe bodies and hashes, decision traces, native response, exact replay
and formal SLO classification. Check artifact hashes before using other files.
An emitted operation or a terminal journal entry alone is insufficient; the
stolen credential must receive the specific admission denial without a
downstream operation, and the legitimate credential must continue to succeed.

`decisions` and `selection-traces.json` preserve the original pre-dispatch
shadow-brain output. Their dispatch fields remain `not-attempted` and are used
for exact decision replay. Completed enforcement is recorded separately in
`dispatch`, the protected journal, API policy readback and behavioral probes.
Do not read the shadow selection trace as an execution receipt.

The report separates real wall-clock probe measurements from the frozen brain
clock. Sampled availability and a bounded hold do not establish unobserved
behavior between probes, long-term durability, co-tenant safety or production
deployment behavior.

This is the first vertical slice of the proposed verification-loop architecture.
Customer scanning, attack generation, iterative adaptation, new actuator design,
learning proposals and production promotion remain separate work.
