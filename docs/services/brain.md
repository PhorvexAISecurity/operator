# Brain service

The brain chooses defensive actions. It owns the decision engine (`decision`,
`actionset`, `recon`, `cost`, `killchain`) and its learning state, and records
Math Lab snapshots (`mathlab`). The SLO predicate it selects under (`feasibility`)
and the M99 outcome assessment (`model.AssessOutcomes`) are shared: the
dispatcher re-applies both at its gate and emit boundary. It holds no Kubernetes credentials.
See [ADR-0001](../architecture/ADR-0001-service-monorepo.md) for the service split.

The manager runs the brain in one of two ways, behind one contract
(`phorvex/internal/brainapi`):

| Mode | Manager flag | Implementation |
|---|---|---|
| In process (default) | none | `brainsvc.Local` wraps the engine in the manager |
| Remote | `--brain-endpoint=<host:port>` | `brainclient.Client` calls `phorvex-brain` over gRPC; `brainsvc.Server` serves the same `brainsvc.Local` |

Decisions are identical in both modes. `internal/brainclient/parity_test.go`
drives the same ticks through both and requires equal decisions, gate questions,
event-evidence stamps, learning state and Math Lab recordings.

## Running

```sh
go -C phorvex run ./cmd/brain \
  --listen=:9090 --engine=p1 --gpu-envelope-max=1 --flow-residual-classes=vllm
```

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `:9090` | gRPC address |
| `--metrics-bind-address` | `:8080` | Prometheus metrics (decision and Math Lab metrics are recorded here in remote mode) |
| `--health-probe-bind-address` | `:8081` | `/healthz`, `/readyz`; the gRPC health service is also served |
| `--engine`, `--gpu-envelope-max`, `--flow-residual-classes` | as the manager | must match the manager, or the handshake refuses it |
| `--math-lab-capture-policies`, `--math-lab-capture-dir`, ... | off | Math Lab capture; in remote mode configure it here, not on the manager |
| `--shutdown-grace` | `20s` | time in-flight evaluations get on SIGTERM |
| `--log-level`, `--log-format` | `info`, `json` | structured logs (`libs/logging`) |

Run exactly one replica: the cost learner, kill-chain stage clocks and retired
owners live in memory. A restart starts learning over, as a manager restart does
in process. The manager re-registers live owners and the persistence authority
every tick, so a restarted brain is usable from the next tick on.

Manager flags for remote mode: `--brain-endpoint`, `--brain-connect-timeout`
(startup waits this long for the handshake, default 2m), `--brain-call-timeout`
(5s) and `--brain-decide-timeout` (1m).

## Contract

`phorvex/api/proto/phorvex/brain/v1/brain.proto` defines `BrainService`.
Regenerate with `tools/generate-proto.sh`; CI fails when the generated code in
`phorvex/internal/brainpb` is stale. Domain values cross the wire as CBOR
encodings of the shared `model` types (`wire.Encode`/`Decode`, shared with the
sensor service): CBOR carries NaN and infinities and keeps empty and nil
collections apart, so decisions audit the same on both sides.
`brainpb/codec_test.go` runs `wire.Problems` over every brain wire type and
fails on any field CBOR would drop.

**Handshake.** `Hello` carries the contract version (`brainapi.ContractVersion`)
and the SHA-256 of the decision configuration (`brainapi.DecisionConfig`: engine,
recon profile, GPU envelope, flow-residual classes, parameter manifest). The
brain refuses a client that differs in either. Both binaries derive the
configuration with `phorvex/cmd/internal/decisionconfig`.

**Decide stream.** One evaluation is one bidirectional stream:

1. The manager sends `start`: the views, the policy, which gates it can answer,
   and the Math Lab capture marker.
2. While the engine generates candidates it asks a `CapabilityQuestion` or a
   `FailureQuestion` for each surviving (asset, action), in generation order. The
   manager answers each from its own gate (capability witness, RBAC review,
   actuator support probe, failure cooldowns) before the engine continues, so the
   probes and their order are those of the single binary. A question names its
   view by index and carries the event-evidence stamp the engine may already have
   written.
3. The brain ends the stream with `result`: the decisions, the event-evidence
   stamps of a committing evaluation (the manager applies them to its views), the
   Math Lab recording id and any evaluation error.

**Audit provenance.** `ParameterSet` returns the decision parameter set a policy
is decided with, which the audit retains once per content hash, and
`RejectedDecisions` builds the M99 records of a tick whose action set the brain
rejected. Both come from the brain, so with a remote brain the audit names the
parameters of the build that decided. They were added in contract version 2.

**Errors keep their identity.** `ErrOwnerRetired`, `ErrShadowCapabilityUnavailable`
and `model.CrossBlockCollision` return to the manager as the same values with the
same messages, so the runner's rejection reasons and audit rows do not change.

## Failure semantics

- A transport failure or timeout during `Decide` rejects the tick: nothing is
  actuated and the rejection is audited (`decision-contract-error`).
- If the stream breaks mid-evaluation, the brain answers every remaining gate
  question closed (excluded, `brain-gate-unavailable`); the manager never sees
  those decisions.
- An owner removal the brain did not acknowledge is replayed before the next
  evaluation, and evaluations fail closed until it is.
- `ParameterSet` and `RejectedDecisions` fail like an invalid policy: the tick
  retains no parameter set or records no M99 rows, and the manager logs why.
- Calls whose contract has no error (calibration, owner epochs, stage clocks,
  rotation feedback) log the failure; each is repeated by the next tick.
  `SelectAlternative` fails to "no alternative".
- The Math Lab recording is closed asynchronously; a failed close drops the
  snapshot, as a full snapshot queue does in process.
- Observed-outcome authorization stays with the manager: it resolves the
  authority's answer for each observation and the brain replays it for exactly
  that observation.

## Testing

```sh
go -C phorvex test -race ./internal/brainpb ./internal/brainsvc ./internal/brainclient ./cmd/brain
```
