# BENCH-V3 implementation evidence

## Version anchors and scope

- Base: `bb92355cf7b6c4a696f44caf52bd5fa1268e7303`.
- Proposed source: `193923cc32c52269f66cb8617940b96d9d555b1e` on `fix/benchmark-v3-capture`.
- Targeted proof: Go 1.26.10 at `/workspace/.phorvex-go/go/bin/go`.
- Selected full preflight: module Go 1.26.1, Python 3.11.17/3.12.15, Helm 3.16.4.
- Prior recorded/deployed corpus source: `0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`; this worker made no production query or rollout.

Adds UID-bound controller replica-spec observations, immutable bounded replica
history export, a default-off manager capture option, actual brain/sensor
transport coverage and optional snapshot inspection. Existing DesiredReplicas,
admission, selection, policy defaults and actuators remain unchanged.

The integrated proposal preserves upstream's --version flag, StatefulRotation
model/observer and GVK-aware cache identity. Evidence reads the owner cache only
after both existing observers; it cannot issue additional API Get/List calls.
Existing StatefulSet reads can now supply spec observations. Unobserved direct
Deployment owners remain unknown. A counting-reader regression compares the
exact upstream producer chain, and a separate GVK test prevents cross-kind aliasing.

The lead-approved delivery dependency repairs preflight's obsolete CI filename
and recognizes exact pinned Python provisioning. Every current chart check is
retained, including the newly added committed-staging reconstruction. Historical
receipts still resolve their own source authority. No checks were waived.

## RED and positive control

`evidence/integration-bb92355c/baseline-red.txt` executes the real ingest
counterexample on an isolated archive of the pinned bb92355c baseline. The
positive control verifies one observed pod, actual Deployment spec.replicas 4,
valid UID-bound rotation lineage, and existing desired count 1. The intended
assertion then fails because the new authoritative observation is absent.
Exit 1 is expected RED, not a build or fixture error. The exact script is
`evidence/integration-bb92355c/reproduce-baseline.sh`.

The same producer positive control passes at head in
`evidence/integration-bb92355c/l1.txt`. Independent lead baseline reproduction is
`evidence/lead-integrated-baseline.txt`.

## L0, L1 and L2

Current-head raw logs are in `evidence/integration-bb92355c/`:

- `l0.txt`: complete affected suites pass for ingest, slo, mathlab, runner,
  brainclient and sensorclient.
- `l1.txt`: real producer spec 4/observed 1 control, missing/stale identities and
  known zero, unchanged owner-GET map, GVK isolation, immutable policy-isolated
  exports, real censored-to-settled replacement, default-off capture, nil ledger,
  count/byte limits and unavailable endpoint status.
- `l2.txt`: actual manager -> brain -> recorder propagation, gRPC brain and
  sensor paths, old gob Inputs without the added field, frozen capture/inspection
  copies, unchanged audit decisions and exact legacy replay.
- `adapter-tests.txt`: eight regressions pass on exact Python 3.11.17, covering
  current authority, historical pinned lookup, setup/recipe hashes, version
  mismatch refusal and receipt tampering rejection.

Full preflight is running; a receipt PASS is not yet claimed. The independently
executed integrated lead tests are `evidence/lead-integrated-head.txt`. Formal P3
remains the lead's separate decision after the completed handoff.

## Superseded and initial verification results

The previous source 773f782b on base 1c23931 remains in branch
`fix/benchmark-v3-capture-before-bb92355c`. Its proofs and the exact old diff/summary
remain retained, with integration notes under `evidence/pre-bb92355c/`.

Two incomplete preflight runs were stopped via SIGINT on the lead's instruction
when upstream introduced an actual cache/observer integration conflict. Both
sessions exited 130 and cleaned up their owned child process groups before any
source changed. No completed receipt or PASS was invented. Raw logs remain in
`evidence/pre-bb92355c/preflight-initial` and `preflight-rerun`.

The first run's workflow unit tests all passed, but doctor rejected a worker
packaging mistake in the reserved manifest. The malformed notes are retained as
`evidence/run-environment.yaml`; the index was restored from the existing signed
check hashes/producers/timestamps without changing signatures or roles.
`evidence/doctor-after-manifest-repair.txt` exits 0 with historical warnings only.

Unchanged M174 scheduler timing controls failed under initial cold-build load on
each source. The original outputs are retained (`evidence/l0-initial.txt` and
`evidence/integration-bb92355c/l0-first.txt`); the complete warm same-command
reruns passed. No scheduler or timing test was modified or weakened.

## Remaining data requirements and activation

`evidence/producer-findings.md` records the source limitations. Current
EndpointSlice point observations and Pod.ReadyAt are not durable, move-attributed
endpoint-loss intervals. Exported history remains replica-readiness, with
history_complete=false, endpoint loss unavailable and admission ledger
not-authoritative. Accepted endpoint availability targets, authoritative endpoint
budget history and a faithful pre-selection candidate export remain prerequisites.
No historical completeness or complete V3 benchmark readiness is claimed.

Collection remains off until --math-lab-capture-cost-evidence is enabled on the
manager, alongside the existing brain capture allowlist/storage. Compatible
manager/brain/sensor source is needed for the full additive flow. Phoenix without
an owner reader remains unknown. Exact flags, bounds and rollout components are
in `docs/math-lab/SNAPSHOT_AND_REPLAY.md`. No operator deployment, L3/L4,
shared-cluster or soak result is claimed.
