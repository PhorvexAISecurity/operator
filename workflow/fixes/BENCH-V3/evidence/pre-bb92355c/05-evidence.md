# BENCH-V3 implementation evidence

## Version anchors and scope

- Base: `1c23931621d47218ded424b58e4db127344fb33b`.
- Proposed source: `773f782bdf8fc3fc068b4293d2ebad8f75328e43` on `fix/benchmark-v3-capture`.
- Targeted proof toolchain: Go 1.26.10, executable `/workspace/.phorvex-go/go/bin/go`.
- Full preflight uses the existing Go module pin 1.26.1, exact provisioned Python 3.11.17/3.12.15, and Helm 3.16.4.
- Prior recorded/deployed corpus source is `0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`; this worker made no production query or rollout.

Adds UID-bound controller replica-spec observations, immutable bounded replica
history export, a default-off manager capture option, brain/sensor transport
coverage and optional snapshot inspection. Existing DesiredReplicas, admission,
selection, policy defaults and actuators remain unchanged. The evidence reader
can only inspect existing snapshot owner-cache entries and cannot issue API
Get/List calls. Unsupported/unobserved owner paths remain explicitly unknown.

The amended delivery dependency repairs preflight's obsolete CI filename and
recognizes exact pinned Python provisioning. Every current chart check is
retained; historical receipts still resolve their own source authority. The
original failure is `evidence/preflight-adapter-failure.txt`. No checks were waived.

## RED and positive control

`evidence/baseline-red.txt` and repeat `evidence/baseline-confirmed.txt` execute the
same real ingest counterexample on an isolated archive of the pinned baseline.
Both first confirm the fixture: one observed pod, actual Deployment spec.replicas
4, valid UID-bound rotation lineage, and legacy desired count 1. The intended
assertion then fails because the additive authoritative observation is absent.
Exit 1 is the expected RED result, not a build or fixture error.

`evidence/reproduce-baseline.sh` retains the exact reproduction recipe. The same
producer positive control passes at head and is retained in `evidence/l1.txt`.
Independent lead reproduction is in `evidence/lead-baseline-red.txt`.

## L0, L1 and L2

- `evidence/l0.txt`: complete affected suites pass for ingest, slo, mathlab,
  runner, brainclient and sensorclient at the committed source.
- `evidence/l1.txt`: producer controls, exact spec4/observed1 distinction,
  missing/stale identities and known zero, unchanged actual owner-GET map,
  immutable policy-isolated exports, censored-to-settled replacement, default-off
  behavior, nil ledger, capture count/byte bounds and unavailable endpoint status.
- `evidence/l2.txt`: actual manager -> brain -> recorder propagation, gRPC brain
  and sensor paths, old gob Inputs without the added field, frozen capture and
  inspection copies, unchanged audit decisions and exact legacy replay.
- `evidence/preflight-adapter-tests-pinned.txt`: eight adapter regressions pass on
  exact Python3.11.17, including current authority, pinned legacy source lookup,
  recipe hashes, version mismatch refusal and tampered receipt rejection.

Full preflight is running; its receipt is not yet claimed PASS. It includes
workflow, all current chart checks, and module build/test/vet. Independent lead
head/integration/adapter outputs are in `evidence/lead-head-tests.txt`,
`evidence/lead-integration-tests.txt` and `evidence/lead-preflight-adapter.txt`;
formal P3 remains the lead's separate decision.

## Initial verification failures

`evidence/l0-initial.txt` retains an initial timing-sensitive failure in unchanged
`TestM174StartFasterBasePositiveControl`: 68.258ms versus its 70ms threshold while
first builds competed for the two-CPU quota. No timing test or scheduler source
was changed. The full warm affected-package rerun passes, including that control.
The initial adapter-test typo and its corrected pass are retained separately.

## Remaining data requirements and activation

`evidence/producer-findings.md` records the inspected source limitations. Current
EndpointSlice point observations and Pod.ReadyAt are not durable, move-attributed
endpoint-loss intervals. The exported source remains `replica-readiness`, with
`history_complete=false`, endpoint loss unavailable and admission ledger
not-authoritative. Accepted endpoint availability targets, authoritative endpoint
budget history and a faithful pre-selection candidate export remain prerequisites.
No historical completeness or end-to-end V3 benchmark readiness is claimed.

Collection remains off until `--math-lab-capture-cost-evidence` is enabled on the
manager, alongside the existing brain capture allowlist/storage. Compatible
manager/brain/sensor source is needed for the full additive flow. Phoenix without
an owner reader remains unknown. Exact flags, bounds and rollout components are
in `docs/math-lab/SNAPSHOT_AND_REPLAY.md`. No operator deployment is authorized by
this proposed-source record. No L3/L4, shared-cluster or soak result is claimed.
