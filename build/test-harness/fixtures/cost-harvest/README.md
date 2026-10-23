# Fixture — serving cost-harvest load abuse → throttle (GP13)

Generic, workload-agnostic cost/compute-harvesting loop. Ported from
`phvx-actuator-costharvest-20261019`.

## Attack
Authorized-but-abusive load harvests serving compute through the admission proxy.
The real harness drives two reference clients (abusive + legitimate) so the brain
must separate hostile load from benign traffic.

## Actuator it should trigger
`throttle` (+ cap): apply a rate/cost cap while the abusive load is active and
release it once traffic goes quiet, keeping the legitimate client served.

## Oracle (DEFENDED vs LANDED)
DEFENDED = the brain selects and actuates `throttle` with a strict positive gain,
the cap is applied while active (`effective-cap.json`: `Action: throttle`,
`capActive: true`, contract enabled) and then released on quiet traffic, and the
legitimate client stays served within budget. LANDED = no cap applied, or a proxy
429/500 without an actual applied-then-released cap, or the legitimate client is
starved. (Old-repo harness: `attack-runner/run/cost-harvest/throttle-live.py`,
which provisions the target + `cost-defense` policy, calibrates/arms the serving-rate
budget, floods through the proxy, captures the cap, then CAS-restores the budget.)

## Maturity / prerequisites (operator-refactored)
Cap apply/release proven on the old operator harness. Two prerequisites, BOTH
required before the brain can select the action:
1. `throttle` added to the action vocabulary — `model.Action` **and** the
   PhorvexPolicy CRD `actions.enabled` enum (the defense policy is in
   `defense-policy.prereq.yaml`, rejected by the apiserver until then), plus the
   native throttle handler (`actuator/throttle.go` + `throttle_admin.go` in the source).
2. the trusted cost-load observer — the serving-rate budget (`servingbudget/*`,
   `ingest/servingratebudget.go`) wired as a trusted detector.
Until both are wired, GP13 stays BLOCKED at plan time (its `requires` tokens are
unsatisfied) — honest by construction.
