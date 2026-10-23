# Fixture — attacker controller persistence → controller-stop (GP12)

Generic, workload-agnostic persistence loop. Ported from
`phvx-actuator-persistence-20261019`.

## Attack
An attacker plants an UNMANAGED controller (the `persistence-foothold` StatefulSet)
the operator did not create. Deleting its Pods is not enough — the controller
recreates them, so pod-level eviction/quarantine does not remove the foothold.

## Actuator it should trigger
`controller-stop`: scale the attacker's owner to 0, delete the exact children, and
observe sustained no-recreation past the handler's bounded-completion window. It
covers the control-plane-persistence fact that dominates quarantine, while a hard
controller-removal authority holds the benign availability floor (the attacker owner
declares its own guarantee of 0, so its floor does not block removal).

## Oracle (DEFENDED vs LANDED)
DEFENDED = `controller-stop` selected with a strict positive gain AND brain bounded
completion within the reviewed window (old-repo verdict
`DEFENDED_BOUNDED_COMPLETION_90S`): owner scaled to 0, exact children 404, sustained
native no-recreation, benign workload Ready throughout, owned provenance/observer
records cleaned. LANDED = children recreate, or native absence is shorter than the
confirmation window (the old-repo live re-fires V2/V3 were NOT_DEFENDED for exactly
this timing reason — absence ended before the handler deadline).

## Maturity / prerequisites (operator-refactored)
Selection- and bounded-completion-proven on the old operator harness; native
no-recreation timing was fragile under grace/kubelet retirement. Two prerequisites,
BOTH required before the brain can select the action:
1. `controller-stop` added to the action vocabulary — `model.Action` **and** the
   PhorvexPolicy CRD `actions.enabled` enum (the defense policy is in
   `defense-policy.prereq.yaml`, rejected by the apiserver until then), plus the
   native handler and the `feasibility/controller_removal.go` authority.
2. the trusted persistence observer emitting `phorvex.attack.controller-persistence`
   bound to the owner UID (`ingest/persistence_detector.go` in the source case).
Until both are wired, GP12 stays BLOCKED at plan time (its `requires` tokens are
unsatisfied) — honest by construction.
