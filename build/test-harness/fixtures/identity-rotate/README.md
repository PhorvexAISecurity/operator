# Fixture — stolen pod-bound SA-token identity reuse (GP11)

Generic, workload-agnostic identity-reuse loop. Ported from
`phvx-actuator-identity-rotate-20261018`, which reached a **live
old-identity-invalidation PASS** on the old operator cluster (2026-10-18). This is
the one loop of the three whose defending actuator was built and proven end-to-end.

## Attack
A mounted pod-bound ServiceAccount token (`console-id-fixture`) is captured and
replayed from off-pod. AML.T0012 / ATT&CK T1078 (valid accounts).

## Actuator it should trigger
`identity-rotate`: rotate the ServiceAccount so its UID changes (so the replayed
token TokenReviews `authenticated=false`), delete any legacy token Secret, and let
the workload pick up a fresh projected token — a two-sided containment.

## Fire mechanism
The attacks service injects the trusted stolen-token SecurityEvent bound to the
fixture Pod UID; the brain observes it and decides the action. (Old-repo harness:
`phvx-actuator-identity-rotate-20261018/build/run/fire-live/remote-live.sh`.)

## Oracle (DEFENDED vs LANDED)
From the frozen acceptance contract (`verify/ACCEPTANCE-CONTRACT.md`). DEFENDED
requires all of:
1. positive control — the replayed token TokenReviews `true` and `GET pods` is 200 before the move;
2. the brain SELECTS identity-rotate (decision trace, pinned gitSHA, not capability-unsupported);
3. the actuator FIRES (dispatch emitted, handler Enact success);
4. the SAME pre-rotation token now TokenReviews `false` / `GET pods` 401 (three successive rejections past the auth-cache TTL, before token expiry);
5. two-sided — the workload re-authenticates with its fresh identity and an independent control bearer stays 200;
6. owned UID-preconditioned cleanup reaches native 404; shared ledger `{records:{}}`.
LANDED = the replayed token keeps authenticating after the window (or only a cosmetic
`identity-epoch` label changed). A changed label alone fails the effect test.

## Maturity / prerequisite (operator-refactored)
`identity-rotate` is **declared-only** here (`model.types` + the PhorvexPolicy CRD
`actions.enabled` enum) and refused for new native dispatch. The attack, fixture and
oracle are ported; a **live DEFENDED in this repo requires porting the identity-rotate
security effect** (un-gate in the generator + real credential invalidation in the
handler). The defense policy above is valid and appliable; dispatch stays a no-op
until that effect lands.
