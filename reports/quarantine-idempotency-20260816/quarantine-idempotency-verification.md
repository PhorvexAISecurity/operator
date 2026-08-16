# Quarantine Idempotency and A03 Verification Report

**Date:** 2026-08-16  
**Branch:** `fix/quarantine-idempotency`

## Problem

A post-merge attack test against the three stateful NATS pods confirmed the `F03` contract—no `rotate` was selected—but exposed a separate `A03` failure:

- Phorvex emitted three quarantine SecurityEvents and recorded them as actuated.
- The deterministic deny-all NetworkPolicy already existed from an older pod.
- The current `nats-0` pod did not carry the NetworkPolicy's selector label.
- Therefore the policy selected zero pods and quarantine was not active.

The E2E ground-truth check also tested the wrong contract. It expected the pod to be owned by an `AdaptiveMovingTargetDefense`, while Phoenix implements quarantine through a deny-all NetworkPolicy and a matching pod label.

## Root cause

Phoenix placed all quarantine relabeling inside the `NetworkPolicy IsNotFound` branch. When a replacement pod reused a deterministic policy name, the existing policy caused the relabel step to be skipped. The SecurityEvent was still stored as applied before action dispatch, creating a false success signal.

## Fix

- Reapply the quarantine selector label for every quarantine event, whether the NetworkPolicy is new or already exists.
- Preserve existing non-AMTD labels under annotations as before.
- Return unexpected NetworkPolicy read/create errors instead of continuing with a false success path.
- Change A03 independent verification to require all of the real isolation conditions:
  - the pod carries the expected Phoenix NetworkPolicy label;
  - the NetworkPolicy selector matches that label;
  - both ingress and egress policy types are present;
  - both rule lists are empty, making the policy deny-all.

## Regression coverage

The Go regression test recreates the production state: a stateful replacement pod without the quarantine label and an older deny-all NetworkPolicy with the deterministic name. It proves reconciliation reuses the policy and reconnects the pod to it.

Five Python tests cover active, inactive, and unreadable quarantine ground truth, including the exact stale-policy/replacement-pod case.

## Validation

- Phoenix full test suite: passed
- Phorvex full test suite: passed
- Go vet for both modules: passed
- Phoenix manager build: passed
- Focused Go race test: passed
- Python compile and unit tests: **5/5 passed**
- Isolated AWS execution:
  - Go production-regression test: passed
  - Python ground-truth tests: **5/5 passed**
- Post-test production health:
  - Phorvex deployment: ready and available
  - Phorvex containers: ready, zero restarts
  - NATS StatefulSet: **3/3 ready**

## Production deployment verification

The first production candidate exposed two image/startup defects that CI had not caught:

- the Phoenix image used Go 1.24 although the module requires Go 1.26.1, and copied only `internal/controller` while the build also needs `internal/scheduler`;
- four extended controllers started by default even though production does not yet install their CRDs/RBAC, causing repeated cache-sync and `Forbidden` errors.

The Dockerfile now uses Go 1.26 and copies all of `internal/`. The baseline admission webhook and extended controllers are disabled by default behind explicit opt-in flags. This keeps the current production controller set compatible while preserving the new capabilities for environments that install their prerequisites.

Production image `sha256:44f911592bff11cd9cfd5cdfe634f332c25eb02f6b46fd5409d421f26bd16c94` was deployed with automatic rollback protection and verified on AWS:

- Phoenix deployment: **1/1 ready**, zero restarts;
- startup logs: extended controllers and admission webhook intentionally disabled;
- RBAC/cache-sync errors after startup: **0**;
- manual NATS attack E2E, without Telegram: **36 passed, 0 failed, 1 warning, 2 not applicable**;
- `F03`: passed — no rotate against any of the three stateful NATS pods;
- `A03`: passed — the claimed change was independently confirmed in Kubernetes;
- NATS after cleanup: **3/3 ready**, zero restarts, and the deny-all policy selects `nats-0` through the restored label.

The one warning was expected availability behavior: the new foothold signal targeted a NATS pod while the namespace had no headroom above its two-replica availability floor, so Phorvex correctly vetoed spending another move. It is not a quarantine regression.
