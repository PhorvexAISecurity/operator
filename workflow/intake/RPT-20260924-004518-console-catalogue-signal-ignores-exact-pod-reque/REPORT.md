# Report

## Claim

fire-scenario ignores targetPod/targetUid and selects another namespace Pod; emitted events target only namespace/name, so same-name replacement can consume a prior Pod lifetime signal. Reproduced with actual serialized event handler and real KubeSource test.

## Expected behavior

Describe the contract, invariant, or desired outcome.

## Observed behavior

Separate direct observation from interpretation.

## Reproduction and scope

Record inputs, frequency, affected population, first/last observation, and
whether any mutation is required.

## Initial evidence

Point to retained artifacts; do not paste large raw logs here.
