# Report

## Claim

The real submit/gate/Approve HTTP path permits two concurrent approvers to enter the external Apply callback for the same pending request. Pending records are keyed only by caller-provided ID and can overwrite another tenant request; nil applier can still return applied. The shipped nil applier limits current cluster-write impact, but duplicate execution occurs with the supported real callback.

## Expected behavior

Describe the contract, invariant, or desired outcome.

## Observed behavior

Separate direct observation from interpretation.

## Reproduction and scope

Record inputs, frequency, affected population, first/last observation, and
whether any mutation is required.

## Initial evidence

Point to retained artifacts; do not paste large raw logs here.
