# Report

## Claim

The attack watcher mutates result fields outside the lock while HTTP readers/persistence marshal shared pointers; the real watcher/result read fixture triggers the Go race detector. Locking only writes or map lookup cannot protect references after unlock.

## Expected behavior

Describe the contract, invariant, or desired outcome.

## Observed behavior

Separate direct observation from interpretation.

## Reproduction and scope

Record inputs, frequency, affected population, first/last observation, and
whether any mutation is required.

## Initial evidence

Point to retained artifacts; do not paste large raw logs here.
