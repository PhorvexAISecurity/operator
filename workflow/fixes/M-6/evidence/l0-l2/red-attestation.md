# M-6 RED attestation — what is and is NOT baseline execution (truthful labeling)

The `red` check attests these artifacts. They are HEAD non-vacuity controls and BASELINE
SOURCE — NOT an executed run at the baseline SHA. Baseline BEHAVIORAL execution of the original
admission gap is the skeptic's incident/L3 gate (real producers against the real subresource),
which remains **UNAVAILABLE** — this attestation does not claim or waive it.

## Head non-vacuity mutation controls (proving each new guard is load-bearing, at HEAD 9eb1427)
- `red-demo-content.log` — the verifier's full-spec compare disabled ⇒ the 14 enforcement-drift
  cases are ACCEPTED (unsafe) ⇒ `TestEnforcementContentDriftRejected` FAILS. Restored.
- `red-demo-gate.log` — the capability gate's code-exec leg disabled ⇒ the exclusion test FAILS. Restored.
- `red-demo-handler.log` — the handler image reverted to mutable `busybox:1.36` ⇒ the paired-profile
  tests FAIL. Restored.
These are executed at HEAD with the fix temporarily removed; they are NOT baseline (5a0fd3f/79c0370) runs.

## Baseline SOURCE (not execution)
- `red-baseline-source.md` — the literal `5a0fd3f` source: the handler emitted `busybox:1.36` with no
  securityContext, the gate had no code-exec leg, and `internal/codeexec` did not exist. This shows the
  pre-M6 protection was ABSENT; it is source inspection, not a behavioral run.

## Skeptic-executed RED (prior head, real production reader)
- `evidence/p3/rev1/adversarial.log` and `evidence/p3/rev2/adversarial.log` — the skeptic executed the
  enforcement-drift, stale-scope, API-defaulting, Cluster-scope and final-I/O-race bypasses through the
  production reader/verifier at the prior heads (8da845a / d68a9ed). Those are the executed RED for the
  review findings; every case is now rejected at HEAD (see `reviewer-rev2-overlay-green.log`).

## Baseline BEHAVIORAL / original-incident RED — NOT provided here
Reproducing the original admission gap through the real producers on the real
`pods/ephemeralcontainers` subresource is the incident-evidence gate, owned by the skeptic and
currently UNAVAILABLE. This `red` attestation is explicitly NOT that proof.
