# Verification levels

These are verification layers, independent of the P1/P2/P3 protocol
checkpoints used for design and diff review.

## L0 — build and focused tests

Required for every code change:

- formatting and generated-file checks;
- `go build ./...`;
- `go test ./...`;
- relevant static analysis/lint;
- focused tests for the changed packages;
- a pinned list of pre-existing failures.

Until M-159 is fixed, do not describe GitHub CI as proving Go tests ran.
Record where and with which Go toolchain they actually ran.

## L1 — invariant and property suite

Run the entire cheap invariant suite on every fix, regardless of a
reachability estimate. Examples:

- budget and feasibility laws;
- no NaN/Inf;
- determinism for equal inputs;
- dry-run/kill-switch non-emission;
- conformal bounds dominate point estimates;
- selected actions carry valid cover and capability witnesses.

Known-broken invariants are explicit expected failures keyed to issue IDs.
Closing an issue flips its invariant to enforced. Definition changes require
separate human approval and may not ride in the fix being judged.

## L2 — offline behavioral comparison

Run a recorded, multi-tick scenario battery before and after the fix.

- Class A: declared differences appear and all other compared output is
  identical.
- Class B: distributional metrics land inside both agents' pre-registered
  falsifiable bands.
- Both: no safe-to-unsafe transition and no feasibility-law violation.

If the battery cannot exercise the changed path, say `UNAVAILABLE` or
`NON-DISCRIMINATING`; do not call the layer passed.

A new baseline is published only after the verdict passes.

## L3 — scoped deployed verification

Required for live-observed defects and changes involving deployment, CRDs,
RBAC, routing, actuation, external systems, controller interaction,
cache/informer behavior, timing, metrics/status, or audit records.

Every L3 record includes:

- running image tag/digest and embedded `gitSHA`;
- rollout timestamp and observation window;
- baseline and target population;
- exact acceptance thresholds;
- positive control;
- ambient conditions;
- mutation/cleanup ledger;
- raw artifact hashes.

The default posture is read-only. Any mutation or attack requires explicit
human approval.

## L4 — soak

Required when a short run cannot establish the claim, including changes to:

- belief or event decay;
- lambda/dual state;
- learned cost/RLS;
- exposure clocks and cadence;
- long-running retries/backoff;
- churn or starvation behavior.

State the duration and minimum independent observations before the run.
Do not turn one time series into a confidence claim about a population.

## Positive-control rule

A positive control must traverse the same observation instrument as the
claim. A unit test is not a live positive control unless the live path is
provably unavailable and that coverage admission is approved in advance.

## Evidence result vocabulary

Use exactly:

- `PASS`
- `FAIL`
- `UNAVAILABLE`
- `NON_DISCRIMINATING`
- `NOT_REQUIRED` (with pre-approved rationale)
- `BLOCKED`

“Looks good,” “clean,” and “probably unchanged” are not verdicts.
