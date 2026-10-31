# Corrections after complete preflight at 193923cc

The coherent failed receipt and all its raw logs are retained at
`../pre-dto-193923cc/preflight-failed/`. Its five findings are not rewritten into
passes. The original source remains commit 193923cc.

- GNU tar 1.34 encoded ordinary-file device headers differently. The official
  GNU tar 1.35 build makes the unchanged baseline chart archives byte-identical;
  `../integration-bb92355c/chart-tool-fidelity.md` records proof and hashes.
- Architecture test found shared/brain imports of dispatcher `slo` through new
  DTOs. Pure DTOs, schema, bounds and Clone now live in shared `model`; explicit
  scalar export retains all 26 ledger fields. Runtime accounting stays in `slo`.
  A real ledger JSON-equivalence regression guards every field. The initial
  correction left one unused import because a text cleanup matched `spec.slo.*`
  JSON keys; actual archtest caught it and that import was removed.
- Generated cover-map freshness failed. Its exact checked-in generator must run
  after final source edits, and its committed result must pass the freshness test.
- Two existing console tests sampled still-running records at 2/1-second
  polling deadlines. Exact idle and untouched baseline controls reproduced the
  1-second failure. A separate logging-only baseline overlay retained that
  failure and showed correct done/LANDED/completed terminal cleanup at 1.370s.
  Both tests already wait for this watcher during cleanup. Lead-approved
  00eac153 moves that existing Wait before snapshot/assertions in precisely the
  two loops; all assertions, cleanup fallback and the CI 15m deadline remain.
  See console-diagnosis.md; final coherent preflight is now PASS at 00eac153.
- CI's go-unit job uses the highest-version file build/test-harness/go.mod,
  Go 1.26.3 local mode, exact non-cluster environment, Helm 3.16.4, and seven
  module suites. Recipe 2 adapts every gating command exactly and captures the
  informational affected-services output locally using the pinned plan base.
  Historical recipe 1 retains its old module-minimum semantics only for historical
  validation; current submission cannot reuse or relabel such a receipt.

Remote go-envtest, other remote CI jobs, images and deployment remain unexecuted
here. Source review and final preflight status are recorded separately.

The completed current-source receipt is ../preflight/receipt.json: all 18 selected
checks passed in one run at 00eac153, 2026-10-31 21:05:46 UTC. Its raw logs are
not spliced from earlier failures. Workflow296 PASS; tooling441 successful with
one existing skip and nine expected failures; all seven module suites and
build/vet PASS. Final acceptance L0/L1/L2 and independent source/console controls
also pass. No remote CI, envtest cluster or deployment result is inferred.
