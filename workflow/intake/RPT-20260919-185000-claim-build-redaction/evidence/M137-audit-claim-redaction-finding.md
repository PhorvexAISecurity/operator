# M137 audit claim build-identity redaction finding

Date: 2026-09-19 UTC

Reviewed canonical full Tier23: `63318842` (the executed checkout's
`decision_trace.go` SHA-256 was
`70e83df2f00b72e00604c479cfb1212beed8dce39f48eaf9501f642998c872b1`).
Reviewed T24 guard product: `1bef9a37eddc15b7edf757873187d7d5070b71c1`.
This was a source-only follow-up. No Go command, process, cluster action, product
edit, or workflow edit was performed.

## Finding

The failed logger arm found a separate pre-existing redaction inconsistency. It
does not refute the T24 necessary-condition guards: the frozen corpus passed
through both `DecisionTraceV2.Canonical` and its JSON marshaler on the canonical
original. The failure came from a distinct top-level `ClaimScope` field that is
built from the raw image identity before nested trace marshaling.

The exact `https://user:password@...` fixture is not a valid ordinary container
image reference and therefore is not produced by the standard chart when its
repository/tag also has to start the Pod. It was too broad as an equivalence
assertion over the complete audit record. It is not wholly unreachable source
input, however, and the boundary is not limited to that URI form:

- `buildinfo.Current` accepts any trimmed `PHORVEX_BRAIN_IMAGE` string and does
  no format or credential validation (`phorvex/internal/buildinfo/buildinfo.go:23-45`).
  A custom manifest or direct binary invocation can therefore supply the URI
  fixture independently of the standard chart.
- The chart copies the free repository/tag values into both the container image
  and `PHORVEX_BRAIN_IMAGE` without a template validation predicate
  (`phorvex/charts/phorvex/templates/deployment.yaml:35-38,178-184`). A valid
  image-shaped value such as `registry.example/team/credential:s3cr3t-token`
  also matches the existing credential regexp, so the nested/claim discrepancy
  does not depend on URI user-info syntax. Whether such a tag is truly secret is
  configuration-specific; the current redactor nevertheless classifies it as
  credential-bearing.

The production path is direct:

1. Manager construction stores `buildinfo.Current().BrainImage`
   (`internal/runner/manager.go:520-527`) and copies it to each policy
   (`manager.go:1860-1864`).
2. The decision builder writes it to `DecisionTraceV2.BrainImage`
   (`internal/decision/coverage.go:1153-1159`).
3. The reporting path independently constructs the decision claim from the same
   manager value and attaches it before audit (`manager.go:2122-2132,2157-2163`).
4. `audit.ToRecord` reconstructs a claim from the raw explicit claim, or from the
   raw trace when the explicit claim is absent (`internal/audit/log.go:284-292`),
   while retaining the trace pointer separately at line 369.
5. `DecisionTraceV2.MarshalJSON` invokes `Canonical`, which redacts BrainImage
   (`internal/model/decision_trace.go:518-530,695-699`). `NewClaimScope` only
   defaults empty values and copies BrainImage/GitSHA unchanged
   (`internal/model/claim.go:18-44`). The result is one record with a redacted
   nested trace and raw top-level claim.
6. The same raw claim is also passed to the structured logger
   (`internal/audit/log.go:515-534`) and the console owner projection reconstructs
   its claim from the stored raw claim (`internal/console/owner.go:178-188`).

No source in that chain changed between canonical parent `4110ff55` and guard
product `1bef9a37`; the finding predates T24. The product's new
`TestAuditLoggerSerializesRedactedRecordWithoutMutatingProducer` currently uses
the unsupported URI fixture and asserts that `registry-password` is absent from
the entire record (`internal/audit/decision_trace_test.go:46-83`). It therefore
encounters this same pre-existing claim behavior rather than isolating guard
equivalence. That expectation must not be reported as a T24 guard regression or
silently weakened without retaining the separate counterexample.

## Evidence disposition

The original private probe and its failing canonical log remain immutable. The
corrected v2 equivalence probe explicitly requires the pre-existing raw claim
value while continuing to require frozen predecessor output for the nested
trace, every other nested credential fixture, malformed UTF-8 wire
normalization, and producer non-mutation. A separate counterexample uses both
`ToRecord` paths:

- trace fallback (`Decision.Claim == nil`); and
- the real runtime shape with an explicit `NewClaimScope` claim.

It uses `registry.example/team/credential:s3cr3t-token`, verifies that the nested
trace redacts the value, and then fails if the top-level claim retains the same
secret token. It is intentionally excluded from the equivalence overlays and is
expected RED on both canonical original and current guard product.

## Bounded recommended follow-up

Do not widen T24's signed guard optimization implicitly. Record a separate
redaction issue and decide the ClaimScope contract. For the demonstrated
production constructors, the smallest correction is to apply the existing
same-package `redactTraceString` to `image` and `sha` inside `NewClaimScope`
before returning. Every production ClaimScope constructor found in source uses
that function; this would cover the manager reporting path, `ToRecord` fallback
and explicit-claim paths, and the owner projection without exporting a new
redactor or changing trace order.

That narrow correction needs these controls:

1. actual manager/buildinfo-shaped image identity into `NewClaimScope`,
   `Logger.Record` JSONL, and a capturing structured logger;
2. explicit-claim and trace-fallback paths, with a normal image reference
   unchanged and each existing credential family redacted;
3. owner projection bytes, so a stored unsafe legacy/raw claim is not
   inadvertently re-exposed during reconstruction;
4. producer ownership and detector-set ordering unchanged; and
5. direct construction/replay documented as a residual unless the signed scope
   also adds a defensive `ClaimScope.MarshalJSON` boundary.

Sanitizing only `buildinfo.Current` would miss decoded/directly constructed
claims and trace-fallback fixtures. Adding a custom `ClaimScope.MarshalJSON`
would defend those paths but changes the general wire boundary and needs an
explicit compatibility decision. Neither option belongs in the current T24
product without a signed extension. The current evidence establishes source
reachability and an inconsistent redaction boundary; it does not establish that
a deployed standard-chart image presently contains an actual credential.
