# M100 reporting representation

Audit decisions may contain an additive `representation` object. It describes the scoped assertion, available evidence and reporting limits; it does not change optimization or action selection. Existing score fields and the legacy `claim` wire contract retain their meanings.

The current runner captures source inputs before actuation and appends reporting afterward. Its trace is not a complete denominator inventory. Fact-to-protected-assertion semantics, complete final-weight/cover snapshots, applicable detector capabilities and a qualifying event-to-loss mapping are not bound at this source boundary. Raw M99 protected-outcome assertions appear as unresolved entries. Expect `coverageShare.share.present=false`, a null value, and explicit limitations. No count-based percentage is substituted.

`unknown` is the safe state. A positive `at-risk` classification requires an observation and declared reversible-condition semantics. `already-lost` requires retained admissible evidence of a completed irreversible loss for the specific tenant/asset/version/property. Unsupported actions, high scores, raw outcome labels and successful dispatch do not establish a loss or confirmed defensive effect. Out-of-band scope remains unmeasured.

Loss count means recorded scoped losses, not actual total loss or loss magnitude. The current loss mapping and live history source are unavailable. The audit schema can retain supplied histories and replay them independently of current configuration, but this change does not provide an authenticated durable loss-ledger loader or correction-ingestion service. Empty current mappings do not erase supplied admissible old witnesses.

Snapshots are detached, canonical and credential-redacted. Credential-bearing weight-map keys are dropped with an unavailable-binding marker rather than merged or converted to zero. Historic records without representation remain absent on disk; read projections are unknown and never borrow today's metadata.

The owner API exposes only allowlisted status/scope summaries, with no engine weights, fact keys or raw evidence. `representationPresent` says a report exists, not that a coverage fraction is measurable. Dispatch remains unconfirmed. The existing legacy `AttackPrevented`/`SLOKept` behavior belongs to the independent PR139/M14 correction; this representation does not endorse those fields as measured effects.

For the full contract, source binding, T01–T16 test matrix, synthetic examples, and open review/deployment boundaries, see [the M100 conformance submission](../../reports/m100-representation-209/CONFORMANCE_REPORT.md). No deployment or mathematical approval is implied by these documents.
