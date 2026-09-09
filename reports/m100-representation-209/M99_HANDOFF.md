# M100 definition handoff to M99

Source: Zeinab's 2026-09-08 M100 ruling §7; implementation submission based on `345c0ade12ac5b0d6ec71fe96c70cb9bc1d9cbac`, with the source manifest binding the implementation. The exact commit and PR are in the accompanying Plane submission receipt. Team review remains pending.

An assertion is **already-lost** only when retained admissible evidence establishes a completed irreversible loss of the specified protected asset, property or version. Unsupported remediation, temporary infeasibility and absence of a covering action do not establish that state. **At-risk** identifies an established current exposure within the declared reversible model; **unknown** identifies insufficient observation or classification evidence. These classifications remain scoped: a known loss does not automatically classify every other property of the asset as lost.

The reporting enum has unknown as its zero value. M100's current runner adapter produces no positive qualifying event-to-loss witnesses. M99's raw protected-outcomes-v1 payload and `Qualified`/basis strings are insufficient to cross that boundary. A future source adapter needs reviewed payload predicates, authenticated ingestion evidence and durable history; it must not infer a loss from an unavailable cover, current trust configuration or a defender rollback flag.

M100 supplies no mandatory action, budget suppression, existential weight, objective penalty or selection constraint. Existing M99 arithmetic and behavior are unchanged. This is the definition handoff, not evidence that M99 has adopted it or that either ticket is closed.
