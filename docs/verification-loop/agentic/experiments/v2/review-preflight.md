# V2 independent preflight

**Decision: READY for the frozen, supervised local pilot.** This permits collection of fresh V2 evidence; it is not an architecture or defense acceptance result. No V2 runtime episode was executed in this review.

Reviewer: `/root/agentic_reviewer`, role `independent_reviewer`; supervisor assignment `v2-pilot / credential-reuse-local / v2-review-preflight-1 / design`. The reviewed authors are `/root`, `/root/agentic_defense` and `/root/agentic_stack_v1`, all distinct from the reviewer. Source remains `f73d04cd6aac9f5945da1515e2dac76554869920`. First sampled review time was 2026-10-10T11:05:17Z; preliminary reading started before that sample. The JSON companion records completion time, exact hashes, test commands and observed results.

## Final inputs

The accepted CASE hash is `d8f00fdf3cdce1553456ed80279d8dc08b352e319174c2715621d8f6181023ed`. Case proposal attempt `v2-case-2` has JSON hash `762b23fa715627b9393caba427ade50a22afe7e4a248ef214eec53b493107524`. The reviewed protocol hash is `d767c656c6b31782b6b2d77f64458bf46b1c58125890864838ef1008b4fe07b2`; its tests hash is `b47b6dd0fbab0f14f73cffd25ec41c025c2e0205a48d6f8f7f0abce42b2460c6`.

At 11:18:47.329986Z, I checked the actual brain, fixture and five production source files against the CASE maps, checked the executable and both envtest binaries, and recomputed the ordered five-file NUL-separated source digest: `870c8709a5da026d01449be737939fa35420ebd1bda341ea2371c6081926fda4`. There was no diff in those tracked production, brain or fixture files. These expected pins came from the supervisor CASE, not from the report being evaluated.

The architecture, prompts, LangGraph handoff and new HANDOFF-SCHEMA.json agree on a supervised prototype. Schema shape alone does not establish assignment, source identity, permissions or acceptance; the actual validator must bind the assignment and immutable dependencies. Extra JSON fields remain non-authoritative. The archived draft CASE and proposal are deliberately stale.

## Findings and their disposition

- **V2-PF-001 — contract reissue and routing, CLOSED for this pilot.** The draft runtime owner was inconsistent with the verifier role and its source closure was missing. The final CASE corrects both; case-2 is bound to the new contract. The actual archived proposal is rejected. An intermediate gate rejected stale identity/contract correctly but incorrectly routed it as verifier evidence repair. The final boundary marks assignment, schema, dependency and self-review failures as contract failures owned by the orchestrator. Independently tested wrong actor, isolated stale contract, archived attempt, missing dependency and self-review all take that route. Physical malformed probe evidence still routes to the verifier.
- **V2-PF-002 — unsupported capability claims, CLOSED for this pilot.** An earlier candidate accepted persistent lifecycle, adaptive post-run reattack and a missing lifecycle while judging the same response-only report. Final independent checks reject those claims, real detector mode and a full detector chain requirement at the contract stage. Supported modes must be explicit. No confidence threshold promotes an unsupported claim.
- **V2-PF-003 — behavioral duration and evidence binding, CLOSED for this pilot.** Hold proof uses first-to-last A request starts, paired B samples and dispatch overlap, so a slow final B request cannot pad A denial coverage. The file gate cross-checks resolved recon/policy/clock/capability/typed observations, current API authority, source, journal operation and state digests, final UID and exact predicted state. Rehashed UID/source/journal tampering is rejected. Caller must run file verification before classification and provide trusted pins and actual executable/tool paths.
- **V2-PF-004 — controls and first-failure ownership, READY to measure.** Retained V1 positive, independent positive, skip-dispatch and authority-outage files pass read-only V2 compatibility checks. The two negatives receive control credit, not defense credit; outage threat remains unknown. Fresh V2 episodes must demonstrate this routing and classification. Formal SLO remains unknown. Unsupported actuator selection must remain unsupported verification, without forcing the deterministic engine to choose revoke.
- **V2-PF-005 — duplicate and interrupted operations, PARTIAL by explicit scope.** SQLite tests show one admission under concurrent duplicate IDs, terminal caching across reopened connections, rejection of changed input hashes and no restart of an ambiguous operation. This is operation-state persistence, not physical recovery or authenticated lease enforcement. The supervisor must own input construction, operation IDs, runtime lease and interrupted-side-effect reconciliation. Ambiguous mutation cannot be blindly retried.
- **V2-PF-006 — workflow scope and worker failure, EXPLICIT LIMITATION.** V1's provider-terminated worker remains a worker failure with an attributed bounded fallback, not a failed attack or a completed independent role. V2 has a provider route to the orchestrator with no blind retry. Normal role instructions are not tool permission isolation. The LangGraph scheduler, remote actor authentication, physical lease service, persistent twin and customer detector are future components; none was executed here.

## Independent validation

The final command was `python3 -m unittest discover -s build/test-harness/verification-workflow -p test_protocol.py -v`, with bytecode writes disabled. It ran from 11:15:47.515705Z to 11:15:47.677676Z, exited 0 and passed all six methods with no skips, including the four real retained reports and adverse cases.

Two preceding suites also passed, but independent probes found the lifecycle claim and contract-routing defects afterward. Their command results and observed failures are preserved in the JSON. Those passes do not certify the superseded candidates. The final separate checks reproduce the corrected boundaries using the actual current and archived handoffs. Historical files establish compatibility only; they are not fresh V2 measurements. No claim of perfect workflow coverage follows from six test methods.

## Next owner and action

The orchestrator should freeze the exact reviewed docs, schema, CASE, case-2, protocol and tests, then assign the verifier fresh positive and configured negative episodes with exclusive runtime ownership. Construct execution inputs and their durable hash from trusted frozen values; verify source/tools before running, bind raw files before classification, and retain exit, time and cleanup evidence. Independent physical reproduction requires a new reviewer episode after explicit lease transfer. Only those measured results can support local prototype acceptance or the next revision.

The JSON companion pins 100 reviewed input/artifact files and records external envtest tool hashes. Only this review pair was authored by the reviewer.

