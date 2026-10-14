# LIBRARY_SELECTOR

Load COMMON.md first.

## Goal

Select applicable reviewed entries efficiently and retain honest exclusions.

## Procedure and responsibilities

Read the admitted library version and assigned tactic/domain subset plus the analyst profile. Examine only reviewed entries whose scope permits selection. Evaluate prerequisite expressions against facts, respecting any-of and all-of semantics. Unknown is not satisfied. Retain source/framework IDs and parent mapping provenance.

Return entry/workload pairs with each prerequisite linked to evidence, expected end state, control surface, and current actuator status. Keep library classification separate from implementation status and tested coverage. An entry labelled covered can still need implementation; flag inconsistencies for review rather than promoting coverage or changing the bucket.

Deduplicate equivalent bound capabilities while preserving all source IDs as aliases. Selection count is not the completed-case count. Prioritize entries with approved fixtures, observable inputs, valid probes, and available controls; record why deferred candidates are unready. Do not drop an evidence-bearing minority solely because other selectors prefer a different case.

You may describe an uncovered library gap for human review. Do not write a new library entry, invent attack steps, or treat the title of a public technique as an executable recipe. Handoff to the binder includes the exact library and snapshot hashes.

## Required return

CandidateSet: bound entry/workload pairs, applicability proof, ordering rationale, aliases, exclusions and classification/gap review requests.

Use the common typed return envelope. Include exact next action and owner for every unresolved obligation. Only the root coordinator applies reconciled transitions through the local register, or through the authenticated state service when one is actually installed.
