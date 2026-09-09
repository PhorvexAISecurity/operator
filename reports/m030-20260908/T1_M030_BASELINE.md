# PHORVEXSEC-191 / M-30 baseline and implementation evidence

Date: 2026-09-08. Baseline: `ea5d5cad4990365f55e61eddb3da2c6bfc2009a1` (main, v0.4.96).
Dependency M-23 / task 183 / PR 123 is merged. Scope is removal of unused clock production, not placement-aware selection.

## Reader verdict

There are **zero readers of the nodePlacement exposure duration in a decision formula** at this baseline. `M030_BASELINE_REFERENCES.txt` records every literal/constant reference. `M030_READER_INVENTORY.txt` lists current generic exposure-map readers as well.

- `model.ExposureFingerprints` creates the node-name fingerprint consumed by the generic Clock. `runner.ablation_run` has a second, reduced producer. Both need the single nodePlacement entry removed to stop observation. Changing only LiveExposureVariables would leave observation running because Clock iterates the fingerprint map, not the registry.
- `feasibility.ExposureVarFor` never returns VarNodePlacement. Its generic lookup therefore cannot consume this clock. No mapping or veto semantics changed.
- Belief, context, coverage trace and ablation comparison read VarPodIdentity only.
- `cost.structuralComponents` includes the **name** VarNodePlacement in a fixed three-element denominator. It does not read the clock. The list and quarantine cost 1/3 are untouched. Its stale comment is corrected.
- `runner.manager` forwards the full clock map to metrics. This is observability, not feedback into a guard or score. Its only output difference is omission of the nodePlacement sample on a fresh process. Existing Prometheus historical samples are not deleted by this change.
- Historical audit aliases `cover:nodePlacement` / `retired:nodePlacement` refer to a retired fact, not this clock, and remain unchanged.
- Generic Clock remains capable of arbitrary fingerprints. The old generic unit fixture containing nodePlacement is not a live producer.

**Ticket wording reconciliation:** the ticket asks to keep the fingerprint map unchanged, but also requires stopping observation. On the post-M23 source these cannot both hold literally. We remove only the unread nodePlacement source entry (and the duplicate ablation entry), preserving all action-to-variable mappings, remaining fingerprints, and clock/reset algorithms. No guard reads the removed key, so no veto behavior changes. This is recorded explicitly for DEV review.

## Result and invariants

The vocabulary retains all **12** Var declarations. **8** are clocked and consumed, **4** are declared-only: nodePlacement, image, env, gpuBinding. All four have explicit source markers. The runtime declared-only list is extended, not deleted.

`TestM030EveryDeclaredVariableClassified` parses the actual Var declarations independently of both registries. Each must be either live and mapped from an action, or explicitly declared-only and not consumed. It rejects missing/duplicate/undeclared registry entries and overlapping classifications. The existing M23 tests check that all action mappings are clocked and emitted fingerprints match the live registry.

## Verification

- Full `go test ./...`, `go vet ./...`, pendingcheck: passed (attached logs).
- `TestM030ReplayOnlyRemovesNodePlacement`: four deterministic ticks exercise initial observation, node move, session/drain epoch updates, and UID replacement. Compare old producer (same fingerprints plus nodePlacement) with new producer. Every remaining clock matches exactly and the complete serialized decisions match byte-for-byte at every tick. `M030_REPLAY.json` includes both exposure maps and decision outputs.
- Positive control: temporarily remove image from DeclaredExposureVariables. Completeness test fails with `image neither clocked-and-consumed nor explicitly declared-only`. Mutation was restored. See `M030_POSITIVE_CONTROL.log`.
- `git diff --check`: passed. No action mapping, formula, policy, handler, CRD or chart changes.

The replay is a deterministic fixture, **not a production T0-D capture**. A production baseline replay / independent AI-engineer acceptance is still a separate verification sign-off. No deployment or release is claimed.

## Anatomy / register handoff

CLOCK now has 12 declared dimensions: 8 clocked-and-consumed and 4 declared-only. The module graph has no interaction-class change. The named canonical anatomy, master register and PHORVEX_MODULE_GRAPH.json are not present in this checkout, so this document supplies the exact update for their owner rather than editing a guessed copy.

Do not mark the external register closed with a build tag until independent review, any required production replay, merge and release establish that tag. Placement wiring proposals remain a separate Math-first ticket.
