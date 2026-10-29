# Console catalogue adapter map

`catalogue-map.json` is the offline, fail-closed join from the repository's exact
192-ID catalogue to 13 deduplicated family adapter profiles. It is integration
metadata only: it does not deploy, select a live context, or grant launch authority.

## Authorities and meaning

The validator joins three existing sources without inventing IDs or availability:

- `tools/live-attack-runner/catalog-192.txt` fixes exact ID membership and order.
- `phorvex/internal/attackcatalog/catalog.json` fixes family, expected action,
  event type, and lane metadata.
- `tools/live-attack-runner/runner/fires.d/*.json` fixes each ID's reviewed lane
  and target specification. `phvx-attack.py:LANE_FAMILIES` proves that a reference
  family implementation symbol currently exists.

Each mapping row names the exact source spec and references the family's fixed
destination, preflight, signal/decision binding, physical oracle, cleanup, and
runtime-mode contracts. The implementation bodies stay family-level; the 192
rows contain membership and references, not copied implementations.

`supportingImplementationExists` has a narrower meaning than the family profile's
`referenceImplementation.exists`: it is true only when the current Console source
contains a concrete exact-ID launch integration wired through the central registry.
A reviewed Python lane-family implementation is useful source evidence, but it is
not silently treated as an in-process Console adapter.

Consequently, this source revision has:

- 192 exact mapped IDs in 13 exact families;
- 13 reference family implementations;
- 186 exact Console implementations marked `registrationStatus: eligible`;
- 6 `agent-action` rows marked `registrationStatus: unavailable`, each with the
  precise missing immutable-fixture packaging reason.

There is intentionally no `launchable` field. Runtime availability also depends on
server-owned configuration and preflight; the static map cannot assert it.

## Runtime modes

The artifact keeps two independent enums:

- `executionMode`: `active | dryRun` — whether effects may be applied;
- `triggerMode`: `reactive | proactive+reactive` — the policy's trigger posture.

Both are resolved by adapter preflight. A `DEFENDED` result requires active
execution, but active execution does not imply either trigger posture.

## Core registry seam

The core registry defines `console.AttackCatalogAdapterRegistry.Register` over
exact-ID `console.AttackCatalogAdapter` instances. The adapter owns `CatalogueID`,
`Availability`, fixed `Destination`, `Preflight`, bounded `Execute`, exact `Cleanup`,
`ValidateDefended`, and `DefendedReason`; shared runtime code retains authorization,
admission, persistence, evidence, cleanup gating, and verdict ownership.

The integrated registration contract is:

1. Look up one exact mapping row; never normalize or alias its ID.
2. Resolve its family profile to a concrete adapter implementation.
3. Register an exact-ID adapter only when `registrationStatus` is `eligible` and
   the concrete implementation reference still exists.
4. Keep the six agent-action rows visible but unavailable with their immutable
   packaging blocker. Metadata membership or a family reference alone must never
   create runtime availability.

A family implementation may be shared internally, but every object passed to the
registry retains the exact catalogue ID required by the registry. Static eligibility
does not bypass deployment configuration or launch-time preflight.

## Validation

From the repository root:

```text
python3 tools/console-adapter-map/validate.py
python3 -m unittest -v tools/console-adapter-map/test_validate.py
```

Regenerate after an intentional, reviewed source change with:

```text
python3 tools/console-adapter-map/validate.py --write
```

The validator pins the exact family distribution and rejects missing, duplicate, or
unknown IDs; family/source drift; incomplete stage references; missing implementation
evidence; unsupported registration; conflated modes; and any static launchable claim.

## Current blocker

The six `agent-action` rows remain unavailable because packaging has no
digest-pinned server-owned agent-sim image, immutable fixed fixture manifest, or
attacks-service fixture RBAC. The registry rejects launch for those exact IDs.
