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
contains a concrete exact-ID launch integration. A reviewed Python lane-family
implementation is useful source evidence, but it is not silently treated as an
in-process Console adapter.

Consequently, this source revision has:

- 192 exact mapped IDs in 13 exact families;
- 13 reference family implementations;
- 1 exact Console implementation (`AML.T0012`);
- 191 rows marked `registrationStatus: unavailable`.

There is intentionally no `launchable` field. Runtime availability also depends on
server-owned configuration and preflight; the static map cannot assert it.

## Runtime modes

The artifact keeps two independent enums:

- `executionMode`: `active | dryRun` — whether effects may be applied;
- `triggerMode`: `reactive | proactive+reactive` — the policy's trigger posture.

Both are resolved by adapter preflight. A `DEFENDED` result requires active
execution, but active execution does not imply either trigger posture.

## Core registry seam

The in-progress core registry was inspected at commit
`a2e69b3b44c6c5ac40072310bea2c2bf43b7c3a7` on
`farm/catalog-core-runtime`; this mapping does not modify or replace that interface.
That revision defines `console.AttackCatalogAdapterRegistry.Register` over exact-ID
`console.AttackCatalogAdapter` instances. The adapter owns `CatalogueID`,
`Availability`, fixed `Destination`, `Preflight`, bounded `Execute`, exact `Cleanup`,
`ValidateDefended`, and `DefendedReason`; shared runtime code retains authorization,
admission, persistence, evidence, cleanup gating, and verdict ownership.

The small integration step is therefore:

1. Look up one exact mapping row; never normalize or alias its ID.
2. Resolve its family profile to a concrete adapter implementation.
3. Register an exact-ID adapter only when `registrationStatus` is `eligible` and
   the concrete implementation reference still exists.
4. Leave all other catalogue rows visible but unavailable. Metadata membership or
   a family reference alone must never create runtime availability.

The artifact deliberately does not guess a loader, constructor, or factory API for
the core branch. A family implementation may be shared internally, but every object
passed to the registry must retain the exact catalogue ID required by the registry.

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

## Current blockers

- The current Console source proves an exact launch integration only for
  `AML.T0012`. The other 191 rows remain unavailable until concrete exact-ID Console
  adapters implement the reviewed family contracts and are added through the core
  registry seam.
- The 10 `controller-stop` catalogue rows expect the native `controller-stop`
  decision action, while the current lane reference `ControllerStopFamily` inherits
  `RotateFamily` and observes `rotate`. The repository now contains a native
  `controller-stop` model/actuator, but the old lane reference does not by itself
  prove the Console contract for those rows.
