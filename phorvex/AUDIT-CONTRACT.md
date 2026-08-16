# Phorvex audit contract

The decision JSONL stream is a public, versioned contract. Fact-kind tokens inside
`attribution[].source` and decision field names require a schema bump whenever their
wire meaning changes.

## Current schema

`phorvex.audit.v2` is the only schema written by this release.

- `coverageValue` is the P1 recon-fact value at stake.
- `threatRisk` is the deprecated P0 engine's distinct threat-weighted value and is
  omitted under P1. The two meanings no longer share `risk`.
- `pHold` is authoritative. `belief` is not emitted.
- `threatPosture` and `residual` are observational under the default P1 coverage
  engine: they are recorded for diagnosis but do not affect P1 selection.

## v1 to v2 migration map

| Category | Old token | Canonical v2 token | Disposition |
|---|---|---|---|
| fact kind | `modelFingerprint` | `modelIdentity` | renamed; model identity/version learned by the attacker |
| fact kind | `session` | `session` | same token, narrowed to ephemeral in-process KV/agent-session state; it does not mean identity, route, or generic compromise |
| fact kind | `nodePlacement` | `retired:nodePlacement` | retired; the historical contribution is preserved but is not current cover |
| decision field | `risk` | `coverageValue` | P1 only; old P0 `risk` becomes `threatRisk` so its meaning is preserved |
| decision field | `belief` | `pHold` | consolidated; an explicitly present old `pHold` wins if both exist |
| decision field | `threatPosture` | `threatPosture` | retained and labelled observational under P1 |
| decision field | `residual` | `residual` | retained and labelled observational under P1 |

### GPU hold

`sideChannel` is deliberately excluded from the migration map. The coversets
documents still do not publish one authoritative GPU taxonomy in this repository:
one proposal merges it into GPU co-residency while PHVX-26a renames it to
`gpuContentionChannel`. Until the required authoritative cross-link is published,
the read shim preserves `cover:sideChannel` byte-for-byte and publishes no GPU
rename.

## Translation direction and lifetime

Compatibility is **old to new on read**:

1. Records without `schemaVersion` are classified as `phorvex.audit.v0`.
2. `v0` and `v1` are decoded and translated into the canonical v2 in-memory shape.
3. Re-serialization always writes v2. There is no new-to-old writer.
4. Unknown/future versions fail instead of being guessed.

The v0/v1 read shim expires when `phorvex.audit.v4` becomes current. At that
version it must be removed or renewed by an explicit contract decision and tests;
it cannot silently become permanent.

## Translation examples

```text
risk=4.25, engine=p1-coverage  -> coverageValue=4.25
risk=0.80, engine=p0-greedy    -> threatRisk=0.80
belief=0.20, pHold=0.75        -> pHold=0.75
cover:modelFingerprint         -> cover:modelIdentity
cover:nodePlacement            -> retired:nodePlacement
cover:sideChannel              -> cover:sideChannel  (held, not mapped)
```

Translation tests assert the output tokens and values, including the retired kind;
merely accepting or silently dropping an old field is not sufficient.
