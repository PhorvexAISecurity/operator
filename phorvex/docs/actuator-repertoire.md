# Phorvex actuator repertoire (v1)

GENERATED — do not edit by hand. Regenerate with:

```sh
go test ./internal/actuator/ -run TestRepertoireDocumentIsCurrent -update
```

`PHORVEX_ACTUATOR` selects the backend. Accepted values: `phoenix`, `native`, `hybrid`. Unset or empty selects the default `phoenix`; every other value is rejected at startup — no trimming, no case folding, no fallback.

## What the columns mean

These are four DIFFERENT properties and the table keeps them apart on purpose:

- **Route** — the backend that actually receives the dispatch. For `hybrid` this is
  the same predicate `Actuate` routes on, never a union of both backends.
- **Adapter acceptance** — this route implements the action. It is NOT authorization,
  NOT target readiness, and NOT proof that anything executed.
- **Prerequisite** — a runtime precondition this route additionally checks before it
  reports support.
- **Unverified** — what acceptance explicitly does not establish. Confirmed effect is
  tracked separately (M-9); RBAC, CRD admission and per-target capability are
  enforced by their own layers and are not implied by any row here.

A historical live result (for example the 2026-08-21 Phoenix rotate observation under
M-9) is evidence about ONE build, target and configuration. It is not a standing
guarantee for any other deployment and is deliberately absent from this table.

## phoenix

| Action | Route | Adapter acceptance | Reason / qualification | Prerequisite | Unverified |
|---|---|---|---|---|---|
| `noop` | phoenix | no | backend-unsupported: phoenix cannot enact "noop" (control sentinel, not an emitted move) | — | — |
| `disable` | phoenix | no | backend-unsupported: phoenix cannot enact "disable" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `rotate` | phoenix | yes | unverified: phoenix-amtd-repertoire — P-08 | — | Phoenix receives the SecurityEvent; execution and security effect are not verified here |
| `quarantine` | phoenix | yes | unverified: phoenix-amtd-repertoire — P-08 | — | Phoenix receives the SecurityEvent; execution and security effect are not verified here |
| `debugger` | phoenix | no | backend-unsupported: phoenix cannot enact "debugger" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `custom-inject` | phoenix | no | backend-unsupported: phoenix cannot enact "custom-inject" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `identity-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "identity-rotate" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `route-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "route-rotate" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `warm-swap` | phoenix | no | backend-unsupported: phoenix cannot enact "warm-swap" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `mig-rebind` | phoenix | no | backend-unsupported: phoenix cannot enact "mig-rebind" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `kv-reset` | phoenix | no | backend-unsupported: phoenix cannot enact "kv-reset" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `endpoint-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "endpoint-rotate" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `model-shard-replace` | phoenix | no | backend-unsupported: phoenix cannot enact "model-shard-replace" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `adapter-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "adapter-rotate" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `request-drain` | phoenix | no | backend-unsupported: phoenix cannot enact "request-drain" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `guardrail-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "guardrail-rotate" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |
| `kv-migrate-invalidate` | phoenix | no | backend-unsupported: phoenix cannot enact "kv-migrate-invalidate" (no Phoenix AMTD rule mapping; this route enacts only rotate and quarantine) | — | — |

## native

| Action | Route | Adapter acceptance | Reason / qualification | Prerequisite | Unverified |
|---|---|---|---|---|---|
| `noop` | native | no | backend-unsupported: native cannot enact "noop" (control sentinel, not an emitted move) | — | — |
| `disable` | native | no | backend-unsupported: native cannot enact "disable" (declared-not-implemented capability) | — | — |
| `rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `quarantine` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `debugger` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `custom-inject` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `identity-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `route-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `warm-swap` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `mig-rebind` | native | yes | — | transport-unwired is reported unless the node-exec transport is wired (M-79) | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-reset` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `endpoint-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `model-shard-replace` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `adapter-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `request-drain` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `guardrail-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-migrate-invalidate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |

## hybrid

| Action | Route | Adapter acceptance | Reason / qualification | Prerequisite | Unverified |
|---|---|---|---|---|---|
| `noop` | native | no | backend-unsupported: native cannot enact "noop" (control sentinel, not an emitted move) | — | — |
| `disable` | native | no | backend-unsupported: native cannot enact "disable" (declared-not-implemented capability) | — | — |
| `rotate` | phoenix | yes | unverified: phoenix-amtd-repertoire — P-08 | — | Phoenix receives the SecurityEvent; execution and security effect are not verified here |
| `quarantine` | phoenix | yes | unverified: phoenix-amtd-repertoire — P-08 | — | Phoenix receives the SecurityEvent; execution and security effect are not verified here |
| `debugger` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `custom-inject` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `identity-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `route-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `warm-swap` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `mig-rebind` | native | yes | — | transport-unwired is reported unless the node-exec transport is wired (M-79) | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-reset` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `endpoint-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `model-shard-replace` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `adapter-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `request-drain` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `guardrail-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-migrate-invalidate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
