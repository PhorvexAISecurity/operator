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
M-9) is evidence about ONE build, target and configuration. Current pure Phoenix
refuses bounded rotate because its Delete strategy cannot carry the policy cap;
select `native` or `hybrid` for bounded rotate. Historical evidence is not a standing
guarantee for any other deployment and is deliberately absent from this table.
`identity-rotate` is retained as stored policy vocabulary and for cleanup of historical
epoch-label snapshots. It is declared-only for new dispatch: it cannot rotate UID, IP
or ServiceAccount credentials. `route-rotate` is a real Service-selector restitch;
the per-target capability gate requires its declared Service to select the target
route-key with the target Ready and at least two Ready backends.

## phoenix

| Action | Route | Adapter acceptance | Reason / qualification | Prerequisite | Unverified |
|---|---|---|---|---|---|
| `noop` | phoenix | no | backend-unsupported: phoenix cannot enact "noop" (control sentinel, not an emitted move) | — | — |
| `disable` | phoenix | no | backend-unsupported: phoenix cannot enact "disable" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "rotate" (Phoenix Delete cannot enforce the selecting policy maxGracePeriodSeconds contract) | — | — |
| `quarantine` | phoenix | yes | unverified: phoenix-amtd-repertoire — P-08 | — | Phoenix receives the SecurityEvent; execution and security effect are not verified here |
| `debugger` | phoenix | no | backend-unsupported: phoenix cannot enact "debugger" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `custom-inject` | phoenix | no | backend-unsupported: phoenix cannot enact "custom-inject" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `identity-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "identity-rotate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `route-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "route-rotate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `warm-swap` | phoenix | no | backend-unsupported: phoenix cannot enact "warm-swap" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `mig-rebind` | phoenix | no | backend-unsupported: phoenix cannot enact "mig-rebind" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `kv-reset` | phoenix | no | backend-unsupported: phoenix cannot enact "kv-reset" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `endpoint-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "endpoint-rotate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `model-shard-replace` | phoenix | no | backend-unsupported: phoenix cannot enact "model-shard-replace" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `adapter-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "adapter-rotate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `request-drain` | phoenix | no | backend-unsupported: phoenix cannot enact "request-drain" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `guardrail-rotate` | phoenix | no | backend-unsupported: phoenix cannot enact "guardrail-rotate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `kv-migrate-invalidate` | phoenix | no | backend-unsupported: phoenix cannot enact "kv-migrate-invalidate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `sensitive-output-policy-activate` | phoenix | no | backend-unsupported: phoenix cannot enact "sensitive-output-policy-activate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `voice-memory-note-revoke` | phoenix | no | backend-unsupported: phoenix cannot enact "voice-memory-note-revoke" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `litellm-client-revoke` | phoenix | no | backend-unsupported: phoenix cannot enact "litellm-client-revoke" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `voice-refund-pair-deny` | phoenix | no | backend-unsupported: phoenix cannot enact "voice-refund-pair-deny" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `voice-output-policy-activate` | phoenix | no | backend-unsupported: phoenix cannot enact "voice-output-policy-activate" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |
| `voice-mcp-tool-pin` | phoenix | no | backend-unsupported: phoenix cannot enact "voice-mcp-tool-pin" (no accepted Phoenix controlled route; this backend enacts only quarantine) | — | — |

## native

| Action | Route | Adapter acceptance | Reason / qualification | Prerequisite | Unverified |
|---|---|---|---|---|---|
| `noop` | native | no | backend-unsupported: native cannot enact "noop" (control sentinel, not an emitted move) | — | — |
| `disable` | native | no | backend-unsupported: native cannot enact "disable" (declared-not-implemented capability) | — | — |
| `rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `quarantine` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `debugger` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `custom-inject` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `identity-rotate` | native | no | backend-unsupported: native cannot enact "identity-rotate" (declared-only: identity-epoch relabel cannot rotate UID, IP or ServiceAccount credentials) | — | — |
| `route-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `warm-swap` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `mig-rebind` | native | yes | — | transport-unwired is reported unless the node-exec transport is wired (M-79) | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-reset` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `endpoint-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `model-shard-replace` | native | yes | — | parallel-group-unavailable: distributed readiness, atomic activation and replenishment are unverified for every target declaring phorvex.ai/parallel-group | registered handler supports only controller-owned scalar replacement; full TP/PP group replacement remains unavailable |
| `adapter-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `request-drain` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `guardrail-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-migrate-invalidate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `sensitive-output-policy-activate` | native | yes | — | exact live Pod, preinstalled rule ConfigMap and operation journal | support does not verify the authenticated event, CAS activation, mounted projection or proxy effect; dispatch and recovery check these |
| `voice-memory-note-revoke` | native | yes | — | exact live Voice Deployment, owned policy ConfigMap, private readback Secret and operation journal | support does not verify the observed note, CAS append or per-Pod application effect; dispatch checks these |
| `litellm-client-revoke` | native | yes | — | reviewed LiteLLM gateway on two Ready Service Pods, one owned-client observation, policy ConfigMap and protected journal | support does not revoke LiteLLM's master key or undo prior queries; dispatch checks CAS and both gateway readbacks |
| `voice-refund-pair-deny` | native | yes | — | exact live Voice Deployment, owned refund ConfigMap, private readback Secret and operation journal | support does not verify the observed refund pair, CAS append or per-Pod application effect; dispatch checks these |
| `voice-output-policy-activate` | native | yes | — | exact Voice Deployment, owned output rule, authenticated all-Pod readback and fixed protected journal | support does not verify the observed raw output, CAS append, per-Pod projection, or post-action speech suppression |
| `voice-mcp-tool-pin` | native | yes | — | reviewed MCP image, exact Voice and MCP sources, owned descriptor ConfigMap, private readback and protected journal | support does not verify the observed model steering, CAS append or later tool behavior; dispatch checks installed sources and per-Pod projection |

## hybrid

| Action | Route | Adapter acceptance | Reason / qualification | Prerequisite | Unverified |
|---|---|---|---|---|---|
| `noop` | native | no | backend-unsupported: native cannot enact "noop" (control sentinel, not an emitted move) | — | — |
| `disable` | native | no | backend-unsupported: native cannot enact "disable" (declared-not-implemented capability) | — | — |
| `rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `quarantine` | phoenix | yes | unverified: phoenix-amtd-repertoire — P-08 | — | Phoenix receives the SecurityEvent; execution and security effect are not verified here |
| `debugger` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `custom-inject` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `identity-rotate` | native | no | backend-unsupported: native cannot enact "identity-rotate" (declared-only: identity-epoch relabel cannot rotate UID, IP or ServiceAccount credentials) | — | — |
| `route-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `warm-swap` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `mig-rebind` | native | yes | — | transport-unwired is reported unless the node-exec transport is wired (M-79) | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-reset` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `endpoint-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `model-shard-replace` | native | yes | — | parallel-group-unavailable: distributed readiness, atomic activation and replenishment are unverified for every target declaring phorvex.ai/parallel-group | registered handler supports only controller-owned scalar replacement; full TP/PP group replacement remains unavailable |
| `adapter-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `request-drain` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `guardrail-rotate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `kv-migrate-invalidate` | native | yes | — | — | handler is registered; per-target fixtures, emission and effect are verified elsewhere |
| `sensitive-output-policy-activate` | native | yes | — | exact live Pod, preinstalled rule ConfigMap and operation journal | support does not verify the authenticated event, CAS activation, mounted projection or proxy effect; dispatch and recovery check these |
| `voice-memory-note-revoke` | native | yes | — | exact live Voice Deployment, owned policy ConfigMap, private readback Secret and operation journal | support does not verify the observed note, CAS append or per-Pod application effect; dispatch checks these |
| `litellm-client-revoke` | native | yes | — | reviewed LiteLLM gateway on two Ready Service Pods, one owned-client observation, policy ConfigMap and protected journal | support does not revoke LiteLLM's master key or undo prior queries; dispatch checks CAS and both gateway readbacks |
| `voice-refund-pair-deny` | native | yes | — | exact live Voice Deployment, owned refund ConfigMap, private readback Secret and operation journal | support does not verify the observed refund pair, CAS append or per-Pod application effect; dispatch checks these |
| `voice-output-policy-activate` | native | yes | — | exact Voice Deployment, owned output rule, authenticated all-Pod readback and fixed protected journal | support does not verify the observed raw output, CAS append, per-Pod projection, or post-action speech suppression |
| `voice-mcp-tool-pin` | native | yes | — | reviewed MCP image, exact Voice and MCP sources, owned descriptor ConfigMap, private readback and protected journal | support does not verify the observed model steering, CAS append or later tool behavior; dispatch checks installed sources and per-Pod projection |
