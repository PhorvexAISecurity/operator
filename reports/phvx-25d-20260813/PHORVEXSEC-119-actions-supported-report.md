# PHORVEXSEC-119 — PHVX-25d enabled-action capability report

Date: 2026-08-13

Branch: `feat/phvx-25d-actions-supported`

Base: `origin/main` at `77e1b95` (`v0.4.11`)

## Result

The operator now reports whether the nine enabled AI/GPU actions have matching,
currently observed fleet capabilities. This is an operator-facing status signal only:
it does not reject a policy, add an admission webhook, or change optimizer/actuator
selection.

| Enabled action | Observed support requirement |
|---|---|
| `warm-swap` | a selected AI target with a Ready, model-loaded warm shadow in the same namespace and exact swap group, plus at least two schedulable GPU nodes |
| `mig-rebind` | a selected pod with a MIG device, scheduled node, GPU id, and target MIG profile |
| `kv-reset` | a Ready serving endpoint |
| `endpoint-rotate` | a selected AI pod declaring `phorvex.ai/route-service` |
| `model-shard-replace` | an independent selected shard with a matching Ready/model-loaded shadow, or a TP/PP target with valid `parallel-size` and a complete matching replacement group containing distinct Ready ranks, plus at least two schedulable GPU nodes |
| `adapter-rotate` | a selected pod labeled `phorvex.ai/lora-enabled=true` that names the adapter to rotate |
| `request-drain` | a matching Service whose selector includes `phorvex.ai/serving` |
| `guardrail-rotate` | a selected `guardrail-tier=true` pod with at least two distinct declared guardrail variants |
| `kv-migrate-invalidate` | a Ready serving endpoint |

Every unsupported entry names the exact enabled action and the missing capability.
Non-AI actions are intentionally outside this condition.

## Condition and event behavior

- `ActionsSupported=True / AllEnabledActionsSupported` when all enabled AI actions match.
- A new or changed mismatch is debounced as `Unknown / Degraded` for the first two
  consecutive observations by default.
- The third consecutive identical mismatch becomes
  `False / UnsupportedActionsEnabled`.
- Recovery is immediate on the next supported observation and resets the counter.
- A policy generation change resets stale debounce state.
- A Kubernetes Warning Event is emitted when a stable unsupported failure first
  appears or changes; the same failure is not re-emitted every tick.

The debounce threshold is configurable with
`--actions-supported-debounce`; the Helm value is
`phorvex.actionsSupportedDebounce` and defaults to `3`.

## Kubernetes integration

- `kubectl get phorvexpolicies` now includes an `Actions` printer column sourced
  from the `ActionsSupported` condition message, so unsupported action names and
  their reasons are visible directly instead of only as `True`/`False`.
- Snapshot ingest projects only the minimum read-only capability data: Service
  selectors, node readiness/schedulability, serving endpoint readiness, route
  Service name, guardrail variants, TP/PP group size, and the static MIG target
  configuration already present on Pods.
- RBAC adds read-only Service access and only `create;patch` for Kubernetes Events.
- The chart and config CRD copies remain byte-identical.

## Tests added

- all nine enabled actions pass against a fully capable fleet;
- every action is named when its base AI capability is absent;
- each capability predicate is independently removed and identifies only the
  affected action or action pair;
- unrelated swap/model-shard pools cannot satisfy a selected target, and a
  tensor/pipeline-parallel replacement must match the target's group and contain
  every distinct rank required by a valid `parallel-size`;
- MIG, adapter, and guardrail support requires every static precondition consumed
  by the matching actuator on the same selected target;
- zero-valued MIG capacity and non-canonical capability label values cannot produce
  false-positive support;
- the generated CRD test pins the `Actions` printer column to the condition message
  and keeps the chart/config CRD copies byte-identical;
- debounce, recovery, and policy-generation reset behavior;
- one Warning Event for a stable failure, without per-tick duplication;
- Pod, node, and Service capability projection.

## Verification

- `go test -count=1 ./api/v1alpha1 ./internal/ingest ./internal/runner`
- `go test -race -count=1 ./internal/runner`
- `go test -count=1 -skip TestScenariosExport ./...`
- `go build ./...`
- `go vet ./...`
- `go test -count=1 ./...` in `build/test-harness`
- YAML parsing for both CRD/config manifests, values, and RBAC; byte comparison
  of the two CRD copies; static chart wiring checks
- vendored `phorvex-0.1.3.tgz` repackaged and verified with the same
  extracted-content and parsed-`Chart.yaml` comparison used by CI `chart-sync`
- `git diff --check`

The unfiltered Phorvex suite still fails only at the pre-existing
`TestScenariosExport` missing `bin/scenarios-instances.jsonl` fixture. That failure
is owned by PHORVEXSEC-123 / PR #21 and is not changed or hidden here. Helm is not
installed in this environment, so the vendored chart was repackaged directly and
verified by extracting it and running CI's source-content comparison rather than
`helm template`.

## Scope boundary

This change provides truthful observability for unsupported enabled actions. It
does not claim runtime GPU validation, probe remote actuator transports, mutate
Services, block decisions, or alter action feasibility and costs.
