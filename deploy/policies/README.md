# Tenant defense policies — source of record

The nine `PhorvexPolicy` objects that defend the dev cluster's tenants live here, one file
per policy (`<namespace>--<name>.yaml`). Until 2026-09-23 they existed only as hand-applied
objects on the cluster, edited live by people, console scenarios and scripts, so no file
anywhere described what was deployed. Each file was exported verbatim from the live object on
2026-09-23 (the header records its generation) and re-parses to exactly the live `spec`.

Verification fixtures (`phorvex-verify-*` namespaces) are not here: their policies are owned
by the fixture that created them.

## How a change reaches the cluster

Argo CD Application `phorvex-policies` (`deploy/argocd/apps/phorvex-policies.yaml`) tracks this
directory with **manual sync**:

1. Propose the change as a pull request against the file(s) here.
2. After review and merge, open Argo CD → `phorvex-policies` → review the diff → **Sync**
   (or sync only the changed resources).

Merging alone never mutates a live policy. The Application has **no resources finalizer**,
so removing it from `deploy/argocd/apps/` leaves every policy in place.

Live edits (the console's policy editor or approved apply-fix requests) are still possible
and show up as `OutOfSync` drift against these files. Before syncing, make sure no
intentional live edit is overwritten.

## Constraints the operator enforces at startup

- Every namespace here must be listed in `phorvex.actuatorNamespaces` in
  `deploy/helm/phorvex-stack/values-eks.yaml`, or the operator refuses to start.
- Do not enable `debugger` or `custom-inject`: the chart intentionally withholds the
  `pods/ephemeralcontainers` write permission, and the startup authorization preflight
  refuses to start the operator if any policy enables them.
- Two policies in the same namespace must use distinct `spec.tenant` values (the Phoenix
  AMTD name is `phorvex-<namespace>-<tenant>`; a duplicate collides on the AMTD rule IDs and
  stops every decision).
- A single-replica workload with `slo.minAvailableReplicas: 1` makes every action
  infeasible (`availability: ready=1-1 < minAvailable=1`); today `mongo` and `chroma` are in
  that state by their own SLO.

## Notable values at export time

| policy | minAvailableReplicas | enabled actions | objective |
| --- | --- | --- | --- |
| ci-reports, mcp | 0 | 11 (full repertoire incl. quarantine) | lambda 0.4 |
| crm | 0 | 12 (full repertoire incl. quarantine; `crm-refund-revoke` added 2026-10-05 for the CRM Live refund deny-guard) | lambda 0.4 |
| chroma, mongo | 1 | 11 | lambda 0.4 |
| nats | 2 | 11 | lambda 0.4 |
| voice | 1 | 10 (no quarantine: isolating a serving pod makes it return 503) | lambda 0.4 |
| litellm | 1 | 11 (no quarantine; `litellm-client-revoke` added 2026-09-28 for the Live gateway) | lambda 0.5 |
| vllm | 0 | 8 (no quarantine; no warm-swap or model-shard-replace, because a second model copy never loads on the single time-sliced T4) | lambda 0.5 |

None of the nine sets `spec.objective.disruptionAversion` (a persistent preference against
costly or disruptive actions, parsed by `EffectiveDisruptionAversion()` in
`phorvex/api/v1alpha1/defaults.go`, range 0–10). See
`phorvex/config/samples/fixed-disruption-aversion.yaml` for the field's shape.
