# Cluster mutation ledger — K3, 2026-09-03 (bus 282, governance)

Standing rule confirmed and followed: **reads + server dry-runs + short-lived read-only reader
pods, cleaned up in the same session; nothing else.** Production is the only cluster; the DCP
patch stays human-gated and was never touched by me.

## Writes (complete list — every object I created/modified/deleted today)

| # | Kind | Namespace/Name | When (UTC) | Why | Still exists? |
|---|------|----------------|------------|-----|---------------|
| 1 | Pod | `phorvex-system/audit-scan-k3` (reader, python:3.11-slim, PVC `phorvex-phorvex-audit` mounted **`readOnly: true`**, node-pinned to the brain node) | ~13:20–13:40 | T1-A L3: read the audit PVC post-deploy | **No** — died with node `ip-172-27-12-250` recycle at 15:17Z (node NotFound; pod garbage-collected with the node) |
| 2 | Pod | `phorvex-system/audit-scan-k3` (re-created, same spec, re-pinned to the new brain node) | ~15:45–16:20 | T0-C live baseline scan (00-facts.md) | **No** — deleted same session after the scan |
| 3 | Pod | `phorvex-system/audit-scan-k3-gitsha` (same read-only spec) | ~17:50 | Bus 280 follow-up: read gitSHA/brainImage of the 5 current selected records | **No** — deleted same session (~17:58Z); confirmed Terminating→gone |
| 4 | Pod | `phorvex/audit-scan-k3-gitsha` (first attempt) | ~17:47 | Same as #3; **failed to create** — namespace `phorvex` does not exist (server rejected, nothing persisted) | No (never existed) |
| 5 | Pod | `phorvex-system/audit-scan-k3-gitsha` (second attempt) | ~17:48 | Same as #3; pinned to a **stale node name** (`ip-172-27-12-251.ec2.internal` — wrong suffix, node never existed); stayed Pending, reaped by the node-lifecycle controller | **No** — confirmed NotFound before recreating correctly as #3 |

## Read-only operations (for completeness — nothing persisted)

- `kubectl get` on: CRDs, Deployments, Lease (`phorvex-system` leader lease), Roles,
  ClusterRoles, ClusterRoleBindings, RoleBindings, ServiceAccounts,
  ValidatingWebhookConfigurations, Pods, Nodes, Events, PVCs, PhorvexPolicy specs.
- `kubectl apply --dry-run=server` probes for M-2 (adapter-rotate policy) and M-3 (four invalid
  policies: `tickInterval 0s`, `proactiveFloor 30s`, `lambda 99999`, out-of-enum action) —
  admission exercised, **nothing persisted** (server dry-run).
- Prometheus HTTP queries (read-only).
- `kubectl exec` into the reader pods above (python reading `/audit` **read-only** mount).

## Explicit confirmations

- **No** DaemonSet/Deployment/ConfigMap/CRD/Role/ClusterRole/binding/policy object was created,
  patched, or deleted by me at any point today.
- The DCP patch remains human-gated; I have never applied it.
- All scratch pods are deleted (verified `kubectl get pods -A | grep audit-scan` → clean at
  ~17:58Z; the terminating gitsha pod completed deletion).
- No scratch namespaces were created (`NO_SCRATCH_NS` verified).
- Reader pods always mounted the audit PVC with `readOnly: true` (both the pod spec's
  volumeMount and the PVC volume reference), ran as `Never` restart policy, and were pinned to
  the brain node only because the PVC is RWO.

## Note for the record

The two 15:17Z pod deaths were not a cleanup skip: node `ip-172-27-12-250` was recycled
(NotFound) with the reader on it; the replacement reader (#2) was deleted by hand in-session.
The ledger rule going forward (until a dev cluster exists): this table is maintained per
session, reader pods are named `audit-scan-k3*`, and cleanup is verified before session end.
