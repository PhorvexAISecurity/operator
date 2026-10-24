# dev-eks migration evidence — 2026-10-24

The migration is **held before merge/sync**. Read
[DECISION.md](../../../DECISION.md) for the tenant list, ownership finding,
capability gaps and per-policy before/after table. Read
[RETIREMENT-RUNBOOK.md](../../../RETIREMENT-RUNBOOK.md) for the separately gated
retirement and rollback procedure.

## What was observed

`baseline.json` contains selected API evidence, not deployable manifests:

- `context`, `namespaceIdentity`, `captureMetadata`: explicit cluster identity,
  request start times, success codes, response sizes/counts and raw-response hashes.
- `stability`, `policies`: three stable policy identity/generation inventories,
  followed by full policy spec/status from round 3. There are 13 policies in 12
  namespaces; the two document-store policies are distinct tenants by display name.
- `deployments`, `podImages`, `leases`: observed flags, mounts, credential
  *references*, template images, running digests and simultaneous independent leaders.
- `oldManagerRoleBindings`, `oldManagerRoles`, `oldManagerClusterRoleBindings`,
  `oldManagerClusterRoles`: exact existing grants tied to the old manager identity.
  Two additional RBAC-only namespaces are recorded separately from policy tenants.
- `apps`, `liveProjectDestinations`, `admissionDependencies`: current source/sync
  configuration, the old app's managed-resource inventory and old webhook endpoints.
- `oldServingSecurityReferences`: exact vLLM binding metadata; no credential contents.
- `observations`: source-attributed old/new tick samples, selected decision metrics,
  old maintenance-log counts and new actuator startup/version/preflight messages.
- `sourcePins`, `sourceChecks`: separate source identities and reproducible blob
  checks for ownership, election and the KV-reset behavior difference.
- `finalReadback`: all 13 policy specs, all 45 deployment specs and all 11
  Application specs remained unchanged; the temporary demo Role and RoleBinding
  retained their UIDs and permissions.

Raw API/log responses were retained outside the checkout in the task directory's
`migration-evidence-dev-eks/`. Capture metadata hashes are of each original command
stdout, before pretty-printing or reduction; they are not hashes of this reduced
baseline. No Secret API was read or copied. Reads accidentally taken in the
initial gateway default `phorvex-281-lab` context are excluded from the evidence.

The new actuator startup and manager logs both report source
`f34bc429582fc1418b680b9e159942c07aea4438`. Running pod image IDs match the staged
manager/actuator digest pins. The old image-tag source was fetched separately from
`PhorvexSecurity/operator@0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec`; this is
separate from the old Argo target `6d581657...` and from refactored main `aa1f711a...`.
The old image-tag source identifies the warm-drain behavior; it is not presented
as independently attested build provenance for every byte of the old image.

Old logs were in tab-separated development format; new logs were JSON after the
kubectl timestamp. Each was parsed accordingly. Both managers had active demo ticks
and decision counters. No simultaneous destructive mutation was provoked, and no
positive NEW defense effect is claimed. Old maintenance messages are reported
as the runtime's observations, not an independently fired probe result.

## Reproduce the read-only inventory

Always include the full context; do not change the gateway's default context:

```bash
ssh -o BatchMode=yes phorvex-gw kubectl \
  --context=arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks \
  --request-timeout=35s get phorvexpolicy -A -o json
ssh -o BatchMode=yes phorvex-gw kubectl \
  --context=arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks \
  --request-timeout=35s get deployments -A -o json
ssh -o BatchMode=yes phorvex-gw kubectl \
  --context=arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks \
  --request-timeout=35s get rolebindings -A -o json
ssh -o BatchMode=yes phorvex-gw kubectl \
  --context=arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks \
  --request-timeout=35s get leases -A -o json
ssh -o BatchMode=yes phorvex-gw kubectl \
  --context=arn:aws:eks:us-east-2:753556437180:cluster/phorvex-dev-eks \
  --request-timeout=35s get applications -n argocd -o json
```

Repeat and cross-check rather than accepting one list. Compare policy UIDs and
generations, workload/SA scope, bindings, both manager-specific logs/metrics and
actual image digests. Policy status has no stack provenance where both managers
watch it. Historical metrics or AMTDs alone do not establish a current tenant.

## Validation

Using Helm **v3.16.4**, matching the repository's PR-validation pin:

```bash
python3 -m unittest tools.test_argocd_services -v
python3 -m unittest \
  tools.test_service_charts.RBACLibraryTests.test_workload_writes_stay_with_the_actuator \
  tools.test_service_charts.ActuatorChartTests.test_the_actuator_holds_the_workload_writes \
  tools.test_service_charts.AttacksServiceTests.test_attack_namespaces_confine_what_the_attacks_service_changes \
  tools.test_service_charts.AttacksServiceTests.test_attack_namespaces_confine_policy_edits \
  tools.test_service_charts.AttacksServiceTests.test_the_attacks_service_targets_only_its_namespaces -v
git diff --check
```

The 17 ArgoCD checks cover exact inventory-derived scope (including both
verification tenants), all six chart renders within AppProject destinations,
service scope/TLS agreement, native actuator eviction/quarantine grants for every
tenant, admission isolation, and demo-only console/e2e grants. The five focused
service-chart checks cover workload-write privilege separation and attack namespace
confinement. Results are recorded in `validation.txt`.

`workflow doctor` ran once: **0 errors, 20 warnings** about archived evidence,
legacy records and stale source/deployment reconciliation. It does not certify
this migration or update the canonical deployment pin. No attack, cluster write,
merge, Argo sync, old-app disable, scale-down or RBAC cleanup was performed.
Independent review/live acceptance remains with Milad/Claude.
