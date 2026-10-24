# Split services (ADR-0001)

`applicationset.yaml` gives every Phorvex service its own Argo CD Application in
each environment: `phorvex-manager-<env>` (the manager chart in remote mode),
`phorvex-brain-<env>`, `phorvex-sensor-<env>`, `phorvex-actuator-<env>`,
`phorvex-attacks-<env>` and `phorvex-console-<env>`. Each has its own chart, sync
status, history and logs.
- **The attacks service** renders only where the console runs. It takes the attack
  routes once the environment names it in `phorvex.services.attacks.endpoint`
  (`docs/services/attacks.md`).
- **The console** renders in its own Application where the environment sets
  `phorvex.console.separate`, and in the manager's elsewhere
  (`docs/services/console.md`).
`project.yaml` limits them to this repository, each environment's namespace and
the cluster-scoped kinds the charts render there.

The root app (`../root.yaml`) watches `../apps` of the production repository,
not this directory: these manifests are applied by hand.

## Environments

An environment names its cluster, namespace and Helm release in the
ApplicationSet's list, and keeps its values in `deploy/environments/<environment>/`
(see its README).

**The dev-eks migration proposal is held.** Read [DECISION.md](../../../DECISION.md)
and [RETIREMENT-RUNBOOK.md](../../../RETIREMENT-RUNBOOK.md) before merging or
syncing. The live services still watch only `phorvex-staging-demo`; proposed
`policyNamespaces` and `actuatorNamespaces` cover all 12 namespaces in the frozen
inventory, and `project.yaml` lists their exact destinations. The proposal does
not establish exclusive ownership or feature parity.

The old `operator.git` monolith in `phorvex-system` watches policies cluster-wide.
Its manager and the new manager hold separate namespace-local leader leases, and
both currently tick the demo policy. The old manager also has the temporary
`phvx93-rotate-eviction-proof` grant there. Neither `UniqueOwner` nor the services'
scope handshake coordinates those two managers. Do not expand this overlap or
remove the temporary grant before a verified handoff.

The proposed new stack remains in `phorvex-staging`, release `staging`, with:

- Explicit tenant policy and native-actuator RBAC scope; neither operator namespace
  is a defended tenant. Native execution creates no Phoenix SecurityEvents/AMTDs.
- Ten established application attack scopes; the two verification fixtures are
  defense-only, and existing console subjects retain demo-only tenant grants.
- Admission disabled locally and the old creator-identity guard referenced
  externally. The old admission endpoint and guard must be rehomed before retiring
  the monolith; the shared Phoenix operator must remain untouched.
- Shared CRDs skipped, release-prefixed ClusterRoles/bindings, and staging-specific
  monitoring. `tools/test_argocd_services.py` checks rendered scope, permissions,
  service handshakes, project destinations and unchanged console grants.

The child Applications track `main` with automatic sync. **Merging the migration
values would trigger deployment**; leaving a PR open does not require changing
any live sync policy. The existing AppProject was applied separately and is not
reconciled by the production root. Before migration, adopt its destinations under
a reviewed operator-refactored Argo bootstrap; do not edit tenant scope with an
ad-hoc kubectl apply. The project must permit the namespaces before the service
Applications can sync their Roles there.

`phorvex-demo-staging` (`demo-staging.yaml`) deploys `deploy/demo` into its own
namespace, `phorvex-staging-demo`:
- `demo-api`, a stateless nginx for the services to defend. Its Pods are the
  console's workload attack targets (`r6th.io/rotation-target`).
- Its PhorvexPolicy, which selects only those Pods and enables only the native
  backend's rotate and quarantine.
- Its measured load. An exporter sidecar and a PodMonitor give each Pod an
  `http_requests_total`, and `demo-load` sends about five requests a second.
  Without a measured load the brain prices every rotation at its conservative
  bound, above the policy's cost ceiling.

That namespace remains every existing console grant's tenant; the proposed service
attack scope also covers the other established application tenants. The console
is reachable at `staging-console.phorvex.ai`, through its own ALB and Cognito app
client.

End-to-End runs reach the staging console with a bearer token instead. The token
belongs to `staging-phorvex-console-e2e`, a ServiceAccount with no RBAC, and its
audience is staging's own:

```sh
kubectl -n phorvex-staging create token staging-phorvex-console-e2e \
  --audience phorvex-staging-console --duration 10m
```

The grant confines it to `phorvex-staging-demo`, like the operator's.

## Original installation and migration bootstrap

1. Argo CD reads this repository over HTTPS with the credential it uses for the
   production repository, in a repository Secret for this repository's URL. The
   enterprise disables deploy keys.
2. The original installation applied `project.yaml`, then `applicationset.yaml`
   and `demo-staging.yaml` manually. For this tenant migration, first adopt project
   scope management under the reviewed refactored Argo bootstrap. All tenant
   scope/RBAC changes must go through PR and Argo CD; the original manual install
   procedure does not authorize a migration rollout.

The services start in any order: the manager waits up to two minutes for each
handshake and restarts until every service answers. Deleting the ApplicationSet
removes the Applications and, through their finalizers, everything they created.

## Operating staging

- **A new namespace.** Commit the project destination and tenant values together.
  Under the approved migration controls, sync the GitOps-managed project before
  a service change renders into that namespace, or the services' Applications
  fail with "namespace ... is not permitted in project". The current manually
  installed project first needs the adoption described above.
- **A changed scope.** The ApplicationSet does not prune, so changing
  `policyNamespaces`, `actuatorNamespaces` or `console.attackNamespaces` leaves the
  old namespace's Roles in place, with their grants. Prune exactly those
  `Role`/`RoleBinding` objects with a selective Argo CD sync (`prune: true` and
  their `resources`).
- **The manager's first Recreate.** Enabling audit persistence switches the
  manager to `strategy: Recreate`. Under server-side apply the defaulted
  `rollingUpdate` stays unowned, and the API refuses it beside Recreate. Replace
  the strategy once, then sync:

  ```sh
  kubectl -n phorvex-staging patch deploy staging-phorvex --type json \
    -p '[{"op":"replace","path":"/spec/strategy","value":{"type":"Recreate"}}]'
  ```

## Webhook certificate

The manager chart generates its admission webhook certificate when it finds none
(`lookup`). Argo CD renders charts without cluster access, so every render brings
a new certificate. The ApplicationSet therefore ignores the certificate Secret's
data and the webhook configurations' CA bundles, and respects those ignores on
sync. Staging's webhook is off, so this matters only to an environment that enables
it.

`tools/test_argocd_services.py` checks these manifests against the charts and
environments.
