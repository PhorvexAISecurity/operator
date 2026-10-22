# Split services (ADR-0001)

`applicationset.yaml` gives every Phorvex service its own Argo CD Application in
each environment: `phorvex-manager-<env>` (the manager and console chart in
remote mode), `phorvex-brain-<env>`, `phorvex-sensor-<env>`,
`phorvex-actuator-<env>` and `phorvex-attacks-<env>`. Each has its own chart,
sync status, history and logs. The attacks service renders only where the console
runs, and takes the attack routes once the environment names it in
`phorvex.services.attacks.endpoint` (`docs/services/attacks.md`).
`project.yaml` limits them to this repository, each environment's namespace and
the cluster-scoped kinds the charts render there.

The root app (`../root.yaml`) watches `../apps` of the production repository,
not this directory: these manifests are applied by hand.

## Environments

An environment names its cluster, namespace and Helm release in the
ApplicationSet's list, and keeps its values in `deploy/environments/<environment>/`
(see its README).

**Staging runs beside the production stack on the production cluster**, in the
namespace `phorvex-staging` under the release name `staging`. Sharing the API
server with production, it must leave production alone, and its values see to it
(`tools/test_argocd_services.py` checks each):

- **Its own policies only.** `policyNamespaces: [phorvex-staging]`: the manager
  reconciles and ticks, the sensor lists and the actuator authorizes only the
  PhorvexPolicies of its namespace. Without the scope, the manager would write
  production's policy status and act on its policies.
- **Its own hands.** The native backend (`actuator: native`) creates no
  SecurityEvent or AMTD for production's Phoenix to act on, and changes workloads
  only in `actuatorNamespaces: [phorvex-staging]`. Production's Phoenix acts on
  every SecurityEvent, but its AMTDs cover only production's namespaces. The
  global kill switch stays on until the console and the attacks service run here.
- **No cluster-wide admission.** Its admission webhooks and the SecurityEvent
  identity policy are off, since they would also admit production's requests.
  Without that policy, no external detector is trusted.
- **No shared cluster-scoped object.** The CRDs are skipped (they are
  production's), and every ClusterRole and binding carries the release name.
- **Its own monitoring.** Its series carry `environment=staging`. Its dashboard and
  severity-info alerts filter on it, and production's one unscoped rule never sees
  its cost counter (`deploy/monitoring/README.md`).

`phorvex-demo-staging` (`demo-staging.yaml`) deploys `deploy/demo`: a stateless
`demo-api` for the services to defend, and its PhorvexPolicy, which selects only
its Pods and enables only the native backend's rotate and quarantine. Its Pods are
the console's workload attack targets (`r6th.io/rotation-target`), never a
Phorvex service Pod. The console is reachable at `staging-console.phorvex.ai`,
through its own ALB and Cognito app client.

## Applying

1. Argo CD reads this repository over HTTPS with the credential it uses for the
   production repository, in a repository Secret for this repository's URL. The
   enterprise disables deploy keys.
2. Apply `project.yaml`, then `applicationset.yaml` and `demo-staging.yaml`.

The services start in any order: the manager waits up to two minutes for each
handshake and restarts until every service answers. Deleting the ApplicationSet
removes the Applications and, through their finalizers, everything they created.

## Webhook certificate

The manager chart generates its admission webhook certificate when it finds none
(`lookup`). Argo CD renders charts without cluster access, so every render brings
a new certificate. The ApplicationSet therefore ignores the certificate Secret's
data and the webhook configurations' CA bundles, and respects those ignores on
sync. Staging's webhook is off, so this matters only to an environment that enables
it.

`tools/test_argocd_services.py` checks these manifests against the charts and
environments.
