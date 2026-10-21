# Split services (ADR-0001)

`applicationset.yaml` gives every Phorvex service its own Argo CD Application on
each cluster registered for an environment: `phorvex-manager-<env>` (the manager
and console chart in remote mode), `phorvex-brain-<env>`, `phorvex-sensor-<env>`
and `phorvex-actuator-<env>`. Each has its own chart, sync status, history and
logs. `project.yaml` limits them to this repository, the `phorvex-system`
namespace and the cluster-scoped kinds the charts render.

**Nothing here is applied.** The root app (`../root.yaml`) watches `../apps` of the
production repository, and nothing watches this directory. Applying it is phase 5e
and needs separate approval.

## Environments

The cluster generator selects Argo CD clusters by the label
`phorvex.ai/environment` on their cluster Secret. Each environment's values live in
`deploy/environments/<environment>/` (see its README). Production keeps the
stack (`../apps/phorvex-stack.yaml`) until the split services have run in
staging.

**Staging is a virtual cluster on the production cluster.** It is the vcluster
`phorvex-staging` in the namespace `phorvex-staging` of `phorvex-dev-eks`. A
vcluster has its own API server, so staging has its own PhorvexPolicy CRD,
policies, admission webhooks and cluster-scoped RBAC, while its pods run on the
production cluster's nodes.

Never register the production cluster's own API server for an environment while
the stack runs there. The manager reconciles every PhorvexPolicy in its cluster
and writes their status and finalizers, so two managers would act on the same
policies, and the cluster-scoped objects would collide.

## Before applying (phase 5e)

1. **Images.** The release workflow publishes the images to ECR and pins them in
   `deploy/environments/staging/<service>.yaml` (`docs/services/releasing.md`).
2. **The staging infrastructure.** The vcluster, the Phoenix CRDs inside it,
   Argo CD's read access to this repository and the vcluster's registration with
   the label `phorvex.ai/environment: staging`: see `../staging/README.md`.
3. **Apply.** Apply `project.yaml`, then `applicationset.yaml`.

The services start in any order: the manager waits up to two minutes for each
handshake and restarts until every service answers.

## Webhook certificate

The manager chart generates its admission webhook certificate when it finds none
(`lookup`). Argo CD renders charts without cluster access, so every render brings
a new certificate. The ApplicationSet therefore ignores the certificate Secret's
data and the webhook configurations' CA bundles, and respects those ignores on
sync. The first sync installs both together, and later syncs keep them.

`tools/test_argocd_services.py` checks these manifests against the charts and
environments.
