# Staging infrastructure

Staging (ADR-0001) is the vcluster `phorvex-staging`, in the namespace
`phorvex-staging` of the production cluster `phorvex-dev-eks`. A vcluster has its
own API server, so staging has its own PhorvexPolicy CRD, policies, admission
webhooks and cluster-scoped RBAC; its pods run on the production cluster's nodes.
The services' Applications (`../services`) deploy into it.

| Manifest | Creates |
|---|---|
| `project.yaml` | the AppProject `phorvex-staging-infra`: the vcluster chart and this repository, into `phorvex-staging` here and into the vcluster |
| `vcluster.yaml` | the vcluster (chart `vcluster` 0.37.3 from charts.loft.sh). Volume snapshot rules are off, so it holds no cluster-wide role here, and NetworkPolicies are synced to this cluster |
| `phoenix-crds.yaml` | the SecurityEvent and AdaptiveMovingTargetDefense CRDs inside the vcluster. No Phoenix operator runs in staging, so the defenses the services record there are not executed |

Nothing watches this directory: the production root app watches
`deploy/argocd/apps` of the production repository. These manifests and the
services' project and ApplicationSet are applied with `kubectl apply`, and two
Secrets that hold credentials are created out of band, never in git:

- **Repository access.** A repository Secret in `argocd` for
  `https://github.com/PhorvexSecurity/operator-refactored.git`. It holds the same
  HTTPS credential as the production stack's repository Secret: the enterprise's
  policy disables deploy keys. A GitHub App with read access to this repository
  alone would narrow it.
- **The cluster.** A cluster Secret in `argocd` for
  `https://phorvex-staging.phorvex-staging:443`, built from the kubeconfig the
  vcluster writes into the Secret `vc-phorvex-staging`. It carries the label
  `phorvex.ai/environment: staging`, which the services' ApplicationSet selects.

## Order

1. `project.yaml`, then `vcluster.yaml`; wait for the StatefulSet
   `phorvex-staging` to be ready.
2. The two Secrets above.
3. `phoenix-crds.yaml`.
4. `../services/project.yaml`, then `../services/applicationset.yaml`.

## Removing staging

Delete the ApplicationSet and the services' project, then `phoenix-crds.yaml`,
`vcluster.yaml` and this project, and the two Secrets. The Applications'
finalizers delete what they created. Deleting the vcluster deletes everything
inside it.
