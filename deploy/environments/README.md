# Environments

One directory per environment the split services run in (ADR-0001). The Argo CD
ApplicationSet `deploy/argocd/services/applicationset.yaml` deploys every service
chart to each cluster registered for an environment, with two value files:

| File | Read by | Holds |
|---|---|---|
| `phorvex.yaml` | every chart | the manager chart's keys under `phorvex`: the service endpoints, the trust, the decision values and the features that decide each service's access |
| `<service>.yaml` | that service's chart | its own values, such as its image |

The brain, sensor and actuator charts read the manager chart's keys under the same
name, so the values their handshakes compare are set once and cannot diverge.
`tools/test_argocd_services.py` renders every chart of every environment from these
files.

| Environment | Cluster | State |
|---|---|---|
| `staging` | the vcluster `phorvex-staging` on `phorvex-dev-eks`, registered in Argo CD with the cluster Secret label `phorvex.ai/environment: staging` | written, not applied (phase 5e) |

Production keeps running the stack in `deploy/helm/phorvex-stack` until the split
services have run in staging.
