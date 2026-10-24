# Environments

One directory per environment the split services run in (ADR-0001). The Argo CD
ApplicationSet `deploy/argocd/services/applicationset.yaml` deploys every service
chart to each environment it lists, with two value files:

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
| `staging` | `phorvex-dev-eks`: service namespace `phorvex-staging`, release `staging`, native actuator, explicit tenant scopes and staging monitoring | Live: demo scope. Proposed: all 12 policy namespaces; **do not merge/sync** until [DECISION.md](../../DECISION.md) is resolved. AppProject/ApplicationSet are applied separately ([service README](../argocd/services/README.md)). |

The old `operator.git` monolith remains running. Its retirement is separately
gated by [RETIREMENT-RUNBOOK.md](../../RETIREMENT-RUNBOOK.md).
