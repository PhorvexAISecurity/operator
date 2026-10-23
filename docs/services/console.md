# Console

The console is the operator UI and its API, behind the console's identity
boundary (`phorvex/docs/CONSOLE-AUTH.md`). It reads the manager's decision history
over the audit source's mutual TLS. Where the attacks service is remote, it forwards
the attack routes there (`attacks.md`).

## Which chart deploys it

| `phorvex.console.separate` | Deploys the console | Pins its image in |
|---|---|---|
| `false` (default) | the manager chart (`phorvex/charts/phorvex`), as part of the manager's release | the manager's values |
| `true` | its own chart (`deploy/charts/phorvex-console`), as its own Application and version | `deploy/environments/<env>/console.yaml` |

Either way the objects are the same, under the same names:
- the Deployment;
- its ServiceAccount and RBAC;
- the grants;
- the state claim;
- the Service and Ingress;
- the live arms' Roles;
- the e2e identity.

The templates live once, in the shared library (`phorvex-common.console.*`,
`phorvex-common.consoleDeployment`). Each chart renders them only on its side of
the switch. The console chart defines the manager chart's name and label helpers
identically.

`ConsoleChartTests` in `tools/test_service_charts.py` holds the two to one
rendering: the manager chart alone renders exactly what the manager chart and the
console chart render together with the switch on. Moving an environment therefore
recreates nothing. The console Deployment's selector, which Kubernetes never
changes, stays the same.

The production stack (`deploy/helm/phorvex-stack`) leaves the switch off. Staging
sets it.

## Moving an environment's console

1. In `deploy/environments/<env>/`, move the console's image pin from
   `manager.yaml` to `console.yaml`, and set `phorvex.console.separate: true` in
   `phorvex.yaml`.
2. Sync. The manager's Application stops rendering the console's objects, and the
   console's Application renders and takes them over: Argo CD tracks resources by
   annotation, and the ApplicationSet never prunes. Nothing is deleted or
   recreated.

## Releasing

The console is released as the `console` component (`releasing.md`). Its inputs
are its binaries, the web UI and its chart. The release pins it in `console.yaml`.
