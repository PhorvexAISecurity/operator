# Service charts

One Helm chart per service (ADR-0001), each its own Argo CD Application and
version. The manager and console chart is still `phorvex/charts/phorvex`. Its
`phorvex.services.<brain|sensor|actuator>.endpoint` values point the manager at
the services; with a remote actuator it holds only the dispatcher's share of the
access below.

| Chart | Deploys |
|---|---|
| `phorvex-brain` | the brain service: no Kubernetes credentials, one replica, gRPC from the manager only |
| `phorvex-sensor` | the sensor service: its read-only access, one replica, gRPC from the manager only |
| `phorvex-actuator` | the actuator service: the actuation access and the operator-owned files it reads, one replica, gRPC from the manager only |
| `phorvex-common` | library: what the services must agree on, defined once: their Kubernetes access and trust |

## Access (`phorvex-common.rbac.objects`)

`phorvex-common.rbac.objects` renders one service's ClusterRole, Roles and bindings
from a single catalog of every permission the manager's ServiceAccount holds
today, keyed by the same `phorvex` values:

- **read verbs** (get, list, watch) go to the sensor, the dispatcher and the
  actuator, unless a rule names its readers. Secret rules always do: the
  actuator reads the serving, Voice and LiteLLM credentials it acts with; the
  sensor reads only the LiteLLM objective seeds its observation binds; the
  dispatcher reads no Secret.
- **every other verb** goes to the rule's writers: workload, SecurityEvent and
  AMTD writes, exec into the MIG agent and the protected journals to the
  actuator; policy status and finalizers, Events and the leader lease to the
  dispatcher; the operator-namespace ledgers and access reviews to both.
- service `all` is the manager acting in process: every verb, with the manager
  chart's names and labels.

`tools/test_service_charts.py` proves it against the manager chart, with the
default values and with every feature that adds access enabled
(`tools/testdata/charts/rbac-all-features.yaml`):

- mode `all` renders the manager chart's RBAC objects unchanged;
- the dispatcher, sensor and actuator together hold exactly the manager's
  access, nothing more and nothing less;
- the sensor holds no write verb, and workload writes, policy status and the
  leader lease each stay with one service.

Reads are shared for now so no service loses an inventory it reads; narrowing
them per service is a follow-up that needs per-service evidence.

## Trust (`phorvex-common.trusted*`, `phorvex-common.endpointLeaseEnv`)

The sensor and actuator handshakes compare the trusted detector and observer
identities and the endpoint lease authority with the manager's. These templates
derive them from the same `phorvex` values as the manager chart, including the
identities of the manager's own detector and observer ServiceAccounts, named
after the manager release (`managerFullname`, default `<release>-phorvex`). A
service chart therefore reads the manager chart's keys under `phorvex`, with the
same defaults, so one environment file configures every chart.

## Vendoring

Argo CD renders a chart's `charts/*.tgz`, not `deploy/charts/phorvex-common`.
After changing the library, refresh every chart that depends on it:

```sh
helm dependency update deploy/charts/phorvex-sensor
helm dependency update deploy/charts/phorvex-actuator
helm dependency update phorvex/charts/phorvex
helm dependency update deploy/helm/phorvex-stack   # re-vendors the manager chart
```

`VendoredLibraryTests` in `tools/test_service_charts.py` fails while a vendored
copy differs from the library.
