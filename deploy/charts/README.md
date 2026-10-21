# Service charts

One Helm chart per service (ADR-0001), each its own Argo CD Application and
version. The manager and console chart is still `phorvex/charts/phorvex`.

| Chart | Deploys |
|---|---|
| `phorvex-brain` | the brain service: no Kubernetes credentials, one replica, gRPC from the manager only |
| `phorvex-common` | library: what the services must agree on, defined once; today their Kubernetes access |

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
