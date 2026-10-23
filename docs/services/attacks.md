# Attacks service

The attacks service fires the catalogue attacks, runs the harness, and serves the
evidence they produce: the run records and streams, the attack records and their
observations, and the benchmark corpus built from finished runs. See
[ADR-0001](../architecture/ADR-0001-service-monorepo.md) for the service split.

The console runs it in one of two ways:

| Mode | Console flag | What serves the attack routes |
|---|---|---|
| In process (default) | none | the console itself, as before phase 6 (`console.ServiceAll`) |
| Remote | `--attacks-url=<origin>` (`PHORVEX_CONSOLE_ATTACKS_URL`) | `phorvex-attacks` (`cmd/attacks`, `console.ServiceAttacks`); the console forwards them (`console.ServiceConsole`) |

The routes the attacks service owns are marked in the console's route table
(`phorvex/internal/console/routes.go`, `attack(...)`) and listed in
`service_test.go`. A route moves between the services only by changing both.

## The boundary

The interface is the console's own HTTP/JSON API. The UI's requests and the attack
routes' contracts are unchanged; this boundary is HTTP/JSON rather than gRPC
(ADR-0001, phase 6).

A forwarding console admits the caller as it admits its own routes: authentication,
the route's method and role, and the CSRF origin check (`Server.admit`). It then
forwards the request with every header the caller sent, the signed ALB identity and
the `Origin` among them. The attacks service applies the whole boundary again,
including the tenant, target and run scope, because it holds the runs and attack
records those checks read. It therefore takes the same identity configuration as
the console (`PHORVEX_CONSOLE_ALB_*`, `PHORVEX_CONSOLE_OIDC_*`, the grant table
and the trusted origins). It serves no UI. A console route requested from it
answers 404, and an unreachable attacks service answers 502 through the console.

## Running

```sh
go -C phorvex run ./cmd/attacks --addr=:8090 --state-dir=/var/lib/phorvex-attacks
go -C phorvex run ./cmd/console --addr=:8091 --attacks-url=http://localhost:8090
```

`cmd/console` and `cmd/attacks` share their configuration
(`phorvex/cmd/internal/consoleserver`), so every console flag and variable applies
to both. The process that fires red-team SecurityEvents reaps them
(`StartRedTeamSweeper`) and recovers interrupted availability experiments. The
console keeps the uptime sampler and the decision history.

The workload live arms create their SecurityEvents as the attacks service's
ServiceAccount once it is remote. The sensor and the actuator admit those arms only
from the injector identity (`--injector-identity`, `phorvex.injectorIdentity`), so
an environment that runs the attacks service sets it to that account.

## Image and release

The `phorvex-attacks` image is the `attacks` stage of the console's Dockerfile:

```sh
docker build -f deploy/docker/console.Dockerfile --target attacks -t phorvex-attacks .
```

- **Contents.** The harness and its data, the NATS observer, the phorvex binary
  and kubectl, run as `/app/attacks`, without the UI.
- **Release.** It is released as the `attacks` component (`phorvex/attacks` in
  ECR, tags `attacks-vX.Y.Z`, `docs/services/releasing.md`).
- **Inputs.** It builds what the console's image builds, so the two share their
  inputs except the UI.

## Deploying

`deploy/charts/phorvex-attacks` deploys it beside a manager release of the same name.

- **The pod.** The chart renders the console's own Deployment template
  (`phorvex-common.consoleDeployment`), so the attacks service gets the console's
  whole configuration: identity, audit source, catalogue and live-arm environment,
  mounts. It runs it as `cmd/attacks`, with these differences:
  - its image (`image`, pinned by `digest`);
  - its ServiceAccount, Deployment and Service, all named `<release>-attacks`;
  - its own state claim, `<release>-attacks-state`;
  - its own copy of the rendered grants, `<release>-attacks-grants`. The pod reads
    them once, at startup, so they arrive in the same sync as the pod they roll;
  - `/api/health` probes, and no UI.
- **Rendering.** It renders only where `phorvex.console.enabled` is set. It reads
  the manager chart's keys under `phorvex`; its defaults are copies of the manager's,
  and `tools/test_service_charts.py` keeps them equal.
- **Network.** A NetworkPolicy admits only the console's pods.

Setting `phorvex.services.attacks.endpoint` (`<release>-attacks:8090`) in the
environment's values turns the split on in the manager chart:

- **Forwarding.** The console forwards the attack routes to that address
  (`PHORVEX_CONSOLE_ATTACKS_URL`).
- **Injector identity.** The manager, console, sensor and actuator name
  `<namespace>/<release>-attacks` as the injector, unless `phorvex.injectorIdentity`
  says otherwise. The attacks service names itself.
- **Grants.** The console keeps its reads, SecurityEvent reads and the policy
  edit. Everything it fired with moves to the attacks service's account:
  - exec into Pods, the opted-in Pod and Service changes, and creating and
    reaping SecurityEvents;
  - every live arm's and catalogue run's Roles.

  The two accounts together hold exactly what the console held.
- **Namespace scope.** `phorvex.console.attackNamespaces` confines exec, workload
  changes and policy edits, the console's and the attacks service's, to Roles in
  those namespaces. SecurityEvents are cluster-scoped, so creating them stays
  cluster-wide.
- **SecurityEvents.** SecurityEvents are cluster-scoped, so RBAC cannot confine
  them. With `attackNamespaces` set, two guards do instead:
  - A ValidatingAdmissionPolicy (`<release>-attacks-targets-*`) matches only the
    attacks service's own requests. It refuses any SecurityEvent it creates,
    changes or deletes with a target outside those namespaces. Production's
    requests never match it.
  - The red-team sweeper reaps only events every target of which is in those
    namespaces (`PHORVEX_CONSOLE_SWEEP_NAMESPACES`).
- **Exposure.** `phorvex.console.ingress` renders the console's own Service (port 80)
  and Ingress, for an environment outside the production stack's dashboard.

Four live arms pin the reviewed production console as their injector in their
profiles: `endpointLease`, `voiceAgencyLive`, `voiceOutputLive` and
`voiceMCPLive`. The chart refuses them while the attacks service is remote, until
their profiles are reviewed for its account.

## What has not moved yet

The attack code still lives in package `console`. `cmd/attacks` serves it from
there, and archtest lists the `console → cataloguev1` crossing as debt until the
code moves into `phorvex/internal/attacks`, the attacks domain's package.
[attacks-migration.md](attacks-migration.md) is the plan for that move: the
inventory of the attack routes and their files, the order and the checks.
