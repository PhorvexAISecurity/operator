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

## What has not moved yet

The attack code still lives in package `console`. `cmd/attacks` serves it from
there, and archtest lists the `console → cataloguev1` crossing as debt until the
code moves into a package of the attacks domain.
