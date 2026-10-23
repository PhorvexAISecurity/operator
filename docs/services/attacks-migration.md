# Moving the attack code out of package console

The attacks service runs as its own binary, image, chart and Argo CD Application
(`attacks.md`), but its code is still package `console`. `cmd/attacks` serves it
with `console.ServiceAttacks`. This page is the plan for moving that code into
`phorvex/internal/attacks`, the attacks domain's package, which exists and is
empty but for its package comment.

## Done means

- `phorvex/internal/attacks` holds the attack routes' handlers, their state and
  their tests, and `cmd/attacks` serves them without package `console`.
- Package `console` holds no attack code. It forwards the attack routes after
  admitting the caller, to the attacks service or, in a single binary, to the
  handler `cmd` composes in.
- archtest's debt list (`phorvex/internal/archtest/boundaries_test.go`) has no
  `console → cataloguev1` entry, and no new one. The `attacks` domain may import
  shared packages and `cataloguev1`; `console` may not import `attacks`.
- The UI's requests and every route's contract are unchanged.

## Where the code is

- **Route table.** `phorvex/internal/console/routes.go`: each attack route is
  wrapped in `attack(...)`. `service_test.go` lists them, and a route moves between
  the services only by changing both.
- **Service split.** `service.go` (`ServiceAll`, `ServiceConsole`, `ServiceAttacks`,
  the forwarding proxy) and `auth_middleware.go` (`admit` for the forwarding
  console, `guard` for the full boundary).
- **Binaries.** `phorvex/cmd/console` and `phorvex/cmd/attacks` share their
  configuration through `phorvex/cmd/internal/consoleserver`.

The attack routes and the files that hold their handlers (generated from the route
table on 2026-10-23; regenerate it before starting, the table moves):

| File | Lines | Attack routes (handler) |
|---|---:|---|
| `server.go` | 1138 | `/api/suites` (`suites`)<br>`/api/catalog` (`catalog`)<br>`/api/threat-matrix` (`threatMatrix`)<br>`/api/effectiveness` (`effectiveness`)<br>`/api/frontier` (`frontier`)<br>`/api/benchmarks` (`benchmarks`)<br>`/api/posture` (`posture`)<br>`/api/rawlog` (`rawlog`)<br>`/api/matrix` (`matrix`)<br>`/api/ai-surface` (`aiSurface`)<br>`/api/reports` (`reports`)<br>`/api/runs/start` (`startRun`)<br>`/api/runs/scenario` (`startScenario`)<br>`/api/runs/functional` (`startFunctional`)<br>`/api/runs/functional/admission` (`functionalAdmission`)<br>`/api/runs/stop` (`runStop`)<br>`/api/runs/nats-reconcile` (`runNATSReconcile`)<br>`/api/runs/voice-cleanup-reconcile` (`runVoiceCleanupReconcile`)<br>`/api/runs/list` (`runsList`)<br>`/api/runs/status` (`runStatus`)<br>`/api/runs/evidence` (`runEvidence`) |
| `benchmark_sim.go` | 480 | `/api/benchmark-sim` (`benchmarkSim`) |
| `attack_results.go` | 2034 | `/api/attack-results` (`attackResults`) |
| `attack_monitoring.go` | 334 | `/api/attack-monitoring` (`attackMonitoringHandler`) |
| `availability_arms.go` | 404 | `/api/availability-arms` (`availabilityArms`) |
| `attack_compat.go` | 622 | `/api/workload/attacks` (`workloadAttacks`) |
| `runstream.go` | 196 | `/api/runs/stream` (`runStream`) |
| `vllm_attack.go` | 487 | `/api/vllm/attack` (`vllmAttack`) |
| `voice_live_memory.go` | 826 | `/api/voice/live/fire` (`voiceMemoryLiveFire`) |
| `voice_agency_live.go` | 420 | `/api/voice/agency/live/fire` (`voiceAgencyLiveFire`) |
| `voice_mcp_live.go` | 330 | `/api/voice/mcp/live/fire` (`voiceMCPLiveFire`) |
| `litellm_live.go` | 1337 | `/api/litellm/live/fire` (`liteLLMLiveFire`) |
| `litellm_output_live.go` | 1376 | `/api/litellm/output/fire` (`liteLLMOutputFire`) |
| `workload_attack.go` | 258 | `/api/workload/attack` (`workloadAttack`) |
| `scenario_fire.go` | 401 | `/api/workload/fire-scenario` (`fireScenarioLive`) |
| `arms_runner.go` | 506 | `/api/availability-arms/run` (`runArmsExperiment`) |

These files import `cataloguev1`, the crossing archtest lists as debt:
`catalogue_v1.go`, `disjoint_admission.go`, `evidence.go`, `mongo_prior_admission.go`,
`pod_bound_token_admission.go`, `pod_bound_token_cpu_admission.go`,
`pod_bound_token_cpu_post_request.go`, `pod_bound_token_cpu_reconcile.go`,
`routes.go`, `runs.go`, `runs_catalogue_v1.go`, `server.go` and
`voice_cleanup_reconcile.go`.

A handler's file is where it starts, not where it ends: most handlers call helpers
in other files, and some share state with console routes (the run history, the
state directory). Follow each handler's calls before moving it.

## Order

1. **The boundary first.** Both services apply the same authorization (principal,
   grants, `routeSpec`, tenant, target and run scope). Move it out of package
   `console` into a shared package both import, unchanged, with its tests. Every
   later step depends on it.
2. **The attacks server.** Give `internal/attacks` its own server and route table
   for the attack routes, built from the same configuration
   (`cmd/internal/consoleserver`). Start it empty and route nothing to it yet.
3. **One group at a time.** Move a group of routes with its handlers, helpers and
   tests, then switch `cmd/attacks` to serve that group from `internal/attacks`.
   Suggested groups, smallest coupling first:
   - the read-only evidence: `/api/attack-results`, `/api/attack-monitoring`,
     `/api/availability-arms`, `/api/workload/attacks`;
   - the live arms: `vllm`, `voice`, `litellm` and the workload fire routes;
   - the runs: `/api/runs/*` and their stream, with the catalogue (`cataloguev1`);
   - the corpus reads in `server.go`: `/api/effectiveness` through `/api/reports`.
4. **The single binary.** `ServiceAll` serves both halves in one process. Compose
   it in `cmd`: give the console the attacks handler to forward to in process,
   instead of importing `internal/attacks` from `console`.
5. **Remove the debt.** Delete the `console → cataloguev1` entry and the code it
   covered.

## Checks for every step

- `go test ./internal/archtest/ ./internal/console/... ./internal/attacks/...`
- `python3 -m pytest tools/test_service_charts.py tools/test_argocd_services.py`
- The staging foothold, end to end: mint the e2e token and fire
  (`deploy/argocd/services/README.md`). Then read the decision in `/api/live` and
  the actuator's effect in `phorvex-staging-demo`.

## Keep in mind

- The four live arms whose reviewed profiles pin the production console as their
  injector (`attacks.md`) stay refused while the attacks service is remote.
- The process that fires red-team SecurityEvents reaps them (the sweeper) and
  recovers interrupted availability experiments; the console keeps the uptime
  sampler and the decision history.
- Each service has its own state claim; a handler that reads console state must
  get it through the console's API, not its disk.
