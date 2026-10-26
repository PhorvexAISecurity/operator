# LiteLLM defense benchmark

A self-contained benchmark that stands up operator-refactored on a single **GPU VM**
with K3s, puts a GPU-backed **LiteLLM** workload under its protection, fires the
product's own catalogue foothold at that workload twice — once defended, once with the
operator's actuation off — and reports the **attacker's dwell time** and the brain's
decision parameters.

It measures the product defending a real workload; it is not an attack tool. The "attack"
is the product's catalogue foothold: a synthetic, trusted `SecurityEvent` the console
fires at a governed workload (`POST /api/workload/attack`), the same signal used against
the demo workload throughout the project. No exploit, jailbreak or model payload is
involved — the brain reads the signal and the pod's request rate, not any prompt content.

## What it shows

| Mode | operator-refactored | Outcome |
|---|---|---|
| **defended** | acting (kill switch off) | the native **rotate** actuator replaces the compromised LiteLLM pod; dwell time = fire → rotation |
| **undefended** | actuation off (kill switch engaged) | the brain still evaluates the trusted signal, but nothing acts — the attack lands and the attacker dwells for the whole observation window |

Running "undefended" as *kill switch engaged* (rather than deleting the operator) keeps the
firing and measurement path identical between the two runs, so the only difference is
whether the actuator is allowed to act. The reports state this.

## Topology (one GPU VM)

```
            K3s (single node)
┌───────────────────────────────────────────────┐
│ phorvex-system                                 │
│   bench-phorvex  = manager + in-process        │  native backend, defends `litellm`
│                    sensor/brain/actuator       │
│   bench-phorvex-console (own pod) ─ mTLS to    │  the API the foothold is fired through
│                    the manager's audit source  │
│ litellm                                        │
│   litellm (proxy, 3 replicas) ◄─ rotate target │  ◄── foothold fired here
│   vllm (GPU, 1 replica) ◄─ model upstream      │
│   demo-load ─ steady chat traffic              │  so the pod has a measured request rate
│ monitoring                                     │
│   kube-prometheus-stack                        │  the brain prices rotation on that rate
└───────────────────────────────────────────────┘
```

## Prerequisites

- A VM with an NVIDIA GPU, its **driver and the NVIDIA Container Toolkit already
  installed** (`nvidia-smi` works). K3s picks up the NVIDIA container runtime.
- Outbound internet (K3s, Helm charts, the vLLM/LiteLLM images, the model download).
- The AWS CLI, logged in to the account holding the operator-refactored ECR images
  (`aws sts get-caller-identity` works); the VM can reach ECR in `AWS_REGION`.
- Run as root (K3s install needs it).

## Run it

```sh
# 1. Install everything (idempotent). ~15–30 min the first time: K3s, the GPU plugin,
#    kube-prometheus-stack, the operator, and the model download into vLLM.
sudo deploy/benchmarks/litellm-defense/install.sh

# 2. Fire the foothold in both modes and collect the decision records.
deploy/benchmarks/litellm-defense/benchmark.sh

# 3. Build the HTML and CSV reports.
python3 deploy/benchmarks/litellm-defense/report.py
```

Outputs, written next to the scripts (git-ignored):

- `report.html` — the dwell-time contrast, the brain's decision side by side, and every
  parameter of each decision record.
- `report.csv` — one curated row per mode (dwell, containment, and the headline brain
  parameters), with the full decision record in the last column.
- `report-parameters.csv` — long format `(mode, parameter, value)`: **every** scalar in
  each decision record, so no brain/decision parameter is dropped.

## Configuration

Environment variables (defaults in parentheses), honored by all three scripts:

| Variable | Meaning |
|---|---|
| `MODEL` (`Qwen/Qwen2.5-0.5B-Instruct`) | the model vLLM serves; pick one that fits the GPU |
| `OPNS` (`phorvex-system`) | the operator's namespace |
| `RELEASE` (`bench`) | the Helm release name |
| `ECR` (`753556437180.dkr.ecr.us-east-2.amazonaws.com`) | the image registry |
| `AWS_REGION` (`us-east-2`) | the ECR region |
| `MANAGER_TAG` / `CONSOLE_TAG` | the released image tags to pull (install.sh resolves their digests) |
| `WINDOW` (`150`) | seconds benchmark.sh watches for containment before calling a run uncontained |

## The parameters in the report

`report.py` pulls these from each decision record, and lists every other scalar in
`report-parameters.csv`:

- **Outcome** — `action`, `selected`, `feasible`, `actuated`, `dispatchOutcome`,
  `dispatchReason`/`noopReason`, and the measured **dwell time** / `contained`.
- **Threat** — `threatPosture`, `eventEvidence`, the event's `threatLevel` and
  `trustVerdict`, the kill-chain `stage`, `pHold`, `preemptMargin`, `projNextStageSec`,
  `infectionFrontier`.
- **Economics / availability** — `assetValue`, `blastRadius`, `blindCost`, `cost`,
  `coverageValue`, the SLO cost ceiling and worst-case cost in the action trace, the
  rotation `flowRegime` (whether the pod's load was measured), and `killSwitch`.
- **Provenance** — the claim `scope`, `brainImage`, `gitSHA`.

## Cleaning up

```sh
helm -n phorvex-system uninstall bench
kubectl delete namespace litellm
helm -n monitoring uninstall kube-prometheus-stack
# and, to remove K3s entirely:  /usr/local/bin/k3s-uninstall.sh
```

## Two benchmarks

- `benchmark.sh` fires the generic foothold repeatedly at each workload and reports dwell
  time per attack (rotate on litellm, quarantine configured on vllm).
- `scenarios.sh` + `report-scenarios.py` run **named catalogue attacks** (ATLAS/OWASP
  mapping) against the serving workloads, each defended by its designated actuator, with
  and without the operator. Default scenarios cover Denial of AI Service (T0029), Full AI
  Model Access (T0044), Chaff spam (T0046) and a generic compromise foothold on litellm,
  plus one on vllm. Override the per-attack actuator with the `SCENARIOS` env var.

## Notes and limits

- **Actuators exercised.** The native backend implements `rotate`, `quarantine` and
  `endpoint-rotate`. In this harness **rotate** contains every serving foothold
  reproducibly (~4 s on the 3-replica litellm). **quarantine** is implemented and isolates
  a litellm pod in an isolated manual test, but did not reproduce reliably when driven
  per-attack in-run; its NetworkPolicy is `phorvex-quarantine-<hash>` (detect by the
  `app.kubernetes.io/managed-by=phorvex` label, not a pod-named policy). `endpoint-rotate`
  is supported but needs the M-35 endpoint-discovery condition, not a generic foothold.

- **Two tenants, one per namespace.** `litellm` (the 3-replica proxy) is defended with
  **rotate** and `vllm` (the single GPU model server) with **quarantine** — each in its own
  namespace, because a cluster-scoped SecurityEvent routes to a policy by its target's
  namespace. The operator watches both (`policyNamespaces`/`actuatorNamespaces`).
- **Observed result (build `manager:0.11.1`).** LiteLLM is contained cleanly: each foothold
  is rotated away in a few seconds, and with actuation off the brain decides the same rotate
  but dispatch is suppressed. vLLM is where single-replica stateful defense shows its edge:
  rotating the sole GPU pod is *emitted-unconfirmed* (the replacement cannot schedule until
  the one GPU is freed, so the operator will not tear down the only model server), and in
  this build the dedicated `vllm` tenant did not turn a foothold on its pod into a
  containment decision even though the event is attached to the pod's evidence. Independent
  containment of a single-replica GPU model server is therefore a known gap here, worth
  raising with the brain/actuator owners; a replicated model server, or node-level action,
  would not hit it.
- **The load matters.** `demo-load` keeps a request rate on LiteLLM so the brain can price
  a rotation under the SLO cost ceiling. With no load the brain prices rotation at its
  conservative bound and the SLO gate refuses it — which the report will show honestly as
  a `conformal-slo` / `missing-load` no-op.
- **The request metric.** LiteLLM's own Prometheus metrics are version-dependent and
  were absent in testing, so an nginx sidecar fronts LiteLLM in each pod and the
  nginx-prometheus-exporter turns nginx's request count into `http_requests_total` (the
  proven demo-api pattern). Traffic flows demo-load → Service → nginx → LiteLLM → vLLM.
- **Single binary.** The operator runs the sensor, brain and actuator in one process, so
  there is no inter-service gRPC and the service mTLS (`docs/services/service-tls.md`) is
  not exercised here.
