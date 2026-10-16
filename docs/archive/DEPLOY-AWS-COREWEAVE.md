# DEPLOY-AWS-COREWEAVE — Runbook: extended Phoenix + the attack harness on real GPU clusters

*A step-by-step runbook to take `build/phoenix-extended` (the operator) and
`build/test-harness` (the attack/benchmark lab) from kind onto **AWS EKS** and
**CoreWeave**, run all suites, and finally exercise the 6 GPU/multi-node
capability-pending scenarios + the GPU headline numbers. Commands are exact. Everything
pulls only from what exists in the repo; **what cannot be obtained by a config swap alone
is marked `PENDING` and why.** No code is changed.*

---

## 0. Read this first — the two honest levels of a "GPU run"

The harness is environment-agnostic *by config*, but the GPU headline numbers come in two
tiers, and conflating them would be dishonest:

- **Tier A — obtainable by config swap (this runbook, Steps 1-9):** point the harness at a
  real EKS/CoreWeave cluster; capability detection passes (`GPU=true`, `MultiNode=true`,
  `MIG=…`); the **6 capability-pending scenarios now EXECUTE**, the **WarmSwap/NodeRotate
  control planes run on REAL multi-node/GPU infrastructure**, and you get **real
  cross-node NodeRotate MTTR, panic-action latency, and the full MTD-effect spectrum on
  real hardware** — plus a dollars view recomputed at your real GPU $/hr.
- **Tier B — needs a real inference workload wired in (Step 8.2, marked PENDING):** the
  *true* GPU headline numbers — **warm-swap 400s→15s downtime, `MODEL_ROTATION 3.2s`, real
  LLM-jacking GPU-utilization detection, GPU overhead %, availability %, KV-cache
  behavior** — require a **real model server (NVIDIA NIM / vLLM / Triton)** as the
  protected target *and* a **GPU-utilization emitter (DCGM → Prometheus integrator)**. The
  harness ships **CPU/mock stand-ins** (e.g. `ai1-llm-jacking` runs a `work_accrued` CPU
  proxy with `capabilityPending: true`), so on GPU those scenarios *execute* and report
  their MTD-effect, but their headline GPU number **stays PENDING** until a real workload
  is wired. This is integration work beyond a config swap.

Keep Tier A and Tier B separate in any report you produce.

---

## 1. Prerequisites

On your workstation (the machine that drives the benchmark):
- **Go 1.26+**, **kubectl**, **Helm 3**, **git**, and (for the production Helm deploy)
  **Docker** + push access to a registry the cluster can pull from (ECR / GHCR / CoreWeave
  registry).
- The repo checked out; you will run the harness from `build/test-harness/`.
- Network reachability to the cluster apiserver (the harness's `d-fullphoenix` arm runs the
  operator *locally, pinned to the cluster context* — see Step 4.2 — so the workstation must
  reach the apiserver and be able to `go build` the operator).

On the cluster:
- **Cluster-admin** kube-context (the harness creates a namespace, CRDs, RBAC, pods).
- A **GPU node pool** with the **NVIDIA device plugin** installed (so nodes advertise
  `nvidia.com/gpu`). For the multi-node scenarios, **≥2 schedulable nodes**. For MIG
  scenarios, MIG-enabled GPUs.

---

## 2. Step 1 — Get an owned cluster + kubeconfig

### AWS EKS
```sh
# Create (or identify) the cluster, then add a GPU node group (example: g5 / A10G).
eksctl create cluster --name phoenix-bench --region us-east-1 --without-nodegroup
eksctl create nodegroup --cluster phoenix-bench --region us-east-1 \
  --name gpu-ng --node-type g5.2xlarge --nodes 2 --nodes-min 2 --nodes-max 2

# NVIDIA device plugin so nodes advertise nvidia.com/gpu:
kubectl create -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.15.0/deployments/static/nvidia-device-plugin.yml

# Write kubeconfig + note the context name:
aws eks update-kubeconfig --name phoenix-bench --region us-east-1
kubectl config current-context        # e.g. arn:aws:eks:us-east-1:<acct>:cluster/phoenix-bench
```

### CoreWeave
CoreWeave is GPU-native (Kubernetes-as-a-service; GPU nodes + the device plugin are already
present). Download the kubeconfig from the CoreWeave Cloud console (or `kubectl` token), then:
```sh
export KUBECONFIG=$HOME/.kube/coreweave   # the file CoreWeave gave you
kubectl config current-context            # e.g. coreweave
kubectl get nodes -L gpu.nvidia.com/class # confirm GPU node classes (H100/A100/etc.)
```

---

## 3. Step 2 — Verify GPU / multi-node / MIG readiness

The harness's capability detector keys on exactly these signals, so verify them first:
```sh
# GPU: at least one node must advertise nvidia.com/gpu allocatable > 0
kubectl get nodes -o "custom-columns=NODE:.metadata.name,GPU:.status.allocatable.nvidia\.com/gpu"

# Multi-node: >=2 schedulable nodes
kubectl get nodes --field-selector spec.unschedulable!=true

# MIG (optional): MIG profile labels present on the node
kubectl get nodes -L nvidia.com/mig.config -L nvidia.com/gpu.product
```
If `nvidia.com/gpu` is empty, the device plugin is not running — fix that before continuing
(otherwise the GPU scenarios will keep skip-with-noting exactly as on kind).

---

## 4. Step 3 — Point the harness at the owned cluster (config only)

### 4.1 Write the per-target config
The harness reads one YAML per target. Nothing is hardcoded; the **owned/authorized
acknowledgement is required**, and the safety guard **refuses any cluster whose live
context AND apiserver host do not match** before any mutation. Create
`build/test-harness/config.eks.yaml` (or `config.coreweave.yaml`):
```yaml
kubeconfig: ""                       # "" = current KUBECONFIG/context; or an explicit path
context: "arn:aws:eks:us-east-1:<acct>:cluster/phoenix-bench"   # EXACT context name
namespace: "amtd-attack-test"        # dedicated sandbox; all attack objects confined here
ownedAck: true                       # REQUIRED — you assert you OWN/are AUTHORIZED
trialsPerArm: 20                     # >=20 for the statistical benchmark
masterSeed: 1337                     # same seed => comparable to the kind runs
phoenixSrcDir: "../phoenix-extended" # the d-fullphoenix arm builds+runs the operator from here
outDir: "out-eks"                    # results land here
# $ knobs for the dollars view — set to YOUR real GPU economics:
gpuCount: 8
dollarsPerGpuHour: 2.50              # SWAP for your EKS/CoreWeave contract rate
avoidedBreachValue: 4880000
defenderFilter: []                   # all arms
scenarioFilter: []                   # all scenarios
```

### 4.2 Prove the safety guard accepts THIS cluster and refuses others
```sh
cd build/test-harness
go run ./cmd/harness -config config.eks.yaml -dry-run   # validates guard+caps, NO mutation
```
Expected: `Safety guard OK: context=<your ctx> host=<apiserver> namespace=amtd-attack-test
ownedAck=true` and `Detected capabilities: GPU=true MultiNode=true MIG=<…> Nodes=<n>`. If
`ownedAck` is false or the live context/host doesn't match `context:`, the run **refuses** —
that is the intended guardrail, not an error.

---

## 5. Step 4 — Deploy extended Phoenix

There are two deployment paths. **For the benchmark numbers, you do NOT need the Helm
deploy** — the harness's `d-fullphoenix` arm builds and runs the operator for you (4.2/5.2).
The Helm deploy is for **production-style validation** of the operator in-cluster.

### 5.1 Production-style Helm deploy (honest caveats)
The chart lives at `build/phoenix-extended/charts/phoenix/` (chart `phoenix` v0.1.4). **Two
honest caveats before you `helm install`:**
1. The chart's **default image is the UPSTREAM operator** (`values.yaml`:
   `ghcr.io/r6security/phoenix/amtd-operator:v0.2.2`) — *not* the extended operator with
   Rotate/WarmSwap/Regenerate/NodeRotate. To run **extended** Phoenix you must build and
   push the extended operator image and override the value.
2. The chart's `templates/crds/` ships **only 2 CRDs** (AMTD + SecurityEvent). The extended
   operator needs **all 6** — install them from `config/crd/bases/` (which `controller-gen`
   generated with the new fields), and `--skip-crds` on the chart so it does not overwrite
   them with the smaller schema.

```sh
cd build/phoenix-extended

# (a) install ALL 6 extended CRDs (server-side; schemas are large):
kubectl apply --server-side --force-conflicts -f config/crd/bases/

# (b) build + push the EXTENDED operator image (kubebuilder Dockerfile at the module root):
docker build -t <your-registry>/amtd-operator-extended:local .
docker push   <your-registry>/amtd-operator-extended:local

# (c) install the chart pointed at YOUR image, skipping its 2-CRD subset:
helm install phoenix charts/phoenix \
  --namespace phoenix-system --create-namespace --skip-crds \
  --set amtd.image.repository=<your-registry>/amtd-operator-extended \
  --set amtd.image.tag=local
kubectl -n phoenix-system rollout status deploy/phoenix-amtd
```
Validate it reacts (apply an AMTD + a SecurityEvent and watch a pod rotate):
```sh
kubectl get crds | grep amtd.r6security.com   # expect amtd, securityevents, warminferencesets,
                                               # workloadbaselines, noderotations, contextmutationpolicies
```
> **If you cannot build/push an image**, skip 5.1 entirely and use 5.2 — the benchmark's
> operator path does not need a registry.

### 5.2 The benchmark's operator path (what actually produces the numbers)
The `d-fullphoenix` arm **builds `bin/manager` from `phoenixSrcDir` and runs it as a local
process pinned to the cluster context** (a minified, flattened kubeconfig — it cannot wander
off the authorized cluster), installs the CRDs, applies an AMTD, and injects the trigger
event where a scenario needs it. This is the path validated end-to-end on kind. **Do not run
the Helm-deployed operator (5.1) and the benchmark at the same time** on overlapping
PodSelectors — they would double-operate the same pods. For the benchmark, uninstall 5.1
(`helm uninstall phoenix -n phoenix-system`) or scope them to different namespaces.

---

## 6. Step 5 — Confirm capability detection flipped the 6 scenarios "on"
```sh
cd build/test-harness
go run ./cmd/harness -config config.eks.yaml -dry-run | grep -i capab
```
On kind these 6 skip-with-note; on a real GPU + multi-node cluster they become **applicable**
(no longer skipped): `ai1-llm-jacking` (CapGPU), `ai1-pillar03-panic-mutation` (CapMultiNode),
`ai2-co-location-cross-tenant` (CapGPU+CapMultiNode), `ai2-gpu-side-channel`
(CapGPU+CapMultiNode), `ai2-kvcache-poisoning-cross-session-leak` (CapGPU),
`ai2-unbounded-consumption` (CapGPU).

---

## 7. Step 6 — Run the Kubernetes attack suite (18 scenarios)
```sh
cd build/test-harness
cp config.eks.yaml config.eks.k8s.yaml
#   edit scenarioFilter to the 18 K8s scenarios (c1-*/c2-*/c3-*), or leave [] and use a
#   defenderFilter; outDir: out-eks-k8s
go run ./cmd/harness -config config.eks.k8s.yaml
```
This re-runs the Pass-A K8s benchmark on real infrastructure (same `masterSeed=1337`, so it's
directly comparable to `out-bench/`). **Real-node payoff:** the `nodeRotate` paths that were
"kind nodes are fake containers → MTTR PENDING" now execute against **real nodes**.

---

## 8. Step 7 — Run the AI attack suite (27 scenarios, the 6 now execute)

### 8.1 The full AI run (Tier A — by config swap)
```sh
cd build/test-harness
#   config.eks.ai.yaml: trialsPerArm: 20, outDir: out-eks-ai, scenarioFilter: []  (all 27)
#   you can batch + -resume exactly as on kind:
go run ./cmd/harness -config config.eks.ai.yaml -resume
```
You now get, on real hardware: all 21 CPU scenarios **plus** the 6 previously-pending ones
executing; the **MTD-effect spectrum + H1/H2/H3** across the full 27; real **cross-node
NodeRotate** behavior for `pillar03`/`co-location`; and **panic-action latency** measured
against a real cluster. The 6 scenarios still carry `capabilityPending: true` for their
**headline GPU number** — which is Tier B.

### 8.2 The GPU headline numbers — honest status

| GPU headline number | R6 claim | Tier | How to obtain |
|---|---|---|---|
| **Cross-node NodeRotate MTTR** | node-level MTD | **A (config swap)** | real multi-node EKS/CoreWeave; read `timeToActionSeconds` + the `NodeRotation` status on the real node-drain |
| **Panic MTTR (event→action latency)** | MTTR < 5 min | **A** | injected-panic path on the real cluster; read `timeToActionSeconds` (was ≈0.1 s on kind) |
| **Warm-swap downtime 400s→15s** | Adaptive Security §5.1 | **B (PENDING)** | wire a **real model server** behind a `WarmInferenceSet`, drive steady inference traffic, trigger a `WarmSwap`, and measure client-observed downtime across the leader cutover. The CPU mock has no model to load, so there is no 400 s to cut. |
| **`MODEL_ROTATION 3.2s`** | Phoenix-for-AI | **B (PENDING)** | a real model's weight-reload time on rotation; needs a real NIM/vLLM target. |
| **Real LLM-jacking GPU-util detection** | Phoenix-for-AI | **B (PENDING)** | deploy **DCGM exporter → Prometheus → the prometheus-integrator** so a real GPU-utilization spike emits a scored `SecurityEvent` (today the detector is RECEIVER-ONLY; `ai1-llm-jacking` runs a `work_accrued` CPU proxy). |
| **GPU/compute overhead 1-2%** | Phoenix-for-AI | **B (PENDING)** | measure GPU utilization with vs without Phoenix under load (currently a *swappable input* to the $ model, not a measurement). |
| **Availability 99.8%** | Proactive Security | **B (PENDING)** | a sustained-load uptime test against the real workload (out of the harness's disruption scope). |
| **KV-cache cross-session leak** | audit #11 | **B (PENDING)** | requires real LLM serving with a real KV cache. |

**To advance Tier B numbers** (beyond this repo's mocks), the additional, non-code integration
is: (1) deploy a real inference workload (NVIDIA NIM / vLLM / Triton) and label it as the AMTD
`PodSelector` target + the `WarmInferenceSet` pool; (2) deploy the **DCGM exporter** and wire
Prometheus + the `prometheus-integrator` so GPU-utilization/anomaly metrics emit scored
SecurityEvents; (3) point Phoenix's `WorkloadBaseline` at the real signed model image. Then
the warm-swap, model-rotation, GPU-util, and overhead numbers become directly measurable. The
operator-side mechanisms for all of these are **already built** (per `AI-MTD-AUDIT.md`); what's
pending is the **real GPU workload + emitter**, not Phoenix code.

---

## 9. Step 8 — Collect + read the metrics
Each run writes to its `outDir`:
```sh
cd build/test-harness/out-eks-ai     # (or out-eks-k8s)
wc -l metrics.jsonl                  # one JSON row per (scenario, defender, trial)
sed -n '1,40p' report.md             # per-arm Disruption% (95% CI), OracleHit%, dwell, MTD-effect
cat report-dollars.md                # $ROI / Schwartau / attack-reusability + H1/H2/H3
cat mitre_matrix.md                  # ATT&CK / ATLAS coverage
ls raw/                              # per-trial logs + operator_*.log (provenance)
cat provenance.json                  # every number -> its command + raw log + seed
```
Regenerate the dollars view at your **real GPU $/hr** without re-running anything:
```sh
go run ./cmd/harness -dollars-from out-eks-ai/metrics.jsonl
#   (edit gpuCount / dollarsPerGpuHour / avoidedBreachValue in the config first; the
#    GPU-overhead $/yr and security-per-cost recompute from those swappable knobs)
```
Because `masterSeed=1337` matches the kind runs, the EKS/CoreWeave `metrics.jsonl` is
**directly comparable** to `out-bench/` and `out-ai-bench/` — same schema, same seeds.

---

## 10. Honest summary of what this runbook delivers vs. defers

- **Delivered by config swap (Tier A):** the operator validated on EKS/CoreWeave; the full
  K8s + AI suites on real GPU/multi-node hardware; the **6 capability-pending scenarios
  executing**; **real cross-node NodeRotate + panic MTTR**; and a $ view at your real GPU
  economics — all reproducible from `masterSeed=1337` and comparable to the kind benchmarks.
- **Deferred to a real-workload integration (Tier B, honestly PENDING):** warm-swap
  downtime (400→15s), `MODEL_ROTATION 3.2s`, real LLM-jacking GPU-utilization detection,
  GPU overhead %, availability %, and KV-cache behavior — each needs a real model server +
  GPU-utilization emitter wired to Phoenix; the **operator mechanisms are built**, the
  **real GPU workload is the missing input**, and the harness ships CPU/mock stand-ins so
  it never fabricates these numbers.
- **The Phorvex arm** remains the reserved `d-phorvex-slot`; when it exists it drops in as
  one file and fills its column in every report above with zero harness changes.

*Sources: the harness config model (`build/test-harness/internal/config`), capability
detector (`internal/capability`), and CLI (`cmd/harness`); the Helm chart
(`build/phoenix-extended/charts/phoenix`); the capability classes + GPU-pending list
(`build/AI-MTD-AUDIT.md`, `build/EFFECTIVENESS-AI.md`); and the scenario capability tags
(`build/test-harness/scenarios/ai*.go`). No code was changed to write this runbook.*
