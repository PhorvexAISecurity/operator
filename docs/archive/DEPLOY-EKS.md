# DEPLOY-EKS — Production runbook: the Phorvex stack on AWS EKS (or any Kubernetes)

Stand up the full Phorvex stack on a real cluster: the **Phorvex operator** (the
deterministic brain), the **extended Phoenix operator** (the AMTD executor it emits CRs
to), and the **read-only console/dashboard**. Signal-source integrators
(time-based-trigger, Falco, KubeArmor, Prometheus) are an optional final step.

> This is the *operator stack* runbook. For driving the GPU attack/benchmark **harness**
> on real GPU clusters, see [DEPLOY-AWS-COREWEAVE.md](DEPLOY-AWS-COREWEAVE.md) — a
> separate concern.

---

## 0. What gets deployed

| Component | Image (built from) | Role | K8s objects |
|---|---|---|---|
| Phorvex operator | `deploy/docker/operator.Dockerfile` (`phorvex/`) | The brain: ingest → decide → emit | Deployment, SA, ClusterRole, `PhorvexPolicy` CRD |
| Phoenix operator | upstream `ghcr.io/r6security/phoenix/amtd-operator` (or `build/phoenix-extended/Dockerfile`) | The executor: runs AMTD moves | Deployment, SA, RBAC, `SecurityEvent` + `AdaptiveMovingTargetDefense` CRDs |
| Console / dashboard | `deploy/docker/console.Dockerfile` (`dashboard-web/` + `phorvex/cmd/console`) | Read-only report/metrics/audit viewer | Deployment, Service, optional Ingress |

Dependency order (handled automatically by Helm, which installs CRDs before workloads):
**Phoenix CRDs → Phorvex CRD → operators → dashboard.** Phorvex registers the Phoenix
`SecurityEvent`/`AMTD` schemes at startup, so those CRDs must exist first.

### Why the operator image needs a repo-root build context
`phorvex/go.mod` has `replace github.com/r6security/phoenix => ../build/phoenix-extended`.
The image therefore compiles **two modules** and must see both at their relative paths.
Both Dockerfiles set the build context to the **repo root** (the deploy scripts do this
for you); a `.dockerignore` keeps the context lean. Both modules declare `go 1.26.1`, so
the images use `golang:1.26` (not the upstream Phoenix `golang:1.24`).

---

## 1. Prerequisites

On the machine driving the deploy:

- **awscli v2** (`aws configure` done, with ECR + EKS + IAM permissions)
- **eksctl** ≥ 0.190
- **kubectl** ≥ 1.30
- **helm** ≥ 3.14
- **docker** with **buildx** (for cross-arch `linux/amd64` builds from an Apple-silicon Mac)
- **envsubst** (ships with gettext: `brew install gettext` if missing)

Quick check:
```sh
for t in aws eksctl kubectl helm docker; do command -v $t || echo "MISSING: $t"; done
docker buildx version
```

Already in this environment: `kubectl`, `helm`, `docker`, `node`, `npm`.
You will need to install **eksctl** and **awscli** before Step 2.

---

## 2. One-shot deploy

From the repo root:

```sh
cd deploy/eks

# (optional) override defaults — see env.sh for the full list
export AWS_REGION=us-east-1
export CLUSTER_NAME=phorvex

./01-create-cluster.sh        # ~15-20 min; idempotent (reuses an existing cluster)
./02-ecr-build-push.sh        # builds + pushes phorvex + phorvex-console to ECR
./03-deploy.sh                # helm upgrade --install the whole stack
./04-integrators.sh           # OPTIONAL signal sources (default: time-based-trigger)
```

Each script `source`s `env.sh` and is safe to re-run. Defaults:
`AWS_REGION=us-east-1`, `CLUSTER_NAME=phorvex`, namespace `phorvex-system`,
release `phorvex`, image tags `0.1.0` (Phoenix `v0.2.3`).

---

## 3. Step-by-step (what each script does)

### 3.1 `01-create-cluster.sh` — cluster + kubeconfig
Creates an EKS cluster from [deploy/eks/cluster.yaml](deploy/eks/cluster.yaml) (2× `t3.large`
managed nodes, OIDC enabled, vpc-cni/coredns/kube-proxy/ebs-csi add-ons), then runs
`aws eks update-kubeconfig`. The operators are tiny (10m CPU / 64Mi requested each), so
this CPU-only pool is plenty. **No GPU pool is needed to run the stack** — add one only
for the GPU benchmark scenarios (see DEPLOY-AWS-COREWEAVE.md).

> **Already have a cluster?** Skip this script. Just make sure
> `kubectl config current-context` points at your cluster, then go to Step 3.2.

### 3.2 `02-ecr-build-push.sh` — build + push images
- Resolves your account id and ECR registry host (`<acct>.dkr.ecr.<region>.amazonaws.com`).
- Creates ECR repos `phorvex` and `phorvex-console` (scan-on-push).
- `docker login` to ECR, then `docker buildx build --platform linux/amd64 --push` for both
  images from the **repo root** context.
- Phoenix stays on its public ghcr image by default. To push the *extended* Phoenix into
  your ECR instead: `BUILD_PHOENIX=true ./02-ecr-build-push.sh`.
- Building on Graviton/arm nodes? `PLATFORM=linux/arm64 ./02-ecr-build-push.sh`.

### 3.3 `03-deploy.sh` — Helm install
- `helm dependency build` vendors the Phoenix + Phorvex subcharts into the umbrella chart
  [deploy/helm/phorvex-stack](deploy/helm/phorvex-stack).
- `helm upgrade --install` into `phorvex-system`, wiring every image to your ECR registry
  via `--set`. `--wait` blocks until rollouts are healthy.
- Prints the CRDs and the port-forward command for the dashboard.

Pass extra Helm flags straight through, e.g. expose the dashboard via an AWS load balancer:
```sh
./03-deploy.sh --set dashboard.service.type=LoadBalancer
```

### 3.4 `04-integrators.sh` — optional signal sources
Applies `time-based-trigger` by default (self-contained). Falco/KubeArmor are privileged
DaemonSets that require those tools installed first; Prometheus requires an in-cluster
Prometheus plus setting `phorvex.phorvex.prometheusUrl`. The script prints the exact
prerequisites for each. Select with `INTEGRATORS="falco kubearmor" ./04-integrators.sh`.

---

## 4. Verify

```sh
kubectl -n phorvex-system get pods,svc
kubectl get crd | grep -E 'phorvex.ai|amtd.r6security.com'
#   phorvexpolicies.phorvex.ai
#   securityevents.amtd.r6security.com
#   adaptivemovingtargetdefenses.amtd.r6security.com

# operator logs (should show the decision loop ticking on baseInterval)
kubectl -n phorvex-system logs deploy/phorvex-phorvex-manager

# dashboard
kubectl -n phorvex-system port-forward svc/phorvex-console 8090:80
open http://localhost:8090
```

Create a policy to make the brain act on a namespace (sample CRDs live in
[phorvex/config/samples](phorvex/config/samples)):
```sh
kubectl apply -f phorvex/config/samples/
```

---

## 5. Operational knobs (Helm values)

Set via `./03-deploy.sh --set <key>=<val>` or a custom `-f values.override.yaml`.
Full list: [deploy/helm/phorvex-stack/values.yaml](deploy/helm/phorvex-stack/values.yaml).

| Key | Default | Meaning |
|---|---|---|
| `phorvex.phorvex.globalKillSwitch` | `false` | `true` = observe-only; the brain decides but emits **no** AMTD CRs (FR8). Use for a dry-run rollout. |
| `phorvex.phorvex.baseInterval` | `10s` | Decision-loop cadence. |
| `phorvex.phorvex.leaderElect` | `true` | HA single-active controller. |
| `phorvex.phorvex.prometheusUrl` | `""` | Prometheus base URL for telemetry ingest (empty = K8s-only signals, no fabricated metrics). |
| `dashboard.service.type` | `ClusterIP` | `LoadBalancer` for an external IP on EKS. |
| `dashboard.ingress.enabled` | `false` | ALB/nginx ingress; set `dashboard.ingress.host`. |
| `phoenix.enabled` / `phorvex.enabled` / `dashboard.enabled` | `true` | Toggle individual components. |

**Safe first rollout:** install with `--set phorvex.phorvex.globalKillSwitch=true`, watch
the decision logs + dashboard to confirm the brain's choices look right, then re-run
`./03-deploy.sh` without the flag to let it actuate.

---

## 6. The dashboard's data is a baked snapshot

The console is a **read-only** viewer. Its image bakes the current
`build/test-harness/out-*` metrics and `phorvex/bin/console-audit.jsonl` at
`/data` (see [deploy/docker/console.Dockerfile](deploy/docker/console.Dockerfile)). It does
**not** read live cluster state. To refresh what the dashboard shows, re-run the harness
locally to regenerate `out-*`, then rebuild + redeploy the console image
(`./02-ecr-build-push.sh && ./03-deploy.sh`). Wiring the console to live cluster metrics is
future integration work, not covered here.

---

## 7. Teardown

```sh
helm -n phorvex-system uninstall phorvex
kubectl delete ns phorvex-system
# CRDs are cluster-scoped — remove explicitly if you want them gone:
kubectl delete crd phorvexpolicies.phorvex.ai \
  securityevents.amtd.r6security.com adaptivemovingtargetdefenses.amtd.r6security.com
# the cluster itself:
eksctl delete cluster --name "${CLUSTER_NAME:-phorvex}" --region "${AWS_REGION:-us-east-1}"
```

---

## 8. Non-EKS Kubernetes (existing cluster / kind / GKE / AKS)

The Helm chart is cloud-agnostic. Only Steps 1–2 are AWS-specific:

1. Skip `01-create-cluster.sh`; point `kubectl` at your cluster.
2. Build + push to **any** registry your cluster can pull from:
   ```sh
   REG=ghcr.io/yourorg
   docker buildx build --platform linux/amd64 -f deploy/docker/operator.Dockerfile -t $REG/phorvex:0.1.0 --push .
   docker buildx build --platform linux/amd64 -f deploy/docker/console.Dockerfile  -t $REG/phorvex-console:0.1.0 --push .
   ```
3. Install, pointing images at your registry:
   ```sh
   helm dependency build deploy/helm/phorvex-stack
   helm upgrade --install phorvex deploy/helm/phorvex-stack -n phorvex-system --create-namespace \
     --set global.registry=$REG \
     --set phorvex.phorvex.image.repository=$REG/phorvex \
     --set dashboard.image.repository=$REG/phorvex-console
   ```

For **kind**, you can side-load images instead of pushing
(`kind load docker-image $REG/phorvex:0.1.0`) and leave `global.registry` empty.

---

## 9. Artifacts created for this deploy

```
.dockerignore                              # lean build context (repo root)
deploy/
  docker/operator.Dockerfile               # Phorvex operator (multi-module, go 1.26)
  docker/console.Dockerfile                # Next.js export + Go console + data snapshot
  helm/phorvex-stack/                       # umbrella chart (phoenix + phorvex subcharts + dashboard)
    Chart.yaml  values.yaml  templates/dashboard.yaml  templates/_helpers.tpl
  eks/
    env.sh  cluster.yaml
    01-create-cluster.sh  02-ecr-build-push.sh  03-deploy.sh  04-integrators.sh
```
