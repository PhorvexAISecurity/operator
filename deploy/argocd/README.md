# ArgoCD — continuous delivery for the operator

ArgoCD replaced the retired `litellm`, `mock-rag-chatbot` and `phorvex-live-demo` demo
namespaces on the EKS cluster. It is the only thing that deploys to `phorvex-system`.

## How a change reaches the cluster

```
merge to main
   └─ CI builds phorvex + phorvex-console, pushes them to ECR as sha-<short>
        └─ deploy job: computes vX.Y.Z, re-tags those exact manifests as X.Y.Z,
           writes X.Y.Z into deploy/helm/phorvex-stack/values-eks.yaml, commits, tags, pushes
                └─ ArgoCD sees the new commit and syncs
                     └─ e2e-main runs the End-to-End suite against what is now serving
```

The deploy is a **commit**, not a cluster call. Every state the cluster has ever been in
has a commit that explains it, and a rollback is `git revert` — not a scramble through
shell history. The image is *re-tagged*, never rebuilt, so the artifact that ships is
byte-identical to the one CI tested.

## Layout

```
root.yaml            app-of-apps; applied once by hand, watches apps/
apps/
  phorvex-stack.yaml the Helm release in phorvex-system (release name: phorvex)
  ci-reports.yaml    the nginx host behind ci-report.phorvex.ai
install/             ArgoCD itself — kustomize, pinned to v3.4.6
```

`root.yaml` deliberately sits *outside* `apps/`. A root that watched its own directory
would manage itself, and a bad commit to it could not then be repaired by the controller
the commit had just broken.

## Bootstrap

```bash
kubectl apply -k deploy/argocd/install/          # ArgoCD + argocd.phorvex.ai ingress
kubectl -n argocd rollout status deploy/argocd-server
kubectl apply -f deploy/argocd/root.yaml         # everything else follows from this

# initial admin password
kubectl -n argocd get secret argocd-initial-admin-secret \
  -o jsonpath='{.data.password}' | base64 -d; echo
```

ArgoCD is **not** managed by ArgoCD, and its version is pinned rather than tracking
`stable`: a CD controller that silently upgrades itself is the one component whose breakage
you cannot roll back with CD.

## What ArgoCD deliberately does not own

**Phoenix** (`phoenix.enabled: false` in `values-eks.yaml`). Phoenix is unmodified
third-party software, and the copy vendored at `charts/phoenix-0.1.4.tgz` is *older* than
what runs: its CRDs were generated with controller-gen v0.16.0 while the live
`SecurityEvent` / `AdaptiveMovingTargetDefense` CRDs are v0.17.2. A `kubectl diff` of the
rendered chart against the cluster showed the sync would **delete 18 schema fields** —
`spec.baseline`, `spec.anomalyScore` and `spec.evidence` among them. Upgrade Phoenix
deliberately: refresh the vendored chart, diff it against the cluster, then flip the flag.

**The `console.phorvex.ai` ingress**, which was applied by hand and is not in the chart.
This is why `phorvex-stack` runs with `prune: false` — a prune would delete every resource
in `phorvex-system` the chart does not render, including that ingress and the Phoenix CRs
the operator writes at runtime.

**The report contents** on the `ci-reports` PVC. A report is evidence produced by a run,
not desired state.

## Adoption notes

`values-eks.yaml` was written to reproduce the running deployment exactly, so the first
sync is close to a no-op. It was verified with `kubectl diff` against the live cluster
until only one object differed: `phorvex-phorvex`, which gains back the container port
declarations, `resources.limits` and the `securityContext` that hand-patching had stripped
(the Deployment had reached generation 52 under `kubectl-patch`/`kubectl-set`/
`kubectl-rollout`). That sync restarts the operator pod once.

Several settings existed **only** as hand-patches and were not expressible in the chart at
all — `--epss-cache` and its ConfigMap volume, `--operator-namespace`, and
`PHORVEX_ACTUATOR=hybrid`. They are chart values now, which is the point: the cluster is
no longer holding configuration that git does not know about.
