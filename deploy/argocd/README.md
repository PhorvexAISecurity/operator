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

## Diagnosing a deployment that waits on an old image

`Wait for ArgoCD to roll it out` is read-only: it runs
`deploy/argocd/wait-for-rollout.sh` on the jump host (Bash, kubectl and Python 3
required). It polls the manager image up to 60 times, 15 seconds apart, then waits
up to 180 seconds for rollout readiness. API reads have a 10-second request timeout;
API/SSH latency is additional. It requires the exact released tag, not a newer one.
The console shares that Deployment, so rollout readiness also requires its readiness
probe. This is not a functional or security-effect test.

When the image is old, `automated.enabled: false` or an absent automated policy
fails immediately with a configuration diagnosis. Missing/unreadable Applications,
bad responses and unreadable Deployments also fail explicitly. ArgoCD treats an
empty automated policy or an omitted/null `enabled` field as enabled. An already
matching image may pass readiness while auto-sync is paused; the output says so.
No branch of the waiter changes the cluster or silently resumes a deliberate pause.

For recovery, inspect the exact Application source revision, sync operation/errors,
pending rendered diff, Deployment events and image tags first. `Healthy` only
describes the running resources; `Healthy/OutOfSync` can still be an old release.
After deployment authorization and diff review, explicitly resume this application's
automated policy or sync the reviewed revision. Preserve `prune: false`, existing
sync options and the audit PVC. The manifest pins `enabled: true`; verify any parent
app actually reconciles that manifest rather than assuming it enforces live state.
Re-running a completed release can create another version and invoke live E2E;
it is not a substitute for fixing sync policy.

An intentional pause must account for the parent app's desired state: record a
reviewed Git change to `enabled: false` (or use the approved maintenance procedure),
not just a UI toggle that a parent may undo. CI will not override the pause. For an
unhealthy rollout, pause further application syncs, retain audit data, and restore
the previously reviewed compatible Git values/images through the approved rollback
procedure; do not use prune/force/replace to make the status green. Verify readiness,
service endpoints, console health/version and admission TLS after recovery.

## Layout

```
root.yaml            app-of-apps; applied once by hand, watches apps/
apps/
  phorvex-stack.yaml the Helm release in phorvex-system (release name: phorvex)
  ci-reports.yaml    the nginx host behind ci-report.phorvex.ai
install/             ArgoCD itself — kustomize, pinned to v3.4.6
services/            one Application per split service (ADR-0001); not applied, see services/README.md
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
