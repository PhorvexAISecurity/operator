# Controller-managed scalar warm pool

Phorvex scalar `warm-swap` and ungrouped `model-shard-replace` require a user-owned ReplicaSet warm pool. The ReplicaSet, not Phorvex, creates replacement Pods. The supported pool size is 2 through 128 replicas. Incomplete or paginated membership and inventory beyond 128 members are refused. A capability snapshot verifies at most 128 distinct ReplicaSet identities per collection; pools beyond that bound remain unverified. The pool uses a selector that does not mention `phorvex.ai/role` or `phorvex.ai/model-loaded`, and a clean Pod template whose initial role is `warm-shadow` and model-loaded label is `false`. A Deployment may own the ReplicaSet; its rollout/scaling must remain stable during a cutover. Phorvex does not modify the workload controller, template, replica count or owner references.

For a swap group `example`, this is the essential structure (add your real container, volumes, resources, probes and model configuration):

```yaml
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: model-warm-pool
spec:
  replicas: 2
  selector:
    matchLabels:
      app: model-server
      phorvex.ai/swap-group: example
  template:
    metadata:
      labels:
        app: model-server
        phorvex.ai/swap-group: example
        phorvex.ai/role: warm-shadow
        phorvex.ai/model-loaded: "false"
      annotations:
        phorvex.ai/route-service: model-serving
        phorvex.ai/serving-port: "8000"
    spec:
      containers:
      - name: model
        image: your-model-image
        ports:
        - containerPort: 8000
---
apiVersion: v1
kind: Service
metadata:
  name: model-serving
spec:
  selector:
    app: model-server
    phorvex.ai/swap-group: example
    phorvex.ai/role: leader
  ports:
  - port: 8000
    targetPort: 8000
```

Bootstrap one ready, model-loaded template-created shadow as the initial `leader` while leaving another ready shadow in the pool. This bootstrap and the model-loaded signal are external responsibilities; the ReplicaSet template must continue creating `warm-shadow` Pods. A truthful readiness actor marks model-loaded only after the server has loaded the model. The Service routes leaders only. Other ingress/route selectors must likewise avoid routing warm or retiring Pods. Local CPU fixtures may set Kubernetes Ready and the model-loaded label explicitly to validate controller orchestration; they do not validate GPU/model-load timing.

During a cutover, avoid simultaneous scaling, rollout, parent deletion, selector/template changes, member termination or route Service changes. Phorvex refuses or retains a pending administrative receipt when it cannot confirm a stable pool. Its immediate result separates submitted serving cutover, controller-created replacement Pod observation and warm-capacity readiness. Recovery can finish a retained version-2 receipt after the verified survivor and controller pool become ready. Version-1 synthetic-clone receipts never trigger another clone Create on upgrade; unresolved partial receipts require explicit reconciliation. Removing the PhorvexPolicy does not garbage-collect workload Pods; deleting the ReplicaSet/Deployment retains ordinary Kubernetes lifecycle behavior.

This contract covers scalar paths only. Tensor/pipeline-parallel model-shard replacement has a separate group-coherent path and is not certified by the scalar pool. Recon placement cover for warm-swap and model fingerprint validation remain separate limitations.

The generic native demo creates only the ReplicaSet and leader-only Service scaffold. It reports the warm-swap case as unavailable until controller membership, initial leader selection, and serving readiness have been observed; it does not claim that a cutover ran. The isolated local-controller test covers the supported replenishment path.
