# MIG rebind authority and deployment contract

`mig-rebind` is disabled by default. Enabling it requires an operator-owned profile file and the
trusted node agent configured by `phorvex.mig.nodeExec`. A tenant Pod annotation is never allocation
or profile authority.

Enabling node exec also requires `exclusiveMaintenance: true`. This is an explicit deployment
declaration that an external scheduler or maintenance process prevents new GPU allocations during
the operation; the sampled PodResources checks do not create that exclusion themselves.

The profile file is versioned JSON. Every rule maps one exact namespace and current device-plugin
resource class to one approved target geometry; wildcards and duplicate rules are rejected:

```json
{
  "version": 1,
  "rules": [
    {"namespace": "inference", "resource": "nvidia.com/mig-1g.10gb", "profile": "2g.20gb"}
  ]
}
```

The chart's optional DaemonSet has two named containers. The helper container comes from the
Phorvex manager image and is the only container with the kubelet PodResources directory mounted
read-only. The GPU container image and long-running command are supplied by DevOps. The chart
requires that privileged GPU tooling image by `repository@sha256:digest`; it ships no guessed vendor
image. The manager may exec only in the configured agent namespace, and it binds the DaemonSet UID,
Pod UID, ServiceAccount, node, labels, readiness, and both container names before every exec.
The profile file is validated and loaded once at manager startup; a profile change requires a
manager rollout, so one process never changes desired geometry midway through an operation.

Before any workload effect, the manager combines a bounded PodResources v1 `List` response with
bounded `nvidia-smi -L` inventory. The exact target namespace/name/current UID/node/resource/container
must have one MIG UUID, and that UUID must map to one physical GPU UUID. Any other NVIDIA allocation
for the target, any unknown or shared resource alias, and any other slice or whole-GPU allocation on
that physical GPU refuse the move. A legacy GPU or profile annotation, when present, is only a
matching assertion and a conflict refuses the move.

Repartition changes a whole physical GPU, so scheduling must already be under an exclusive
maintenance contract. The manager re-reads the target allocation before route removal and eviction,
waits for its release after UID-preconditioned deletion, then re-reads node-wide allocation,
inventory, agent identity, and protected receipt ownership before every destructive GPU command.
These observations are bounded samples. They are not an atomic reservation against another
scheduler, and enabling the chart does not create that reservation.

Receipt version 2 records the PodResources/profile binding. Version 1 receipts remain visible in
administrative inventory as manual-only evidence and cannot authorize destructive recovery.
Activation and hardware acceptance require an exclusive MIG-capable node fixture. A node where
`nvidia-smi` reports MIG `N/A` cannot establish that acceptance.
