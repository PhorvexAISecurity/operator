# Quarantine attempt: preflight blocked

Deployment: Phorvex 0.4.95; source 743a9d46b840543916cbb3d7e044b4bc4518f29c;
manager image digest sha256:e69abb524801cdc76fb8c603085c0243ff1ba8db9722e14a04571fc237c46e61.

The GP10 stateful-foothold experiment did not enter its attack phase. The
pre-registered network-enforcement control failed before Phorvex enrollment:
HTTP to canary-2 succeeded before, during and after an ingress+egress deny-all
NetworkPolicy. The selected pod label matched. The aws-eks-nodeagent DaemonSet
explicitly runs with `--enable-network-policy=false`.

This reproduces the environmental limitation documented by M-50. It does not
establish a new optimizer defect or that Phorvex selected quarantine in this run.
No foothold marker or SecurityEvent was injected, and no fixture PhorvexPolicy
was created after the failed control. Brain response is NOT TESTED.

A second prerequisite remains: no deployed general foothold detector was found;
visible detectors cover LoRA inventory and KV canaries. The current brain trusts
admission-stamped allowlisted detector identities, not a self-declared event
source. An SSH-user event would not be a valid positive brain stimulus. Trust
configuration and credentials were not changed or borrowed to manufacture a hit.

Evidence: setup.jsonl (fixture and exact commands), control.jsonl (three HTTP
observations and deny-all creation/removal), diagnosis.jsonl (CNI flag and pod
selector), pin-trace.json (observed embedded source), cleanup.jsonl (removal).

Scope: disposable three-replica StatefulSet plus probe, fake data in emptyDir,
existing CPU node. No production workload, policy, operator or CNI changes.
