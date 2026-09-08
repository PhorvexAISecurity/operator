# G1 — MIG rebind

Require MIG-capable hardware, wired transport, authorized target ownership and
independent partition/isolation probes. A GPU resource count or time-sliced T4
is not evidence of MIG. Confirm this attack's mechanism applies to the hardware;
a named side-channel paper/CVE is not sufficient by itself.

Pre-register placement, isolation, capacity and serving postconditions. Within
approved limits, trigger rebind and verify partition/device mapping, workload
recovery and the attacker's measured capability after the move. Observe failure
and recovery paths without affecting unrelated GPU tenants.

Unavailable hardware/transport is BLOCKED, never PASS. Abort on out-of-scope device
changes. Restore allocation and validate all affected workloads. Historical G1
was hardware-gated; it supplies no successful live-effect baseline.
